#!/usr/bin/env python3
"""traffic-mix.py - realistic traffic for the ECMP testbed.

Unlike ping or iperf, this traffic has the pauses that real traffic has, so
flows can move between links (bpfc-ecmp only moves a flow during a pause of at
least `gap`, 50 ms by default).

  serve   on the data side (H1): sends what clients ask for, echoes voice
  run     on the client side (H2): starts sessions of each kind

Kinds (data flows server -> client):
  video   adaptive streaming: a segment every few seconds, downloaded at full
          speed, idle until the next (on/off, the best case for moves)
  web     page loads: Poisson arrivals, 1-4 objects per connection, sizes
          heavy-tailed (bounded Pareto: most a few kB, a few several MB)
  bulk    large transfers with think time between them
  voice   RTP-like UDP, 50 packets/s each way, never idle (never moved)

Each session binds to the next address of --src-pool, so l3 modes see many
flows. Every interval it prints throughput per kind and the pauses seen
between transfers, which tell whether moves are possible.

Only the Python standard library is used (3.6+).
"""
import argparse, collections, json, math, os, random, select, signal, socket
import struct, sys, threading, time

KINDS = ("video", "web", "bulk", "voice")
DEFAULT_DSCP = {"video": 34, "web": 0, "bulk": 8, "voice": 46}  # AF41, BE, CS1, EF
PROFILES = {
    # video sessions, web pages/s, bulk sessions, voice calls
    "light": dict(video=6, web=2.0, bulk=1, voice=2),
    "mixed": dict(video=20, web=6.0, bulk=3, voice=4),
    "heavy": dict(video=40, web=15.0, bulk=6, voice=8),
}
CHUNK = 256 * 1024
ZERO = bytes(CHUNK)
STOP = threading.Event()


# ---------------------------------------------------------------- server
def set_tos(sock, tos):
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos)
    except OSError:
        pass


def serve_conn(conn):
    """Requests are lines "<bytes> <tos>"; the reply is that many bytes."""
    tos_now = -1
    f = conn.makefile("rb")
    try:
        for line in f:
            parts = line.split()
            if len(parts) != 2:
                return
            n, tos = int(parts[0]), int(parts[1]) & 0xFC
            if tos != tos_now:
                set_tos(conn, tos)
                tos_now = tos
            view = memoryview(ZERO)
            while n > 0:
                k = conn.send(view[:min(n, CHUNK)])
                n -= k
    except (OSError, ValueError):
        pass
    finally:
        try:
            f.close()
            conn.close()
        except OSError:
            pass


def voice_echo(port, bind):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 1)
    s.bind((bind, port))
    while not STOP.is_set():
        r, _, _ = select.select([s], [], [], 0.5)
        if not r:
            continue
        data, anc, _, addr = s.recvmsg(2048, socket.CMSG_SPACE(1))
        tos = 0
        for lvl, typ, val in anc:
            if lvl == socket.IPPROTO_IP and typ == socket.IP_TOS and val:
                tos = val[0]
        try:
            s.sendmsg([data], [(socket.IPPROTO_IP, socket.IP_TOS, struct.pack("i", tos & 0xFC))], 0, addr)
        except OSError:
            set_tos(s, tos & 0xFC)
            s.sendto(data, addr)


def cmd_serve(a):
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((a.bind, a.port))
    ls.listen(1024)
    threading.Thread(target=voice_echo, args=(a.port, a.bind), daemon=True).start()
    print("serving on %s:%d (tcp data, udp voice echo)" % (a.bind or "*", a.port), flush=True)
    signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    try:
        while not STOP.is_set():
            r, _, _ = select.select([ls], [], [], 0.5)
            if r:
                c, _ = ls.accept()
                c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                threading.Thread(target=serve_conn, args=(c,), daemon=True).start()
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------- client side
class Stats:
    """Per kind: bytes, transfers, active sessions, pauses between transfers."""

    def __init__(self):
        self.lock = threading.Lock()
        self.bytes = collections.Counter()
        self.done = collections.Counter()
        self.active = collections.Counter()
        self.errors = collections.Counter()
        self.gaps = collections.defaultdict(list)        # seconds, since last report
        self.allgaps = collections.defaultdict(list)     # a sample of every pause, for the total
        self.ngaps = collections.Counter()
        self.nmovable = collections.Counter()
        self.extra = collections.defaultdict(collections.Counter)

    def add(self, kind, field, n=1):
        with self.lock:
            getattr(self, field)[kind] += n

    def gap(self, kind, sec):
        with self.lock:
            self.gaps[kind].append(sec)
            self.ngaps[kind] += 1
            if sec >= GAP_THRESHOLD[0]:
                self.nmovable[kind] += 1
            g = self.allgaps[kind]
            if len(g) < 20000:
                g.append(sec)
            else:                                        # reservoir sample
                j = random.randrange(self.ngaps[kind])
                if j < len(g):
                    g[j] = sec

    def x(self, kind, key, n=1):
        with self.lock:
            self.extra[kind][key] += n


ST = Stats()
GAP_THRESHOLD = [0.05]


def err(kind):
    if not STOP.is_set():                                # a transfer cut off by the stop is not an error
        ST.add(kind, "errors")


class Pool:
    def __init__(self, addrs):
        self.addrs = addrs or [""]
        self.i = 0
        self.lock = threading.Lock()

    def next(self):
        with self.lock:
            a = self.addrs[self.i % len(self.addrs)]
            self.i += 1
            return a


def parse_pool(spec):
    """a.b.c.d-a.b.c.e, comma lists, or empty."""
    out = []
    for part in filter(None, (spec or "").split(",")):
        if "-" in part:
            lo, hi = part.split("-")
            a = struct.unpack("!I", socket.inet_aton(lo))[0]
            b = struct.unpack("!I", socket.inet_aton(hi))[0]
            out += [socket.inet_ntoa(struct.pack("!I", x)) for x in range(a, b + 1)]
        else:
            socket.inet_aton(part)
            out.append(part)
    return out


class Conn:
    """A persistent connection that fetches objects; counts bytes as they arrive."""

    def __init__(self, a, kind, src):
        self.kind = kind
        self.tos = a.dscp[kind] << 2
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        set_tos(self.s, self.tos)
        if src:
            self.s.bind((src, 0))
        self.s.settimeout(30)
        self.s.connect((a.server, a.port))
        self.buf = bytearray(CHUNK)

    def fetch(self, n):
        self.s.sendall(b"%d %d\n" % (n, self.tos))
        left = n
        while left > 0:
            if STOP.is_set():
                raise OSError("stopped")
            k = self.s.recv_into(self.buf, min(left, CHUNK))
            if k == 0:
                raise OSError("closed")
            left -= k
            ST.add(self.kind, "bytes", k)
        ST.add(self.kind, "done")

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def wait(sec):
    return STOP.wait(max(sec, 0))


def video_session(a, pool, rng):
    """Buffer-based player: fill to `target`, then one segment per segment time."""
    ladder = a.video_ladder
    seg, target = a.segment, a.video_buffer
    rung = rng.randrange(len(ladder))
    est = None
    wait(rng.uniform(0, seg))
    while not STOP.is_set():
        try:
            c = Conn(a, "video", pool.next())
        except OSError:
            err("video"); wait(1); continue
        ST.add("video", "active")
        buffer, last_end = 0.0, None
        try:
            for _ in range(a.video_segments):
                n = int(ladder[rung] * 1e6 * seg / 8)
                t0 = time.monotonic()
                if last_end is not None:
                    ST.gap("video", t0 - last_end)
                c.fetch(n)
                t1 = time.monotonic()
                last_end = t1
                dt = t1 - t0
                buffer -= dt
                if buffer < 0:
                    if est is not None:                  # not the start-up
                        ST.x("video", "stalls"); ST.x("video", "stall_ms", int(-buffer * 1000))
                    buffer = 0.0
                buffer += seg
                tp = n * 8 / max(dt, 1e-6)
                est = tp if est is None else 0.7 * est + 0.3 * tp
                # adapt: the highest rung below 80 % of what the link gave, one step at a time
                want = max([i for i, r in enumerate(ladder) if r * 1e6 <= 0.8 * est] or [0])
                if buffer < seg:
                    want = min(want, rung - 1)
                rung = max(0, min(want, rung + 1))
                ST.x("video", "segments"); ST.x("video", "kbit_sum", int(ladder[rung] * 1000))
                if buffer > target:
                    if wait(buffer - target):
                        break
                    buffer = target
        except OSError:
            err("video")
        finally:
            c.close()
            ST.add("video", "active", -1)


def bounded_pareto(rng, alpha, lo, hi):
    u = rng.random()
    return int(lo / (1 - u * (1 - (lo / hi) ** alpha)) ** (1 / alpha))


def web_page(a, pool, rng, sem):
    try:
        c = Conn(a, "web", pool.next())
    except OSError:
        err("web"); sem.release(); return
    ST.add("web", "active")
    try:
        last = None
        for _ in range(rng.randint(1, 4)):
            if last is not None:
                think = rng.expovariate(1 / 0.05)        # a browser parsing: short
                wait(think)
                ST.gap("web", time.monotonic() - last)
            c.fetch(bounded_pareto(rng, a.web_alpha, a.web_min, a.web_max))
            last = time.monotonic()
    except OSError:
        err("web")
    finally:
        c.close()
        ST.add("web", "active", -1)
        sem.release()


def web_arrivals(a, pool, rng):
    sem = threading.Semaphore(a.web_max_open)
    while not STOP.is_set():
        if wait(rng.expovariate(a.web)):
            return
        if not sem.acquire(blocking=False):
            ST.x("web", "refused")                       # too many open: skip this page
            continue
        threading.Thread(target=web_page, args=(a, pool, random.Random(rng.random()), sem), daemon=True).start()


def bulk_session(a, pool, rng):
    wait(rng.uniform(0, a.bulk_think))
    while not STOP.is_set():
        try:
            c = Conn(a, "bulk", pool.next())
        except OSError:
            err("bulk"); wait(1); continue
        ST.add("bulk", "active")
        try:
            for _ in range(rng.randint(2, 6)):           # a few transfers per connection
                mu = math.log(a.bulk_size)
                n = int(min(max(rng.lognormvariate(mu, 0.8), 1e6), 20 * a.bulk_size))
                c.fetch(n)
                t = time.monotonic()
                if wait(rng.expovariate(1 / a.bulk_think)):
                    break
                ST.gap("bulk", time.monotonic() - t)
        except OSError:
            err("bulk")
        finally:
            c.close()
            ST.add("bulk", "active", -1)


def voice_call(a, pool, rng):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    set_tos(s, a.dscp["voice"] << 2)
    src = pool.next()
    try:
        s.bind((src, 0))
    except OSError:
        err("voice"); s.close(); return
    s.setblocking(False)
    payload = bytes(172)                                  # RTP header + 20 ms of G.711
    ST.add("voice", "active")
    nxt = time.monotonic() + rng.uniform(0, 0.02)
    seq = 0
    try:
        while not STOP.is_set():
            now = time.monotonic()
            if now >= nxt:
                s.sendto(struct.pack("!Hd", seq & 0xFFFF, now) + payload[10:], (a.server, a.port))
                seq += 1
                ST.x("voice", "sent")
                nxt += 0.02
            r, _, _ = select.select([s], [], [], max(0, nxt - time.monotonic()))
            while r:
                try:
                    d = s.recv(2048)
                except BlockingIOError:
                    break
                ST.add("voice", "bytes", len(d))
                ST.x("voice", "received")
                ST.x("voice", "rtt_us", int((time.monotonic() - struct.unpack("!Hd", d[:10])[1]) * 1e6))
    finally:
        s.close()
        ST.add("voice", "active", -1)


def pct(v, p):
    if not v:
        return None
    v = sorted(v)
    return v[min(len(v) - 1, int(p / 100 * len(v)))]


def report(a, t_start, last, final=False):
    now = time.monotonic()
    with ST.lock:
        b = dict(ST.bytes)
        if final:
            gaps = {k: list(v) for k, v in ST.allgaps.items()}
            ngaps, nmov = dict(ST.ngaps), dict(ST.nmovable)
        else:
            gaps = {k: list(v) for k, v in ST.gaps.items()}
            ngaps = {k: len(v) for k, v in gaps.items()}
            nmov = {k: sum(1 for x in v if x >= a.gap_threshold) for k, v in gaps.items()}
            ST.gaps.clear()
        extra = {k: dict(v) for k, v in ST.extra.items()}
        act, done, errs = dict(ST.active), dict(ST.done), dict(ST.errors)
    dt = now - last["t"]
    rows = []
    for k in KINDS:
        if not getattr(a, k):
            continue
        rate = (b.get(k, 0) - (0 if final else last["b"].get(k, 0))) * 8 / ((now - t_start) if final else dt)
        g = gaps.get(k, [])
        movable = nmov.get(k, 0)
        e = extra.get(k, {})
        row = dict(kind=k, mbit_s=round(rate / 1e6, 2), active=act.get(k, 0), transfers=done.get(k, 0),
                   errors=errs.get(k, 0), pauses=ngaps.get(k, 0),
                   pause_median_ms=None if not g else round(pct(g, 50) * 1000),
                   pauses_ge_gap=movable)
        if k == "video" and e.get("segments"):
            row["avg_bitrate_mbit"] = round(e["kbit_sum"] / e["segments"] / 1000, 2)
            row["stalls"] = e.get("stalls", 0)
        if k == "voice" and e.get("sent"):
            row["loss_pct"] = round(100 * (1 - e.get("received", 0) / e["sent"]), 2)
            row["rtt_ms"] = round(e.get("rtt_us", 0) / max(e.get("received", 1), 1) / 1000, 1)
        if k == "web" and e.get("refused"):
            row["pages_skipped"] = e["refused"]
        rows.append(row)
    last["t"], last["b"] = now, b
    if a.json:
        print(json.dumps(dict(t=round(now - t_start, 1), final=final, kinds=rows)), flush=True)
        return
    title = "total over %.0f s" % (now - t_start) if final else "t=%.0f s" % (now - t_start)
    print("%-6s %8s %6s %9s %7s %13s %10s  %s" % (title.split()[0] if not final else "TOTAL",
          "Mbit/s", "active", "transfers", "pauses", "pause median", ">= gap", "notes"))
    for r in rows:
        notes = []
        if "avg_bitrate_mbit" in r:
            notes.append("bitrate %.1fM, %d stalls" % (r["avg_bitrate_mbit"], r["stalls"]))
        if "loss_pct" in r:
            notes.append("loss %.2f%%, rtt %.1f ms" % (r["loss_pct"], r["rtt_ms"]))
        if r.get("pages_skipped"):
            notes.append("%d pages skipped (max open)" % r["pages_skipped"])
        if r["errors"]:
            notes.append("%d errors" % r["errors"])
        print("%-6s %8.2f %6d %9d %7d %13s %10d  %s" % (
            r["kind"], r["mbit_s"], r["active"], r["transfers"], r["pauses"],
            "-" if r["pause_median_ms"] is None else "%d ms" % r["pause_median_ms"],
            r["pauses_ge_gap"], ", ".join(notes)))
    print(flush=True)


def cmd_run(a):
    p = PROFILES[a.profile]
    for k in ("video", "web", "bulk", "voice"):
        if getattr(a, k) is None:
            setattr(a, k, p[k])
    a.dscp = dict(DEFAULT_DSCP)
    for d in a.dscp_set or []:
        k, v = d.split("=")
        if k not in a.dscp:
            sys.exit("--dscp: one of %s" % ", ".join(KINDS))
        a.dscp[k] = int(v)
    a.video_ladder = [float(x) for x in a.video_ladder.split(",")]
    GAP_THRESHOLD[0] = a.gap_threshold
    pool = Pool(parse_pool(a.src_pool))
    rng = random.Random(a.seed)
    print("server %s:%d  video %d  web %.1f/s  bulk %d  voice %d  sources %d  dscp %s" % (
        a.server, a.port, a.video, a.web, a.bulk, a.voice, len(pool.addrs),
        " ".join("%s=%d" % kv for kv in a.dscp.items())), flush=True)
    th = []
    for _ in range(a.video):
        th.append(threading.Thread(target=video_session, args=(a, pool, random.Random(rng.random())), daemon=True))
    for _ in range(a.bulk):
        th.append(threading.Thread(target=bulk_session, args=(a, pool, random.Random(rng.random())), daemon=True))
    for _ in range(a.voice):
        th.append(threading.Thread(target=voice_call, args=(a, pool, random.Random(rng.random())), daemon=True))
    if a.web > 0:
        th.append(threading.Thread(target=web_arrivals, args=(a, pool, random.Random(rng.random())), daemon=True))
    for t in th:
        t.start()
    signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    t_start = time.monotonic()
    last = dict(t=t_start, b={})
    end = t_start + a.duration if a.duration > 0 else None
    try:
        while not STOP.is_set():
            step = a.interval if end is None else min(a.interval, end - time.monotonic())
            if step <= 0 or STOP.wait(step):
                break
            report(a, t_start, last)
    except KeyboardInterrupt:
        pass
    STOP.set()
    time.sleep(0.3)
    report(a, t_start, last, final=True)


def rate_arg(s):
    s = s.lower()
    m = {"k": 1e3, "m": 1e6, "g": 1e9}.get(s[-1:], 1)
    return int(float(s.rstrip("kmg")) * m)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("serve", help="run on the data side (H1)")
    s.add_argument("--bind", default="")
    s.add_argument("--port", type=int, default=7000)
    r = sub.add_parser("run", help="run on the client side (H2)")
    r.add_argument("server")
    r.add_argument("--port", type=int, default=7000)
    r.add_argument("--profile", choices=sorted(PROFILES), default="mixed",
                   help="session counts (default mixed: 20 video, 6 web pages/s, 3 bulk, 4 voice)")
    r.add_argument("--video", type=int, help="video sessions")
    r.add_argument("--web", type=float, help="web pages per second")
    r.add_argument("--bulk", type=int, help="bulk sessions")
    r.add_argument("--voice", type=int, help="voice calls")
    r.add_argument("--src-pool", default="", help="source addresses, e.g. 10.0.2.65-10.0.2.124")
    r.add_argument("--dscp", dest="dscp_set", action="append", metavar="KIND=N",
                   help="DSCP per kind (default video=34 web=0 bulk=8 voice=46)")
    r.add_argument("--duration", type=float, default=0, help="seconds (default: until interrupted)")
    r.add_argument("--interval", type=float, default=10, help="report every N seconds")
    r.add_argument("--json", action="store_true", help="one JSON line per report")
    r.add_argument("--seed", type=int, default=1)
    r.add_argument("--gap-threshold", type=float, default=0.05,
                   help="pauses at least this long are counted as movable (default 0.05 s, bpfc-ecmp's gap)")
    r.add_argument("--segment", type=float, default=2.0, help="video segment length, s")
    r.add_argument("--video-buffer", type=float, default=10.0, help="video buffer target, s")
    r.add_argument("--video-ladder", default="1,2.5,5,8", help="video bitrates, Mbit/s")
    r.add_argument("--video-segments", type=int, default=150, help="segments per video before it ends and a new one starts")
    r.add_argument("--web-min", type=rate_arg, default=rate_arg("4k"), help="smallest web object, bytes")
    r.add_argument("--web-max", type=rate_arg, default=rate_arg("20m"), help="largest web object, bytes")
    r.add_argument("--web-alpha", type=float, default=1.2, help="Pareto shape of web object sizes")
    r.add_argument("--web-max-open", type=int, default=200, help="most pages open at once")
    r.add_argument("--bulk-size", type=rate_arg, default=rate_arg("30m"), help="median bulk transfer, bytes")
    r.add_argument("--bulk-think", type=float, default=5.0, help="mean pause between bulk transfers, s")
    a = p.parse_args()
    if a.cmd == "serve":
        cmd_serve(a)
    elif a.cmd == "run":
        cmd_run(a)
    else:
        p.print_help()


if __name__ == "__main__":
    main()
