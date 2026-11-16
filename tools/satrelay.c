// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Starlink-like link emulator: a user-space relay between two interfaces.
 *
 * Traffic is not serialized at a bit rate.  Instead, every frame (default
 * 1.333 ms, 1/750 s) each direction may release up to rate * frame bytes,
 * and whatever is released in a frame goes out back-to-back.  Rates are
 * re-drawn every slot (default 15 s, globally aligned to wall-clock
 * offset 12 s, i.e. :12/:27/:42/:57) within +/- vary percent of the base,
 * as Starlink's global scheduler reallocates paths.  Each direction has a
 * fixed one-way delay, a drop-tail queue, and optional loss right after a
 * slot boundary.
 *
 * Reordering, two mechanisms, both growing with load:
 *
 * 1. Load-dependent reordering.  Starlink delivers a large share of
 *    packets out of order under load (a quarter of outer packets in one
 *    saturated IPsec IP-TFS test) by a few packet positions, and little
 *    when the link is lightly used.  Each direction tracks its
 *    utilization (credit used per frame, smoothed over load_tau_ms).
 *    Below reorder_onset_pct of utilization nothing is reordered; above
 *    it, both the share of packets reordered and how late they are rise
 *    linearly, to reorder_pct and reorder_max positions at full load.  A
 *    reordered packet is held back and released after the next 1..max
 *    packets of its direction that are not held themselves (consecutive
 *    held packets add up), or after reorder_hold_us (default two frames)
 *    when no more traffic follows.  Held packets have already used their
 *    frame's credit, so the rate is unchanged.
 *
 * 2. Route changes.  When a reconfiguration moves traffic to a shorter
 *    path, packets sent on the new path overtake those still in flight on
 *    the old one, so the reordering extent is the packets in flight
 *    times the delay saved: it grows with the rate (Kumar et al., "Packet
 *    reordering in LEO satellite networks", arXiv:2405.07627, see
 *    hundreds of packets on fast inter-satellite links).  With
 *    reroute_ms, every slot boundary moves each direction's path delay to
 *    a new value within +/- reroute_ms of delay_ms; packets already
 *    queued keep the old delay, new ones get the new one, and release
 *    takes whichever is due first.  A longer path only adds delay.
 *
 * usage: satrelay IF_A IF_B UP_KBPS DOWN_KBPS [key=value...]
 *   UP is A->B, DOWN is B->A.  keys: frame_us delay_ms slot_ms offset_ms
 *   vary_pct qlimit_ms bloss_ms bloss_pct reorder_pct reorder_max
 *   reorder_onset_pct load_tau_ms reorder_hold_us reroute_ms
 *   noreorder_proto seed log=FILE
 *   noreorder_proto=N exempts IPv4 protocol N (e.g. 89, OSPF) from the
 *   load-dependent reordering, to tell its effect on a protocol apart.
 *
 * The relay is the only path between IF_A and IF_B: it puts both into
 * promiscuous mode (a NIC otherwise drops the unicast frames it relays),
 * and refuses interfaces that are bridge ports, since a bridge would
 * forward every frame a second time, undelayed (OSPF, for one, restarts
 * its database exchange on such duplicates).  force=1 overrides that.
 * Turn off GRO/LRO on the interfaces (ethtool -K IF gro off lro off):
 * merged packets longer than PKTMAX are dropped.
 *
 * Loops: if IF_A and IF_B reach the same Layer-2 segment (both on one
 * VLAN of a switch, say), every frame relayed out of one comes back in
 * and circulates, with no STP to stop it, and the far side gets late
 * duplicates.  The relay learns which side each source MAC address is on;
 * in a proper setup an address never shows up on both.  When one does,
 * it reports the loop once, drops frames from addresses that belong to
 * the other side, and from then on also drops frames identical to one it
 * sent in the last loop_ms (default 500; 0 disables all this).  Only a
 * detected loop turns that on: legitimate traffic repeats identical
 * frames too (TCP duplicate ACKs).
 *   The log has one line per slot: start (epoch s), up kbit/s, down
 *   kbit/s, then (with reroute_ms) up and down path delay in us.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define QMAX 4096
#define HOLDMAX 1024
#define PKTMAX 9216 /* jumbo frames; anything longer is dropped, not cut */

struct pkt {
	uint64_t due_ns; /* arrival + path delay */
	uint16_t len;
	uint8_t data[PKTMAX];
};

/* One path's packets in flight, in arrival order (so also in due order). */
struct pathq {
	struct pkt *q;
	unsigned head, cnt;
	int64_t delay_ns;
};

struct dir {
	const char *name;
	int rx, tx;
	int txidx;
	uint64_t base_kbps, kbps;
	int64_t credit; /* bytes */
	struct pathq path[2]; /* current, and the previous one draining */
	unsigned cur;
	uint64_t qbytes;
	uint64_t fwd, drop_q, drop_b, bytes;
	int side;    /* 1: receives on IF_A, 2: on IF_B */
	double load; /* smoothed utilization, 0..1 */
	uint64_t reroutes, overtaking;
	uint64_t drop_trunc;	 /* longer than PKTMAX */
	uint64_t drop_loop;	 /* came back after we sent it */
	uint64_t held_proto[256]; /* held back, by IPv4 protocol */
	/* reordering: packets held back, in the order they were held */
	struct pkt *hold;
	int hcnt[HOLDMAX];	   /* packets still to pass them */
	uint64_t hdeadline[HOLDMAX]; /* release by then regardless */
	unsigned nhold;
	uint64_t reordered;
};

static uint64_t frame_us = 1333, delay_ms = 20, slot_ms = 15000,
		offset_ms = 12000, vary_pct = 40, qlimit_ms = 150,
		bloss_ms = 0, bloss_pct = 0, seed = 1, reorder_pct = 0,
		reorder_max = 8, reorder_hold_us = 0, reorder_onset_pct = 30,
		load_tau_ms = 20, reroute_ms = 0, noreorder_proto = 256,
		force = 0, loop_ms = 500;
static FILE *logf;
static volatile int stop;

/* Source MAC addresses: which side they were last seen on. */
#define MACMAX 4096
static struct macent {
	uint8_t mac[6];
	uint8_t side; /* 1 = IF_A, 2 = IF_B */
	uint64_t ns;
} macs[MACMAX];
static int loop_detected;

/* 1 if this source address was seen on the other side within 10 s. */
static int mac_conflict(const uint8_t *src, int side, uint64_t ns)
{
	unsigned h = ((uint32_t)src[2] << 24 | (uint32_t)src[3] << 16 |
		      (uint32_t)src[4] << 8 | src[5]) % MACMAX, k;

	if (src[0] & 1)
		return 0; /* not a unicast source */
	for (k = 0; k < 16; k++, h = (h + 1) % MACMAX) {
		struct macent *m = &macs[h];

		if (!m->side || ns - m->ns > 60000000000ULL) {
			memcpy(m->mac, src, 6);
			m->side = side;
			m->ns = ns;
			return 0;
		}
		if (memcmp(m->mac, src, 6))
			continue;
		if (m->side != side && ns - m->ns < 10000000000ULL)
			return 1;
		m->side = side;
		m->ns = ns;
		return 0;
	}
	return 0; /* table crowded: no verdict */
}

/* Frames sent recently: fingerprint and when, in an open-addressed table. */
#define SEENMAX 65536
static struct seen {
	uint64_t fp;
	uint64_t ns;
} seen[SEENMAX];

static uint64_t fingerprint(const uint8_t *p, unsigned len)
{
	uint64_t h = 1469598103934665603ULL ^ len; /* FNV-1a */
	unsigned i;

	for (i = 0; i < len; i++) {
		h ^= p[i];
		h *= 1099511628211ULL;
	}
	return h ? h : 1;
}

static void seen_add(uint64_t fp, uint64_t ns)
{
	unsigned i = fp % SEENMAX, k;

	/* reuse the first expired or matching slot of a short probe */
	for (k = 0; k < 8; k++, i = (i + 1) % SEENMAX)
		if (!seen[i].fp || seen[i].fp == fp ||
		    ns - seen[i].ns > loop_ms * 1000000ULL)
			break;
	seen[i].fp = fp;
	seen[i].ns = ns;
}

static int seen_recently(uint64_t fp, uint64_t ns)
{
	unsigned i = fp % SEENMAX, k;

	for (k = 0; k < 8; k++, i = (i + 1) % SEENMAX)
		if (seen[i].fp == fp)
			return ns - seen[i].ns <= loop_ms * 1000000ULL;
	return 0;
}

static uint64_t now_ns(clockid_t c)
{
	struct timespec ts;

	clock_gettime(c, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* A bridge port, or another interface's lower/upper link, also forwards. */
static void check_if(const char *ifn)
{
	char path[256];

	snprintf(path, sizeof(path), "/sys/class/net/%s/brport", ifn);
	if (access(path, F_OK) == 0 && !force) {
		fprintf(stderr,
			"satrelay: %s is a bridge port: the bridge would forward "
			"every frame too, undelayed, and the far side would get "
			"each packet twice.  Remove it from the bridge (ip link "
			"set %s nomaster), or pass force=1.\n",
			ifn, ifn);
		exit(1);
	}
}

static int open_if(const char *ifn, int *idx)
{
	struct sockaddr_ll sll = { .sll_family = AF_PACKET };
	int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)), one = 1;

	if (fd < 0) {
		perror("socket");
		exit(1);
	}
	*idx = if_nametoindex(ifn);
	if (!*idx) {
		fprintf(stderr, "no interface %s\n", ifn);
		exit(1);
	}
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = *idx;
	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		perror("bind");
		exit(1);
	}
#ifdef PACKET_IGNORE_OUTGOING
	setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof(one));
#endif
	{
		/* receive frames for the far side's MAC address too; the kernel
		 * drops this when the socket closes */
		struct packet_mreq mr = { .mr_ifindex = *idx,
					  .mr_type = PACKET_MR_PROMISC };

		if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,
			       sizeof(mr)) < 0) {
			perror("promiscuous mode");
			exit(1);
		}
	}
	setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &one, sizeof(one));
	{
		int sz = 16 << 20;

		setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &sz, sizeof(sz));
		setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &sz, sizeof(sz));
	}
	return fd;
}

static void rx(struct dir *d, uint64_t mono)
{
	struct sockaddr_ll from;
	socklen_t fl;
	uint8_t buf[PKTMAX];
	ssize_t n;
	uint64_t limit = d->kbps * qlimit_ms / 8; /* bytes */

	for (;;) {
		fl = sizeof(from);
		n = recvfrom(d->rx, buf, sizeof(buf), MSG_DONTWAIT | MSG_TRUNC,
			     (struct sockaddr *)&from, &fl);
		if (n <= 0)
			return;
		if (from.sll_pkttype == PACKET_OUTGOING)
			continue;
		if (n > (ssize_t)sizeof(buf)) {
			/* forwarding it cut short would corrupt it */
			if (!d->drop_trunc++)
				fprintf(stderr,
					"satrelay: dropping %zd-byte packets (GRO/LRO?): "
					"ethtool -K <if> gro off lro off\n",
					n);
			continue;
		}
		struct pathq *pq = &d->path[d->cur];

		if (loop_ms && n >= 14 &&
		    (mac_conflict(buf + 6, d->side, mono) ||
		     (loop_detected && seen_recently(fingerprint(buf, n), mono)))) {
			if (!loop_detected)
				fprintf(stderr,
					"satrelay: %02x:%02x:%02x:%02x:%02x:%02x seen on both "
					"sides: the two interfaces reach the same L2 segment "
					"(a loop, or a bridge alongside); dropping looped "
					"frames, but the far side still gets duplicates "
					"until that is fixed\n",
					buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]);
			loop_detected = 1;
			d->drop_loop++;
			continue;
		}
		if (pq->cnt == QMAX || d->qbytes + n > limit + 3000) {
			d->drop_q++;
			continue;
		}
		struct pkt *p = &pq->q[(pq->head + pq->cnt) % QMAX];

		p->due_ns = mono + pq->delay_ns;
		p->len = n;
		memcpy(p->data, buf, n);
		pq->cnt++;
		d->qbytes += n;
	}
}

/* IPv4 protocol of an Ethernet frame (one VLAN tag allowed), -1 if none. */
static int ip_proto(const struct pkt *p)
{
	unsigned off = 12;
	uint16_t et;

	if (p->len < 14)
		return -1;
	et = (uint16_t)(p->data[off] << 8 | p->data[off + 1]);
	if (et == 0x8100 && p->len >= 18) {
		off += 4;
		et = (uint16_t)(p->data[off] << 8 | p->data[off + 1]);
	}
	if (et != 0x0800 || p->len < off + 2 + 20)
		return -1;
	return p->data[off + 2 + 9];
}

struct burst {
	struct mmsghdr m[2 * HOLDMAX];
	struct iovec iov[2 * HOLDMAX];
	struct sockaddr_ll *to;
	int k;
};

static void emit(struct burst *b, struct dir *d, const struct pkt *p)
{
	if (b->k >= 2 * HOLDMAX)
		return;
	b->iov[b->k].iov_base = (void *)p->data;
	b->iov[b->k].iov_len = p->len;
	memset(&b->m[b->k], 0, sizeof(b->m[b->k]));
	b->m[b->k].msg_hdr.msg_iov = &b->iov[b->k];
	b->m[b->k].msg_hdr.msg_iovlen = 1;
	b->m[b->k].msg_hdr.msg_name = b->to;
	b->m[b->k].msg_hdr.msg_namelen = sizeof(*b->to);
	d->fwd++;
	d->bytes += p->len;
	b->k++;
	if (loop_ms && loop_detected)
		seen_add(fingerprint(p->data, p->len), now_ns(CLOCK_MONOTONIC));
}

/* Another packet went out: held packets it passed may follow it now. */
static void passed(struct burst *b, struct dir *d, uint64_t mono, int all)
{
	unsigned i;

	for (i = 0; i < d->nhold; i++) {
		if (d->hcnt[i] <= 0)
			continue; /* already released in this burst */
		if (!all)
			d->hcnt[i]--;
		if (d->hcnt[i] <= 0 || mono >= d->hdeadline[i]) {
			d->hcnt[i] = 0;
			emit(b, d, &d->hold[i]);
		}
	}
}

/* Drop released packets from the hold list, after they were sent. */
static void compact(struct dir *d)
{
	unsigned i, j = 0;

	for (i = 0; i < d->nhold; i++) {
		if (d->hcnt[i] <= 0)
			continue;
		if (i != j) {
			d->hold[j] = d->hold[i];
			d->hcnt[j] = d->hcnt[i];
			d->hdeadline[j] = d->hdeadline[i];
		}
		j++;
	}
	d->nhold = j;
}

/* One frame: release what the credit allows and the delay permits. */
static void frame(struct dir *d, uint64_t mono, int in_bloss)
{
	static struct burst b;
	struct sockaddr_ll to = { .sll_family = AF_PACKET,
				  .sll_ifindex = d->txidx };
	int64_t quantum = (int64_t)(d->kbps * frame_us / 8000);
	uint64_t hold_ns = (reorder_hold_us ? reorder_hold_us : 2 * frame_us) *
			   1000ULL;
	int64_t used = 0;
	double f = 0, onset = reorder_onset_pct / 100.0, alpha;
	unsigned pct = 0, late_max = 1;

	b.k = 0;
	b.to = &to;

	/* how far into the reordering range the smoothed load is */
	if (reorder_pct && onset < 1.0 && d->load > onset)
		f = (d->load - onset) / (1.0 - onset);
	if (f > 1)
		f = 1;
	pct = (unsigned)(reorder_pct * 100 * f + 0.5); /* in 1/100 % */
	late_max = (unsigned)(reorder_max * f + 0.999);
	if (late_max < 1)
		late_max = 1;

	/* Unused credit carries over only up to one MTU: idle frames are not
	 * saved up, but a rate that is not a multiple of the packet size is
	 * still met on average. */
	d->credit += quantum;
	if (d->credit > quantum + 1600)
		d->credit = quantum + 1600;
	if (!d->path[0].cnt && !d->path[1].cnt && d->credit > quantum)
		d->credit = quantum;

	while (b.k < HOLDMAX) {
		struct pathq *pq = NULL;
		struct pkt *p = NULL;
		unsigned i;

		/* the earliest due head of the two paths */
		for (i = 0; i < 2; i++) {
			struct pathq *c = &d->path[i];
			struct pkt *h;

			if (!c->cnt)
				continue;
			h = &c->q[c->head];
			if (h->due_ns <= mono && (!p || h->due_ns < p->due_ns)) {
				p = h;
				pq = c;
			}
		}
		if (!p)
			break;
		if (d->credit < (int64_t)p->len)
			break;
		/* new path's packet ahead of the old path's in flight */
		if (pq == &d->path[d->cur] && d->path[!d->cur].cnt)
			d->overtaking++;
		d->credit -= p->len;
		used += p->len;
		pq->head = (pq->head + 1) % QMAX;
		pq->cnt--;
		d->qbytes -= p->len;
		if (in_bloss && (uint64_t)(rand() % 100) < bloss_pct) {
			d->drop_b++;
			continue;
		}
		if (pct && d->nhold < HOLDMAX &&
		    (unsigned)(rand() % 10000) < pct &&
		    (noreorder_proto > 255 ||
		     ip_proto(p) != (int)noreorder_proto)) {
			int proto = ip_proto(p);

			if (proto >= 0)
				d->held_proto[proto]++;
			/* hold back: it will arrive after the next 1..max */
			d->hold[d->nhold] = *p;
			d->hcnt[d->nhold] = 1 + rand() % late_max;
			d->hdeadline[d->nhold] = mono + hold_ns;
			d->nhold++;
			d->reordered++;
			continue;
		}
		emit(&b, d, p);
		passed(&b, d, mono, 0);
	}
	/* held packets whose time is up go out even without more traffic */
	passed(&b, d, mono, 1);

	/* utilization: share of this frame's credit used, smoothed */
	alpha = (double)frame_us / (load_tau_ms ? load_tau_ms * 1000.0 : 1.0);
	if (alpha > 1)
		alpha = 1;
	{
		double u = quantum ? (double)used / quantum : 0;

		d->load += alpha * ((u > 1 ? 1 : u) - d->load);
	}
	if (b.k && sendmmsg(d->tx, b.m, b.k, 0) < 0)
		perror("sendmmsg");
	compact(d);
}

static uint64_t draw(uint64_t base)
{
	double u = (double)rand() / RAND_MAX * 2.0 - 1.0;

	return (uint64_t)(base * (1.0 + u * vary_pct / 100.0));
}

/*
 * A route change: new arrivals take a path whose delay is within
 * +/- reroute_ms of the base; what is in flight keeps its old delay.
 * Skipped while the previous path is still draining.
 */
static void reroute(struct dir *d)
{
	double u = (double)rand() / RAND_MAX * 2.0 - 1.0;
	int64_t delay = (int64_t)delay_ms * 1000000LL +
			(int64_t)(u * reroute_ms * 1000000.0);
	struct pathq *next = &d->path[!d->cur];

	if (next->cnt)
		return;
	if (delay < 1000000)
		delay = 1000000;
	next->head = 0;
	next->delay_ns = delay;
	d->cur = !d->cur;
	d->reroutes++;
}

static void onsig(int s)
{
	(void)s;
	stop = 1;
}

int main(int argc, char **argv)
{
	struct dir up = { .name = "up", .side = 1 },
		   down = { .name = "down", .side = 2 };
	int ia, ib, i;
	uint64_t next_frame, cur_slot = UINT64_MAX;

	if (argc < 5) {
		fprintf(stderr, "usage: %s IF_A IF_B UP_KBPS DOWN_KBPS [k=v]\n",
			argv[0]);
		return 1;
	}
	for (i = 5; i < argc; i++) {
		char *v = strchr(argv[i], '=');

		if (!v)
			continue;
		*v++ = 0;
#define K(n) if (!strcmp(argv[i], #n)) n = strtoull(v, NULL, 0); else
		K(frame_us) K(delay_ms) K(slot_ms) K(offset_ms) K(vary_pct)
		K(qlimit_ms) K(bloss_ms) K(bloss_pct) K(seed)
		K(reorder_pct) K(reorder_max) K(reorder_hold_us)
		K(reorder_onset_pct) K(load_tau_ms) K(reroute_ms)
		K(noreorder_proto) K(force) K(loop_ms)
		if (!strcmp(argv[i], "log"))
			logf = fopen(v, "w");
	}
	srand(seed);
	up.base_kbps = up.kbps = strtoull(argv[3], NULL, 0);
	down.base_kbps = down.kbps = strtoull(argv[4], NULL, 0);
	for (i = 0; i < 2; i++) {
		up.path[i].q = calloc(QMAX, sizeof(struct pkt));
		down.path[i].q = calloc(QMAX, sizeof(struct pkt));
		up.path[i].delay_ns = down.path[i].delay_ns =
			(int64_t)delay_ms * 1000000LL;
	}
	up.hold = calloc(HOLDMAX, sizeof(struct pkt));
	down.hold = calloc(HOLDMAX, sizeof(struct pkt));
	check_if(argv[1]);
	check_if(argv[2]);
	up.rx = open_if(argv[1], &ia);
	down.rx = open_if(argv[2], &ib);
	up.tx = down.rx; /* A->B goes out on B */
	up.txidx = ib;
	down.tx = up.rx;
	down.txidx = ia;
	signal(SIGTERM, onsig);
	signal(SIGINT, onsig);

	next_frame = now_ns(CLOCK_MONOTONIC);
	while (!stop) {
		uint64_t mono = now_ns(CLOCK_MONOTONIC);
		uint64_t real_ms = now_ns(CLOCK_REALTIME) / 1000000ULL;
		uint64_t phase = (real_ms + slot_ms - offset_ms % slot_ms) % slot_ms;
		uint64_t slot = (real_ms + slot_ms - offset_ms % slot_ms) / slot_ms;
		struct pollfd pf[2] = { { .fd = up.rx, .events = POLLIN },
					{ .fd = down.rx, .events = POLLIN } };
		int64_t wait_us;

		if (slot != cur_slot) {
			int first = cur_slot == UINT64_MAX;

			cur_slot = slot;
			up.kbps = draw(up.base_kbps);
			down.kbps = draw(down.base_kbps);
			if (reroute_ms && !first) {
				reroute(&up);
				reroute(&down);
			}
			if (logf) {
				fprintf(logf, "%.3f %" PRIu64 " %" PRIu64,
					(double)(real_ms - phase) / 1000.0,
					up.kbps, down.kbps);
				if (reroute_ms)
					fprintf(logf, " %" PRId64 " %" PRId64,
						up.path[up.cur].delay_ns / 1000,
						down.path[down.cur].delay_ns / 1000);
				fprintf(logf, "\n");
				fflush(logf);
			}
		}

		if (mono >= next_frame) {
			int bl = bloss_ms && phase < bloss_ms;

			frame(&up, mono, bl);
			frame(&down, mono, bl);
			next_frame += frame_us * 1000ULL;
			if (next_frame < mono)
				next_frame = mono + frame_us * 1000ULL;
			continue;
		}
		wait_us = (int64_t)(next_frame - mono) / 1000;
		if (poll(pf, 2, wait_us > 1000 ? (int)(wait_us / 1000) : 0) > 0 ||
		    1) {
			uint64_t t = now_ns(CLOCK_MONOTONIC);

			rx(&up, t);
			rx(&down, t);
		}
		if (wait_us > 0 && wait_us <= 1000) {
			struct timespec ts = { 0, 0 };
			uint64_t nf = next_frame;

			/* sleep until the frame, still polling briefly */
			if (poll(pf, 2, 0) <= 0) {
				ts.tv_sec = nf / 1000000000ULL;
				ts.tv_nsec = nf % 1000000000ULL;
				clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME,
						&ts, NULL);
			}
		}
	}
	fprintf(stderr,
		"up: fwd %" PRIu64 " bytes %" PRIu64 " qdrop %" PRIu64
		" bdrop %" PRIu64 " held %" PRIu64 " reroutes %" PRIu64
		" overtaking %" PRIu64 "\ndown: fwd %" PRIu64 " bytes %" PRIu64
		" qdrop %" PRIu64 " bdrop %" PRIu64 " held %" PRIu64
		" reroutes %" PRIu64 " overtaking %" PRIu64 "\n",
		up.fwd, up.bytes, up.drop_q, up.drop_b, up.reordered,
		up.reroutes, up.overtaking, down.fwd, down.bytes, down.drop_q,
		down.drop_b, down.reordered, down.reroutes, down.overtaking);
	fprintf(stderr,
		"held OSPF packets: up %" PRIu64 ", down %" PRIu64
		"; dropped as too long (> %d bytes): up %" PRIu64
		", down %" PRIu64 "; dropped as looped back: up %" PRIu64
		", down %" PRIu64 "\n",
		up.held_proto[89], down.held_proto[89], PKTMAX, up.drop_trunc,
		down.drop_trunc, up.drop_loop, down.drop_loop);
	return 0;
}
