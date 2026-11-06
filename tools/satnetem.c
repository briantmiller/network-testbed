// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * satnetem: Starlink-like link emulation with netem, driven over rtnetlink.
 *
 * The netlink counterpart of satrelay: instead of forwarding packets in
 * user space, it configures a netem qdisc on the egress of each direction
 * and keeps reconfiguring it in place:
 *
 *   frames      netem "rate" sets the average rate and "slot T T" holds
 *               packets and releases everything due in one burst per slot
 *               (default 1.333 ms = 1/750 s, Starlink's frame), so traffic
 *               arrives in per-frame bursts instead of serialized at a bit
 *               rate.
 *   15 s slots  at wall-clock boundaries (default every 15 s at offset
 *               12 s: :12, :27, :42, :57) each direction's rate is re-drawn
 *               within +/- vary percent of its base, like Starlink's global
 *               path reallocation; the qdisc is changed in place, so queued
 *               packets are kept.
 *   boundary    for bloss-ms after each boundary, loss is raised to
 *   loss        bloss-pct, then set back to the base loss.
 *   delay       a fixed one-way delay (plus optional jitter).
 *   queue       netem's limit counts every packet it holds, including
 *               those still in the delay line, so it is sized as
 *               (delay + jitter + qlimit) ms worth of the current rate.
 *
 * Typical use, with r1 (customer) and r2 (hub) bridged in a namespace "sw"
 * whose ports p1 (towards r1) and p2 (towards r2) carry the two directions:
 *
 *   ip netns exec sw ./satnetem --up-if p2 --down-if p1 \
 *       --up-kbps 15000 --down-kbps 150000 --log slots.log
 *
 * "up" is the direction leaving through --up-if.  Each slot's rates are
 * logged as "<slot start, epoch seconds> <up kbps> <down kbps>", the same
 * format as satrelay, as ground truth for scoring measurements.  --print
 * shows the equivalent tc commands instead of applying anything.
 *
 * The requests are the same, byte for byte, as iproute2's
 * "tc qdisc replace dev IF root handle 1: netem ..." for the same settings.
 *
 * Needs CAP_NET_ADMIN and a kernel with sch_netem (slot support: 4.20+).
 * Turn off GSO/TSO on the interfaces feeding the qdisc (e.g. ethtool -K
 * eth0 tso off gso off gro off), or netem will rate- and slot-limit whole
 * 64 KB super-packets.
 *
 * Build: cc -O2 -Wall -o satnetem satnetem.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <linux/netlink.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <math.h>
#include <net/if.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define HANDLE 0x00010000U /* "1:" */

struct dir {
	const char *name;
	const char *ifname;
	int ifindex;
	double base_kbps, kbps;
};

static struct {
	double up_kbps, down_kbps;
	long frame_us;
	double delay_ms, jitter_ms;
	long slot_ms, offset_ms;
	double vary_pct, qlimit_ms, loss_pct;
	long bloss_ms;
	double bloss_pct;
	long mtu;
	long seed;
	const char *log;
	const char *netns;
	bool keep, print;
} cfg = {
	.up_kbps = 15000,
	.down_kbps = 150000,
	.frame_us = 1333,
	.delay_ms = 20,
	.slot_ms = 15000,
	.offset_ms = 12000,
	.vary_pct = 40,
	.qlimit_ms = 150,
	.mtu = 1500,
	.seed = 1,
};

static volatile sig_atomic_t stop;
static int nlfd = -1;
static uint32_t nlseq;

/* ------------------------------------------------------------------ */
/* rtnetlink                                                          */
/* ------------------------------------------------------------------ */

struct msg {
	union {
		struct nlmsghdr nh;
		char buf[1024];
	};
};

static struct rtattr *msg_tail(struct msg *m)
{
	return (struct rtattr *)(m->buf + NLMSG_ALIGN(m->nh.nlmsg_len));
}

static struct rtattr *msg_attr(struct msg *m, unsigned short type,
			       const void *data, size_t len)
{
	struct rtattr *rta = msg_tail(m);
	size_t total = NLMSG_ALIGN(m->nh.nlmsg_len) + RTA_SPACE(len);

	if (total > sizeof(m->buf)) {
		fprintf(stderr, "satnetem: netlink message too long\n");
		exit(1);
	}
	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(len);
	if (len)
		memcpy(RTA_DATA(rta), data, len);
	memset((char *)RTA_DATA(rta) + len, 0, RTA_ALIGN(len) - len);
	m->nh.nlmsg_len = total;
	return rta;
}

static void msg_init(struct msg *m, uint16_t type, uint16_t flags, int ifindex)
{
	struct tcmsg *tcm;

	memset(m, 0, sizeof(*m));
	m->nh.nlmsg_len = NLMSG_LENGTH(sizeof(*tcm));
	m->nh.nlmsg_type = type;
	m->nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
	m->nh.nlmsg_seq = ++nlseq;
	tcm = NLMSG_DATA(&m->nh);
	tcm->tcm_family = AF_UNSPEC;
	tcm->tcm_ifindex = ifindex;
	tcm->tcm_handle = HANDLE;
	tcm->tcm_parent = TC_H_ROOT;
}

/* Send m and wait for its ack; returns 0 or a negative errno. */
static int nl_request(struct msg *m)
{
	char buf[8192];
	ssize_t n;

	if (send(nlfd, m->buf, m->nh.nlmsg_len, 0) < 0)
		return -errno;
	for (;;) {
		struct nlmsghdr *h;

		n = recv(nlfd, buf, sizeof(buf), 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, (size_t)n);
		     h = NLMSG_NEXT(h, n)) {
			if (h->nlmsg_type == NLMSG_ERROR &&
			    h->nlmsg_seq == m->nh.nlmsg_seq) {
				struct nlmsgerr *e = NLMSG_DATA(h);

				return e->error;
			}
		}
	}
}

/* ------------------------------------------------------------------ */
/* netem                                                              */
/* ------------------------------------------------------------------ */

/* Packets: the delay line plus qlimit_ms of queue at this rate. */
static uint32_t netem_limit(double kbps)
{
	double ms = cfg.delay_ms + cfg.jitter_ms + cfg.qlimit_ms;
	double pkts = kbps * ms / (8.0 * cfg.mtu);

	return pkts < 64 ? 64 : (uint32_t)pkts + 1;
}

/*
 * RTM_NEWQDISC with NLM_F_CREATE | NLM_F_REPLACE: on an existing root netem
 * a change in place (queued packets are kept); if it was removed meanwhile,
 * it is recreated.  TCA_OPTIONS is struct tc_netem_qopt followed by netem
 * attributes, with the same attributes in the same order as iproute2.
 */
static int netem_apply(const struct dir *d, double loss_pct, uint32_t limit)
{
	struct msg m;
	struct tc_netem_qopt qopt = {};
	struct rtattr *opts;
	uint64_t delay_ns = (uint64_t)llround(cfg.delay_ms * 1e6);
	uint64_t jitter_ns = (uint64_t)llround(cfg.jitter_ms * 1e6);
	uint64_t rate_Bps = (uint64_t)(d->kbps * 1000.0 / 8.0);
	double loss = loss_pct / 100.0 * UINT32_MAX;

	msg_init(&m, RTM_NEWQDISC, NLM_F_CREATE | NLM_F_REPLACE, d->ifindex);
	msg_attr(&m, TCA_KIND, "netem", sizeof("netem"));

	/* latency/jitter in qopt are psched ticks (ns >> 6) */
	qopt.latency = (delay_ns >> 6) > UINT32_MAX ? UINT32_MAX
						    : (uint32_t)(delay_ns >> 6);
	qopt.jitter = (jitter_ns >> 6) > UINT32_MAX
			      ? UINT32_MAX
			      : (uint32_t)(jitter_ns >> 6);
	qopt.limit = limit;
	/* truncated, as tc does */
	qopt.loss = loss >= UINT32_MAX ? UINT32_MAX : (uint32_t)loss;
	opts = msg_attr(&m, TCA_OPTIONS, &qopt, sizeof(qopt));

	if ((delay_ns >> 6) > UINT32_MAX) {
		int64_t v = delay_ns;

		msg_attr(&m, TCA_NETEM_LATENCY64, &v, sizeof(v));
	}
	if ((jitter_ns >> 6) > UINT32_MAX) {
		int64_t v = jitter_ns;

		msg_attr(&m, TCA_NETEM_JITTER64, &v, sizeof(v));
	}
	if (cfg.frame_us) {
		/* min/max gap between slots; no packet/byte cap per slot: the
		 * rate decides what is due; no delay distribution */
		struct tc_netem_slot slot = {
			.min_delay = (int64_t)cfg.frame_us * 1000,
			.max_delay = (int64_t)cfg.frame_us * 1000,
		};

		msg_attr(&m, TCA_NETEM_SLOT, &slot, sizeof(slot));
	}
	if (rate_Bps >= UINT32_MAX) {
		struct tc_netem_rate r = { .rate = UINT32_MAX };

		msg_attr(&m, TCA_NETEM_RATE64, &rate_Bps, sizeof(rate_Bps));
		msg_attr(&m, TCA_NETEM_RATE, &r, sizeof(r));
	} else {
		struct tc_netem_rate r = { .rate = (uint32_t)rate_Bps };

		msg_attr(&m, TCA_NETEM_RATE, &r, sizeof(r));
	}
	/* TCA_OPTIONS spans the qopt and everything after it */
	opts->rta_len = (char *)msg_tail(&m) - (char *)opts;

	return nl_request(&m);
}

static int netem_delete(const struct dir *d)
{
	struct msg m;

	msg_init(&m, RTM_DELQDISC, 0, d->ifindex);
	return nl_request(&m);
}

/* The equivalent tc command, for --print. */
static void netem_print(const struct dir *d, double loss_pct, uint32_t limit)
{
	printf("tc qdisc replace dev %s root handle 1: netem limit %u",
	       d->ifname, limit);
	if (cfg.delay_ms) {
		printf(" delay %ldus", lround(cfg.delay_ms * 1000));
		if (cfg.jitter_ms)
			printf(" %ldus", lround(cfg.jitter_ms * 1000));
	}
	if (loss_pct)
		printf(" loss %g%%", loss_pct);
	printf(" rate %" PRIu64 "kbit", (uint64_t)d->kbps);
	if (cfg.frame_us)
		printf(" slot %ldus %ldus", cfg.frame_us, cfg.frame_us);
	printf("\n");
}

/* ------------------------------------------------------------------ */
/* Main loop                                                          */
/* ------------------------------------------------------------------ */

static int64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Start of the slot containing t (ms since the epoch). */
static int64_t slot_start(int64_t t)
{
	int64_t phase;

	if (!cfg.slot_ms)
		return t;
	phase = (t - cfg.offset_ms) % cfg.slot_ms;
	if (phase < 0)
		phase += cfg.slot_ms;
	return t - phase;
}

static void draw(struct dir *d)
{
	if (cfg.slot_ms && cfg.vary_pct)
		d->kbps = d->base_kbps *
			  (1.0 + (drand48() * 2.0 - 1.0) * cfg.vary_pct / 100.0);
	else
		d->kbps = d->base_kbps;
}

static void apply(struct dir *d, double loss_pct)
{
	uint32_t limit = netem_limit(d->kbps);
	int err;

	if (cfg.print) {
		netem_print(d, loss_pct, limit);
		return;
	}
	err = netem_apply(d, loss_pct, limit);
	if (err == -ENOENT) {
		fprintf(stderr,
			"satnetem: %s: the kernel has no netem qdisc (modprobe sch_netem)\n",
			d->ifname);
		exit(1);
	}
	if (err) {
		fprintf(stderr, "satnetem: %s: %s\n", d->ifname, strerror(-err));
		exit(1);
	}
}

static void log_slot(FILE *lf, int64_t start, struct dir *dirs)
{
	if (!lf)
		return;
	fprintf(lf, "%.3f %.0f %.0f\n", start / 1000.0, floor(dirs[0].kbps),
		floor(dirs[1].kbps));
	fflush(lf);
}

static void sleep_ms(int64_t ms)
{
	struct timespec ts;

	if (ms < 1)
		ms = 1;
	if (ms > 1000)
		ms = 1000;
	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (ms % 1000) * 1000000;
	nanosleep(&ts, NULL); /* a signal ends it early */
}

static void onsig(int s)
{
	(void)s;
	stop = 1;
}

static void usage(const char *prog, int rc)
{
	fprintf(rc ? stderr : stdout,
		"usage: %s --up-if IF --down-if IF [options]\n"
		"  --up-if IF          egress interface of the uplink direction\n"
		"  --down-if IF        egress interface of the downlink direction\n"
		"  --up-kbps N         uplink base rate (15000)\n"
		"  --down-kbps N       downlink base rate (150000)\n"
		"  --frame-us N        slot (frame) length, 0 = no slots (1333)\n"
		"  --delay-ms N        one-way delay (20)\n"
		"  --jitter-ms N       one-way jitter, reorders packets (0)\n"
		"  --slot-ms N         rate re-draw period, 0 = fixed rates (15000)\n"
		"  --offset-ms N       first boundary within each period, UTC (12000)\n"
		"  --vary-pct N        rates re-drawn within +/- this (40)\n"
		"  --qlimit-ms N       queue beyond the delay line (150)\n"
		"  --loss-pct N        base random loss (0)\n"
		"  --bloss-ms N        loss window after each boundary (0)\n"
		"  --bloss-pct N       loss within that window (0)\n"
		"  --mtu N             packet size used to size the queue limit (1500)\n"
		"  --seed N            random seed (1)\n"
		"  --log FILE          append each slot's rates to FILE\n"
		"  --netns NAME        network namespace to configure\n"
		"  --keep              leave the qdiscs in place on exit\n"
		"  --print             print the tc commands of the first slot and exit\n",
		prog);
	exit(rc);
}

int main(int argc, char **argv)
{
	enum {
		O_UPIF = 256, O_DOWNIF, O_UPK, O_DOWNK, O_FRAME, O_DELAY,
		O_JITTER, O_SLOT, O_OFFSET, O_VARY, O_QLIMIT, O_LOSS, O_BLOSSMS,
		O_BLOSSPCT, O_MTU, O_SEED, O_LOG, O_NETNS, O_KEEP, O_PRINT,
	};
	static const struct option opts[] = {
		{ "up-if", required_argument, NULL, O_UPIF },
		{ "down-if", required_argument, NULL, O_DOWNIF },
		{ "up-kbps", required_argument, NULL, O_UPK },
		{ "down-kbps", required_argument, NULL, O_DOWNK },
		{ "frame-us", required_argument, NULL, O_FRAME },
		{ "delay-ms", required_argument, NULL, O_DELAY },
		{ "jitter-ms", required_argument, NULL, O_JITTER },
		{ "slot-ms", required_argument, NULL, O_SLOT },
		{ "offset-ms", required_argument, NULL, O_OFFSET },
		{ "vary-pct", required_argument, NULL, O_VARY },
		{ "qlimit-ms", required_argument, NULL, O_QLIMIT },
		{ "loss-pct", required_argument, NULL, O_LOSS },
		{ "bloss-ms", required_argument, NULL, O_BLOSSMS },
		{ "bloss-pct", required_argument, NULL, O_BLOSSPCT },
		{ "mtu", required_argument, NULL, O_MTU },
		{ "seed", required_argument, NULL, O_SEED },
		{ "log", required_argument, NULL, O_LOG },
		{ "netns", required_argument, NULL, O_NETNS },
		{ "keep", no_argument, NULL, O_KEEP },
		{ "print", no_argument, NULL, O_PRINT },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	struct dir dirs[2] = { { .name = "up" }, { .name = "down" } };
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	struct sigaction act = { .sa_handler = onsig };
	int64_t t, start, next_boundary, bloss_end;
	bool in_bloss;
	FILE *lf = NULL;
	int c, i;

	while ((c = getopt_long(argc, argv, "h", opts, NULL)) != -1) {
		switch (c) {
		case O_UPIF: dirs[0].ifname = optarg; break;
		case O_DOWNIF: dirs[1].ifname = optarg; break;
		case O_UPK: cfg.up_kbps = atof(optarg); break;
		case O_DOWNK: cfg.down_kbps = atof(optarg); break;
		case O_FRAME: cfg.frame_us = atol(optarg); break;
		case O_DELAY: cfg.delay_ms = atof(optarg); break;
		case O_JITTER: cfg.jitter_ms = atof(optarg); break;
		case O_SLOT: cfg.slot_ms = atol(optarg); break;
		case O_OFFSET: cfg.offset_ms = atol(optarg); break;
		case O_VARY: cfg.vary_pct = atof(optarg); break;
		case O_QLIMIT: cfg.qlimit_ms = atof(optarg); break;
		case O_LOSS: cfg.loss_pct = atof(optarg); break;
		case O_BLOSSMS: cfg.bloss_ms = atol(optarg); break;
		case O_BLOSSPCT: cfg.bloss_pct = atof(optarg); break;
		case O_MTU: cfg.mtu = atol(optarg); break;
		case O_SEED: cfg.seed = atol(optarg); break;
		case O_LOG: cfg.log = optarg; break;
		case O_NETNS: cfg.netns = optarg; break;
		case O_KEEP: cfg.keep = true; break;
		case O_PRINT: cfg.print = true; break;
		case 'h': usage(argv[0], 0); break;
		default: usage(argv[0], 1);
		}
	}
	if (!dirs[0].ifname || !dirs[1].ifname || optind != argc)
		usage(argv[0], 1);
	if (cfg.mtu < 64 || cfg.frame_us < 0 || cfg.slot_ms < 0 ||
	    cfg.bloss_ms < 0 || (cfg.slot_ms && cfg.bloss_ms >= cfg.slot_ms)) {
		fprintf(stderr, "satnetem: invalid option values\n");
		return 1;
	}

	if (cfg.netns) {
		char path[256];
		int fd;

		snprintf(path, sizeof(path), "/var/run/netns/%s", cfg.netns);
		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0 || setns(fd, CLONE_NEWNET) < 0) {
			fprintf(stderr, "satnetem: netns %s: %s\n", cfg.netns,
				strerror(errno));
			return 1;
		}
		close(fd);
	}

	srand48(cfg.seed);
	dirs[0].base_kbps = cfg.up_kbps;
	dirs[1].base_kbps = cfg.down_kbps;
	for (i = 0; i < 2; i++) {
		dirs[i].ifindex = if_nametoindex(dirs[i].ifname);
		if (!dirs[i].ifindex) {
			fprintf(stderr, "satnetem: no interface %s\n",
				dirs[i].ifname);
			return 1;
		}
	}

	if (!cfg.print) {
		nlfd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
		if (nlfd < 0 || bind(nlfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
			perror("satnetem: netlink");
			return 1;
		}
		nlseq = time(NULL);
		if (cfg.log) {
			lf = fopen(cfg.log, "a");
			if (!lf) {
				perror(cfg.log);
				return 1;
			}
		}
	}

	t = now_ms();
	start = slot_start(t);
	in_bloss = cfg.slot_ms && cfg.bloss_ms && t - start < cfg.bloss_ms;
	for (i = 0; i < 2; i++) {
		draw(&dirs[i]);
		apply(&dirs[i], in_bloss ? cfg.bloss_pct : cfg.loss_pct);
	}
	if (cfg.print)
		return 0;
	log_slot(lf, start, dirs);
	printf("satnetem: up %s %.0f kbit/s, down %s %.0f kbit/s, frame %ld us, delay %g ms\n",
	       dirs[0].ifname, floor(dirs[0].kbps), dirs[1].ifname,
	       floor(dirs[1].kbps),
	       cfg.frame_us, cfg.delay_ms);
	fflush(stdout);

	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);

	next_boundary = start + cfg.slot_ms;
	bloss_end = start + cfg.bloss_ms;
	while (!stop) {
		int64_t wake;

		t = now_ms();
		if (!cfg.slot_ms) {
			sleep_ms(1000);
			continue;
		}
		if (in_bloss && t >= bloss_end) {
			in_bloss = false;
			for (i = 0; i < 2; i++)
				apply(&dirs[i], cfg.loss_pct);
		}
		if (t >= next_boundary) {
			/* new rates, and the loss window if configured; if we
			 * overslept by whole periods, resync to the current one */
			start = slot_start(t);
			next_boundary = start + cfg.slot_ms;
			bloss_end = start + cfg.bloss_ms;
			in_bloss = cfg.bloss_ms && t < bloss_end;
			for (i = 0; i < 2; i++) {
				draw(&dirs[i]);
				apply(&dirs[i], in_bloss ? cfg.bloss_pct
							 : cfg.loss_pct);
			}
			log_slot(lf, start, dirs);
		}
		wake = in_bloss && bloss_end < next_boundary ? bloss_end
							      : next_boundary;
		sleep_ms(wake - now_ms());
	}

	if (!cfg.keep) {
		for (i = 0; i < 2; i++) {
			int err = netem_delete(&dirs[i]);

			if (err && err != -ENOENT && err != -EINVAL)
				fprintf(stderr, "satnetem: %s: %s\n",
					dirs[i].ifname, strerror(-err));
		}
	}
	return 0;
}
