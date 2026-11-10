#!/bin/bash
# traffic-mix.sh - realistic traffic between H1 and H2 (see tools/traffic-mix.py).
#
#   ./traffic-mix.sh setup [N]     give H2 N extra addresses (default 60) and route
#                                  them, so l3 modes see many flows
#   ./traffic-mix.sh start [ARGS]  server on H1, client on H2 (data H1 -> H2,
#                                  so it leaves R1 by the wan1 members); ARGS go
#                                  to "traffic-mix.py run", e.g. --profile heavy
#   ./traffic-mix.sh stop
#   ./traffic-mix.sh teardown      remove what setup added
#
# Runs the host's python3 inside the hosts' network namespaces, so the
# containers need nothing installed. Needs root (ip netns exec).
#
# The extra addresses are 10.0.2.65 and up: inside 10.0.2.0/24, so the WEB
# access-list on R2 still matches, outside H2's /30. R2 gets a static route for
# 10.0.2.64/26 and redistributes it into OSPF, so R1 reaches them over every
# WAN link like 10.0.2.0/30.

cd "$(dirname "$0")" || exit 1
GEN=$PWD/tools/traffic-mix.py
PORT=7000
H1_ADDR=10.0.1.2
H2_IF=${H2_IF:-net0.502}
NET=10.0.2.64/26
FIRST=65

die() { echo "Error: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root"
command -v python3 >/dev/null || die "python3 is needed on this host"
mkdir -p logs pids

aliases() { ip -n H2 -4 -o addr show dev $H2_IF | awk '{print $4}' | grep -E "^10\.0\.2\.(6[5-9]|[7-9][0-9]|1[01][0-9]|12[0-6])/32$" | cut -d/ -f1; }

case $1 in
setup)
	N=${2:-60}
	[ "$N" -ge 1 ] && [ "$N" -le 62 ] || die "N must be 1-62 (the /26)"
	for i in $(seq 0 $((N - 1))); do
		ip -n H2 addr replace 10.0.2.$((FIRST + i))/32 dev $H2_IF
	done
	podman exec R2 vtysh -c 'configure terminal' -c "ip route $NET 10.0.2.2" \
		-c 'router ospf' -c 'redistribute static' >/dev/null || die "could not configure R2"
	echo "H2 has $N extra addresses (10.0.2.$FIRST-10.0.2.$((FIRST + N - 1))); waiting for R1 to learn $NET"
	for _ in $(seq 30); do
		ip -n R1 route show $NET | grep -q . && break
		sleep 1
	done
	ip -n R1 route show $NET | grep -q . || die "R1 has no route to $NET yet (check OSPF)"
	ip -n R1 route show $NET
	;;
teardown)
	for a in $(aliases); do ip -n H2 addr del $a/32 dev $H2_IF; done
	podman exec R2 vtysh -c 'configure terminal' -c "no ip route $NET 10.0.2.2" \
		-c 'router ospf' -c 'no redistribute static' >/dev/null
	echo "removed"
	;;
start)
	shift
	[ -e pids/traffic-mix-server.pid ] && kill "$(cat pids/traffic-mix-server.pid)" 2>/dev/null
	ip netns exec H1 python3 "$GEN" serve --port $PORT > logs/traffic-mix-server.log 2>&1 &
	echo $! > pids/traffic-mix-server.pid
	sleep 0.5
	POOL=$(aliases | sort -t. -k4 -n | paste -sd, -)
	[ -n "$POOL" ] && POOL="--src-pool $POOL" || echo "Note: no extra H2 addresses (./traffic-mix.sh setup): l3 modes will see few flows" >&2
	ip netns exec H2 python3 "$GEN" run $H1_ADDR --port $PORT $POOL "$@" &
	echo $! > pids/traffic-mix-client.pid
	trap '$0 stop' INT TERM
	wait $!
	"$0" stop
	;;
stop)
	for f in pids/traffic-mix-client.pid pids/traffic-mix-server.pid; do
		[ -e $f ] || continue
		p=$(cat $f); rm -f $f
		kill "$p" 2>/dev/null || continue
		for _ in $(seq 30); do kill -0 "$p" 2>/dev/null || break; sleep 0.1; done
		kill -9 "$p" 2>/dev/null
	done
	;;
*)
	sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
	exit 2
	;;
esac
