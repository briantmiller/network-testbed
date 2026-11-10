#!/bin/bash
pkill ping
for Q in {0..56}
do
	Q=$(( $Q << 2 ))
	ip netns exec H1 ping -Q $Q -i 0.001 -s 1400 10.0.2.2 &>/dev/null &
	ip netns exec H2 ping -Q $Q -i 0.001 -s 1400 10.0.1.2 &>/dev/null &
done
