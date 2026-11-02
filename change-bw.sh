#!/bin/bash
R1=$1
R2=$2
[ "$R1" == "" ] && R1=10
[ "$R2" == "" ] && R2=20
tc qdisc change dev wan1-100 root netem rate ${R1}mbit delay 200ms 20ms loss 3%
tc qdisc change dev wan2-100 root netem rate ${R2}mbit delay 150ms 10ms loss 3%
