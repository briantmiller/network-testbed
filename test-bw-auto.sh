#!/bin/bash

function get_bw()
{
	RTR=$1
	IFACE=$2
	TMPFILE=$(mktemp) || return
	podman exec -ti $RTR vtysh -c "show qos int $IFACE json" | jq ".\"$IFACE\"" | tr -d ' ' | tr -d '\n' > $TMPFILE
	BW=$(cat $TMPFILE | jq .qosBandwidth)
	BWM=$(cat $TMPFILE | jq .qosBandwidthMeasured)
	echo $BW/$BWM
}

function set_bw()
{
	IFACE=$1
	RATE=$2
	tc qdisc change dev $IFACE root netem rate ${RATE}mbit delay 200ms 20ms loss 0.2%
}

function get_rate()
{
	IFACE=$1
	RATE=$(tc -j qdisc show dev $IFACE | jq .[0].options.rate.rate)
	echo $(( 100 * RATE / 125 ))
}

function check_sample()
{
	#Need to reverse interfaces here to get outbound
	R2=$(get_rate wan1.100)
	R1=$(get_rate wan2.100)
	#set_bw wan1.100 8
	#set_bw wan2.100 8
	_BW1=$(get_bw R1 wan1.100)
	_BW2=$(get_bw R2 wan2.100)
	BWM1=$( echo $_BW1 | cut -f 2 -d / )
	BWM2=$( echo $_BW2 | cut -f 2 -d / )
	#echo $_BW1 $R1
	#echo $_BW2 $R2
	PCT1=$(( 10 * $BWM1 / $R1 ))
	PCT2=$(( 10 * $BWM2 / $R2 ))
	RET=PASS
	[ $PCT1 -lt 90 ]  && echo "wan1 measured BW low  $PCT1% $BWM1 $R1" && RET=FAIL
	[ $PCT1 -gt 110 ] && echo "wan1 measured BW high $PCT1% $BWM1 $R1" && RET=FAIL 
	[ $PCT2 -lt 90 ]  && echo "wan2 measured BW low  $PCT2% $BWM2 $R2" && RET=FAIL
	[ $PCT2 -gt 110 ] && echo "wan2 measured BW high $PCT2% $BWM2 $R2" && RET=FAIL
	DATE=$(date +%F\ %T)
	MBPS1=$(( $R1 / 100000 ))
	MBPS2=$(( $R2 / 100000 ))
	echo $DATE wan1=${MBPS1}Mbps,$PCT1% wan2=${MBPS2}Mbps,$PCT2% $RET
}

function rand_rate()
{
	shuf -i 2-50 -n 1
}

function test_sample()
{

	set_bw wan1.100 $(rand_rate)
	set_bw wan2.100 $(rand_rate)
	sleep 15s
	check_sample 
}

function run_test()
{
	while true
	do
		test_sample
		sleep 10s
	done
}

#test_sample
#check_sample
run_test
