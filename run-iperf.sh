#!/bin/bash
podman exec -d H1 iperf3 -s &> /dev/null
sleep 1s
while true
do
	podman exec H2 iperf3 -P 15 -i 10 -t 3600 --bidir --forceflush -c 10.0.1.2 &> ./logs/iperf.log
done
#podman stop $( cat iperf3.H1.id )
podman exec -ti H1 pkill iperf3
