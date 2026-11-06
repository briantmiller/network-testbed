#!/bin/bash
podman exec -d H1 iperf3 -s &> /dev/null
podman exec -ti H2 iperf3 -P 50 -i 10 -t 3600 --bidir --forceflush -c 10.0.1.2 | grep SUM
#podman stop $( cat iperf3.H1.id )
podman exec -ti H1 pkill iperf3
