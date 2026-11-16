#!/bin/bash
for R in R1 R2
do 
	echo $R
	podman exec -ti $R bpfc-ecmp-status
done
echo ; cat logs/iperf.log | grep SUM | tail -n 20
exit 0
for R in R1 R2
do 
	echo $R
	podman exec -ti $R bpfc-ecmp-status flows
done
