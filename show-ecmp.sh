#!/bin/bash
for R in R1 R2
do 
	echo $R
	podman exec -ti $R bpfc-ecmp-status
done
for R in R1 R2
do 
	echo $R
	podman exec -ti $R bpfc-ecmp-status flows
done
