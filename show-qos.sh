#!/bin/bash
for R in 1 2
do
	echo R$R
	for VLAN in 100 101 102 103 104
	do
		echo " wan$R.$VLAN"
		podman exec -ti R$R vtysh -c "show qos int wan$R.$VLAN" | grep Backlog -A1 
	done
done
