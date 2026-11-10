#!/bin/bash
for R in 1 2
do
	echo R$R
	podman exec -ti R$R vtysh -c "show qos int wan$R.100"
done
