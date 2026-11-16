#!/bin/bash
sh run-iperf.sh &
echo $! > iperf.pid
