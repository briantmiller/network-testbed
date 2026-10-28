#!/bin/bash
ip netns exec H1 ping -i 0.001 -s 1400 10.0.2.2 &>/dev/null &
ip netns exec H2 ping -i 0.001 -s 1400 10.0.1.2 &>/dev/null &
