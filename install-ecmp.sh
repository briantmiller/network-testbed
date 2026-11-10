#!/bin/bash
MODE="l3+tos"
podman exec -ti R1 bpfc-ecmp-gen --member wan1.100=10m --member wan1.101=20m --member wan1.102=30m --member wan1.103=40m --member wan1.104=50m --ingress net0 --mode $MODE
podman exec -ti R1 bpfcctl reload
podman exec -ti R2 bpfc-ecmp-gen --member wan2.100=10m --member wan2.101=20m --member wan2.102=30m --member wan2.103=40m --member wan2.104=50m --ingress net0 --mode $MODE
podman exec -ti R2 bpfcctl reload
