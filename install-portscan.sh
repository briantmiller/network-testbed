#!/bin/bash
podman exec R1 mkdir -p /etc/bpfc/interfaces.d/wan1/ingress/
podman cp bpfc/portscan-guard.bpfc R1:/etc/bpfc/interfaces.d/wan1/ingress/10.bpfc
podman exec -ti R1 bpfcctl reload
podman cp bpfc/portscanctl.sh R1:/usr/sbin/portscanctl
podman exec -ti R1 chmod 755 /usr/sbin/portscanctl
