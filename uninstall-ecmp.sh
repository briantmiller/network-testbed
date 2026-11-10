#!/bin/bash
MODE="l3+tos"
podman exec -ti R1 bash -c "rm -Rf /etc/bpfc/interfaces.d/*"
podman exec -ti R1 bpfcctl reload
podman exec -ti R2 bash -c "rm -Rf /etc/bpfc/interfaces.d/*"
podman exec -ti R2 bpfcctl reload
