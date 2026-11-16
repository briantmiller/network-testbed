#!/bin/bash
podman exec -ti H2  nmap -sS -n -v -Pn 10.0.1.2
