#!/bin/bash
podman cp /home/millerbt/rpmbuild/RPMS/*/frr-10.9.0_dev*.rpm RTR:/root/
podman exec -ti RTR bash -c 'rpm -Uvh --force /root/*.rpm; rm -f /root/*.rpm'
#./testbed-ctl stop
podman rmi rtr
podman commit RTR rtr
podman save rtr > rtr.tar
