#!/bin/sh
DIRECTORY = "/opt/ecfs"
echo 'Installing ecfs for a 32bit system'
make V=prod B=32
if [ -d "$DIRECTORY"]; then
mkdir -p /opt/ecfs/bin
mkdir -p /opt/ecfs/cores
fi
sudo cp bin/prod/32/ecfs /opt/ecfs/bin/ecfs
echo '|/opt/ecfs/bin/ecfs -t -e %e -p %p -o /opt/ecfs/cores/%e.%p' > /proc/sys/kernel/core_pattern

