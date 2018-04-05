#!/bin/sh 
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi
echo '|/opt/ecfs/bin/ecfs_handler -th -e %e -p %p -o /opt/ecfs/cores/%e.%p' > /proc/sys/kernel/core_pattern
echo 'ecfs-core handler has been enabled'
