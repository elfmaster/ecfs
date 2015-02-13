# Run this after you've compiled
if [ "$(id -u)" != "0" ]; then
	echo "This script must be run as root" 1>&2
	exit 1
fi
mkdir /opt/ecfs
mkdir /opt/ecfs/bin
mkdir /opt/ecfs/cores
cp ecfs /opt/ecfs/bin
echo '|/opt/ecfs/bin/ecfs -i -e %e -p %p -o /opt/ecfs/cores/%e.%p' > /proc/sys/kernel/core_pattern
echo "Installed ecfs into /proc/sys/kernel/core_pattern. Files will be generated in /opt/ecfs/cores"

