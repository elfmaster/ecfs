CFLAGS	+= -g
COPTS	+= -DDEBUG
LDFLAGS	+= -ldwarf -lelf
TEST	= `test -d /opt/ecfs; echo $$?`
UID	= `id -u`

all: ecfs
	make -C ecfs_api/
	make -C tools/
ecfs: ecfs.o util.o eh_frame.o ptrace.o list.o symresolve.o heuristics.o 
	$(CC) $(COPTS) $(CFLAGS) $^ -o $@ $(LDFLAGS)
ecfs.o: ecfs.c
	$(CC) $(COPTS) $(CFLAGS) -O2 -c $^
util.o: util.c
	$(CC) $(CFLAGS) -c $^
eh_frame.o: eh_frame.c
	$(CC) $(CFLAGS) -c $^
ptrace.o: ptrace.c
	$(CC) $(CFLAGS) -c $^
list.o: list.c
	$(CC) $(CFLAGS) -c $^
symresolve.o: symresolve.c
	$(CC) $(CFLAGS) -c $^
heuristics.o: heuristics.c
	$(CC) $(COPTS) $(CFLAGS) -c $^
clean:
	rm -f *.o ecfs
	$(MAKE) -C ecfs_api/ clean
	$(MAKE) -C tools/ clean

install:
	if [ $(UID) -eq 0 ]; then if [ $(TEST) -eq 1 ]; then mkdir /opt/ecfs; mkdir /opt/ecfs/bin; mkdir /opt/ecfs/cores; cp ecfs /opt/ecfs/bin/ecfs; echo '|/opt/ecfs/bin/ecfs -i -t -e %e -p %p -o /opt/ecfs/cores/%e.%p' > /proc/sys/kernel/core_pattern; echo "Installed ECFS successfully"; else echo "Install failed: /opt/ecfs already exists"; fi; else echo "UID must be root to install."; fi;
