all: ecfs

ecfs: ecfs.o util.o eh_frame.o ptrace.o list.o symresolve.o
	gcc ecfs.o util.o eh_frame.o ptrace.o list.o symresolve.o -o ecfs -ldwarf -lelf
ecfs.o: ecfs.c
	gcc -c ecfs.c
util.o: util.c
	gcc -c util.c
eh_frame.o: eh_frame.c
	gcc -c eh_frame.c
ptrace.o: ptrace.c
	gcc -c ptrace.c
list.o: list.c
	gcc -c list.c
symresolve.o: symresolve.c
	gcc -c symresolve.c

clean:
	rm -f *.o

