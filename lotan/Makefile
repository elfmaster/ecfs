all: ecfs

ecfs: ecfs.o util.o eh_frame.o ptrace.o list.o symresolve.o
	gcc -fno-omit-frame-pointer -Wall -Werror -g ecfs.o util.o eh_frame.o ptrace.o list.o symresolve.o -o ecfs -ldwarf -lelf
ecfs.o: ecfs.c
	gcc -fno-omit-frame-pointer -g -c ecfs.c
util.o: util.c
	gcc -g -c util.c
eh_frame.o: eh_frame.c
	gcc -g -c eh_frame.c
ptrace.o: ptrace.c
	gcc -g -c ptrace.c
list.o: list.c
	gcc -g -c list.c
symresolve.o: symresolve.c
	gcc -g -c symresolve.c

clean:
	rm -f *.o

