all: ecfs

ecfs: ecfs.o util.o eh_frame.o ptrace.o
	gcc -DDEBUG -Wall -g ecfs.o util.o eh_frame.o ptrace.o -o ecfs -ldwarf -lelf
ecfs.o: ecfs.c
	gcc -Wall -g -DDEBUG -c ecfs.c
util.o: util.c
	gcc -g -c util.c
eh_frame.o: eh_frame.c
	gcc -g -c eh_frame.c
ptrace.o: ptrace.c
	gcc -g -c ptrace.c

clean:
	rm -f *.o

