all: ecfs

ecfs: ecfs.o util.o eh_frame.o ptrace.o list.o symresolve.o heuristics.o 
	gcc -DDEBUG ecfs.o util.o eh_frame.o ptrace.o list.o symresolve.o heuristics.o -o ecfs -ldwarf -lelf
ecfs.o: ecfs.c
	gcc -DDEBUG -c ecfs.c
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
heuristics.o: heuristics.c
	gcc -DDEBUG -c heuristics.c
clean:
	rm -f *.o

