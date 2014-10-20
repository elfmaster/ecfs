all: ecfs
ecfs: main.o elf.o list.o snapshot.o util.o ptrace.o eh_frame.o
	gcc -g main.o elf.o list.o snapshot.o util.o ptrace.o eh_frame.o -o ecfs -ldwarf -lelf
main.o: main.c
	gcc -c main.c
elf.o: elf.c
	gcc -c elf.c
list.o: list.c
	gcc -c list.c
snapshot.o: snapshot.c
	gcc -c snapshot.c
util.o: util.c
	gcc -c util.c
ptrace.o: ptrace.c
	gcc -c ptrace.c
eh_frame.o: eh_frame.c
	gcc -c eh_frame.c

clean:
	rm -f *.o ecfs
