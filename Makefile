all:
	gcc -ggdb main.c elf.c list.c snapshot.c util.c ptrace.c eh_frame.c -o snapit -ldwarf -lelf
clean:
	rm -f snapit
