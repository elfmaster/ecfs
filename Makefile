all:
	gcc -ggdb main.c elf.c list.c snapshot.c util.c ptrace.c -o snapit
clean:
	rm -f snapit
