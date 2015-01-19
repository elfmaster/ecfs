all: ecfs

ecfs: ecfs.o util.o eh_frame.o
	gcc -g ecfs.o util.o eh_frame.o -o ecfs -ldwarf -lelf
ecfs.o: ecfs.c
	gcc -c ecfs.c
util.o: util.c
	gcc -c util.c
eh_frame.o: eh_frame.c
	gcc -c eh_frame.c

clean:
	rm -f *.o

