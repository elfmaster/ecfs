all:
	#gcc -fPIC -shared libecfs.c util.c -o libecfs.so
	gcc -c -o libecfs.o libecfs.c
	gcc -c -o util.o util.c
	ar rcs libecfs.a  libecfs.o util.o
clean:
	rm -f libecfs.so libecfs.a
