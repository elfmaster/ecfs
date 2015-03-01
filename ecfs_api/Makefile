CFLAGS	+= -g
ARFLAGS	= rcs
LIBS	+= libecfs.a
AR	= ar
#gcc -fPIC -shared libecfs.c util.c -o libecfs.so

all: libecfs.a libtest test
	$(MAKE) -C examples/
libecfs.o: libecfs.c
	$(CC) -o $@ -c $^
util.o: util.c
	$(CC) -o $@ -c $^
libecfs.a: libecfs.o util.o
	$(AR) $(ARFLAGS) $@  $^
libtest: test.c
	$(CC) $^ $(LIBS) -o $@
test: libtest
	./libtest ./vuln.ecfs; if [ $$? -eq 0 ]; then echo "\n\nlibecfs successfully tested; no errors\n\n"; else echo "\n\nlibecfs failed; did not return 0\n\n"; fi
clean:
	rm -f libecfs.so libecfs.a libtest *.o
	$(MAKE) -C examples/ clean
