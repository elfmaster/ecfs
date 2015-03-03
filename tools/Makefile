CFLAGS	+= -g
LIBS	+= ../ecfs_api/libecfs.a

all: et_flip readecfs

et_flip: et_flip.c util.c
	$(CC) $(CFLAGS) $^ -o $@
readecfs: readecfs.c 
	$(CC) $(CFLAGS) -O2 $^ $(LIBS) -o $@
clean:
	rm -f et_flip readecfs
