CFLAGS	= -g
LIBS	= ../libecfs.a

all: dph

dph: detect_plt_hooks.c
	$(CC) $^ $(LIBS) -o $@
clean:
	rm -f dph

