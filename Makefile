CFLAGS = -DDEBUG -g -D_GNU_SOURCE
CC = clang
LDFLAGS	+= -ldwarf -lelf
OBJ_DIR = build
SRC_DIR = src
BIN_DIR = bin
SRCS = $(shell find ${SRC_DIR} -name '*.c' -printf '%P\n')
OBJS = $(addprefix ${OBJ_DIR}/,${SRCS:.c=.o})
TEST	= `test -d /opt/ecfs; echo $$?`
UID	= `id -u`

all: bin/ecfs
	@echo "USAGE:   make bin/<binname>  # which corresponds to a main source file in main/"
	@echo "	 make ecfs.a   # builds the shared object."

api:
	make -C ecfs_api/

tools:
	make -C tools/

${BIN_DIR}/ecfs.a: ${OBJS}
	@mkdir -p $(dir $@)
	ar rcs $@ $^

${OBJ_DIR}/%.o: ${SRC_DIR}/%.c
	@mkdir -p $(dir $@)
	${CC} ${CFLAGS} -o $@ -c $<

${BIN_DIR}/%: main/%.c ${BIN_DIR}/ecfs.a
	@mkdir -p $(dir $@)
	$(CC) $(COPTS) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -rf ${OBJ_DIR} ${BIN_DIR} *.a
	rm -f *.o ecfs
	$(MAKE) -C ecfs_api/ clean
	$(MAKE) -C tools/ clean

install:
	if [ $(UID) -eq 0 ]; then if [ $(TEST) -eq 1 ]; then mkdir /opt/ecfs; mkdir /opt/ecfs/bin; mkdir /opt/ecfs/cores; cp ecfs /opt/ecfs/bin/ecfs; echo '|/opt/ecfs/bin/ecfs -i -t -e %e -p %p -o /opt/ecfs/cores/%e.%p' > /proc/sys/kernel/core_pattern; echo "Installed ECFS successfully"; else echo "Install failed: /opt/ecfs already exists"; fi; else echo "UID must be root to install."; fi;
