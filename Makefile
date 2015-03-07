CFLAGS = -DDEBUG -g -D_GNU_SOURCE
CC = clang
LDFLAGS	+= -ldwarf -lelf -ldl
OBJ_DIR = build
SRC_DIR = src
INCLUDE_DIR = include
BIN_DIR = bin
MAIN_DIR = main
MAINS = $(shell find ${MAIN_DIR} -name '*.c' -printf '%P\n')
SRCS = $(shell find ${SRC_DIR} -name '*.c' -printf '%P\n')
HEADERS = $(addprefix ${INCLUDE_DIR}/, $(shell find ${INCLUDE_DIR} -name '*.h' -printf '%P\n'))
OBJS = $(addprefix ${OBJ_DIR}/,${SRCS:.c=.o})
BINS = $(addprefix ${BIN_DIR}/,${MAINS:.c=})
USERID = $(shell id -u)

all: libecfs/bin/libecfs.a ${BINS}
	@echo "USAGE:   make bin/<binname>  # which corresponds to a main source file in main/"
	@echo "	 make ecfs.a   # builds the shared object."

libecfs/bin/libecfs.a:
	make -C libecfs/

${BIN_DIR}/ecfs.a: ${OBJS}
	@mkdir -p $(dir $@)
	ar rcs $@ $^

${OBJ_DIR}/%.o: ${SRC_DIR}/%.c ${HEADERS}
	@mkdir -p $(dir $@)
	${CC} ${CFLAGS} -o $@ -c $<

${BIN_DIR}/%: main/%.c ${BIN_DIR}/ecfs.a libecfs/bin/libecfs.a
	@mkdir -p $(dir $@)
	$(CC) $(COPTS) $(CFLAGS) $^ -o $@ $(LDFLAGS)

.PHONY: clean
clean:
	rm -rf ${OBJ_DIR} ${BIN_DIR}
	$(MAKE) -C libecfs/ clean
	$(MAKE) -C tools/ clean

.PHONY: install
install: bin/ecfs
ifeq ($(USERID),0)
	@mkdir -p /opt/ecfs/bin/
	@mkdir -p /opt/ecfs/cores
	cp $(BIN_DIR)/ecfs /opt/ecfs/bin/ecfs
	@echo '|/opt/ecfs/bin/ecfs -t -e %e -p %p -o /opt/ecfs/cores/%e.%p' > /proc/sys/kernel/core_pattern
	@echo "Installed ECFS successfully" 
else
	$(info You must be root to execute this command)
endif

.PHONY: uninstall
uninstall:
ifeq ($(USERID),0)
	rm -Rf /opt/ecfs/bin
	@echo 'core' > /proc/sys/kernel/core_pattern
	@echo "Uninstalled ECFS successfully"
else
	$(info You must be root to execute this command)
endif
