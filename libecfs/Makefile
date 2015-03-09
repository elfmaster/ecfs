V = dev
B = 64

dev_CFLAGS = -DDEBUG -g -D_GNU_SOURCE -Wall -m${B}
dev_LDFLAGS = -ldwarf -lelf
dev_TGT = ${BINS}
dev_CC = clang

asan_CFLAGS = -ggdb -fsanitize=address -O0 -fno-omit-frame-pointer -m${B}
asan_LDFLAGS = -ldwarf -lelf
asan_TGT = ${BINS}
asan_CC = clang

perf_CFLAGS = -g -O3 -fPIC -Wall -m${B}
perf_LDFLAGS = -ldwarf -lelf
perf_TGT = ${BINS}
perf_CC = gcc

prod_CFLAGS = -O3 -Wall -DNDEBUG -D_FORTIFY_SOURCE=2 -fPIC -m${B}
prod_LDFLAGS = -ldwarf -lelf -pie
prod_TGT = ${BINS}
prod_CC = gcc

shared_CFLAGS = -fPIC -m${B}
shared_LDFLAGS = -shared -Wl,-soname,libecfs${B}.so.1 -lc -m${B}
shared_TGT = ${BIN_DIR}/${V}/${B}/libecfs${B}.so.1
shared_CC = gcc

OBJ_DIR = build
SRC_DIR = src
INCLUDE_DIR = include
BIN_DIR = bin
MAIN_DIR = main
MAINS = $(shell find ${MAIN_DIR} -name '*.c' -printf '%P\n')
SRCS = $(shell find ${SRC_DIR} -name '*.c' -printf '%P\n')
HEADERS = $(addprefix ${INCLUDE_DIR}/, $(shell find ${INCLUDE_DIR} -name '*.h' -printf '%P\n'))
OBJS = $(addprefix ${OBJ_DIR}/${V}/${B}/,${SRCS:.c=.o})
BINS = $(addprefix ${BIN_DIR}/${V}/${B}/,${MAINS:.c=})

.PHONY: all
all: ${${V}_TGT}
	@echo "NOTE: use V=<variant>, with dev, asan, perf, prod or shared, and B=<32|64>."

${BIN_DIR}/${V}/${B}/libecfs${B}.so.1: ${OBJS}
	@mkdir -p $(dir $@)
	 ${${V}_CC} -o $@ ${${V}_LDFLAGS} $^

${BIN_DIR}/${V}/${B}/libecfs${B}.a: ${OBJS}
	@mkdir -p $(dir $@)
	ar rcs $@ $^

${OBJ_DIR}/${V}/${B}/%.o: ${SRC_DIR}/%.c ${HEADERS}
	@mkdir -p $(dir $@)
	${${V}_CC} ${${V}_CFLAGS} -o $@ -c $<

${BIN_DIR}/${V}/${B}/%: main/%.c ${BIN_DIR}/${V}/${B}/libecfs${B}.a
	@mkdir -p $(dir $@)
	$(${V}_CC) $(COPTS) $(${V}_CFLAGS) $^ -o $@ $(${V}_LDFLAGS)

.PHONY: clean
clean:
	rm -rf ${OBJ_DIR} ${BIN_DIR}
