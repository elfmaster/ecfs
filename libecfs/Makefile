CFLAGS = -DDEBUG -g -D_GNU_SOURCE
CC = clang
LDFLAGS	+= -ldwarf -lelf
OBJ_DIR = build
SRC_DIR = src
BIN_DIR = bin
MAIN_DIR = main
MAINS = $(shell find ${MAIN_DIR} -name '*.c' -printf '%P\n')
SRCS = $(shell find ${SRC_DIR} -name '*.c' -printf '%P\n')
OBJS = $(addprefix ${OBJ_DIR}/,${SRCS:.c=.o})
BINS = $(addprefix ${BIN_DIR}/,${MAINS:.c=})

all: ${BINS}

${BIN_DIR}/libecfs.a: ${OBJS}
	@mkdir -p $(dir $@)
	ar rcs $@ $^

${OBJ_DIR}/%.o: ${SRC_DIR}/%.c
	@mkdir -p $(dir $@)
	${CC} ${CFLAGS} -o $@ -c $<

${BIN_DIR}/%: main/%.c ${BIN_DIR}/libecfs.a
	@mkdir -p $(dir $@)
	$(CC) $(COPTS) $(CFLAGS) $^ -o $@ $(LDFLAGS)

.PHONY: clean
clean:
	rm -rf ${OBJ_DIR} ${BIN_DIR}
