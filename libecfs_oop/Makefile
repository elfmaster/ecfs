V = dev
B = 64

dev_CXXFLAGS = -std=c++11 -DDEBUG -g -D_GNU_SOURCE -Wall -m${B}
dev_LDFLAGS = -ldwarf -lelf
dev_TGT = ${BINS}
dev_CXX = clang++

asan_CXXFLAGS = -std=c++11 -ggdb -fsanitize=address -O0 -fno-omit-frame-pointer -m${B}
asan_LDFLAGS = -ldwarf -lelf
asan_TGT = ${BINS}
asan_CXX = clang++

perf_CXXFLAGS = -std=c++11 -g -O3 -fPIC -Wall -m${B}
perf_LDFLAGS = -ldwarf -lelf
perf_TGT = ${BINS}
perf_CXX = g++

prod_CXXFLAGS = -std=c++11 -O3 -Wall -DNDEBUG -D_FORTIFY_SOURCE=2 -fPIC -m${B}
prod_LDFLAGS = -ldwarf -lelf -pie
prod_TGT = ${BINS}
prod_CXX = g++

shared_CXXFLAGS = -std=c++11 -fPIC -m${B}
shared_LDFLAGS = -shared -Wl,-soname,libecfsreader${B}.so.1 -lc -m${B}
shared_TGT = ${BIN_DIR}/${V}/${B}/libecfsreader${B}.so.1
shared_CXX = g++

OBJ_DIR = build
SRC_DIR = src
INCLUDE_DIR = include
BIN_DIR = bin
MAIN_DIR = main
MAINS = $(shell find ${MAIN_DIR} -name '*.cpp' -printf '%P\n')
SRCS = $(shell find ${SRC_DIR} -name '*.cpp' -printf '%P\n')
HEADERS = $(addprefix ${INCLUDE_DIR}/, $(shell find ${INCLUDE_DIR} -name '*.hpp' -printf '%P\n'))
OBJS = $(addprefix ${OBJ_DIR}/${V}/${B}/,${SRCS:.cpp=.o})
BINS = $(addprefix ${BIN_DIR}/${V}/${B}/,${MAINS:.cpp=})

.PHONY: all
all: ${${V}_TGT}
	@echo "NOTE: use V=<variant>, with dev, asan, perf, prod or shared, and B=<32|64>."

${BIN_DIR}/${V}/${B}/libecfsreader${B}.so.1: ${OBJS}
	@mkdir -p $(dir $@)
	 ${${V}_CXX} -o $@ ${${V}_LDFLAGS} $^

${BIN_DIR}/${V}/${B}/libecfsreader${B}.a: ${OBJS}
	@mkdir -p $(dir $@)
	ar rcs $@ $^

${OBJ_DIR}/${V}/${B}/%.o: ${SRC_DIR}/%.cpp ${HEADERS}
	@mkdir -p $(dir $@)
	${${V}_CXX} ${${V}_CXXFLAGS} -o $@ -c $<

${BIN_DIR}/${V}/${B}/%: main/%.cpp ${BIN_DIR}/${V}/${B}/libecfsreader${B}.a
	@mkdir -p $(dir $@)
	$(${V}_CXX) $(COPTS) $(${V}_CXXFLAGS) $^ -o $@ $(${V}_LDFLAGS)

.PHONY: clean
clean:
	rm -rf ${OBJ_DIR} ${BIN_DIR}
