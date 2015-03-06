#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dlfcn.h>

typedef struct option_struct {
	int text_all;
	int heuristics;
	int pid;
	char outfile[512];
	char exename[128];
} option_struct_t;
	
