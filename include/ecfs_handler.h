#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef struct option_struct {
	int text_all;
	int heuristics;
	int pid;
	char exename[256];
	char outfile[512];
} option_struct_t;
	
