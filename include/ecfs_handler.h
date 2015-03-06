#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dlfcn.h>

#define ECFS_ENTRY_POINT "ecfs_transform_begin"
#define ECFS_WORKER_32 "/opt/ecfs/bin/ecfs32.so"
#define ECFS_WORKER_64 "/opt/ecfs/bin/ecfs64.so"

typedef struct option_struct {
	int text_all;
	int heuristics;
	int pid;
	char exename[256];
	char outfile[512];
} option_struct_t;
	
