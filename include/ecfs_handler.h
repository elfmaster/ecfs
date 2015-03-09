#ifndef _ECFS_HANDLER_H
#define _ECFS_HANDLER_H


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dlfcn.h>

#include <sys/mman.h>
#include <string.h>

#define ECFS_ENTRY_POINT "ecfs_transform_begin"
#define ECFS_WORKER_32 "/opt/ecfs/bin/libecfs32.so.1"
#define ECFS_WORKER_64 "/opt/ecfs/bin/libecfs64.so.1"

typedef struct option_struct {
	int text_all;
	int heuristics;
	int pid;
	char outfile[512];
	char exename[128];
} option_struct_t;
	
#endif
