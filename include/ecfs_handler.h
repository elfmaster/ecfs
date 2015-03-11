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

#define ECFS_RAMDISK_DIR "/tmp/ecfs_ramdisk"

#define ECFS_WORKER_32 "/opt/ecfs/bin/ecfs32"
#define ECFS_WORKER_64 "/opt/ecfs/bin/ecfs64"

	
#endif
