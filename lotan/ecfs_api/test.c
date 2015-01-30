#include <stdio.h>
#include "libecfs.h"

int main(int argc, char **argv)
{
	if (argc < 2) {
		printf("%s file\n", argv[0]);
		exit(0);
	}
	int i;
	ecfs_elf_t *desc;
	struct fdinfo *fdinfo;
	desc = load_ecfs_file(argv[1]);
	if (desc == NULL) {
		printf("load_ecfs_file failed\n");
		exit(-1);
	} 
	printf("desc->shdr: %p\n", desc->shdr);
	printf("desc: %p\n", desc);
	printf("Calling get_fd_info\n");
	int ret = get_fd_info(desc, &fdinfo);
	if (ret < 0) {
		printf("get_fd_info failed\n");
		exit(-1);
	}
	printf("ret: %d\n", ret);
	for (i = 0; i < ret; i++)
		printf("fd: %d path: %s\n", fdinfo[i].fd, fdinfo[i].file_path);

}

