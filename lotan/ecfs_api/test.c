#include <stdio.h>
#include "libecfs.h"

int main(int argc, char **argv)
{
	if (argc < 2) {
		printf("%s file\n", argv[0]);
		exit(0);
	}
	int i, ret;
	ecfs_elf_t *desc;
	struct fdinfo *fdinfo;
	desc = load_ecfs_file(argv[1]);
	if (desc == NULL) {
		printf("load_ecfs_file failed\n");
		exit(-1);
	} 
	ret = get_thread_count(desc);
	if (ret < 0) {
		printf("get_thread_count failed\n");
		exit(-1);
	}
	printf("# of threads: %d\n", ret);

	ret = get_fd_info(desc, &fdinfo);
	if (ret < 0) {
		printf("get_fd_info failed\n");
		exit(-1);
	}
	for (i = 0; i < ret; i++)
		printf("fd: %d path: %s\n", fdinfo[i].fd, fdinfo[i].file_path);

}

