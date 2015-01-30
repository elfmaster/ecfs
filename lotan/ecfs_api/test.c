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
	struct elf_prstatus *prstatus;
	ecfs_sym_t *dsyms;
	char *path;

	desc = load_ecfs_file(argv[1]);
	path = get_exe_path(desc);
	
	printf("executable: %s\n", path);
	ret = get_thread_count(desc);
	
	printf("# of threads: %d\n", ret);
	
	ret = get_prstatus_structs(desc, &prstatus);
	
	for (i = 0; i < ret; i++) 
		printf("(thread %d) pid: %d\n", i + 1, prstatus[i].pr_pid);

	ret = get_fd_info(desc, &fdinfo);
	
	for (i = 0; i < ret; i++)
		printf("fd: %d path: %s\n", fdinfo[i].fd, fdinfo[i].file_path);
	
	ret = get_dynamic_symbols(desc, &dsyms);
	for (i = 0; i < ret; i++)
		printf("symbol: %s\n", &desc->dynstr[dsyms[i].nameoffset]);
}	

