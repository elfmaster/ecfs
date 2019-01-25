#include <stdio.h>
#include "../include/libecfs.h"

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
	ecfs_sym_t *dsyms, *lsyms;
	char *path;
	siginfo_t siginfo;
	Elf64_auxv_t *auxv;
	ecfs_module_iter_t iter;
	ecfs_iter_t ires;
	struct shlib_module entry;

	desc = ecfs_load_file(argv[1]);
	path = ecfs_exe_path(desc);
	printf("executable: %s\n", path);
	
	ret = ecfs_thread_count(desc);
	printf("# of threads: %d\n", ret);
	
	ret = ecfs_siginfo(desc, &siginfo);
	printf("Exited on signal %d\n", siginfo.si_signo);

	printf("Loaded modules:\n");
	ecfs_module_iterator_init(desc, &iter);
	while (ecfs_module_iterator_next(&iter, &entry) == ECFS_ITER_OK) {
		printf("%#lx - %#lx: %s\n", entry.base_vaddr, entry.base_vaddr + entry.len, entry.path);
	}

	ret = ecfs_prstatus_structs(desc, &prstatus);
	for (i = 0; i < ret; i++) 
		printf("(thread %d) pid: %d\n", i + 1, prstatus[i].pr_pid);

	ret = ecfs_fd_info(desc, &fdinfo);
	for (i = 0; i < ret; i++) {
		printf("fd: %d path: %s\n", fdinfo[i].fd, fdinfo[i].path);
		if (fdinfo[i].net) {
			printf("printing extra socket info\n");
			printf("SRC: %s:%d\n", inet_ntoa(fdinfo[i].socket.src_addr), fdinfo[i].socket.src_port);
			printf("DST: %s:%d\n", inet_ntoa(fdinfo[i].socket.dst_addr), fdinfo[i].socket.dst_port);
		}
	}

	ret = ecfs_dynamic_symbols(desc, &dsyms);
	for (i = 0; i < ret; i++)
		printf("dynamic symbol: %s\n", &desc->dynstr[dsyms[i].nameoffset]);
	
	ret = ecfs_local_symbols(desc, &lsyms);
	for (i = 0; i < ret; i++)
		printf("local symbol: %s\n", &desc->strtab[lsyms[i].nameoffset]);
	
	pltgot_info_t *pltgot;
	ret = ecfs_pltgot_info(desc, &pltgot);
	for (i = 0; i < ret; i++) 
		printf("gotsite: %lx gotvalue: %lx gotshlib: %lx pltval: %lx\n", pltgot[i].got_site, pltgot[i].got_entry_va, 
						pltgot[i].shl_entry_va, pltgot[i].plt_entry_va);

	int ac = ecfs_auxiliary_vector64(desc, &auxv);
	printf("Printing some of AUXV which has %d elements\n", ac);
	for (i = 0; i < ac && auxv[i].a_type != AT_NULL; i++) {
		switch(auxv[i].a_type) {
			case AT_PHDR:
				printf("AT_PHDR: %lx\n", auxv[i].a_un.a_val);
				break;
			case AT_PHENT:
				printf("AT_PHENT: %lx\n", auxv[i].a_un.a_val);
				break;
			case AT_PHNUM:
				printf("AT_PHNUM: %lx\n", auxv[i].a_un.a_val);
				break;
			case AT_PAGESZ:
				printf("AT_PAGESZ: %lx\n", auxv[i].a_un.a_val);
				break;
			case AT_BASE:
				printf("AT_BASE: %lx\n", auxv[i].a_un.a_val);
				break;
		}
	}


return 0;
				
}	

