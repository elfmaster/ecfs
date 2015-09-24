#include <stdio.h>
#include "../include/libecfs.h"
#include "../src/libecfs.hpp"

int main(int argc, char **argv)
{
	if (argc < 2) {
		printf("%s file\n", argv[0]);
		exit(0);
	}
	unsigned int i, ret;
	printf("Creating ecfs object on %s\n", argv[1]);
	Ecfs <ecfs_type64>ecfs(argv[1]);
#if 0
	std::vector<ecfs_sym> dynsym;
	std::vector<ecfs_sym> symtab;
	std::vector<fdinfo> fdinfo = ecfs.get_fdinfo();
	for (i = 0; i < fdinfo.size(); i++) {
		printf("path: %s\n", fdinfo[i].path);
	}
	std::vector<elf_prstatus> prstatus = ecfs.get_prstatus();
	for (i = 0; i < prstatus.size(); i++) {
		printf("pid: %d\n", prstatus[i].pr_pid);
	}
	dynsym = ecfs.get_dynamic_symbols();
	for (i = 0; i < 5; i++) {
		printf("dynsym st_value: %lx\n", dynsym[i].symval);
	}
	symtab = ecfs.get_local_symbols();
	for (i = 0; i < symtab.size(); i++)
		printf("symtab st_value: %lx\n", symtab[i].symval);

	char *exepath = ecfs.get_exe_path();
	printf("Executable path: %s\n", exepath);
	
	siginfo_t siginfo;
	ret = ecfs.get_siginfo(&siginfo);
	if (ret < 0) {
		printf("get_siginfo failed\n");
		exit(-1);
	}
	printf("siginfo: %d\n", siginfo.si_signo);
	
	uint8_t *stackptr;
	ssize_t stacksize = ecfs.get_stack_ptr(&stackptr);
	printf("stacksize: %d\n", stacksize);
	for (i = 0; i < 32; i++)
		printf("%02x", stackptr[i]);
	printf("\n");
	uint8_t *heapptr;
	ssize_t heapsize = ecfs.get_heap_ptr(&heapptr);
	printf("heapsize: %d bytes\n", heapsize);
	for (i = 0; i < 32; i++)
		printf("%02x", heapptr[i]);
	printf("\n");
	struct fdinfo *fdinfo;
	struct elf_prstatus *prstatus;
	ecfs_sym_t *dsyms, *lsyms;
	char *path;
	siginfo_t siginfo;
	Elf64_auxv_t *auxv;
	
	desc = load_ecfs_file(argv[1]);
	path = get_exe_path(desc);
	printf("executable: %s\n", path);
	
	ret = get_thread_count(desc);
	printf("# of threads: %d\n", ret);
	
	ret = get_siginfo(desc, &siginfo);
	printf("Exited on signal %d\n", siginfo.si_signo);
	
	ret = get_prstatus_structs(desc, &prstatus);
	for (i = 0; i < ret; i++) 
		printf("(thread %d) pid: %d\n", i + 1, prstatus[i].pr_pid);

	ret = get_fd_info(desc, &fdinfo);
	for (i = 0; i < ret; i++) {
		printf("fd: %d path: %s\n", fdinfo[i].fd, fdinfo[i].path);
		if (fdinfo[i].net) {
			printf("printing extra socket info\n");
			printf("SRC: %s:%d\n", inet_ntoa(fdinfo[i].socket.src_addr), fdinfo[i].socket.src_port);
			printf("DST: %s:%d\n", inet_ntoa(fdinfo[i].socket.dst_addr), fdinfo[i].socket.dst_port);
		}
	}

	ret = get_dynamic_symbols(desc, &dsyms);
	for (i = 0; i < ret; i++)
		printf("dynamic symbol: %s\n", &desc->dynstr[dsyms[i].nameoffset]);
	
	ret = get_local_symbols(desc, &lsyms);
	for (i = 0; i < ret; i++)
		printf("local symbol: %s\n", &desc->strtab[lsyms[i].nameoffset]);
	
	pltgot_info_t *pltgot;
	ret = get_pltgot_info(desc, &pltgot);
	for (i = 0; i < ret; i++) 
		printf("gotsite: %lx gotvalue: %lx gotshlib: %lx pltval: %lx\n", pltgot[i].got_site, pltgot[i].got_entry_va, 
						pltgot[i].shl_entry_va, pltgot[i].plt_entry_va);

	int ac = get_auxiliary_vector64(desc, &auxv);
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
	#endif			
}	

