#include <stdio.h>
#include "../ecfs_api/libecfs.h"

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
	
	desc = load_ecfs_file(argv[1]);
	path = get_exe_path(desc);
	
	printf("- read_ecfs output for file %s\n", argv[1]);
	printf("- Executable path (.exepath): %s\n", path);
	
	ret = get_thread_count(desc);
	printf("- Thread count (.prstatus): %d\n", ret);
	
	printf("- Thread info (.prstatus)\n");
	ret = get_prstatus_structs(desc, &prstatus);
	for (i = 0; i < ret; i++) 
		printf("\t[thread %d] pid: %d\n", i + 1, prstatus[i].pr_pid);
	printf("\n");

	ret = get_siginfo(desc, &siginfo);
        printf("- Exited on signal (.siginfo): %d\n", siginfo.si_signo);
 	       
	
	ret = get_fd_info(desc, &fdinfo);
	printf("- files/pipes/sockets (.fdinfo):\n");
	for (i = 0; i < ret; i++) {
		printf("\t[fd: %d] path: %s\n", fdinfo[i].fd, fdinfo[i].path);
		if (fdinfo[i].net) {
			switch(fdinfo[i].net) {
				case NET_TCP:
					printf("\tPROTOCOL: TCP\n");
					printf("\tSRC: %s:%d\n", inet_ntoa(fdinfo[i].socket.src_addr), fdinfo[i].socket.src_port);
					printf("\tDST: %s:%d\n", inet_ntoa(fdinfo[i].socket.dst_addr), fdinfo[i].socket.dst_port);
					printf("\n");
					break;
				case NET_UDP:
					printf("\tPROTOCOL: UDP\n");
                                        printf("\tSRC: %s:%d\n", inet_ntoa(fdinfo[i].socket.src_addr), fdinfo[i].socket.src_port);
                                        printf("\tDST: %s:%d\n", inet_ntoa(fdinfo[i].socket.dst_addr), fdinfo[i].socket.dst_port);
                                        printf("\n");
					break;
			}

		}
	}
	printf("\n");

	ret = get_dynamic_symbols(desc, &dsyms);
	for (i = 0; i < ret; i++)
		printf(".dynsym: %s - %lx\n", &desc->dynstr[dsyms[i].nameoffset], dsyms[i].symval);
	printf("\n");
	ret = get_local_symbols(desc, &lsyms);
	for (i = 0; i < ret; i++)
		printf(".symtab: %s - %lx\n", &desc->strtab[lsyms[i].nameoffset], lsyms[i].symval);
	printf("\n");

	pltgot_info_t *pltgot;
	if (!(desc->elfstats->personality & ELF_STATIC)) {
		printf("- Printing out GOT/PLT characteristics (pltgot_info_t):\n");
		ret = get_pltgot_info(desc, &pltgot);
		for (i = 0; i < ret; i++) 
			printf("gotsite: %lx gotvalue: %lx gotshlib: %lx pltval: %lx\n", pltgot[i].got_site, pltgot[i].got_entry_va, 
			pltgot[i].shl_entry_va, pltgot[i].plt_entry_va);
		printf("\n");
	}

	int ac = get_auxiliary_vector64(desc, &auxv);
	printf("- Printing auxiliary vector (.auxilliary):\n");
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
			case AT_EXECFD:
				printf("AT_EXECFD: %lx\n", auxv[i].a_un.a_val);
				break;
			case AT_IGNORE:
				printf("AT_IGNORE: %lx\n", auxv[i].a_un.a_val);
				break;
			case AT_ENTRY:
				printf("AT_ENTRY: %lx\n", auxv[i].a_un.a_val);
				break;
			case AT_FLAGS:
				printf("AT_FLAGS: %lx\n", auxv[i].a_un.a_val);
				break;
			case AT_UID:
				printf("AT_UID: %lx\n", auxv[i].a_un.a_val);
				break;
			case AT_EUID:
				printf("AT_EUID: %lx\n", auxv[i].a_un.a_val);
				break;
			case AT_GID:
				printf("AT_GID: %lx\n", auxv[i].a_un.a_val);
				break;
		}
	}

}	

