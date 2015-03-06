/*
 * Copyright (c) 2015, Ryan O'Neill
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This tool is similar to readelf but for ecfs files. It parses and displays
 * output of ecfs files. (still in the works.
 */

#include <stdio.h>
#include "../libecfs/include/libecfs.h"

struct {
	int raw;
	int shdrs;
	int phdrs;
	int ehdr;
	int symbols;
	int libnames;
	int ecfs_stuff;
	int gotinfo;
	int auxv;
	int personality;
	int all;
} opts = {0};

int main(int argc, char **argv)
{
	int i, ret;
	ecfs_elf_t *desc;
	struct fdinfo *fdinfo;
	struct elf_prstatus *prstatus;
	ecfs_sym_t *dsyms, *lsyms;
	char *path;
	siginfo_t siginfo;
	Elf64_auxv_t *auxv;
	int c;

usage:
	if (argc < 3) {
		printf("Usage: %s [-RAPSslphega] <ecfscore>\n", argv[0]);
		printf("-a	print all (equiv to -Sslphega)\n");
		printf("-s	print symbol table info\n");
		printf("-l	print shared library names\n");
		printf("-p	print ELF program headers\n");
		printf("-S	print ELF section headers\n");
		printf("-h	print ELF header\n");
		printf("-g	print PLTGOT info\n");
		printf("-A	print Auxiliary vector\n");
		printf("-P	print personality info\n");
		printf("-e	print ecfs specific (auiliary vector, process state, sockets, pipes, fd's, etc.)\n"); 
		printf("\n-[Secondary use to view raw data from a section]\n");
		printf("-R <ecfscore> <section>\n\n");
		printf("Examples:\n");
		printf("%s -e <ecfscore>\n", argv[0]);
		printf("%s -Ag <ecfscore>\n", argv[0]);
		printf("%s -R <ecfscore> .stack\n", argv[0]);
		printf("%s -R <ecfscore> .bss\n", argv[0]);
		printf("%s -eR <ecfscore> .heap\n", argv[0]);
		printf("\n");
		exit(-1);
	}
	
	while ((c = getopt(argc, argv, "RAPSslphega")) != -1) {
		switch(c) {
			case 'S':
				opts.shdrs++;
				break;
			case 's':
				opts.symbols++;
				break;
			case 'l':
				opts.libnames++;
				break;
			case 'p':
				opts.phdrs++;
				break;
			case 'h':
				opts.ehdr++;
				break;
			case 'e':
				opts.ecfs_stuff++;
				break;
			case 'g':
				opts.gotinfo++;
				break;
			case 'P':
				opts.personality++;
				break;
			case 'A':
				opts.auxv++;
				break;
			case 'a':
				opts.all++;
				break;
			case 'R':
				if (argc < 4) {
					printf("-R requires you specify either heap, stack, vdso, or vsyscall\n");
					exit(0);
				}
				opts.raw++;
				break;
			default:
				goto usage;
		}
	}

	desc = load_ecfs_file(argv[2]);
	if (desc == NULL) {
		printf("Unable to load ecfs file: %s (Is it an ecfs file?)\n", argv[2]);
		exit(-1);
	}
	
	path = get_exe_path(desc);
	if (path == NULL) {
		printf("Unable to retrieve executable path (is this an ecfs file?)\n");
		exit(-1);
	}

	printf("\n- readecfs output for file %s\n", argv[2]);
	printf("- Executable path (.exepath): %s\n", path);
	
	if (opts.personality || opts.all || opts.ecfs_stuff) {
		printf("- Personality\n");
		printf("\tdynamically linked: %s\n", (desc->elfstats->personality & ELF_STATIC) ? "no" : "yes");
		printf("\tcompiled as PIE: %s\n", (desc->elfstats->personality & ELF_PIE) ? "yes" : "no");
		printf("\tlocal symtab reconstruction: %s\n", (desc->elfstats->personality & ELF_LOCSYM) ? "yes" : "no");
		printf("\tmalware heuristics: %s\n", (desc->elfstats->personality & ELF_HEURISTICS) ? "yes" : "no");
		printf("\toriginal bin had stripped section headers: %s\n", (desc->elfstats->personality & ELF_STRIPPED_SHDRS) ? "yes" : "no");
		printf("\n");
	}

	if (opts.ecfs_stuff || opts.all) {
		ret = get_thread_count(desc);
		printf("- Thread count (.prstatus): %d\n", ret);
	
		printf("- Thread info (.prstatus)\n");
		ret = get_prstatus_structs(desc, &prstatus);
		for (i = 0; i < ret; i++) 
			printf("\t[thread[%d] pid: %d\n", i + 1, prstatus[i].pr_pid);
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
	}
	
	if (opts.libnames || opts.ecfs_stuff || opts.all) {

		char **shlib_names;
		ret = get_shlib_mapping_names(desc, &shlib_names);
		printf("- Printing shared library mappings:\n");
		for (i = 0; i < ret; i++) 
			printf("shlib:\t%s\n", shlib_names[i]);
		printf("\n");
	}

	if (opts.ecfs_stuff || opts.all || opts.symbols) {
		ret = get_dynamic_symbols(desc, &dsyms);
		printf("- Dynamic Symbol section -\n");
		for (i = 0; i < ret; i++)
			printf(".dynsym:\t%s -\t %lx\n", &desc->dynstr[dsyms[i].nameoffset], dsyms[i].symval);
		printf("\n");
			ret = get_local_symbols(desc, &lsyms);
		printf("- Symbol Table section -\n");
		for (i = 0; i < ret; i++)
			printf(".symtab:\t %s -\t %lx\n", &desc->strtab[lsyms[i].nameoffset], lsyms[i].symval);
		printf("\n");
	}
	if (opts.ecfs_stuff || opts.all || opts.gotinfo) {
		pltgot_info_t *pltgot;
		if (!(desc->elfstats->personality & ELF_STATIC)) {
			printf("- Printing out GOT/PLT characteristics (pltgot_info_t):\n");
			ret = get_pltgot_info(desc, &pltgot);
			printf("gotsite            gotvalue          gotshlib          pltval\n");
			for (i = 0; i < ret; i++) 
				printf("0x%-16lx 0x%-16lx 0x%-16lx 0x%-16lx\n", pltgot[i].got_site, pltgot[i].got_entry_va, 
				pltgot[i].shl_entry_va, pltgot[i].plt_entry_va);
			printf("\n");
		}
	}
	
	if (opts.auxv || opts.ecfs_stuff || opts.all) {
		int ac = get_auxiliary_vector64(desc, &auxv);
		printf("- Printing auxiliary vector (.auxilliary):\n");
		for (i = 0; i < ac && auxv[i].a_type != AT_NULL; i++) {
			switch(auxv[i].a_type) {
				case AT_PHDR:
					printf("AT_PHDR:\t 0x%lx\n", auxv[i].a_un.a_val);
					break;
				case AT_PHENT:
					printf("AT_PHENT:\t 0x%lx\n", auxv[i].a_un.a_val);
					break;
				case AT_PHNUM:
					printf("AT_PHNUM:\t 0x%lx\n", auxv[i].a_un.a_val);
					break;
				case AT_PAGESZ:
					printf("AT_PAGESZ:\t 0x%lx\n", auxv[i].a_un.a_val);
					break;
				case AT_BASE:
					printf("AT_BASE:\t 0x%lx\n", auxv[i].a_un.a_val);
					break;
				case AT_EXECFD:
					printf("AT_EXECFD:\t 0x%lx\n", auxv[i].a_un.a_val);
					break;
				case AT_IGNORE:
					printf("AT_IGNORE:\t 0x%lx\n", auxv[i].a_un.a_val);
					break;
				case AT_ENTRY:
					printf("AT_ENTRY:\t 0x%lx\n", auxv[i].a_un.a_val);
					break;
				case AT_FLAGS:
					printf("AT_FLAGS:\t 0x%lx\n", auxv[i].a_un.a_val);
					break;
				case AT_UID:
					printf("AT_UID:\t 0x%lx\n", auxv[i].a_un.a_val);
					break;
				case AT_EUID:
					printf("AT_EUID:\t 0x%lx\n", auxv[i].a_un.a_val);
					break;
				case AT_GID:
					printf("AT_GID:\t 0x%lx\n", auxv[i].a_un.a_val);
					break;
			}
		}
	}
	
	ElfW(Ehdr) *ehdr = desc->ehdr;
	ElfW(Shdr) *shdr = desc->shdr;
	ElfW(Phdr) *phdr = desc->phdr;
	char *shstrtab = desc->shstrtab;
	
	if (opts.all || opts.ehdr) {
		printf("\n- Displaying ELF header:\n");
	
		printf("e_entry:\t0x%lx\n"
		"e_phnum:\t%d\n"
		"e_shnum:\t%d\n"
		"e_shoff:\t0x%lx\n"
		"e_phoff:\t0x%lx\n" 
		"e_shstrndx:\t%d\n", ehdr->e_entry, ehdr->e_phnum, ehdr->e_shnum, 
				    ehdr->e_shoff, ehdr->e_phoff, ehdr->e_shstrndx);
		
	}
	if (opts.all || opts.shdrs) {
		printf("\n- Displaying ELF section headers:\n");
		printf("Address          Offset\t   Size\t   Entsize\t   Name\n");
		for (i = 0; i < desc->ehdr->e_shnum; i++) {
			printf("0x%-16lx 0x%-8lx 0x%-8lx 0x%-4lx %s\n", shdr[i].sh_addr, shdr[i].sh_offset, 
			shdr[i].sh_size, shdr[i].sh_entsize, &shstrtab[shdr[i].sh_name]);
		}
	}
	
	if (opts.all || opts.phdrs) {
		printf("\n- Displaying ELF program headers:\n");
		printf("Address          Offset\t   FileSZ\t MemSZ\tType\n");
		for (i = 0; i < desc->ehdr->e_phnum; i++) {
			printf("0x%-16lx 0x%-8lx 0x%-8lx 0x%-4lx   %s\n", phdr[i].p_vaddr, phdr[i].p_offset,
			phdr[i].p_filesz, phdr[i].p_memsz, phdr[i].p_type == PT_LOAD ? "LOAD" : "NOTE");
		}
		printf("\n");			
	}
	
	if (opts.raw) {
		uint8_t *ptr;
		ssize_t section_size;
		section_size = get_section_pointer(desc, argv[3], &ptr);
		if (section_size < 0) {
			printf("Unable to load section named: '%s'\n", argv[3]);
			goto done;
		}
		for (i = 0; i < section_size; i++) {
			if (i > 0 && (i % 32 == 0))
				printf("\n");
			printf("%02x ", ptr[i]);
		}
		printf("\n");
	}

done:
	unload_ecfs_file(desc);
}		

