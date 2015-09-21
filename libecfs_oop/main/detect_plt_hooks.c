/*
 * This program will detect when a shared library
 * has been injected, or preloaded, and detect when
 * functions have been hijacked.
 */

#include "../include/libecfs.h"

int main(int argc, char **argv)
{
	#if 0
	ecfs_elf_t *desc;
	ecfs_sym_t *dsyms;
	char *progname;
	int i;
	char *libname;
	long evil_addr = 0;
	
	if (argc < 2) {
		printf("Usage: %s <ecfs_file>\n", argv[0]);
		exit(0);
	}

	desc = load_ecfs_file(argv[1]);
	progname = get_exe_path(desc);
	
	printf("Performing analysis on '%s' which corresponds to executable: %s\n", argv[1], progname);

	for (i = 0; i < desc->ehdr->e_shnum; i++) {
		if (desc->shdr[i].sh_type == SHT_INJECTED) {
			libname = strdup(&desc->shstrtab[desc->shdr[i].sh_name]);
			printf("[!] Found malicously injected ET_DYN (Dynamic ELF): %s - base: %lx\n", libname, desc->shdr[i].sh_addr);
		} else
		if (desc->shdr[i].sh_type == SHT_PRELOADED) {
			libname = strdup(&desc->shstrtab[desc->shdr[i].sh_name]);
			printf("[!] Found a preloaded shared library (LD_PRELOAD): %s - base: %lx\n", libname, desc->shdr[i].sh_addr);
		}
	}
	pltgot_info_t *pltgot;
	int gotcount = get_pltgot_info(desc, &pltgot);
	for (i = 0; i < gotcount; i++) {
		if (pltgot[i].got_entry_va != 
		pltgot[i].shl_entry_va && 
		pltgot[i].got_entry_va != pltgot[i].plt_entry_va && pltgot[i].shl_entry_va != 0) {
			printf("[!] Found PLT/GOT hook: A function is pointing at %lx instead of %lx\n", 
				pltgot[i].got_entry_va, evil_addr = pltgot[i].shl_entry_va);
			int symcount = get_dynamic_symbols(desc, &dsyms);
			for (i = 0; i < symcount; i++) {
				if (dsyms[i].symval == evil_addr) {
					printf("[!] %lx corresponds to hijacked function: %s\n", dsyms[i].symval, &dsyms[i].strtab[dsyms[i].nameoffset]);
				break;
				}
			}
		}
	}
#endif
	return 0;
}

