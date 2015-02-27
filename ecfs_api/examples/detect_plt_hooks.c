/*
 * This program will detect when a shared library
 * has been injected, which one it is, and which
 * functions have been hijacked.
 */

#include "../libecfs.h"

int main(int argc, char **argv)
{
	ecfs_elf_t *desc;
	ecfs_sym_t *dsyms, *lsyms;
	char *progname;
	int i;
	char *libname;
	long evil_addr;
	
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
			printf("[!] Found malicously injected shared library: %s\n", libname);
		}
	}
	pltgot_info_t *pltgot;
        int ret = get_pltgot_info(desc, &pltgot);
	for (i = 0; i < ret; i++) {
		if (pltgot[i].got_entry_va != pltgot[i].shl_entry_va && pltgot[i].got_entry_va != pltgot[i].plt_entry_va)
			printf("[!] Found PLT/GOT hook, function 'name' is pointing at %lx instead of %lx\n", 
				pltgot[i].got_entry_va, evil_addr = pltgot[i].shl_entry_va);
	}
	ret = get_dynamic_symbols(desc, &dsyms);
        for (i = 0; i < ret; i++) {
                if (dsyms[i].symval == evil_addr) {
                        printf("[!] %lx corresponds to hijacked function: %s\n", dsyms[i].symval, &dsyms[i].strtab[dsyms[i].nameoffset]);
                        break;
                }
        }

}

