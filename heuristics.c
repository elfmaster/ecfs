

/* 
 * ECFS performs certain heuristics to help aid in forensics analysis.
 * one of these heuristics is showing shared libraries that have been
 * injected vs. loaded by the linker/dlopen/preloaded
 */

#include "ecfs.h"

#define OFFSET_2_PUSH 6 // # of bytes int PLT entry where push instruction begins

static int build_rodata_strings(char ***stra, uint8_t *rodata_ptr, size_t rodata_size)
{
	int i, j, index = 0;
	*stra = (char **)malloc(sizeof(char *) * rodata_size); // this gives us more room than needed
	char *string = alloca(512);
	char *p;

	for (p = (char *)rodata_ptr, j = 0, i = 0; i < rodata_size; i++) {
		if (p[i] != '\0') {
			string[j++] = p[i];
			continue;
		} else {
			string[j + 1] = '\0';
			if (strstr(string, ".so")) 
				*((*stra) + index++) = xstrdup(string);
			j = 0;
		}

	}
	return index;
}

int get_dlopen_libs(list_t *list, const char *exe_path, struct dlopen_libs **dl_libs)
{	
	ElfW(Ehdr) *ehdr;
	ElfW(Shdr) *shdr;
	ElfW(Phdr) *phdr;
	ElfW(Rela) *rela;
	ElfW(Sym) *symtab, *symbol;
	ElfW(Off) dataOffset;
	ElfW(Addr) dataVaddr, textVaddr, dlopen_plt_addr;
	uint8_t *mem;
	uint8_t *text_ptr, *data_ptr, *rodata_ptr;
	size_t text_size, dataSize, rodata_size, i; //text_size refers to size of .text not the text segment
	int fd, scount, relcount;
	char **strings, *dynstr;
	struct stat st;

	/*
	 * If there are is no dlopen() symbol then obviously
	 * no libraries were legally loaded with dlopen. However
	 * its possible __libc_dlopen_mode() was called by an
	 * attacker
	 */
	if (lookup_from_symlist("dlopen", list) == 0)
		return 0;
	
	fd = xopen(exe_path, O_RDONLY);
	xfstat(&st, fd);
	mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}
	ehdr = (ElfW(Ehdr) *)mem;
	shdr = (ElfW(Shdr) *)&shdr[ehdr->e_shoff];
	phdr = (ElfW(Phdr) *)&phdr[ehdr->e_phoff];

	for (i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD) {	
			if (phdr[i].p_offset == 0 && phdr[i].p_flags & PF_X) {
				textVaddr = phdr[i].p_vaddr;
			} else
			if (phdr[i].p_offset != 0 && phdr[i].p_flags & PF_W) {
				dataOffset = phdr[i].p_offset;
				dataVaddr = phdr[i].p_vaddr;
				dataSize = phdr[i].p_memsz;
				break;
			}
		}
	}
	char *shstrtab = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset];
	
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&shstrtab[shdr[i].sh_name], ".text")) {
			text_ptr = (uint8_t *)&mem[shdr[i].sh_offset];
			text_size = shdr[i].sh_size;	
		} else
		if (!strcmp(&shstrtab[shdr[i].sh_name], ".rela.plt")) {
			rela = (ElfW(Rela) *)&mem[shdr[i].sh_offset];
			symtab = (ElfW(Sym) *)&mem[shdr[shdr[i].sh_link].sh_offset];
			relcount = shdr[i].sh_size / sizeof(ElfW(Rela));
		} else
		if (!strcmp(&shstrtab[shdr[i].sh_name], ".rodata")) {
			rodata_ptr = (char *)&mem[shdr[i].sh_offset];
			rodata_size = shdr[i].sh_size;
		} else
		if (!strcmp(&shstrtab[shdr[i].sh_name], ".dynstr")) 
			dynstr = (char *)&mem[shdr[i].sh_offset];
	}
	if (text_ptr == NULL || rela == NULL || symtab == NULL)
		return -1;
	
	data_ptr = &mem[dataOffset];
	uint8_t *ptr;
	for (i = 0; i < relcount; i++) {
	
		ptr = &data_ptr[rela[i].r_offset - dataVaddr];
#if DEBUG
		log_msg(__LINE__, "GOT entry points to PLT addr: %lx\n", *ptr);
#endif
	        symbol = (Elf64_Sym *)&symtab[ELF64_R_SYM(rela[i].r_info)];
		if (!strcmp(&dynstr[symbol->st_name], "dlopen")) { 
#if DEBUG
			log_msg(__LINE__, "found dlopen PLT addr: %lx\n", *ptr);
#endif		
			dlopen_plt_addr = *(long *)ptr;
			break;	
		}
	}
	/*
	 * For now (until we have integrated a disassembler in)
	 * I am not going to check each individual dlopen call.	
 	 * instead just check .rodata to see if any strings for 
	 * shared libraries exist. This combined with the knowledge
	 * that dlopen is used at all in the program, is decent
	 * enough hueristic.
	 */
	scount = build_rodata_strings(&strings, rodata_ptr, rodata_size);
	if (scount == 0)
		return 0;
	*dl_libs = (struct dlopen_libs *)heapAlloc(scount * sizeof(**dl_libs));
	for (i = 0; i < scount; i++) 
		(*dl_libs)[i].libname = xstrdup(strings[scount]);
	
#if DEBUG
	for (i = 0; i < scount; i++)
		printf("dlopen lib: %s\n", (*dl_libs)[i].libname);
#endif
	return scount;
}
	
