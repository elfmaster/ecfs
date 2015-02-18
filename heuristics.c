

/* 
 * ECFS performs certain heuristics to help aid in forensics analysis.
 * one of these heuristics is showing shared libraries that have been
 * injected vs. loaded by the linker/dlopen/preloaded
 */

#include "ecfs.h"

#define OFFSET_2_PUSH 6 // # of bytes int PLT entry where push instruction begins
#define MAX_NEEDED_LIBS 512
#define MAX_STRINGS 8192 * 2

int build_rodata_strings(char ***stra, uint8_t *rodata_ptr, size_t rodata_size)
{
	int i, j, index = 0;
	*stra = (char **)malloc(sizeof(char *) * MAX_STRINGS); 
	char *string = alloca(512);
	char *p;

	for (p = (char *)rodata_ptr, j = 0, i = 0; i < rodata_size; i++) {
		if (p[i] != '\0') {
			string[j++] = p[i];
			continue;
		} else {
			string[j] = '\0';
			if (strstr(string, ".so")) {
				*((*stra) + index++) = xstrdup(string);
			}
			j = 0;
		}

	}
	return index;
}

/* 
 * Find the actual path to DT_NEEDED libraries
 * and take possible symlinks into consideration 
 */
static char * get_real_lib_path(char *name)
{
	char tmp[512] = {0};
	char real[512] = {0};
	char *ptr;

	int ret;
	
	snprintf(tmp, 512, "/lib/x86_64-linux-gnu/%s", name);
	if (access(tmp, F_OK) == 0) {
		ret = readlink(tmp, real, 512);
		if (ret > 0) {
			ptr = get_real_lib_path(real);
			return xstrdup(ptr);
		}
		else
			return xstrdup(tmp);
	}

	snprintf(tmp, 512, "/usr/lib/%s", name);
	if (access(tmp, F_OK) == 0) {
		ret = readlink(tmp, real, 512);
        	if (ret > 0) {
			ptr = get_real_lib_path(real);
                	return xstrdup(ptr);
		}
		else
			return xstrdup(tmp);
	}

	snprintf(tmp, 512, "/lib/%s", name);
	
	if (access(tmp, F_OK) == 0) {
		ret = readlink(tmp, real, 512);
		if (ret > 0) {
			ptr = get_real_lib_path(real);
			return xstrdup(ptr);
		}
		else
			return xstrdup(tmp);
	}
	
	return NULL;
}

/* 
 * From DT_NEEDED (We pass the executable and each shared library to this function)
 */
int get_dt_needed_libs(const char *bin_path, struct needed_libs **needed_libs)
{
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	ElfW(Dyn) *dyn;
	ElfW(Shdr) *shdr;
	int fd, i,  needed_count;
	uint8_t *mem;
	struct stat st;
	char *dynstr;

	fd = xopen(bin_path, O_RDONLY);
	fstat(fd, &st);
	mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	ehdr = (ElfW(Ehdr) *)mem;
	phdr = (ElfW(Phdr) *)&mem[ehdr->e_phoff];
	shdr = (ElfW(Shdr) *)&mem[ehdr->e_shoff];
	char *shstrtab = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset];
	
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&shstrtab[shdr[i].sh_name], ".dynstr")) {
			dynstr = (char *)&mem[shdr[i].sh_offset];
			break;
		}
	}

	if (dynstr == NULL)
		return 0;

	for (i = 0; i < ehdr->e_phnum; i++) { 
		if (phdr[i].p_type == PT_DYNAMIC) {	
			dyn = (ElfW(Dyn) *)&mem[phdr[i].p_offset];
			break;
		}
	}
	if (dyn == NULL)
		return 0;
	
	*needed_libs = (struct needed_libs *)heapAlloc(sizeof(**needed_libs) * MAX_NEEDED_LIBS);
	for (needed_count = 0, i = 0; dyn[i].d_tag != DT_NULL; i++) {
		switch(dyn[i].d_tag) {
			case DT_NEEDED:
				(*needed_libs)[i].libname = xstrdup(&dynstr[dyn[i].d_un.d_val]);
				(*needed_libs)[i].libpath = get_real_lib_path((*needed_libs)[i].libname);
				needed_count++;
				break;
			default:
				break;
		}
	}
	return needed_count;
}
/*
 * Get dlopen libs
 */
int get_dlopen_libs(const char *exe_path, struct dlopen_libs **dl_libs)
{	
	ElfW(Ehdr) *ehdr;
	ElfW(Shdr) *shdr;
	ElfW(Phdr) *phdr;
	ElfW(Rela) *rela;
	ElfW(Sym) *symtab, *symbol;
	ElfW(Off) dataOffset;
	ElfW(Addr) dataVaddr, textVaddr;
	uint8_t *mem;
	uint8_t *text_ptr, *data_ptr, *rodata_ptr;
	size_t text_size, dataSize, rodata_size, i; //text_size refers to size of .text not the text segment
	int ret, fd, scount, relcount, symcount, found_dlopen;
	char **strings, *dynstr, tmp[512];
	struct stat st;
	
	/*
	 * If there are is no dlopen() symbol then obviously
	 * no libraries were legally loaded with dlopen. However
	 * its possible __libc_dlopen_mode() was called by an
	 * attacker
	 */
	
	fd = xopen(exe_path, O_RDONLY);
	xfstat(fd, &st);
	mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}
	ehdr = (ElfW(Ehdr) *)mem;
	shdr = (ElfW(Shdr) *)&mem[ehdr->e_shoff];
	phdr = (ElfW(Phdr) *)&mem[ehdr->e_phoff];
	
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
	log_msg(__LINE__, "dlopen_libs, getting shdr stuff");
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
		else
		if (!strcmp(&shstrtab[shdr[i].sh_name], ".dynsym"))
			symcount = shdr[i].sh_size / sizeof(ElfW(Sym));
	}
	if (text_ptr == NULL || rela == NULL || symtab == NULL)
		return -1;
	
	for (found_dlopen = 0, i = 0; i < symcount; i++) {
		if (!strcmp(&dynstr[symtab[i].st_name], "dlopen")) {
			found_dlopen++;
			break;
		}
	}
	if (!found_dlopen) 
		return 0;			
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
	for (i = 0; i < scount; i++) {
		ret = readlink(strings[i], tmp, 512);
		(*dl_libs)[i].libpath = ret < 0 ? xstrdup(strings[i]) : xstrdup(tmp);
		free(strings[i]);
#if DEBUG
		log_msg(__LINE__, "dlopen libstring: %s", (*dl_libs)[i].libpath);
#endif
	}
	
#if DEBUG
	for (i = 0; i < scount; i++)
		printf("dlopen lib: %s\n", (*dl_libs)[i].libpath);
#endif
	return scount;
}

void mark_dll_injection(notedesc_t *notedesc, memdesc_t *memdesc, elfdesc_t *elfdesc)
{
	struct lib_mappings *lm_files = notedesc->lm_files;
	struct needed_libs *needed_libs;
	struct dlopen_libs *dlopen_libs;
	int needed_count;
	int dlopen_count;
	int valid;
	int i, j, c;
	/*
	 * We just check the immediate executable for dlopen calls
	 */
	
	dlopen_count = get_dlopen_libs(memdesc->exe_path, &dlopen_libs);
#if DEBUG
	if (dlopen_count <= 0) {
		log_msg(__LINE__, "found %d dlopen loaded libraries", dlopen_count);
	}
#endif
	
	/*
	 * We check the dynamic segment of the executable 
	 * (DT_NEEDED) to see what the dependencies are.
	 * XXX ideally this should be done transitively so that
	 * we check the DT_NEEDED of each shared library and get
	 * its dependencies as well, otherwise we may get some
	 * false positives.
	 */
	char *real;
	int ret;
	
	needed_count = get_dt_needed_libs(memdesc->exe_path, &needed_libs);

	for (i = 0; i < lm_files->libcount; i++) {
		for (j = 0; j < needed_count; j++) {
			/*
			 * XXX make this heuristic more sound. This would
			 * allow an attacker to name his evil lib after the
		 	 * dynamic linker or something similar and it would
			 * slip through.	
	 		 */
			
			/*
			 * in the case that the lib path is a symlink
			 */
			//real = strrchr(needed_libs[j].libpath, '/') + 1;
			//if (real == NULL)
				//continue;
			if (!strcmp(lm_files->libs[i].path, needed_libs[j].libpath) || !strncmp(lm_files->libs[i].name, "ld-", 3)) {
				valid++;
				break;
			} else { 
				for (c = 0; c < dlopen_count; c++) {
					if (!strcmp(lm_files->libs[i].path, dlopen_libs[c].libpath)) {
						valid++;
						break;
					}
				}
			}
		}
		if (valid == 0) {
			lm_files->libs[i].injected++;
#if DEBUG
			log_msg(__LINE__, "injected library found: %s", lm_files->libs[i].name);
#endif
		}
		else
			valid = 0;
				
	}
	
}



	
