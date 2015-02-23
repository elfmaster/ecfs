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
 * ECFS performs certain heuristics to help aid in forensics analysis.
 * one of these heuristics is showing shared libraries that have been
 * injected vs. loaded by the linker/dlopen/preloaded
 */

#include "ecfs.h"

#define OFFSET_2_PUSH 6 // # of bytes int PLT entry where push instruction begins
#define MAX_NEEDED_LIBS 512
#define MAX_STRINGS 1024

int build_rodata_strings(char ***stra, uint8_t *rodata_ptr, size_t rodata_size)
{
	int i, j, index = 0;
	*stra = (char **)heapAlloc(sizeof(char *) * MAX_STRINGS); 
	char *string = alloca(8192 * 2);
	char *p;
	size_t cursize = MAX_STRINGS;
	
	log_msg(__LINE__, "rodata_size: %u\n", rodata_size);
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
		if (index >= MAX_STRINGS) {
#if DEBUG
			log_msg(__LINE__, "build_rodata_strings() performing realloc on %p", *stra);
#endif
			cursize <<= 1;
			*stra = (char **)realloc(*stra, sizeof(char *) * cursize);
		}
	}
	return index;
}


/* 
 * Find the actual path to DT_NEEDED libraries
 * and take possible symlinks into consideration 
 * XXX this function will not work if the path is
 * a symlink to a file in a different directory.
 * fix this bug by seeing if readlink returns a
 * totally different file path as the resultant link
 * or if it returns just the base name (Which means
 * that the linked file is in the same dir as the
 * symlink.
 */
static char * get_real_lib_path(char *name)
{
	FILE *fd;
	char tmp[512] = {0};
	char real[512] = {0};
	char *ptr;

	int ret;
	
	/*
	 * Since this function is recursive and since there are
	 * times when 'name' is passed as a path (As the result of
	 * some readlink() calls, we must handle that specially since
	 * we don't want to append a path to a path which will be
	 * incorrect.
	 */
	if (strchr(name, '/') != NULL) {
		ret = readlink(name, real, 512);
		if (ret > 0) {
			if (strchr(real, '/') != NULL)
				return xstrdup(real);
			else {
				ptr = get_real_lib_path(real);
				return xstrdup(ptr);
			}
		}
		return xstrdup(name);
	}
	/*
	 * Check most common paths
	 */

	snprintf(tmp, 512, "/usr/lib/x86_64-linux-gnu/%s", name);
        if (access(tmp, F_OK) == 0) {
                ret = readlink(tmp, real, 512);
                if (ret > 0) {
                        ptr = get_real_lib_path(real);
                        return xstrdup(ptr);
                }
                else
                        return xstrdup(tmp);
        }

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
	
 	snprintf(tmp, 512, "/usr/lib/x86_64-linux-gnu/gio/modules/%s", name);
        if (access(tmp, F_OK) == 0) {
                ret = readlink(tmp, real, 512);
                if (ret > 0) {
                        ptr = get_real_lib_path(real);
                        return xstrdup(ptr);
                }
                else
                        return xstrdup(tmp);
        }

	/*
	 * If we get here then lets try directly from ld.so.cache
	 */
check_ld_cache:
	
	return NULL;
}

/* 
 * From DT_NEEDED (We pass the executable and each shared library to this function)
 */
static int get_dt_needed_libs(const char *bin_path, struct needed_libs *needed_libs, int index)
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
		return 0;
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
	
	for (needed_count = 0, i = 0; dyn[i].d_tag != DT_NULL; i++) {
		switch(dyn[i].d_tag) {
			case DT_NEEDED:
				needed_libs[index + needed_count].libname = xstrdup(&dynstr[dyn[i].d_un.d_val]);
				needed_libs[index + needed_count].libpath = get_real_lib_path(needed_libs[index + needed_count].libname);
				needed_libs[index + needed_count].master = xstrdup(bin_path);
				log_msg(__LINE__, "real libpath: %s", needed_libs[index + needed_count].libpath);
				needed_count++;
				break;
			default:
				break;
		}
	}
	return needed_count;
}

static int cmp_till_dot(const char *lib1, const char *lib2)
{
	char *p;
	char *s1 = xstrdup(lib1);
	char *s2 = xstrdup(lib2);
	int i;

	for (i = 0, p = s1; p[i] != '\0'; i++) {
		if (p[i] == '.' && p[i + 1] == 's' && p[i + 2] == 'o') {
			p[i] = '\0';	
			break;
		}
	}
        for (i = 0, p = s2; p[i] != '\0'; i++) {
                if (p[i] == '.' && p[i + 1] == 's' && p[i + 2] == 'o') {
                        p[i] = '\0';
                        break;
                }
        }
	
	log_msg(__LINE__, "cmp %s and %s", s1, s2);
	
	return strcmp(s1, s2);
}

static int qsort_cmp_by_str(const void *a, const void *b)
{ 
    struct needed_libs *ia = (struct needed_libs *)a;
    struct needed_libs *ib = (struct needed_libs *)b;
    return strcmp(ia->libpath, ib->libpath);
} 

/*
 * This function transitively enumerates a list
 * of all needed dependencies in the process as
 * marked by DT_NEEDED in the executable and its
 * shared libraries.
 */
int get_dt_needed_libs_all(memdesc_t *memdesc, struct needed_libs **needed_libs)
{
	int i, init_count;
	size_t currsize = 8192 * sizeof(struct needed_libs);
	struct needed_libs *all_libs = heapAlloc(currsize);
	struct needed_libs *initial_libs = heapAlloc(512 * sizeof(struct needed_libs));
	
	int total_needed = get_dt_needed_libs(memdesc->exe_path, all_libs, 0);
	if (total_needed == 0)
		return 0;
	/*
	 * Create initial dependencies then transitively check the other dependencies
	 * of those.
	 */
	init_count = total_needed;
	memcpy(initial_libs, all_libs, (total_needed * sizeof(struct needed_libs)));
	
	for (i = 0; i < init_count; i++) {
		if (i >= 1) {
			if (!strcmp(initial_libs[i].libpath, initial_libs[i - 1].libpath))
				continue;
		}
		if ((total_needed * sizeof(struct needed_libs)) >= currsize) {// just to be safe
			currsize <<= 1;
			all_libs = (struct needed_libs *)realloc(all_libs, currsize);
		}
		total_needed += get_dt_needed_libs(initial_libs[i].libpath, all_libs, total_needed);

	}
	
	qsort(all_libs, total_needed, sizeof(struct needed_libs), qsort_cmp_by_str);
#if DEBUG
	for (i = 0; i < total_needed; i++) {
		if (i >= 1)
			if (!strcmp(all_libs[i].libpath, all_libs[i - 1].libpath))
				continue;
		log_msg(__LINE__, "[%s] needs dependency: %s", all_libs[i].master, all_libs[i].libpath);
	}
#endif
	*needed_libs = all_libs;
	return total_needed;
}
/*
 * Get dlopen libs
 */
int get_dlopen_libs(const char *exe_path, struct dlopen_libs *dl_libs, int index)
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
	if (text_ptr == NULL || rela == NULL || symtab == NULL) {
#if DEBUG
		log_msg(__LINE__, "get_dlopen_libs() failing for path: %s", exe_path);
#endif
		return -1;
	}
	
	for (found_dlopen = 0, i = 0; i < symcount; i++) {
		if (!strcmp(&dynstr[symtab[i].st_name], "dlopen")) {
			found_dlopen++;
			break;
		}
	}
	if (!found_dlopen) {
#if DEBUG
		log_msg(__LINE__, "no calls to dlopen found in %s", exe_path);
#endif
		return 0;			
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
	for (i = 0; i < scount; i++) {
		ret = readlink(strings[i], tmp, 512);
		dl_libs[index + i].libpath = ret < 0 ? xstrdup(strings[i]) : xstrdup(tmp);
		free(strings[i]);
	}
	
#if DEBUG
	for (i = 0; i < scount; i++)
		printf("dlopen lib: %s\n", dl_libs[index + i].libpath);
#endif
	return scount;
}

/*
 * This should be called after all needed libs have been found.
 */
int get_dlopen_libs_all(memdesc_t *memdesc, struct needed_libs *needed_libs, int needed_count, struct dlopen_libs **dlopen_libs)
{
	int dlopen_count, i;
	size_t currsize = sizeof(struct dlopen_libs) * 8192;
	struct dlopen_libs *all_libs = heapAlloc(sizeof(struct dlopen_libs) * 8192);
	
	log_msg(__LINE__, "calling get_dlopen_libs(%s, ...)", memdesc->exe_path);
	dlopen_count = get_dlopen_libs(memdesc->exe_path, all_libs, 0);
	log_msg(__LINE__, "dlopen_count initial: %d", dlopen_count);
	for (i = 0; i < needed_count; i++) {
		if (i >= 1) 
			if (!strcmp(needed_libs[i].libpath, needed_libs[i - 1].libpath))
				continue;
		if ((dlopen_count * sizeof(struct dlopen_libs)) >= currsize) {
			currsize <<= 1;
			all_libs = (struct dlopen_libs *)realloc(all_libs, currsize);
		}		
		log_msg(__LINE__, "calling get_dlopen_libs(%s, ...)", needed_libs[i].libpath);
		dlopen_count += get_dlopen_libs(needed_libs[i].libpath, all_libs, dlopen_count);
		log_msg(__LINE__, "dlopen_count increased to %d", dlopen_count);
	}
	*dlopen_libs = all_libs;
	return dlopen_count;
}

void mark_dll_injection(notedesc_t *notedesc, memdesc_t *memdesc, elfdesc_t *elfdesc)
{
	struct lib_mappings *lm_files = notedesc->lm_files;
	struct needed_libs *needed_libs;
	struct dlopen_libs *dlopen_libs;
	int needed_count;
	int dlopen_count;
	int valid;
	int i, j, c, lc;
	/*
	 * We just check the immediate executable for dlopen calls
	 */
	
	/*
	dlopen_count = get_dlopen_libs(memdesc->exe_path, &dlopen_libs);
#if DEBUG
	if (dlopen_count <= 0) {
		log_msg(__LINE__, "found %d dlopen loaded libraries", dlopen_count);
	}
#endif
	*/
	/*
	 * We check the dynamic segment of the executable 
	 * (DT_NEEDED) to see what the dependencies are.
	 * XXX ideally this should be done transitively so that
	 * we check the DT_NEEDED of each shared library and get
	 * its dependencies as well, otherwise we may get some
	 * false positives.
	 */
	
	needed_count = get_dt_needed_libs_all(memdesc, &needed_libs);
	dlopen_count = get_dlopen_libs_all(memdesc, needed_libs, needed_count, &dlopen_libs);
#if DEBUG
	for (i = 0; i < dlopen_count; i++)
		log_msg(__LINE__, "dlopen lib from .rodata: %s", dlopen_libs[i]);
#endif
	for (i = 0; i < lm_files->libcount; i++) {
		for (j = 0; j < needed_count; j++) {
			if (lm_files->libs[i].path == NULL)
				break;
			if (needed_libs[j].libpath == NULL) {
				/* Compare by name since full path couldn't be found */
				if (!cmp_till_dot(needed_libs[j].libname, lm_files->libs[i].name)) {
					valid++;
					break;	
				}
			}	
			if (j >= 1) // avoid duplicates
				if (!strcmp(needed_libs[j].libpath, needed_libs[j - 1].libpath))
					continue;
			log_msg(__LINE__, "Comparing %s and %s", lm_files->libs[i].path, needed_libs[j].libpath);
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



	
