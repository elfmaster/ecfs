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
 * NOTE: heuristics.c is a work in progress
 *
 */
#include "../include/ecfs.h"
#include "../include/util.h"
#include "../include/ldso_cache.h"

#define OFFSET_2_PUSH 6 // # of bytes int PLT entry where push instruction begins
#define MAX_NEEDED_LIBS 512
#define MAX_STRINGS 1024

/*
 * Build an array of pointers to strings for each string in .rodata
 * that appears to be a shared library.
 */
static int __attribute__((unused))
build_rodata_strings(char ***stra, uint8_t *rodata_ptr, size_t rodata_size)
{
	int i, j, index = 0;
	*stra = (char **)heapAlloc(sizeof(char *) * MAX_STRINGS); 
	char *string = alloca(8192 * 2);
	char *p;
	size_t cursize = MAX_STRINGS;

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
		if (index == (MAX_STRINGS - 1)) {
#if DEBUG
			log_msg(__LINE__, "build_rodata_strings() performing realloc on %p", *stra);
#endif
			cursize <<= 1;
			*stra = (char **)realloc(*stra, sizeof(char *) * cursize);
			if (*stra == NULL)
				return -1;
		}
	}
	return index;
}

/*
 * The elfdesc_t is usually for describing the ECFS file, but it also contains a pointer
 * to the corresponding executable path. We use this path to open the original executable
 */
bool resolve_so_deps(elfdesc_t *obj)
{
	elf_shared_object_iterator_t iter;
	struct elf_shared_object entry;
	struct ldso_needed_node *current = NULL;

	if (elf_shared_object_iterator_init(obj, &iter, NULL,
	    ELF_SO_RESOLVE_ALL_F) == false) {
		log_msg2(__LINE__, __FILE__, "elf_shared_object_iterator_init failed\n");
		return false;
	}
	LIST_INIT(&obj->list.needed);
	for (;;) {
		elf_iterator_res_t res;
		struct ldso_needed_node *so;

		res = elf_shared_object_iterator_next(&iter, &entry);
		if (res == ELF_ITER_DONE)
			break;
		if (res == ELF_ITER_ERROR) {
			log_msg2(__LINE__, __FILE__, "elf_shared_object_iterator_next error\n");
			return false;
		}
		if (res == ELF_ITER_NOTFOUND) {
			log_msg2(__LINE__, __FILE__, "ELF_ITER_NOT_FOUND\n");
			continue;
		}
		so = (struct ldso_needed_node *)heapAlloc(sizeof(struct ldso_needed_node));
		/*
		 * NOTE: elf_shared_object and elf_shared_object_node
		 * are nearly identical, but the one with '_node' has
		 * linkage to a list as its last member of the struct.
		 * so memcpy sizeof(elf_shared_object_t) into the
		 * into the elf_shared_object_node_t and then we add
		 * the linkage by inserting it.
		 */
		so->path = xstrdup(entry.path);
		so->basename = xstrdup(entry.basename);
		log_msg2(__LINE__, __FILE__, "inserting so->path: %s\n", so->path);
		LIST_INSERT_HEAD(&obj->list.needed, so, _linkage);
	}
	LIST_FOREACH(current, &obj->list.needed, _linkage) {
		log_msg2(__LINE__, __FILE__, "path: %s basename: %s\n", current->path, current->basename);
	}
	return true;
}

/*
 * See if dlopen is even being used.
 */
static bool dlopen_symbol_found(elfdesc_t *obj)
{	
	ElfW(Ehdr) *ehdr = NULL;
	ElfW(Shdr) *shdr = NULL;
	ElfW(Phdr) *phdr = NULL;
	ElfW(Sym) *symtab = NULL;
	uint8_t *mem = NULL;
	char *dynstr, *shstrtab;
	struct stat st;
	char *exe_path = obj->exe_path;
	int i, fd;
	int symcount = 0;

	fd = xopen(exe_path, O_RDONLY);
	xfstat(fd, &st);
	mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		log_msg2(__LINE__, __FILE__, "mmap: %s\n", strerror(errno));
		exit(-1);
	}

	ehdr = (ElfW(Ehdr) *)mem;
	shdr = (ElfW(Shdr) *)&mem[ehdr->e_shoff];
	phdr = (ElfW(Phdr) *)&mem[ehdr->e_phoff];
	shstrtab = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset];

	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&shstrtab[shdr[i].sh_name], ".dynstr")) {
			dynstr = (char *)&mem[shdr[i].sh_offset];
		} else {
			if (!strcmp(&shstrtab[shdr[i].sh_name], ".dynsym")) {
				symcount = shdr[i].sh_size / sizeof(ElfW(Sym));
				symtab = (ElfW(Sym) *)&mem[shdr[i].sh_offset];
			}
		}
	}
	if (symtab == NULL) {
#if DEBUG
		log_msg2(__LINE__, __FILE__,
		    "dlopen_symbol_found() failing for path: %s", exe_path);
#endif
		return false;
	}
	
	for (i = 0; i < symcount; i++) {
		if (strcmp(&dynstr[symtab[i].st_name], "dlopen") == 0)
			return true;
	}
	return false;
}

static bool lookup_so_path(elfdesc_t *obj, char *lookup_path)
{
	struct ldso_needed_node *current;

	LIST_FOREACH(current, &obj->list.needed, _linkage) {
		log_msg2(__LINE__, __FILE__, "comparing %s and %s\n", lookup_path, current->path);
		if (strcmp(lookup_path, current->path) == 0) {
			log_msg2(__LINE__, __FILE__, "They compare\n");
			return true;
		}
	}
	log_msg2(__LINE__, __FILE__, "They don't compare\n");
	return false;
}

/*
 * Mark libraries as either dlopen'd or injected.
 */
bool mark_dlopen_libs(notedesc_t *notedesc, elfdesc_t *elfdesc)
{
	struct lib_mappings *lm_files = notedesc->lm_files;
	struct elf_shared_object_node *current;
	int i;
	bool __dlopen = false;

	log_msg2(__LINE__, __FILE__, "calling resolve_so_deps(%s) arch: %d\n", elfdesc->exe_path, elfdesc->arch);

	if (resolve_so_deps(elfdesc) == false) {
		log_msg2(__LINE__, __FILE__, "resolve_so_deps failed\n");
		return false;
	}
	log_msg2(__LINE__, __FILE__, "elfdesc->exe_path: %s\n", elfdesc->exe_path);
	/*
	 * Are there any shared library mappings listed in the NT_FILES area of the core
	 * file, that are NOT listed in the transitive DT_NEEDED search? If so then this
	 * is a shared library that has either been dlopen'd or injected maliciously.
	 * For now we will mark this type as SHT_DLOPEN, unless the dlopen symbol doesn't
	 * exist in which case we will call it SHT_INJECTED; indicating it was either
	 * manually injected, or injected using __libc_dlopen_mode.
	 */
	log_msg2(__LINE__, __FILE__, "comparing lm_files to dt_needed list\n");

	if (dlopen_symbol_found(elfdesc) == true) {
		log_msg2(__LINE__, __FILE__, "dlopen is being used\n");
		__dlopen = true;
	}

	for (i = 0; i < lm_files->libcount; i++) {
		char *string;
		char real_path[PATH_MAX];
		ssize_t r;

		r = readlink(lm_files->libs[i].path, real_path, PATH_MAX);
		string = r > 0 ? real_path : lm_files->libs[i].path;
		log_msg2(__LINE__, __FILE__, "string: %s\n", string);

		if (lookup_so_path(elfdesc, string) == false) {
			if (__dlopen == false) {
				lm_files->libs[i].injected = true;
			} else {
				lm_files->libs[i].dlopen = true;
			}
		}
	}
	log_msg2(__LINE__, __FILE__, "Returning true\n");
	return true;
}
