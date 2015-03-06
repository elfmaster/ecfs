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

#include "../include/ecfs.h"
#include "../include/util.h"
#include "../include/list.h"

/* 
 * Each library and its symbols are represented by an array
 * of symentry_t's. Each array has its own node in a doubly
 * linked list.
 *
 * [libc.so.6] <-> [libpthread.so] <-> [NULL]
 * printf	   pthread_create      No library here
 * fgets	   pthread_mutext_lock
 * etc.		   etc.
 */
static int resolve_symbols(list_t **list, const char *path, unsigned long base)
{
	struct stat st;
	int fd, ret;
	char use_addend = 0;
	uint8_t *mem;
	ElfW(Ehdr) *ehdr = NULL;
	ElfW(Shdr) *shdr = NULL;
	ElfW(Phdr) *phdr = NULL;
	ElfW(Sym) *symtab = NULL;
	char *StringTable = NULL, *dynstr = NULL;
	size_t i, symcount =0;
	symentry_t *symvector;

	fd = xopen(path, O_RDONLY);
	xfstat(fd, &st);
	mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		return -1;
	} 
	
	ehdr = (ElfW(Ehdr) *)mem;	
	shdr = (ElfW(Shdr) *)&mem[ehdr->e_shoff];
	phdr = (ElfW(Phdr) *)&mem[ehdr->e_phoff];
	
	for (i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD) {
			if (phdr[i].p_vaddr == 0)
				use_addend++;
			break;
		}
	}
	StringTable = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset];

 	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".dynsym")) {
			symcount = shdr[i].sh_size / shdr[i].sh_entsize;
			symtab = (ElfW(Sym) *)&mem[shdr[i].sh_offset];
		} else
		if (!strcmp(&StringTable[shdr[i].sh_name], ".dynstr")) 
			dynstr = (char *)&mem[shdr[i].sh_offset];
	}

	symvector = (symentry_t *)heapAlloc(symcount * sizeof(symentry_t));
	
	symvector[0].count = symcount;
	symvector[0].library = xstrdup(strchr(path, '/') + 1);

	for (i = 0; i < symcount; i++) { 
		symvector[i].value = use_addend ? (symtab[i].st_value + base) : symtab[i].st_value;
		symvector[i].size = symtab[i].st_size;
		symvector[i].name = xstrdup(&dynstr[symtab[i].st_name]);
	}
	
	ret = insert_item_front(&(*list), (void *)symvector, symcount * sizeof(symentry_t));	
	
	munmap(mem, st.st_size);
	return ret;
	
}

unsigned long lookup_from_symlist(const char *name, list_t *list)
{
	node_t *current;
	symentry_t *symptr;
	int i;

	for (current = list->tail; current != NULL; current = current->prev) {
		symptr = (symentry_t *)current->data;
		for (i = 0; i < symptr[0].count; i++)		
			if (!strcmp(name, symptr[i].name))
				return symptr[i].value;
	}
	return 0;
}



int store_dynamic_symvals(list_t *list, const char *path)
{	
        struct stat st;
        int fd;
        uint8_t *mem;
        ElfW(Ehdr) *ehdr = NULL;
        ElfW(Shdr) *shdr = NULL;
        ElfW(Sym) *symtab = NULL;
        char *StringTable = NULL, *dynstr = NULL;
        size_t i, j, symcount;

        fd = xopen(path, O_RDWR);
        xfstat(fd, &st);
        mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if (mem == MAP_FAILED) {
                perror("mmap");
                return -1;
        }

        ehdr = (ElfW(Ehdr) *)mem;
        shdr = (ElfW(Shdr) *)&mem[ehdr->e_shoff];
        StringTable = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset];
	
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".dynstr")) {
			dynstr = (char *)&mem[shdr[i].sh_offset];
			break;
		}
	}
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".dynsym")) {
			symtab = (ElfW(Sym) *)&mem[shdr[i].sh_offset];
			symcount = shdr[i].sh_size / shdr[i].sh_entsize;
			for (j = 0; j < symcount; j++) 
				symtab[j].st_value = lookup_from_symlist((char *)&dynstr[symtab[j].st_name], list);
		}
	}
	return 0;
}
	

int fill_dynamic_symtab(list_t **list, struct lib_mappings *lm)
{
	int i, ret = -1;
        /*
         * The .dynsym section is in the output ecfs executable and does not exist
         * yet when this function is called. We therefore 
         */ 
	*list = (list_t *)heapAlloc(sizeof(**list));
	(*list)->tail = NULL;
	(*list)->head = NULL;
	
	/*
	 * Resolve symbols for each shared library
	 */
	for (i = 0; i < lm->libcount; i++) {
#if DEBUG
		printf("Resolving symbols for: %s\n", lm->libs[i].path);
#endif
		ret = resolve_symbols((&(*list)), lm->libs[i].path, lm->libs[i].addr);
	}
	
	return ret;
}

