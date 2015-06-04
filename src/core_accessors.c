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

#include <unistd.h> // for syncfs, _GNU_SOURCE is a required build flag
#include "../include/ecfs.h"
#include "../include/util.h"
	
elfdesc_t * load_core_file(const char *path)
{	
	elfdesc_t *elfdesc = (elfdesc_t *)heapAlloc(sizeof(elfdesc_t));
	ElfW(Ehdr) *ehdr = NULL;
	ElfW(Phdr) *phdr = NULL;
	ElfW(Nhdr) *nhdr = NULL; //notes
	uint8_t *mem = NULL;
	struct stat st;
	int i, fd;
	
	elfdesc->path = xstrdup(path);
	
	if ((fd = open(path, O_RDONLY)) < 0) {
		log_msg(__LINE__, "open %s", strerror(errno));
		return NULL;
	}

	if (fstat(fd, &st) < 0) {
		log_msg(__LINE__, "fstat %s", strerror(errno));
		return NULL;
	}
	
	mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		log_msg(__LINE__, "mmap %s", strerror(errno));
		exit(-1);
	}

	ehdr = (ElfW(Ehdr) *)mem;
	phdr = (ElfW(Phdr) *)&mem[ehdr->e_phoff];
	
	if (ehdr->e_type != ET_CORE) {
		log_msg(__LINE__, "File %s is not an ELF core file. exiting with failure", path);
		return NULL;
	}
	
	/*
	 * Setup notes pointer
	 */
	for (i = 0; i < ehdr->e_phnum; i++)
		if (phdr[i].p_type == PT_NOTE) {
			nhdr = (ElfW(Nhdr) *)&mem[phdr[i].p_offset];
			elfdesc->noteSize = phdr[i].p_filesz;
			/*
			 * i + 1 will NOT be the text if this is a pie
			 * executable. So we deal with this case at a 
			 * later point in main()
			 */
			elfdesc->text_filesz = phdr[i + 1].p_filesz;
			elfdesc->text_memsz = phdr[i + 1].p_memsz;
			break;
		}
	
	elfdesc->ehdr = ehdr;
	elfdesc->phdr = phdr;
	elfdesc->nhdr = nhdr;
	elfdesc->mem = mem;
	elfdesc->size = st.st_size;
	
	return elfdesc;
}

elfdesc_t * reload_core_file(elfdesc_t *old)
{
	char *path = xstrdup(old->path);
	
	munmap(old->mem, old->size);
	free(old);

	elfdesc_t *new = load_core_file(path);
	if (new == NULL) {
		log_msg(__LINE__, "reload_core_file(): internal call to load_core_file() failed");
		return NULL;
	}
	return new;
}

static int is_elf_mapping(uint8_t *mem)
{	
	ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)mem;

	if (memcmp(mem, "\x7f\x45\x4c\x46", 4) != 0)
		return -1;
	return ehdr->e_type;
}

#define STACK_CHUNK_SIZE 8192
#define MAX_PRELOADS 64

/*
 * This function locates the environment variable
 * ascii data on the stack and loads them into a
 * heap allocated buffer. We can then store this in
 * our custom .environ ELF section.
 * We want the ascii data after the auxv
 * [argc][argv0][argv1][argvN][envp0][envp1][envpN][auxv][ascii_data]
 */
char * get_envp_ascii(handle_t *handle)
{
	elfdesc_t *elfdesc = handle->elfdesc;
        memdesc_t *memdesc = handle->memdesc;
        ElfW(Phdr) *phdr = elfdesc->phdr;
        uint8_t *mem = elfdesc->mem;
        uint8_t *stack_ptr;
        uint64_t stack_offset;
        char *retval = NULL;
        int i;

        /*
         * Get stack offset and then find which program header
         * it corresponds to. From there we can locate the environment
         * variable ascii data. e.g. LD_PRELOAD=<strval>\0LD_BIND_NOW=1\0
         */
        stack_offset = get_internal_sh_offset(elfdesc, memdesc, STACK);
        for (i = 0; i < elfdesc->ehdr->e_phnum; i++) {
                if (phdr[i].p_offset == stack_offset) {
		}
	}
}
		


/*
 * This function will locate a given environment variable
 * and return its value as a pointer to a heap allocated
 * string.
 */
char * get_envp_strval(handle_t *handle, const char *envname)
{
	elfdesc_t *elfdesc = handle->elfdesc;
        memdesc_t *memdesc = handle->memdesc;
        ElfW(Phdr) *phdr = elfdesc->phdr;
        uint8_t *mem = elfdesc->mem;
	uint8_t *stack_ptr;
	uint64_t stack_offset;
	char *retval = NULL;
	int i;
	
	/*
	 * Get stack offset and then find which program header
	 * it corresponds to. From there we can locate the environment
	 * variable ascii data. e.g. LD_PRELOAD=<strval>\0LD_BIND_NOW=1\0
	 */
	stack_offset = get_internal_sh_offset(elfdesc, memdesc, STACK);
	for (i = 0; i < elfdesc->ehdr->e_phnum; i++) {
		if (phdr[i].p_offset == stack_offset) {
			log_msg(__LINE__, "YO: found stack");
			/*
		         * XXX change to 'char **preloaded' and use realloc's on sizeof(char *) * N
			 */
			char *p;
			size_t c, currsize = MAX_PATH;
			const int envlen = strlen(envname); // + 1 to account for '='
			/*
			 * The environment variable strings are going to be right
			 * after the auxiliary vector. Somewhere in the first 8192
			 * bytes from the bottom of the stack.
		         */
			stack_ptr = (uint8_t *)&mem[phdr[i].p_offset + phdr[i].p_memsz - (STACK_CHUNK_SIZE)];			
			for (i = 0; i < STACK_CHUNK_SIZE; i++) {
				log_msg(__LINE__, "envlen %d: %s", envlen, &stack_ptr[i]);
				if (!strncmp(&stack_ptr[i], envname, envlen)) {
					log_msg(__LINE__, "Found LD_PRELOAD");
					p = &stack_ptr[i + envlen + 1];
					log_msg(__LINE__, "preloaded lib: %s", p);
					retval = (char *)heapAlloc(currsize);
					log_msg(__LINE__, "currsize: %d and retval: %p\n", currsize, retval);
					for (c = 0; *p != '\0'; p++) {
						if (c > currsize - 1) {
							log_msg(__LINE__, "realloc(%p, %d)", currsize + currsize);
							retval = realloc(retval, currsize += currsize);
						}
						log_msg(__LINE__, "retval[%d] = %c", c, *p);
						retval[c++] = *p;
						log_msg(__LINE__, "set retval");
					}
					log_msg(__LINE__, "retval[%d] = 0", c);
					retval[c] = '\0';
					log_msg(__LINE__, "it was set :)");
					return retval;
				}
			}
		}	
	}
	return retval;
}

int mark_preloaded_libs(handle_t *handle, struct lib_mappings *lm)
{
        elfdesc_t *elfdesc = handle->elfdesc;
        memdesc_t *memdesc = handle->memdesc;
        ElfW(Phdr) *phdr = elfdesc->phdr;
        uint8_t *mem = elfdesc->mem;
	char *value, **preloaded;
	int len, i, j, c;

	if ((value = get_envp_strval(handle, "LD_PRELOAD")) == NULL) {
		log_msg(__LINE__, "get_envp_strval() failed");
		return -1;
	}
	
	log_msg(__LINE__, "got value: %s", value);
	int index_count = 1;
	preloaded = (char **)heapAlloc(index_count * sizeof(char *));
	log_msg(__LINE__, "allocated preloaded");
	len = strlen(value);
	for (i = 0; i < len; i++) {
		if (value[i] == '\0')
			break;	
		if (value[i] == 0x20) {
			preloaded[index_count - 1][c] = '\0';
			index_count += 1;
			c = 0;
			preloaded = realloc(preloaded, index_count * sizeof(char *));
			continue;
		}
		preloaded[index_count - 1][c++] = value[i];
	}	
	for (i = 0; i < index_count; i++) {
		for (j = 0; j < lm->libcount; j++) {
			log_msg(__LINE__, "preloaded: %s", preloaded[i]);
			if (!strcmp(preloaded[i], lm->libs[j].path)) {
#if DEBUG
				log_msg(__LINE__, "found preloaded lib: %s\n", preloaded);
#endif
				lm->libs[j].preloaded++;
			}
		}
	}
	xfree(value);
	return 0;		
}

ssize_t check_segments_for_elf_objects(handle_t *handle, struct lib_mappings *lm, struct elfmap **elfmaps)
{
	elfdesc_t *elfdesc = handle->elfdesc;
	memdesc_t *memdesc = handle->memdesc;
	ElfW(Phdr) *phdr = elfdesc->phdr;
	uint8_t *mem = elfdesc->mem;
	int ret, i, j, already_accounted = 0;
	ssize_t c;
	
	*elfmaps = (struct elfmap *)heapAlloc(sizeof(struct elfmap));
	for (c = 0, i = 0; i < elfdesc->ehdr->e_phnum; i++) {
		if (phdr[i].p_filesz == 0 || !(phdr[i].p_flags & PF_X))
			continue;
		ret = is_elf_mapping(&mem[phdr[i].p_offset]);
		if (ret < 0)
			continue;
		if (ret == ET_DYN) {
			/*
			 * Is this dynamic object the program itself? Such as with a PIE
			 * compiled program like sshd.
			 */
			if (phdr[i].p_vaddr == elfdesc->textVaddr)
				continue;
			/*
			 * Is this the VDSO?
			 */
			if (phdr[i].p_vaddr == memdesc->vdso.base)
				continue;
			already_accounted = 0;
			/*
			 * If this program header is a shared library we only
			 * add it as a mapped ELF object if its not already stored
			 * in 'struct lib_mappings'. This would happen with shared libraries
			 * that were loaded but don't have the ".so" string in their name.
			 * such as with Saruman executable injection technique which dlopens()
			 * a PIE binary.
			 */
			for (j = 0; j < lm->libcount; j++) {
				if (lm->libs[j].addr == phdr[i].p_vaddr) {
					already_accounted++;
					break;
				}
			}
			if (already_accounted)
				continue;	
		}
		(*elfmaps)[c].addr = phdr[i].p_vaddr;
		(*elfmaps)[c].offset = phdr[i].p_offset;
		(*elfmaps)[c].size = phdr[i].p_filesz;		
		(*elfmaps)[c].prot = phdr[i].p_flags;
		(*elfmaps)[c].type = ret;
		c++;
		*elfmaps = realloc(*elfmaps, sizeof(struct elfmap) * (c + 1));
		if (*elfmaps == NULL) {
			log_msg(__LINE__, "realloc() failed: %s", strerror(errno));
			return -1;
		}
	}
	return c;

}

void get_text_phdr_size_with_hint(elfdesc_t *elfdesc, unsigned long hint)
{
	ElfW(Phdr) *phdr = elfdesc->phdr;
	int i;
	
	for (i = 0; i < elfdesc->ehdr->e_phnum; i++) {
		if (hint >= phdr[i].p_vaddr && hint < phdr[i].p_vaddr + phdr[i].p_memsz) {
			elfdesc->text_filesz = phdr[i].p_filesz;
			elfdesc->text_memsz = phdr[i].p_memsz;
			break;
		}
	}

}

ElfW(Off) get_internal_sh_offset(elfdesc_t *elfdesc, memdesc_t *memdesc, int type)
{
	int i, j;
	mappings_t *maps = memdesc->maps;
	ElfW(Phdr) *phdr = elfdesc->phdr;

	switch(type) {
		case HEAP:
			for (i = 0; i < memdesc->mapcount; i++) {
				if (maps[i].heap) {
					for (j = 0; j < elfdesc->ehdr->e_phnum; j++) {
						if (phdr[j].p_vaddr == maps[i].base)
							return phdr[j].p_offset;
					}
				}
			}
			break;
		case STACK:
			for (i = 0; i < memdesc->mapcount; i++) {
				if (maps[i].stack) {
					for (j = 0; j < elfdesc->ehdr->e_phnum; j++) {
					   /*
						* For some reason the kernel seems to dump the
						* stack segment 1 page lower than one shows up
						* in the maps file. So we have to check for
						* the range instead of just compare p_vaddr 
						* directly to maps[i].base
						*/

						if (maps[i].base >= phdr[j].p_vaddr && maps[i].base < (phdr[j].p_vaddr + phdr[j].p_memsz))
							return phdr[j].p_offset;
					}
				}
			}
			break;
		case VDSO:
			for (i = 0; i < memdesc->mapcount; i++) {
				if (maps[i].vdso) {
					for (j = 0; j < elfdesc->ehdr->e_phnum; j++) {
						if (phdr[j].p_vaddr == maps[i].base)
							return phdr[j].p_offset;
					}
				}
			}
			break;
		case VSYSCALL:
			for (i = 0; i < memdesc->mapcount; i++) {
				if (maps[i].vsyscall) {
					for (j = 0; j < elfdesc->ehdr->e_phnum; j++) {
						if (phdr[j].p_vaddr == maps[i].base)
							return phdr[j].p_offset;
						}
					} 
				}
			break;
		default:
			/*
			 * if type is unknown then it gets treated as an index
			 * into maps array.
			 */
#if DEBUG
			log_msg(__LINE__, "get_internal_sh_offset is treating 'type' as index into map array");
#endif
			if (type < 0 || type > memdesc->mapcount) {
#if DEBUG
			log_msg(__LINE__, "get_internal_sh_offset was passed an invalid index into map array: %d", type);
#endif
				return 0;
			}

			for (j = 0; j < elfdesc->ehdr->e_phnum; j++) 
				if (phdr[j].p_vaddr == maps[type].base)
					return phdr[j].p_offset;
						break;
	}
	return 0;
}

static ssize_t get_original_shdr_addr(int pid, const char *name)
{
	struct stat st;
	int i;
	char *path = xfmtstrdup("/proc/%d/exe", pid);
	int fd = xopen(path, O_RDONLY);
	xfree(path);
	xfstat(fd, &st);
	uint8_t *mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		log_msg(__LINE__, "mmap %s", strerror(errno));
		return 0;
	}
	ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)mem;
	ElfW(Shdr) *shdr = (ElfW(Shdr) *)(mem + ehdr->e_shoff);
	if (ehdr->e_shstrndx == 0 || ehdr->e_shnum == 0)
		return 0;
	
	char *StringTable = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset];
	for (i = 0; i < ehdr->e_shnum; i++)
		if (!strcmp(&StringTable[shdr[i].sh_name], name))
			return shdr[i].sh_addr;
	return 0;
}

static void pull_unknown_shdr_addrs(int pid, memdesc_t *memdesc)
{	
	
	/*
	 * We create a section in ecfs files called .text
	 * that reflects the original .text section. Whereas our
	 * ._TEXT section reflects the entire text segment. 
	 */
	global_hacks.text_vaddr = get_original_shdr_addr(pid, ".text");
	/*
	 * .data reflects original .data section and ._DATA reflects
	 * the entire text segment. In this case we are getting the
	 * vaddr of the original .data section.	
	 */
	global_hacks.data_vaddr = get_original_shdr_addr(pid, ".data");
	/*
	 * Get plt location since its not marked in dynamic segment
	 */
	global_hacks.plt_vaddr = get_original_shdr_addr(pid, ".plt");
	/*
	 * We actually only rely on getting this from the original executables
	 * section header table if we are dealing with a statically compiled
	 * binary, since there is no PT_GNU_EH_FRAME segment type in them.
	 */
	global_hacks.ehframe_vaddr = get_original_shdr_addr(pid, ".eh_frame");
	/*
	 * I know no other way to find the location of .ctors (.init_array) and
	 * .ctors (.fini_array) that is as reliable as this.
	 */
	global_hacks.ctors_vaddr = get_original_shdr_addr(pid, ".ctors");
	if (global_hacks.ctors_vaddr == 0)
		global_hacks.ctors_vaddr = get_original_shdr_addr(pid, ".init_array");
	
	global_hacks.dtors_vaddr = get_original_shdr_addr(pid, ".dtors");
	if (global_hacks.dtors_vaddr == 0)
		global_hacks.dtors_vaddr = get_original_shdr_addr(pid, ".fini_array");
	
	if (memdesc->pie) {
		if (global_hacks.ctors_vaddr)
			global_hacks.ctors_vaddr += memdesc->text.base;
		if (global_hacks.dtors_vaddr)
			global_hacks.dtors_vaddr += memdesc->text.base;
		if (global_hacks.plt_vaddr)
			global_hacks.plt_vaddr += memdesc->text.base;
		if (global_hacks.ehframe_vaddr)
			global_hacks.ehframe_vaddr += memdesc->text.base;
		if (global_hacks.text_vaddr)
			global_hacks.text_vaddr += memdesc->text.base;
		if (global_hacks.data_vaddr)
			global_hacks.data_vaddr += memdesc->text.base;
	}
}

/*
 * Get size of the original section header used in original executable
 * It is not necessary for this function to succeed (Such as when the original
 * executable has a stripped section header) but it aids in getthg the correct
 * size of the .got and .hash sections, otherwise they are given UNKNOWN_SHDR_SIZE
 */

static ssize_t get_original_shdr_size(int pid, const char *name)
{
	struct stat st;
	int i;
	char *path = xfmtstrdup("/proc/%d/exe", pid);
	int fd = xopen(path, O_RDONLY);
	xfree(path);
	xfstat(fd, &st);
	uint8_t *mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		log_msg(__LINE__, "mmap %s", strerror(errno));
		return -1;
	}
	ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)mem;
	ElfW(Shdr) *shdr = (ElfW(Shdr) *)(mem + ehdr->e_shoff);
	if (ehdr->e_shstrndx == 0 || ehdr->e_shnum == 0)
		return -1;
	char *StringTable = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset];
	for (i = 0; i < ehdr->e_shnum; i++) 
		if (!strcmp(&StringTable[shdr[i].sh_name], name))
			return shdr[i].sh_size;
	return 0;
}
/*
 * Notice we read these and store them in global variables
 * this was an after-the-fact hack that is ugly and needs
 * changing.
 */
static void pull_unknown_shdr_sizes(int pid)
{
	memset(&global_hacks, 0, sizeof(global_hacks));
	global_hacks.hash_size = get_original_shdr_size(pid, ".gnu.hash");
	if (__ELF_NATIVE_CLASS == 64) {
		global_hacks.rela_size = get_original_shdr_size(pid, ".rela.dyn");
		global_hacks.plt_rela_size = get_original_shdr_size(pid, ".rela.plt");
	} else {
		global_hacks.rela_size = get_original_shdr_size(pid, ".rel.dyn");
		global_hacks.plt_rela_size = get_original_shdr_size(pid, ".rel.plt");
	}
	
	global_hacks.text_size = get_original_shdr_size(pid, ".text"); 
	global_hacks.data_size = get_original_shdr_size(pid, ".data");
	global_hacks.init_size = get_original_shdr_size(pid, ".init");
	global_hacks.fini_size = get_original_shdr_size(pid, ".fini");
	global_hacks.got_size = get_original_shdr_size(pid, ".got.plt");
	global_hacks.plt_size = get_original_shdr_size(pid, ".plt");
	global_hacks.ehframe_size = get_original_shdr_size(pid, ".eh_frame");
	global_hacks.ctors_size = get_original_shdr_size(pid, ".ctors");
	if (global_hacks.ctors_size == 0)
		global_hacks.ctors_size = get_original_shdr_size(pid, ".init_array");
	global_hacks.dtors_size = get_original_shdr_size(pid, ".dtors");
	if (global_hacks.dtors_size == 0)
		global_hacks.dtors_size = get_original_shdr_size(pid, ".fini_array");
}

void fill_global_hacks(int pid, memdesc_t *memdesc)
{
	pull_unknown_shdr_sizes(pid);
	pull_unknown_shdr_addrs(pid, memdesc);

}
