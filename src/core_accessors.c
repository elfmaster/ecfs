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
			log_msg(__LINE__, "get_internal_sh_offset() seeking heap offset");
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
			log_msg(__LINE__, "get_internal_sh_offset() seeking stack offset");
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
			log_msg(__LINE__, "get_internal_sh_offset() seeking vdso offset");
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
			log_msg(__LINE__, "get_internal_sh_offset() seeking vsyscall offset");
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
                return -1;
        }
        ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)mem;
        ElfW(Shdr) *shdr = (ElfW(Shdr) *)(mem + ehdr->e_shoff);
        if (ehdr->e_shstrndx == 0 || ehdr->e_shnum == 0)
                return -1;
        char *StringTable = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset];
        for (i = 0; i < ehdr->e_shnum; i++)
                if (!strcmp(&StringTable[shdr[i].sh_name], name))
			return shdr[i].sh_addr;
	return 0;
}

static void pull_unknown_shdr_addrs(int pid)
{	
	
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

void fill_global_hacks(int pid)
{
	pull_unknown_shdr_sizes(pid);
	pull_unknown_shdr_addrs(pid);

}
