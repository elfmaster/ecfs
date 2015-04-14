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

int check_for_pie(int pid)
{
	int i;
	uint8_t *mem;
	struct stat st;
	
	char *path = xfmtstrdup("/proc/%d/exe", pid);
	int fd = xopen(path, O_RDONLY);
	fstat(fd, &st);
	
	mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		log_msg(__LINE__, "mmap %s", strerror(errno));
		exit(-1);
	}
	free(path);
	ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)mem;
	ElfW(Phdr) *phdr = (ElfW(Phdr) *)&mem[ehdr->e_phoff];
	for (i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD) {
			if (phdr[i].p_flags & PF_X) {
				if (phdr[i].p_vaddr == 0)
					return 1;
			}
		}
	}
	return 0;
}
	
int check_for_stripped_shdr(int pid)
{
	uint8_t *mem;
	struct stat st;

	char *path = xfmtstrdup("/proc/%d/exe", pid);
	int fd = xopen(path, O_RDONLY);
	fstat(fd, &st);

	mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		log_msg(__LINE__, "mmap %s", strerror(errno));
		exit(-1);
	}
	free(path);
	ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)mem;
	
	if (ehdr->e_shnum == 0 || ehdr->e_shoff == SHN_UNDEF) {
		munmap(mem, st.st_size);
		return 1;
	}
	munmap(mem, st.st_size);
	return 0;
}

