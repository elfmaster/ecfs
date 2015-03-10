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

/*
 * This function will probably never be used
 */
static ssize_t ptrace_read_mem(pid_t pid, uint8_t *ptr, unsigned long vaddr, size_t len)
{
#if DEBUG
	log_msg(__LINE__, "pid_read(%d, %p, %lx, %d)", pid, ptr, vaddr, len);
#endif
	int ret = pid_read(pid, (void *)ptr, (void *)vaddr, len);
	if (ret < 0)
		return -1;
	return len;
}

static ssize_t read_pmem(pid_t pid, uint8_t *ptr, unsigned long vaddr, size_t len)
{	
	char *path = xfmtstrdup("/proc/%d/mem", pid);
	int fd = xopen(path, O_RDONLY);
#if DEBUG
	log_msg(__LINE__, "reading from %lx bytes from %lx", len, vaddr);
#endif
	ssize_t bytes = pread(fd, ptr, len, vaddr);
	close(fd);
	if (bytes != len) {
		log_msg(__LINE__, "pread failed [read %d bytes]: %s", (int)bytes, strerror(errno));
		return -1;
	}
	return bytes;
}

ssize_t get_segment_from_pmem(unsigned long vaddr, memdesc_t *memdesc, uint8_t **ptr)
{
	/*
	 * We read from /proc/$pid/mem which should already be
	 * stopped (SIGSTOP) unless we are running this program
	 * in debugging mode, in which case we deliver a sigstop
	 * just incase.	
 	 */
	int i;
	size_t len;
	ssize_t ret;
	/*
	 * Are we trying to read from a valid process mapping?
	 */
	for (i = 0; i < memdesc->mapcount; i++) {
		if (vaddr >= memdesc->maps[i].base && vaddr < memdesc->maps[i].base + memdesc->maps[i].size) {
			len = memdesc->maps[i].size;
			*ptr = HUGE_ALLOC(len);
			ret = read_pmem(memdesc->task.pid, *ptr, memdesc->maps[i].base, len);
			if (ret < 0) {
#if DEBUG
				log_msg(__LINE__, "read_pmem() failed, probably due to security protection, attempting again with ptrace");
#endif
				/* It is possible that there was a protection set (Such as with
				 * skype) that prevents reads from /proc/$pid/mem. So we cannot 
				 * get the complete text segment of every single shared lib.
				 */
				return ECFS_EXCEPTION;
			}
			return ret;
		}
	}
	return -1;
	
}

int merge_exe_text_into_core(const char *path, memdesc_t *memdesc)
{
        ElfW(Ehdr) *ehdr;
        ElfW(Phdr) *phdr;
	ElfW(Addr) textVaddr;
	ElfW(Off) textOffset = 0;
        ElfW(Off) dataOffset = 0;
        //size_t textSize;
        uint8_t *mem;
        struct stat st;
        int in, out, i = 0;
        int data_index;

	in = xopen(path, O_RDWR);
	xfstat(in, &st);
	
	/*
	 * tmp will point to the new temporary file that contains
	 * our corefile with a merged in program text segment and
	 * with updated p_filesz, and updated p_offsets for phdr's 
	 * that follow it.
	 */
	char *tmp_dir = opts.use_ramdisk ? ECFS_RAMDISK_DIR : ECFS_CORE_DIR;
	char *tmp = xfmtstrdup("%s/.tmp_merged_core", tmp_dir);
        do {
                if (access(tmp, F_OK) == 0) {
                        free(tmp);
                        tmp = xfmtstrdup("%s/.tmp_merged_core.%d", tmp_dir, ++i);
                } else
                        break;

        } while(1);
        out = xopen(tmp, O_RDWR|O_CREAT);

        /*
         * Earlier on we read the text segment from /proc/$pid/mem
         * into a heap allocated buffer memdesc->textseg 
         */
        uint8_t *textseg = memdesc->textseg;
        ssize_t tlen = (ssize_t)memdesc->text.size;
	/*
	 * Get textVaddr as it pertains to the mappings
	 */
	textVaddr = memdesc->text.base;
	if (textVaddr == 0) {
		log_msg(__LINE__, "(From merge_exe_text_into_core function) Could not find text address");
		return -1;
	}

        /*
         * Get textVaddr as it pertains to the mappings
         */
        textVaddr = memdesc->text.base;
        if (textVaddr == 0) {
            log_msg(__LINE__, "(From merge_texts_into_core function) Could not find text address");
            return -1;
        }

        mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, in, 0);
        if (mem == MAP_FAILED) {
            log_msg(__LINE__, "mmap %s", strerror(errno));
            return -1;
        }
        ehdr = (ElfW(Ehdr) *)mem;
        phdr = (ElfW(Phdr) *)(mem + ehdr->e_phoff);
        int found_text;

        for (found_text = 0, i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_vaddr <= textVaddr && phdr[i].p_vaddr + phdr[i].p_memsz > textVaddr) {
                textOffset = phdr[i].p_offset;
                dataOffset = phdr[i + 1].p_offset;	// data segment is always i + 1 after text
			textVaddr = phdr[i].p_vaddr;
			//textSize = phdr[i].p_memsz;	    // get memsz of text
			phdr[i].p_filesz = phdr[i].p_memsz; // make filesz same as memsz
			found_text++;
			data_index = i + 1;
			phdr[data_index].p_offset += (tlen - 4096);
		}
		else
		if (found_text) {
			if (i == data_index) 	
				continue;
			phdr[i].p_offset += (tlen - 4096); // we must push the other segments forward to make room for whole text image
		}
	}
				
	if (textVaddr == 0) {
		log_msg(__LINE__, "Failed to merge texts into core");
		return -1;
	}
	if (write(out, mem, textOffset) < 0) {
		log_msg(__LINE__, "write %s", strerror(errno));
		return -1;
	}
	if (write(out, textseg, tlen) < 0) {
		log_msg(__LINE__, "write %s", strerror(errno));
		return -1;
	}
	if (write(out, &mem[dataOffset], st.st_size - textOffset) < 0) {
		log_msg(__LINE__, "write %s", strerror(errno));
		return -1;
	}

	fsync(out);
	close(out);
	close(in);

	munmap(mem, st.st_size);

#if DEBUG
	log_msg(__LINE__, "merge_exe_text_into_core(): renaming %s back to %s", tmp, path);
#endif
	if (rename(tmp, path) < 0) {
		log_msg(__LINE__, "rename %s", strerror(errno));
		return -1;
	}
  	chmod(path, S_IRWXU|S_IRWXG|S_IROTH|S_IWOTH|S_IXOTH);
	return 0;
}

static int merge_text_image(const char *path, unsigned long text_addr, uint8_t *text_image, ssize_t text_len)
{
        ElfW(Ehdr) *ehdr;
        ElfW(Phdr) *phdr;
        ElfW(Off) textOffset; // offset of text segment in question
        ElfW(Off) nextOffset; // offset of phdr after the text segment in question
        size_t textSize;
        uint8_t *mem;
        struct stat st;
        int in, out, i = 0;
	ssize_t tlen = text_len;
	
	log_msg(__LINE__, "xopen path: %s", path);
        in = xopen(path, O_RDONLY);
        xfstat(in, &st);
	
        /*
         * tmp will point to the new temporary file that contains
         * our corefile with a merged in program text segment and
         * with updated p_filesz, and updated p_offsets for phdr's 
         * that follow it.
         */
	char *tmp_dir = opts.use_ramdisk ? ECFS_RAMDISK_DIR : ECFS_CORE_DIR;
        char *tmp = xfmtstrdup("%s/.tmp_merging_shlibs", tmp_dir);
        do {
                if (access(tmp, F_OK) == 0) {
                        free(tmp);
                        tmp = xfmtstrdup("%s/.tmp_merging_shlibs.%d", tmp_dir, ++i);
                } else
                        break;

        } while(1);
        out = xopen(tmp, O_RDWR|O_CREAT);
        //fchmod(out, S_IRWXU|S_IRWXG|S_IROTH|S_IWOTH|S_IXOTH);

	mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, in, 0);
        if (mem == MAP_FAILED) {
                log_msg(__LINE__, "mmap %s", strerror(errno));
                return -1;
        }
        ehdr = (ElfW(Ehdr) *)mem;
        phdr = (ElfW(Phdr) *)(mem + ehdr->e_phoff);
        int found_text = 0;
	
	/*
	 * XXX
	 * we must plan to make room for the case where the text segment
	 * in question is the very last phdr in the file in which case phdr[i + 1]
	 * will cause a segfault. (highly unlikely since any real shared library
	 * should have a data segment following the text segment)
	 */
	for (i = 0; i < ehdr->e_phnum; i++) {
		if (text_addr == phdr[i].p_vaddr) {
		 	textOffset = phdr[i].p_offset;
                        nextOffset = phdr[i + 1].p_offset;   // data segment usually always i + 1 after text
                        textSize = phdr[i].p_memsz;         // get memsz of text
                        phdr[i].p_filesz = phdr[i].p_memsz; // make filesz same as memsz
                        found_text++;

                }
                else
                if (found_text && phdr[i].p_type == PT_LOAD) {
#if DEBUG
			log_msg(__LINE__, "re-adjusting offset for phdr(0x%lx) from %lx to %lx\n", 
				phdr[i].p_vaddr, phdr[i].p_offset, phdr[i].p_offset + (tlen - 4096));
#endif
                        phdr[i].p_offset += (tlen - 4096); // we must push the other segments forward to make room for whole text image
                }
        }
        if (found_text == 0) {
                log_msg(__LINE__, "Failed to merge texts into core");
                return -1;
        }
        if (write(out, mem, textOffset) < 0) {
                log_msg(__LINE__, "[FAILURE] write(): %s", strerror(errno));
                return -1;
        }
        if (write(out, text_image, tlen) < 0) {
                log_msg(__LINE__, "[FAILURE] write(): %s", strerror(errno));
                return -1;
        }
	/*
	 * Take special care to free text_image 
	 * we likely have alot of memory mappings taking up	
 	 * memory if we are dealing with a large process and
	 * must free up these mappings as soon as we are done
	 * with them. otherwise resource hogging will happen.	
 	 */
	if (munmap(text_image, tlen) < 0) {
		log_msg(__LINE__, "[FAILURE] munmap(): %s", strerror(errno));
		return -1;
	}

        if (write(out, &mem[nextOffset], st.st_size - textOffset) < 0) {
                log_msg(__LINE__, "[FAILURE] write(): %s", strerror(errno));
                return -1;
        }

        fsync(out);
        close(out);
        close(in);
	munmap(mem, st.st_size);

#if DEBUG
	log_msg(__LINE__, "merge_text_image(): renaming %s back to %s", tmp, path);
#endif
        if (rename(tmp, path) < 0) {
                log_msg(__LINE__, "rename %s", strerror(errno));
                return -1;
        }
	chmod(path, S_IRWXU|S_IRWXG|S_IROTH|S_IWOTH|S_IXOTH); 
        return 0;

}

void create_shlib_text_mappings(memdesc_t *memdesc)
{
	int i;
	mappings_t *maps = memdesc->maps;
	ssize_t tlen;
	
	for (i = 0; i < memdesc->mapcount; i++) {
		if (!maps[i].shlib)
			continue;
		if (!(maps[i].p_flags & PF_X))
			continue;
		tlen = get_segment_from_pmem(maps[i].base, memdesc, &(maps[i].text_image));
		if (tlen < 0) {
			log_msg(__LINE__, "get_segment_from_pmem(%lx, ...) failed", maps[i].base);
			continue;
		} 
		if (tlen == ECFS_EXCEPTION)
			return;
		maps[i].text_len = tlen;
	}
}

int merge_shlib_texts_into_core(const char *corefile, memdesc_t *memdesc)
{
	int i, ret = -1;
	mappings_t *maps = memdesc->maps;
#if DEBUG
	log_msg(__LINE__, "merge_shlib_texts_into_core() has been called");
#endif
	for (i = 0; i < memdesc->mapcount; i++) {
		if (!maps[i].shlib)
			continue;
		if (!(maps[i].p_flags & PF_X))
			continue;
		/* If we got here we have an executable
	 	 * segment of a shared library.
	 	 */
#if DEBUG
		log_msg(__LINE__, "call merge_text_image(%s, %lx, %p, %u)", corefile, maps[i].base, maps[i].text_image, maps[i].text_len);
#endif
		ret = merge_text_image(corefile, maps[i].base, maps[i].text_image, maps[i].text_len); 
		if (ret < 0) {
			log_msg(__LINE__, "merge_text_image(%lx, ...) failed\n", maps[i].base);
			continue;
		}
	}
        return ret;
}
