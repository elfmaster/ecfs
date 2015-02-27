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
#include "ecfs.h"
#include "util.h"
#include "ptrace.h"
#include "symresolve.h"
#include "heuristics.h"

struct opts opts;

typedef struct handle { 
	char arglist[ELF_PRARGSZ];
	elf_stat_t elfstat;
	elfdesc_t *elfdesc;
	memdesc_t *memdesc;
	notedesc_t *notedesc;
	struct nt_file_struct *nt_files;
	struct section_meta smeta;
} handle_t;

/*
 * XXX stay out of habit of using global variables
 * this was put in  because I had to perform a hack
 * after the code had already been designed in order
 * to merge the entire text segment into the corefile
 * prior to processing it into an ECFS file.
 */
static char *tmp_corefile = NULL;

void build_elf_stats(handle_t *);
ElfW(Addr) get_original_ep(int);
ssize_t get_segment_from_pmem(unsigned long, memdesc_t *, uint8_t **);
/*
 * This function simply mmap's the core file into memory
 * and sets up pointers to the ELF header, and the program
 * headers. It also sets up Elf notes pointer (ElfW(Nhdr) *nhdr).
 * after this function is called you may then parse the notes
 * and operate on the core file in any other way.
 */
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

#define RBUF_LEN 4096 * 8

/*
 * This function will read the corefile from stdin
 * then write it to a temporary file which is then read
 * by the load_core_file() function above.
 */
elfdesc_t * load_core_file_stdin(void)
{
        uint8_t *buf = NULL;
        ssize_t nread;
	ssize_t bytes = 0, bw;
	int i = 0;
	int file;
	
	char *filepath = xfmtstrdup("%s/tmp_core", ECFS_CORE_DIR);
        do {
                if (access(filepath, F_OK) == 0) {
                        free(filepath);
                        filepath = xfmtstrdup("%s/tmp_core.%d", ECFS_CORE_DIR, ++i);
                } else
                        break;
                        
        } while(1);
	
	/*
	 * Open tmp file for writing
	 */
	file = xopen(filepath, O_CREAT|O_RDWR);
	fchmod(file, S_IRWXU|S_IRWXG|S_IROTH|S_IWOTH);
	buf = alloca(RBUF_LEN);
	while ((nread = read(STDIN_FILENO, buf, RBUF_LEN)) > 0) {
        	bytes += nread;
		bw = write(file, buf, nread);
		if (bw < 0) {
			log_msg(__LINE__, "write %s", strerror(errno));
			exit(-1);
		}
	}
	syncfs(file);
	close(file);
	tmp_corefile = xstrdup(filepath);
	return load_core_file(filepath);

}		

/*
 * The complete text segment of executables and shared library
 * is not included in core files. Only 4096 bytes are written
 * to save space; this is generally fine since the text presumably
 * doesn't ever change, and can be remarkably big. For our case
 * though we want the complete text of the main executable and
 * its shared libaries. This function merges the executables complete
 * text segment into the core file. And merge_shlib_texts_into_core
 * will do the ones for each shared library.
 */
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
	char *tmp = xfmtstrdup("%s/.tmp_merged_core", ECFS_CORE_DIR);
        do {
                if (access(tmp, F_OK) == 0) {
                        free(tmp);
                        tmp = xfmtstrdup("%s/.tmp_merged_core.%d", ECFS_CORE_DIR, ++i);
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
        log_msg(__LINE__, "textvaddr: %lx\n", textVaddr);

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
	
#if DEBUG
	log_msg(__LINE__, "merge_exe_text_into_core(): renaming %s back to %s", tmp, path);
#endif
	if (rename(tmp, path) < 0) {
		log_msg(__LINE__, "rename %s", strerror(errno));
		return -1;
	}
		
	return 0;
}

/*
 * This function is called by merge_shlib_texts_into_core() and merges a text segment
 * from a given shared library into the core file.
 */
static int merge_text_image(const char *path, unsigned long text_addr, uint8_t *text_image, ssize_t text_len)
{
        ElfW(Ehdr) *ehdr;
        ElfW(Phdr) *phdr;
        ElfW(Off) textOffset; // offset of text segment in question
        ElfW(Off) nextOffset; // offset of phdr after the text segment in question
        size_t textSize;
        uint8_t *mem;
        uint8_t *buf;
        struct stat st;
        ssize_t nread;
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
        char *tmp = xfmtstrdup("%s/tmp_merged_core_t2", ECFS_CORE_DIR);
        do {
                if (access(tmp, F_OK) == 0) {
                        free(tmp);
                        tmp = xfmtstrdup("%s/tmp_merged_core_t2.%d", ECFS_CORE_DIR, ++i);
                } else
                        break;

        } while(1);
        out = xopen(tmp, O_RDWR|O_CREAT);
	
	mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, in, 0);
        if (mem == MAP_FAILED) {
                log_msg(__LINE__, "mmap %s", strerror(errno));
                return -1;
        }
        ehdr = (ElfW(Ehdr) *)mem;
        phdr = (ElfW(Phdr) *)(mem + ehdr->e_phoff);
        int tc, found_text = 0;
	
	/*
	 * XXX
	 * we must plan to make room for the case where the text segment
	 * in question is the very last phdr in the file in which case phdr[i + 1]
	 * will cause a segfault. (highly unlikely since any real shared library
	 * should have a data segment following the text segment)
	 */
	for (i = 0; i < ehdr->e_phnum; i++) {
		if (text_addr == phdr[i].p_vaddr) {
			log_msg(__LINE__, "found text segment in core: addr %lx offset: %lx\n", phdr[i].p_vaddr, phdr[i].p_offset);
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
	log_msg(__LINE__, "Writing first %lx bytes", textOffset);
        if (write(out, mem, textOffset) < 0) {
                log_msg(__LINE__, "[FAILURE] write(): %s", strerror(errno));
                return -1;
        }
	log_msg(__LINE__, "Writing %lx bytes of text image", tlen);
        if (write(out, text_image, tlen) < 0) {
                log_msg(__LINE__, "[FAILURE] write(): %s", strerror(errno));
                return -1;
        }
	
	log_msg(__LINE__, "Writing rest of binary (%lx bytes) starting at data Offset %lx\n", st.st_size - textOffset, nextOffset);
        if (write(out, &mem[nextOffset], st.st_size - textOffset) < 0) {
                log_msg(__LINE__, "[FAILURE] write(): %s", strerror(errno));
                return -1;
        }

        fsync(out);
        close(out);
        close(in);
#if DEBUG
	log_msg(__LINE__, "merge_text_image(): renaming %s back to %s", tmp, path);
#endif
        if (rename(tmp, path) < 0) {
                log_msg(__LINE__, "rename %s", strerror(errno));
                return -1;
        }

        return 0;

}

static void create_shlib_text_mappings(memdesc_t *memdesc)
{
	int i, ret;
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
		maps[i].text_len = tlen;
	}
}

int merge_shlib_texts_into_core(const char *corefile, memdesc_t *memdesc)
{
	int i, ret;
	mappings_t *maps = memdesc->maps;
	uint8_t *text_image;
	ssize_t tlen;
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
			log_msg(__LINE__, "get_segment_from_pmem(%lx, ...) failed\n", maps[i].base);
			continue;
		}
	}
}

/*
 * This function does the opposite of how the kernel packs files into
 * the notes entry. We do the opposite to extract the info out of the
 * core files NT_FILE note.
 */
/* comment taken from kernel: */
/*
 * Format of NT_FILE note:
 *
 * long count     -- how many files are mapped
 * long page_size -- units for file_ofs
 * array of [COUNT] elements of
 *   long start
 *   long end
 *   long file_ofs
 * followed by COUNT filenames in ASCII: "FILE1" NUL "FILE2" NUL...
 */

void parse_nt_files(struct nt_file_struct **nt_files, void *data, size_t size)
{
	long *ptr = (long *)data;
	int offset = 0; // for strtab
	int i, j, name_offset;
	char *p, *cp = (char *)data;
	
	struct file_map_range {
		long start;
		long end;
		long file_ofs;
	} __attribute((packed));
	
	struct file_map_range *file_maps;
	*nt_files = (struct nt_file_struct *)heapAlloc(sizeof(struct nt_file_struct));

	(*nt_files)->fcount = ptr[0]; // filecount is stored here
	file_maps = (struct file_map_range *)heapAlloc((*nt_files)->fcount * sizeof(struct nt_file_struct));
	
	(*nt_files)->page_size = ptr[1];
	
	struct file_map_range *fmp = (struct file_map_range *)((long *)(ptr + 2));
	for (i = 0; i < (*nt_files)->fcount; i++, fmp++) {
		file_maps[i].start = fmp->start;	
		file_maps[i].end = fmp->end;
		file_maps[i].file_ofs = fmp->file_ofs;
	}
	name_offset = (2 + 3 * (int)ptr[0]) * sizeof(ptr[0]); //sizeof(struct file_map_range) * i;
	char *StringTable = (char *)&cp[name_offset];
	for (i = 0; i < (*nt_files)->fcount; i++) {
		for (j = 0, p = &StringTable[offset]; *p != '\0'; p++, j++) 
			(*nt_files)->files[i].path[j] = *p;
		offset += j + 1;
	}	
	fmp = (struct file_map_range *)(long *)(ptr + 2);
	for (i = 0; i < (*nt_files)->fcount; i++) {
		(*nt_files)->files[i].addr = fmp->start;
		(*nt_files)->files[i].size = fmp->end - fmp->start;
		(*nt_files)->files[i].pgoff = fmp->file_ofs;
		fmp++;
	}

}

static void print_nt_files(struct nt_file_struct *file_maps)
{
	int i;
	for (i = 0; i < file_maps->fcount; i++) {
		log_msg(__LINE__, "%lx  %lx  %lx\n", file_maps->files[i].addr, 
					  file_maps->files[i].addr + file_maps->files[i].size, 
					  file_maps->files[i].pgoff);
		log_msg(__LINE__,"\t%s\n", file_maps->files[i].path);
	}
}

/*
 * Parse the ELF notes to extract info such as struct prpsinfo
 * and struct prstatus. These structs hold information about the
 * process, and task state.
 */
notedesc_t * parse_notes_area(elfdesc_t *elfdesc)
{
	notedesc_t *notedesc = (notedesc_t *)heapAlloc(sizeof(notedesc_t));
	size_t i, len;
	int tc;
	uint8_t *desc;
	struct nt_file_struct *nt_files; // for parsing NT_FILE in corefile
	ElfW(Nhdr) *notes = elfdesc->nhdr;

	for (i = 0; i < elfdesc->noteSize; i += len) {
		desc = ELFNOTE_DESC(notes);
		switch(notes->n_type) {
			case NT_PRSTATUS:
#if DEBUG
				printf("Collecting PRSTATUS struct for thread #%d\n", notedesc->thread_count);
#endif
				if (notes->n_descsz != (size_t)sizeof(struct elf_prstatus)) {
#if DEBUG
					printf("error: The ELF note entry for NT_PRSTATUS is not the correct size\n");
#endif
					break;
				}
				tc = !!notedesc->thread_count;
				switch(tc) {
				case 1: 
					notedesc->thread_core_info[notedesc->thread_count].prstatus = (struct elf_prstatus *)heapAlloc(notes->n_descsz);
					memcpy(notedesc->thread_core_info[notedesc->thread_count].prstatus, desc, notes->n_descsz);
					break;
				case 0:
					notedesc->prstatus = (struct elf_prstatus *)heapAlloc(sizeof(struct elf_prstatus));
					memcpy(notedesc->prstatus, desc, notes->n_descsz);
					notedesc->thread_core_info[notedesc->thread_count].prstatus = notedesc->prstatus;
					break;
				}
				notedesc->thread_count++;
				break;
			case NT_PRPSINFO:
				if (notes->n_descsz != (size_t)sizeof(struct elf_prpsinfo)) {
#if DEBUG
					printf("error: The ELF note entry for NT_PRPSINFO is not the correct size\n");	
#endif
					break;
				}
				notedesc->psinfo = (struct elf_prpsinfo *)heapAlloc(sizeof(struct elf_prpsinfo));
				memcpy(notedesc->psinfo, desc, notes->n_descsz);
				break;
			case NT_SIGINFO:
				if (notes->n_descsz != sizeof(siginfo_t)) {
#if DEBUG
					printf("error: the ELF note entry for NT_SIGINFO is not the correct size\n");
#endif
					break;
				}
				notedesc->siginfo = (struct siginfo_t *)heapAlloc(sizeof(siginfo_t));
				memcpy(notedesc->siginfo, desc, notes->n_descsz);
				break;
			case NT_AUXV:
				notedesc->auxv = heapAlloc(notes->n_descsz);
				memcpy((void *)notedesc->auxv, (void *)desc, notes->n_descsz);
				notedesc->auxv_size = notes->n_descsz;
				break;
			case NT_FILE:
				parse_nt_files(&nt_files, (void *)desc, notes->n_descsz);
				print_nt_files(nt_files);
				notedesc->nt_files = (struct nt_file_struct *)heapAlloc(sizeof(struct nt_file_struct));
				memcpy(notedesc->nt_files, nt_files, sizeof(struct nt_file_struct));
				break;
			case NT_FPREGSET:
				if (notes->n_descsz != sizeof(elf_fpregset_t)) {
#if DEBUG
					printf("error: The ELF note entry for NT_PRPSINFO is not the correct size\n");
#endif 
					break;
				}
				notedesc->fpu = (elf_fpregset_t *)heapAlloc(sizeof(elf_fpregset_t));
				memcpy(notedesc->fpu, desc, notes->n_descsz);
				break;
			
		}
		/*
		 * note entries are always word aligned (4 bytes)
		 */
		len = (notes->n_descsz + notes->n_namesz + sizeof(long) + 3) & ~3;
		notes = ELFNOTE_NEXT(notes);
	}

	return notedesc;
}

static  int check_for_pie(int pid)
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
	
static void get_text_phdr_size_with_hint(elfdesc_t *elfdesc, unsigned long hint)
{
	ElfW(Phdr) *phdr = elfdesc->phdr;
	int i;
	
	for (i = 0; i < elfdesc->ehdr->e_phnum; i++) {
		if (hint >= phdr[i].p_vaddr && hint < phdr[i].p_vaddr + phdr[i].p_memsz) {
			log_msg(__LINE__, "setting filesz %lx memsz %lx\n", phdr[i].p_filesz, phdr[i].p_memsz);
			elfdesc->text_filesz = phdr[i].p_filesz;
			elfdesc->text_memsz = phdr[i].p_memsz;
			break;
		}
	}

}

static ssize_t ptrace_get_text_mapping(memdesc_t *memdesc, elfdesc_t *elfdesc, uint8_t **ptr)
{
	void *addr = (void *)elfdesc->textVaddr;
	uint8_t *mem = heapAlloc(elfdesc->textSize);
	
	if (pid_read(memdesc->task.pid, (void *)mem, addr, elfdesc->textSize) < 0) {
		*ptr = NULL;
		return -1;
	}
	*ptr = mem;
	
	return elfdesc->textSize;
}

ssize_t read_pmem(pid_t pid, uint8_t *ptr, unsigned long vaddr, size_t len)
{	
	char *path = xfmtstrdup("/proc/%d/mem", pid);
	int fd = xopen(path, O_RDONLY);
	ssize_t bytes = pread(fd, ptr, len, vaddr);
	if (bytes != len) {
		log_msg(__LINE__, "pread failed [read %d bytes]: %s", (int)bytes, strerror(errno));
		return -1;
	}
	return bytes;
}
	
/*
 * This function will not read directly from vaddr unless vaddr marks
 * the beggining of a segment; otherwise this function finds where the
 * segment begins (The segment range that vaddr fits in) and reads from there.
 */
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
			deliver_signal(memdesc->task.pid, SIGSTOP);
			ret = read_pmem(memdesc->task.pid, *ptr, memdesc->maps[i].base, len);
			deliver_signal(memdesc->task.pid, SIGCONT);
			return ret;
		}
	}
	return -1;
	
}

static ElfW(Addr) get_mapping_flags(ElfW(Addr) addr, memdesc_t *memdesc)
{
	int i;
	for (i = 0; i < memdesc->mapcount; i++) 
		if (memdesc->maps[i].base == addr)
			return memdesc->maps[i].p_flags;
	return -1;
}

static ElfW(Off) get_mapping_offset(ElfW(Addr) addr, elfdesc_t *elfdesc)
{
	ElfW(Ehdr) *ehdr = elfdesc->ehdr;
	ElfW(Phdr) *phdr = elfdesc->phdr;
	int i;

	for (i = 0; i < ehdr->e_phnum; i++)
		if (phdr[i].p_vaddr == addr)
			return phdr[i].p_offset;
	return 0;
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


/*
 * Can only be called after the notes file has been parsed.
 * We really only need these for PIE executables since getting
 * the base address data and text can only otherwise be gotten
 * from maps. The phdr's of a PIE executable won't reflect the
 * actual load addresses.
 */
static ElfW(Addr) lookup_text_base(memdesc_t *memdesc, struct nt_file_struct *fmaps)
{	
	int i;
	char *p;

	for (i = 0; i < fmaps->fcount; i++) {
		p = strrchr(fmaps->files[i].path, '/') + 1;
		if (!strcmp(memdesc->exe_comm, p))
			return fmaps->files[i].addr;
	}
	return 0;
}

static ElfW(Addr) lookup_text_size(memdesc_t *memdesc, struct nt_file_struct *fmaps)
{
        int i;
        char *p;

        for (i = 0; i < fmaps->fcount; i++) {
                p = strrchr(fmaps->files[i].path, '/') + 1;
                if (!strcmp(memdesc->exe_comm, p))
                        return fmaps->files[i].size;
        }
        return 0;
}

/*
 * Same as previous function but for data segment mapping base.
 */
static ElfW(Addr) lookup_data_base(memdesc_t *memdesc, struct nt_file_struct *fmaps)
{
	int i;
	char *p;

        for (i = 0; i < fmaps->fcount; i++) {
                p = strrchr(fmaps->files[i].path, '/') + 1;
                if (!strcmp(memdesc->exe_comm, p)) {
			p = strrchr(fmaps->files[i + 1].path, '/') + 1;
			if (!strcmp(memdesc->exe_comm, p))
				return fmaps->files[i + 1].addr;
        	}
	}
        return 0;
}

static ElfW(Addr) lookup_data_size(memdesc_t *memdesc, struct nt_file_struct *fmaps)
{
        int i;
        char *p;

        for (i = 0; i < fmaps->fcount; i++) {
                p = strrchr(fmaps->files[i].path, '/') + 1;
                if (!strcmp(memdesc->exe_comm, p)) {
                        p = strrchr(fmaps->files[i + 1].path, '/') + 1;
                        if (!strcmp(memdesc->exe_comm, p))
                                return fmaps->files[i + 1].size;
                }
        }
        return 0;
}

/*
 * There should be 3 mappings for each lib
 * .text, relro, and .data.
 */
static void lookup_lib_maps(elfdesc_t *elfdesc, memdesc_t *memdesc, struct nt_file_struct *fmaps, struct lib_mappings *lm)
{
	int i, j;
	char *p, *tmp = alloca(256);
	memset(lm, 0, sizeof(struct lib_mappings));

	for (i = 0; i < fmaps->fcount; i++) {
#if DEBUG	
		log_msg(__LINE__, "filepath: %s", fmaps->files[i].path);
#endif
		p = strrchr(fmaps->files[i].path, '/') + 1;
		if (!strstr(p, ".so"))
			continue;
		for (j = 0; j < strlen(p); j++)
			tmp[j] = p[j];
		tmp[j] = '\0';
		/*
	 	 * path and name are MAX_LIB_N + 1 in size hence no need
		 * to take byte for null terminator into account with strncpy
	 	 */
		strncpy(lm->libs[lm->libcount].path, fmaps->files[i].path, MAX_LIB_PATH);
		strncpy(lm->libs[lm->libcount].name, tmp, MAX_LIB_NAME);
#if DEBUG
		log_msg(__LINE__, "libname: %s", lm->libs[lm->libcount].name);
#endif
		lm->libs[lm->libcount].addr = fmaps->files[i].addr;
		lm->libs[lm->libcount].size = fmaps->files[i].size;
		lm->libs[lm->libcount].flags = get_mapping_flags(lm->libs[lm->libcount].addr, memdesc);
		lm->libs[lm->libcount].offset = get_mapping_offset(lm->libs[lm->libcount].addr, elfdesc);
		lm->libcount++;
	}
		
}

/*
 * Since the process is paused, all /proc data is still available.
 * get_maps() simply extracts all of the memory mapping information
 * including details such as stack, heap, .so's, vdso etc.
 * eventually we pair this info up with the program headers (PT_LOAD's)
 * in the core file to determine where to build certain section headers.
 */
static int get_maps(pid_t pid, mappings_t *maps, const char *path)
{
        char mpath[256], buf[256], tmp[256], *p, *chp, *q = alloca(32);
        FILE *fd;
        int lc, i;
        
        snprintf(mpath, sizeof(mpath), "/proc/%d/maps", pid);
        if ((fd = fopen(mpath, "r")) == NULL) 
                return -1;

        for (lc = 0; (fgets(buf, sizeof(buf), fd) != NULL); lc++) {
                strcpy(tmp, buf); //tmp and buf are same sized buffers
                p = strchr(buf, '-');
                *p = '\0';
                p++;
                maps[lc].elfmap = 0;
                maps[lc].base = strtoul(buf, NULL, 16);
                maps[lc].size = strtoul(p, NULL, 16) - maps[lc].base;
		chp = strrchr(tmp, '/'); 
		if (chp) 
			*(char *)strchr(chp, '\n') = '\0';
		if (chp && !strcmp(&chp[1], path)) {
                        if (!strstr(tmp, "---p")) {
                                maps[lc].filename = xstrdup(strchr(tmp, '/'));
                                maps[lc].elfmap++;
				if (strstr(tmp, "r-xp") || strstr(tmp, "rwxp")) //sometimes text is polymorphic
					maps[lc].textbase++;
			}
                }
                else
                if (strstr(tmp, "[heap]")) 
                        maps[lc].heap++;
                else
                if (strstr(tmp, "[stack]"))
                        maps[lc].stack++;
                else
                if (strstr(tmp, "[stack:")) { /* thread stack */
                        for (i = 0, p = strchr(tmp, ':') + 1; *p != ']'; p++, i++)
                                q[i] = *p;
                        maps[i].thread_stack++;
                        maps[i].stack_tid = atoi(q);
                }
                else 
                if (strstr(tmp, "---p")) 
                        maps[lc].padding++;
                else
                if (strstr(tmp, "[vdso]")) 
                        maps[lc].vdso++; 
                else
                if (strstr(tmp, "[vsyscall]"))
                        maps[lc].vsyscall++;
                else
                if ((p = strrchr(tmp, '/'))) {
                        if (strstr(p, ".so")) {
#if DEBUG
				log_msg(__LINE__, "marked %s as shared library", p);
#endif
                                maps[lc].shlib++;
                                maps[lc].filename = xstrdup(strchr(tmp, '/'));
                        }
                        else
                        if (strstr(p, "rwxp") || strstr(p, "r-xp")) {
                                maps[lc].filename = xstrdup(strchr(tmp, '/'));
                                maps[lc].filemap_exe++; // executable file mapping
                        }
                        else {
                                maps[lc].filename = xstrdup(strchr(tmp, '/'));
                                maps[lc].filemap++; // regular file mapping
                        }       
                } else
                if (strstr(tmp, "rwxp") || strstr(tmp, "r-xp")) 
                        maps[lc].anonmap_exe++; // executable anonymous mapping
                
                /*      
                 * Set segment permissions (Or is it a special file?)
                 */
                if (strstr(tmp, "r--p")) 
                        maps[lc].p_flags = PF_R;
                else
                if (strstr(tmp, "rw-p"))
                        maps[lc].p_flags = PF_R|PF_W;
                else
                if (strstr(tmp, "-w-p"))
                        maps[lc].p_flags = PF_W;
                else
                if (strstr(tmp, "--xp"))
                        maps[lc].p_flags = PF_X;
                else
                if (strstr(tmp, "r-xp"))
                        maps[lc].p_flags = PF_X|PF_R;
                else
                if (strstr(tmp, "-wxp"))
                        maps[lc].p_flags = PF_X|PF_W;
 		else
                if (strstr(tmp, "rwxp"))
                        maps[lc].p_flags = PF_X|PF_W|PF_R;
                else
                if (strstr(tmp, "r--s"))
                        maps[lc].special++;
                else
                if (strstr(tmp, "rw-s"))
                        maps[lc].special++;
                else
                if (strstr(tmp, "-w-s"))
                        maps[lc].special++;
                else
                if (strstr(tmp, "--xs"))
                        maps[lc].special++;
                else
                if (strstr(tmp, "r-xs"))
                        maps[lc].special++;
                else
                if (strstr(tmp, "-wxs"))
                        maps[lc].special++;
                else
                if (strstr(tmp, "rwxs"))
                        maps[lc].special++;
                
        }
        fclose(fd);

        return 0;
}

static void fill_sock_info(fd_info_t *fdinfo, unsigned int inode)
{
	FILE *fp = fopen("/proc/net/tcp", "r");
	char buf[512], local_addr[64], rem_addr[64];
	char more[512];
	int local_port, rem_port, d, state, timer_run, uid, timeout;
	unsigned long rxq, txq, time_len, retr, _inode;
	if( fgets(buf, sizeof(buf), fp) == NULL ) {
		log_msg(__LINE__, "fgets %s", strerror(errno));
		exit(-1);
        }
	while (fgets(buf, sizeof(buf), fp)) {
		sscanf(buf, "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %ld %512s\n",
			&d, local_addr, &local_port, rem_addr, &rem_port, &state,
			&txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &_inode, more);
		if (_inode == inode) {
#if DEBUG
			log_msg(__LINE__, "socket (TCP) inode match");
#endif
			sscanf(local_addr, "%X", &(fdinfo->socket.src_addr.s_addr));
			sscanf(rem_addr, "%X", &(fdinfo->socket.dst_addr.s_addr));
			fdinfo->socket.src_port = local_port;
			fdinfo->socket.dst_port = rem_port;
			fdinfo->net = NET_TCP;
		}
	}	/* Try for UDP if we don't find the socket inode in TCP */
	
	fclose(fp);
	fp = fopen("/proc/net/udp", "r");
	if( fgets(buf, sizeof(buf), fp) == NULL ) {
		log_msg(__LINE__, "fgets %s", strerror(errno));
		exit(-1);
        }
        while (fgets(buf, sizeof(buf), fp)) {
                sscanf(buf, "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %ld %512s\n",
                        &d, local_addr, &local_port, rem_addr, &rem_port, &state,
                        &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &_inode, more);
                if (_inode == inode) {
#if DEBUG
                        log_msg(__LINE__, "socket (UDP) inode match");
#endif
                        sscanf(local_addr, "%X", &(fdinfo->socket.src_addr.s_addr));
                        sscanf(rem_addr, "%X", &(fdinfo->socket.dst_addr.s_addr));
                        fdinfo->socket.src_port = local_port;
                        fdinfo->socket.dst_port = rem_port;
                        fdinfo->net = NET_UDP;
                        log_msg(__LINE__, "setting net UDP");
                }
        }

	fclose(fp);
}

static int get_fd_links(memdesc_t *memdesc, fd_info_t **fdinfo)
{
	DIR *dp;
	struct dirent *dptr = NULL;
	char tmp[256];
	char *dpath = xfmtstrdup("/proc/%d/fd", memdesc->task.pid);
	*fdinfo = (fd_info_t *)heapAlloc(sizeof(fd_info_t) * 256);
	fd_info_t fdinfo_tmp;
	unsigned int inode;
	char *p;
	int fdcount;
 	
        for (fdcount = 0, dp = opendir(dpath); dp != NULL;) {
                dptr = readdir(dp);
                if (dptr == NULL) 
                        break;
		if (dptr->d_name[0] == '.')
			continue;
		snprintf(tmp, sizeof(tmp), "%s/%s", dpath, dptr->d_name); // i.e /proc/pid/fd/3
		if( readlink(tmp, (*fdinfo)[fdcount].path, MAX_PATH) == -1 ) {
                    log_msg(__LINE__, "readlink %s", strerror(errno));
                    exit(-1);
                }
		if (strstr((*fdinfo)[fdcount].path, "socket")) {
			p = strchr((*fdinfo)[fdcount].path, ':') + 2;
			if (p == NULL) {
				fdcount++;
				continue;
			}
			
			inode = atoi(p);
			fill_sock_info(&fdinfo_tmp, inode);
			if (fdinfo_tmp.net) {
				(*fdinfo)[fdcount].net = fdinfo_tmp.net;
				(*fdinfo)[fdcount].socket = fdinfo_tmp.socket;
			}
		}
		(*fdinfo)[fdcount].fd = atoi(dptr->d_name);
		fdcount++;
	}
	return fdcount;
}

static int get_map_count(pid_t pid)
{
        FILE *pd;
        char cmd[256], buf[256];
        int lc;
  	      
        snprintf(cmd, sizeof(cmd), "/usr/bin/wc -l /proc/%d/maps", pid);
	if ((pd = popen(cmd, "r")) == NULL) {
            return -1;
        }
        if( fgets(buf, sizeof(buf), pd) == NULL ) {
            log_msg(__LINE__, "fgets %s", strerror(errno));
            exit(-1);
        }
        lc = atoi(buf);
        pclose(pd);
        return lc;
}

/*
 * Handle the case where say: /bin/someprog is a symbolic link
 */
char * get_exe_path(int pid)
{
	char *path = xfmtstrdup("/proc/%d/exe", pid);
	char *ret = (char *)heapAlloc(MAX_PATH);
	char *ret2 = (char *)heapAlloc(MAX_PATH);
	
	memset(ret, 0, MAX_PATH); // for null termination padding
	if( readlink(path, ret, MAX_PATH) == -1) {
            log_msg(__LINE__, "readlink %s", strerror(errno));
            exit(-1);
        }
	free(path);
	/* Now is our new path also a symbolic link? */
	int rval = readlink(ret, ret2, MAX_PATH);
	return rval < 0 ? ret : ret2;
}

/*
 * Get /proc/pid/maps info to create data
 * about stack, heap etc. This can then be
 * merged with the info retrieved from the
 * core files phdr's.
 */

char *exename = NULL;

memdesc_t * build_proc_metadata(pid_t pid, notedesc_t *notedesc)
{
	int i;
	memdesc_t *memdesc = (memdesc_t *)heapAlloc(sizeof(memdesc_t));
	
	memdesc->mapcount = get_map_count(pid);
        if (memdesc->mapcount < 0) {
                log_msg(__LINE__, "failed to get mapcount from /proc/%d/maps", pid);
                return NULL;
        }
        memdesc->maps = (mappings_t *)heapAlloc(sizeof(mappings_t) * memdesc->mapcount);
        
        memset((void *)memdesc->maps, 0, sizeof(mappings_t) * memdesc->mapcount);
        
	/*
	 * comm and path should be different. comm should be just the filename
	 * whereas path should be the complete filepath. Although due to an early
	 * on coding mistake I named comm, as path. There was no comm. path contained
	 * the filename, and exe_path contained the file path. Then came in a complication
	 * where some executable paths are actually symbolic links. So I had to make
	 * some changes, but still need to clear some things up. Currently memdesc->comm
	 * and memdesc->path both contain the filename (Which might just be a symbolic link)
	 * and exe_path and exe_comm contain the path and filename of the real file that
	 * the link points to.
	 */
	memdesc->comm = memdesc->path = exename; // supplied by core_pattern %e
	memdesc->exe_path = get_exe_path(pid); 
	memdesc->exe_comm = strrchr(memdesc->exe_path, '/') + 1;
	if (get_maps(pid, memdesc->maps, memdesc->exe_comm) < 0) {
                log_msg(__LINE__, "failed to get data from /proc/%d/maps", pid);
                return NULL;
        }
        
        memdesc->task.pid = memdesc->pid = pid;
	

        for (i = 0; i < memdesc->mapcount; i++) {
                if (memdesc->maps[i].heap) {
                        memdesc->heap.base = memdesc->maps[i].base;
                        memdesc->heap.size = memdesc->maps[i].size;
                } else
                if (memdesc->maps[i].stack) {
                        memdesc->stack.base = memdesc->maps[i].base;
                        memdesc->stack.size = memdesc->maps[i].size;
                } else
                if (memdesc->maps[i].vdso) {
                        memdesc->vdso.base = memdesc->maps[i].base;
                        memdesc->vdso.size = memdesc->maps[i].size;
                } else
                if (memdesc->maps[i].vsyscall) {
                        memdesc->vsyscall.base = memdesc->maps[i].base;
                        memdesc->vsyscall.size = memdesc->maps[i].size;
                }
		if (memdesc->maps[i].textbase) {
			memdesc->text.base = memdesc->maps[i].base;
			memdesc->text.size = memdesc->maps[i].size;
		}
        }
#if DEBUG
	log_msg(__LINE__, "executable text base: %lx\n", memdesc->text.base);
#endif
	ssize_t tlen = get_segment_from_pmem(memdesc->text.base, memdesc, &memdesc->textseg);
        if (tlen < 0) {
		log_msg(__LINE__, "get_segment_from_pmem() failed: %s\n", strerror(errno));
                return NULL;
        }
	return memdesc;
	
}

/*
 * This function parses the original phdr's which it must get using
 * ptrace. This is the only part where we use ptrace() and we should
 * possibly change this to using /proc/self/mem instead. In any case
 * we get the original phdr locations so that we can then find them
 * in relation to the corefile that was dumped.
 *
 * NOTE:
 * The dataVaddr is taken from the core file which gives the page aligned
 * segment address, which is not the same as the original data segment address.
 * In our case we use the page aligned dataVaddr which we retrieve with our
 * lookup_data_base() function.
 */
static int parse_orig_phdrs(elfdesc_t *elfdesc, memdesc_t *memdesc, notedesc_t *notedesc)
{
	int fd;
	uint8_t *mem;
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	ElfW(Addr) text_base = 0;
	struct stat st;
	int i;

	/*
	 * For debugging purposes since the core file on disk isn't
	 * going to match the exact one in the process image for PIE
	 * executables (Since we technically have to kill the process
	 * to get the core, then restart the process again)
	 * we won't use lookup_text_base() but instead get it from
	 * the maps. We can change this much later on.
	 */
	text_base = memdesc->text.base;
	if (text_base == 0) {
		log_msg(__LINE__, "Unable to locate executable base address necessary to find phdr's");
		return -1;
	}
	
	/* Instead we use mmap on the original executable file */
#if DEBUG
	log_msg(__LINE__, "exe_path: %s", memdesc->exe_path);
#endif
	fd = xopen(memdesc->exe_path, O_RDONLY);
	xfstat(fd, &st);
	mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		log_msg(__LINE__, "mmap %s", strerror(errno));
		exit(-1);
	}
 
	/*
	 * Now get text_base again but from the core file. During a real crashdump
	 * these values will be the exact same either way.
	 */
	text_base = lookup_text_base(memdesc, notedesc->nt_files);

	ehdr = (ElfW(Ehdr) *)mem;
	phdr = (ElfW(Phdr) *)(mem + ehdr->e_phoff);
	if (ehdr->e_type == ET_DYN)
		memdesc->pie = ++elfdesc->pie;
	
	for (i = 0; i < ehdr->e_phnum; i++) {
		switch(phdr[i].p_type) {
			case PT_LOAD:
#if DEBUG
				printf("Found PT_LOAD segments\n");
#endif
				if(!(!phdr[i].p_offset)) {
                                        elfdesc->dataVaddr = lookup_data_base(memdesc, notedesc->nt_files);
                                        elfdesc->dataSize = lookup_data_size(memdesc, notedesc->nt_files);
                                        elfdesc->bssSize = phdr[i].p_memsz - phdr[i].p_filesz;
                                        elfdesc->o_datafsize = phdr[i].p_filesz;
                                        if (elfdesc->pie == 0)
                                                elfdesc->bssVaddr = phdr[i].p_vaddr + phdr[i].p_filesz;

                                } else {
                                        /* text segment */
                                        elfdesc->textVaddr = text_base;
                                        elfdesc->textSize = lookup_text_size(memdesc, notedesc->nt_files);

				}
				break;
			case PT_DYNAMIC:
				elfdesc->dynVaddr = phdr[i].p_vaddr + (elfdesc->pie ? text_base : 0);
				log_msg(__LINE__, "the fuqin dynvaddr: %lx", elfdesc->dynVaddr);
				elfdesc->dynSize = phdr[i].p_memsz;
				break;
			case PT_GNU_EH_FRAME:
				elfdesc->ehframe_Vaddr = phdr[i].p_vaddr + (elfdesc->pie ? text_base : 0);
				elfdesc->ehframe_Size = phdr[i].p_memsz;
				break;
			case PT_NOTE:
				/*
				 * We don't want the original executables note, but the corefile
				 * notes so we don't fill these in at this point.
				 */
				//elfdesc->noteVaddr = phdr[i].p_vaddr + (elfdesc->pie ? text_base : 0);
				//elfdesc->noteSize = phdr[i].p_filesz;
				break;
			case PT_INTERP:
				elfdesc->dynlinked++;
				elfdesc->interpVaddr = phdr[i].p_vaddr;
				elfdesc->interpSize = phdr[i].p_memsz ? phdr[i].p_memsz : phdr[i].p_filesz; 
				break;
		}
	}
	
	close(fd);
	return 0;
}

/*
 * Parse the dynamic segment to get 
 * a whole lot of needed information
 */

int extract_dyntag_info(handle_t *handle)
{
	int i, j;
	elfdesc_t *elfdesc = handle->elfdesc;
	memdesc_t *memdesc = handle->memdesc;
	ElfW(Phdr) *phdr = elfdesc->phdr;
	ElfW(Dyn) *dyn;
	ElfW(Off) dataOffset = elfdesc->dataOffset; // this was filled in from xref_phdrs_for_offsets
	elfdesc->dyn = NULL;
	struct section_meta smeta;
	
	for (i = 0; i < elfdesc->ehdr->e_phnum; i++) {
		if (phdr[i].p_vaddr == elfdesc->dataVaddr) {
			log_msg(__LINE__, "dynamic segment is at: %lx compared to %lx", phdr[i].p_vaddr, elfdesc->dataVaddr);
			log_msg(__LINE__, "dyn = &mem[%lx + (%lx - %lx)]", phdr[i].p_offset, elfdesc->dynVaddr, elfdesc->dataVaddr);
			elfdesc->dyn = (ElfW(Dyn) *)&elfdesc->mem[phdr[i].p_offset + (elfdesc->dynVaddr - elfdesc->dataVaddr)];
			break;
		}
	}

	if (elfdesc->dyn == NULL) {
		log_msg(__LINE__, "Unable to find dynamic segment in core file, exiting...");
		return -1;
	}
	dyn = elfdesc->dyn;
	for (j = 0; dyn[j].d_tag != DT_NULL; j++) {
        	switch(dyn[j].d_tag) {
			case DT_REL:
                        	smeta.relVaddr = dyn[j].d_un.d_val;
                                smeta.relOff = elfdesc->textOffset + smeta.relVaddr - elfdesc->textVaddr;
#if DEBUG
				log_msg(__LINE__, "DYNSEGMENT: relVaddr: %lx relOff: %lx", smeta.relVaddr, smeta.relOff);
#endif
                        	break;
                        case DT_RELA:
                        	smeta.relaVaddr = dyn[j].d_un.d_val;
                                smeta.relaOff = elfdesc->textOffset + smeta.relaVaddr - elfdesc->textVaddr; 
#if DEBUG
				log_msg(__LINE__, "DYNSEGMENT: %lx relaOffset: %lx", smeta.relaVaddr, smeta.relaOff);
#endif
                        	break;
			case DT_JMPREL:
				smeta.plt_relaVaddr = dyn[j].d_un.d_val;
				smeta.plt_relaOff = elfdesc->textOffset + smeta.plt_relaVaddr - elfdesc->textVaddr;
#if DEBUG
				log_msg(__LINE__, "DYNSEGMENT: relaOffset = %lx + %lx - %lx", elfdesc->textOffset, smeta.plt_relaVaddr, elfdesc->textVaddr);
				log_msg(__LINE__, "DYNSEGMENT: plt_relaVaddr: %lx plt_relaOffset: %lx", smeta.plt_relaVaddr, smeta.plt_relaOff);
#endif
				break;
                        case DT_PLTGOT:
                        	smeta.gotVaddr = dyn[j].d_un.d_val;
                                smeta.gotOff = dyn[j].d_un.d_val - elfdesc->dataVaddr;
                                smeta.gotOff += (ElfW(Off))dataOffset;
#if DEBUG
				log_msg(__LINE__, "DYNSEGMENT: gotVaddr: %lx gotOffset: %lx", smeta.gotVaddr, smeta.gotOff);
#endif
                                break;
                        case DT_GNU_HASH:
                                smeta.hashVaddr = dyn[j].d_un.d_val;
                                smeta.hashOff = elfdesc->textOffset + smeta.hashVaddr - elfdesc->textVaddr;
#if DEBUG
				log_msg(__LINE__, "DYNSEGMENT: hashVaddr: %lx hashOff: %lx", smeta.hashVaddr, smeta.hashOff);
#endif
                                break;
                        case DT_INIT: 
                                smeta.initVaddr = dyn[j].d_un.d_val + (memdesc->pie ? elfdesc->textVaddr : 0);
                                smeta.initOff = elfdesc->textOffset + smeta.initVaddr - elfdesc->textVaddr;
#if DEBUG
				log_msg(__LINE__, "DYNSEGMENT: initVaddr: %lx initOff: %lx", smeta.initVaddr, smeta.initOff);
#endif
                                break;
                        case DT_FINI:
                                smeta.finiVaddr = dyn[j].d_un.d_val + (memdesc->pie ? elfdesc->textVaddr : 0);
                                smeta.finiOff = elfdesc->textOffset + smeta.finiVaddr - elfdesc->textVaddr;
#if DEBUG
				log_msg(__LINE__, "DYNSEGMENT: finiVaddr: %lx finiOff: %lx", smeta.finiVaddr, smeta.finiOff);
#endif
                                break;
                        case DT_STRSZ:
                                smeta.strSiz = dyn[j].d_un.d_val;
                                break;  
                        case DT_PLTRELSZ:
                                smeta.pltSiz = dyn[j].d_un.d_val;
                                break;
                        case DT_SYMTAB:
                                smeta.dsymVaddr = dyn[j].d_un.d_ptr;
                                smeta.dsymOff = elfdesc->textOffset + smeta.dsymVaddr - elfdesc->textVaddr;
#if DEBUG
				log_msg(__LINE__, "DYNSEGMENT: .dynsym addr: %lx offset: %lx", smeta.dsymVaddr, smeta.dsymOff);
#endif
				break;
                        case DT_STRTAB:
                                smeta.dstrVaddr = dyn[j].d_un.d_ptr;
                                smeta.dstrOff = elfdesc->textOffset + smeta.dstrVaddr - elfdesc->textVaddr;
#if DEBUG
				log_msg(__LINE__, "DYNSEGMENT: .dynstr addr: %lx  offset: %lx (%lx + (%lx - %lx)", smeta.dstrVaddr, smeta.dstrOff,
				elfdesc->textOffset, smeta.dstrVaddr, elfdesc->textVaddr); 
#endif
                                break;

		}
	}
	memcpy((void *)&handle->smeta, (void *)&smeta, sizeof(struct section_meta));
	return 0;
}

/*
 * The offsets from when a file is an executable to a corefile
 * change durastically because the phdr table is so much bigger
 * pushing everything else forward. We must find the offsets of
 * certain old phdr's like PT_DYNAMIC and figure out what the offset
 * is in the core file for it. That way we can build appropriate shdrs.
 */
static void xref_phdrs_for_offsets(memdesc_t *memdesc, elfdesc_t *elfdesc)
{
	ElfW(Phdr) *phdr = elfdesc->phdr;
	int i;
	
	for (i = 0; i < elfdesc->ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_NOTE) {
			elfdesc->noteOffset = phdr[i].p_offset;
			elfdesc->noteVaddr = phdr[i].p_vaddr;
#if DEBUG
			log_msg(__LINE__,"noteOffset: %lx\n", elfdesc->noteOffset);
#endif
		}
		if (elfdesc->interpVaddr >= phdr[i].p_vaddr && elfdesc->interpVaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
			elfdesc->interpOffset = phdr[i].p_offset + elfdesc->interpVaddr - phdr[i].p_vaddr;
#if DEBUG
			log_msg(__LINE__, "interpOffset: %lx\n", elfdesc->interpOffset);
#endif
		}
		if (elfdesc->dynVaddr >= phdr[i].p_vaddr && elfdesc->dynVaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
			elfdesc->dynOffset = phdr[i].p_offset + elfdesc->dynVaddr - phdr[i].p_vaddr;
#if DEBUG
			log_msg(__LINE__, "dynOffset: %lx\n", elfdesc->dynOffset);
#endif
		}
		if (elfdesc->ehframe_Vaddr >= phdr[i].p_vaddr && elfdesc->ehframe_Vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
			elfdesc->ehframeOffset = phdr[i].p_offset + elfdesc->ehframe_Vaddr - phdr[i].p_vaddr;
#if DEBUG
			log_msg(__LINE__, "ehframeOffset: %lx\n", elfdesc->ehframeOffset);
#endif
		}
		if (elfdesc->textVaddr == phdr[i].p_vaddr) {
			elfdesc->textOffset = phdr[i].p_offset;
			elfdesc->textSize = phdr[i].p_memsz;
#if DEBUG
			log_msg(__LINE__, "textOffset: %lx", elfdesc->textOffset);
#endif
		}
		if (elfdesc->dataVaddr == phdr[i].p_vaddr) {
			elfdesc->dataOffset = phdr[i].p_offset;
			if (elfdesc->pie)
				elfdesc->bssVaddr = elfdesc->dataVaddr + elfdesc->o_datafsize;
#if DEBUG
			log_msg(__LINE__, "bssVaddr is: %lx\n", elfdesc->bssVaddr);
#endif
			elfdesc->bssOffset = phdr[i].p_offset + elfdesc->bssVaddr - elfdesc->dataVaddr;
#if DEBUG
			log_msg(__LINE__, "bssOffset: %lx "
			       "dataOffset: %lx\n", elfdesc->bssOffset, elfdesc->dataOffset);
#endif
		}
	}
}

/*
 * This function treats type as either HEAP/STACK/VDSO/VSYSCALL. But if it
 * is none of these, then it is treated as an index into the 'mappings_t maps[]'
 * array.
 */
ElfW(Off) get_internal_sh_offset(elfdesc_t *elfdesc, memdesc_t *memdesc, int type)
{
#define HEAP 0
#define STACK 1
#define VDSO 2
#define VSYSCALL 3

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
                                                if (phdr[j].p_vaddr == maps[i].base)
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

/*
 * XXX this gets set by build_section_headers()
 * ugly way to do this and at last minute.
 */
static int text_shdr_index;

static int build_local_symtab_and_finalize(const char *outfile, handle_t *handle)
{
	struct fde_func_data *fndata, *fdp;
        int fncount, fd;
        struct stat st;
	uint8_t *mem;
	ElfW(Ehdr) *ehdr;
	ElfW(Shdr) *shdr;
	int i;
	char *StringTable;
	char *strtab = heapAlloc(8192 * 32);

        fncount = get_all_functions(outfile, &fndata);
 	if (fncount < 0)
		fncount = 0;             	
	
#if DEBUG
	log_msg(__LINE__, "Found %d local functions from .eh_frame\n", fncount);
#endif
        
	ElfW(Sym) *symtab = (ElfW(Sym) *)heapAlloc(fncount * sizeof(ElfW(Sym)));
        fdp = (struct fde_func_data *)fndata; 
        char *sname;
        int symstroff = 0;
        int symcount = fncount;
        int dsymcount = 0;
        
        for (i = 0; i < fncount; i++) {
                symtab[i].st_value = fdp[i].addr;
                symtab[i].st_size = fdp[i].size;
                symtab[i].st_info = (((STB_GLOBAL) << 4) + ((STT_FUNC) & 0xf));
                symtab[i].st_other = 0;
                symtab[i].st_shndx = text_shdr_index;
                symtab[i].st_name = symstroff;
                sname = xfmtstrdup("sub_%lx", fdp[i].addr);
                strcpy(&strtab[symstroff], sname);
                symstroff += strlen(sname) + 1;
                free(sname);    
                
        }
 	 /*
         * We append symbol table sections last 
         */
        if ((fd = open(outfile, O_RDWR)) < 0) {
                log_msg(__LINE__, "open %s", strerror(errno));
                exit(-1);
        }

        if (fstat(fd, &st) < 0) {
                log_msg(__LINE__, "fstat %s", strerror(errno));
                exit(-1);
        }

        mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if (mem == MAP_FAILED) {
                log_msg(__LINE__, "mmap %s", strerror(errno));
                exit(-1);
        }
        ehdr = (ElfW(Ehdr) *)mem;
        shdr = (ElfW(Shdr) *)&mem[ehdr->e_shoff];

        if (lseek(fd, 0, SEEK_END) < 0) {
                log_msg(__LINE__, "lseek %s", strerror(errno));
                exit(-1);
        }
	
        uint64_t symtab_offset = lseek(fd, 0, SEEK_CUR);
        for (i = 0; i < symcount; i++) {
                if( write(fd, (char *)&symtab[i], sizeof(ElfW(Sym))) == -1 ) {
                    log_msg(__LINE__, "write %s", strerror(errno));
                    exit(-1);
                }
        }
      	StringTable = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset];
        /* Write section hdr string table */
        uint64_t stloff = lseek(fd, 0, SEEK_CUR);
        if( write(fd, strtab, symstroff) == -1) {
            log_msg(__LINE__, "write %s", strerror(errno));
            exit(-1);
        }
        shdr = (ElfW(Shdr) *)(mem + ehdr->e_shoff);
	
        for (i = 0; i < ehdr->e_shnum; i++) {
                if (!strcmp(&StringTable[shdr[i].sh_name], ".symtab")) {
                        shdr[i].sh_offset = symtab_offset;
                        shdr[i].sh_size = sizeof(ElfW(Sym)) * fncount;
                } else
                if (!strcmp(&StringTable[shdr[i].sh_name], ".strtab")) {
                        shdr[i].sh_offset = stloff;
                        shdr[i].sh_size = symstroff;
                } else
                if (!strcmp(&StringTable[shdr[i].sh_name], ".dynsym")) 
                        dsymcount = shdr[i].sh_size / sizeof(ElfW(Sym));
                        
        }
	  /*
         * We resize the global offset table now that we know how many dynamic
         * symbols there are. The GOT has the first 3 entries reserved (Which is sizeof(long) * 3)
         * plus the size of dsymcount longwords.
         */
        for (i = 0; i < ehdr->e_shnum; i++) {
                if (!strcmp(&StringTable[shdr[i].sh_name], ".got.plt")) {
                        shdr[i].sh_size = (dsymcount * sizeof(ElfW(Addr))) + (3 * sizeof(ElfW(Addr)));
                        break;
                }
        }
        
	free(strtab);
        msync(mem, st.st_size, MS_SYNC);
        munmap(mem, st.st_size);
        close(fd);

	return 0;
}

static int build_section_headers(int fd, const char *outfile, handle_t *handle, ecfs_file_t *ecfs_file)
{
	elfdesc_t *elfdesc = handle->elfdesc;
        memdesc_t *memdesc = handle->memdesc;
        notedesc_t *notedesc = handle->notedesc;
        struct section_meta *smeta = &handle->smeta;
	ElfW(Shdr) *shdr = heapAlloc(sizeof(ElfW(Shdr)) * MAX_SHDR_COUNT);
        char *StringTable = (char *)heapAlloc(MAX_SHDR_COUNT * 64);
	struct stat st;
        unsigned int stoffset = 0;
        int scount = 0, dynsym_index;
	int i; 

	/*
	 * Get the offset of where the shdrs are being written
	 */
	loff_t e_shoff = lseek(fd, 0, SEEK_CUR);
	
	shdr[scount].sh_type = SHT_NULL;
        shdr[scount].sh_offset = 0;
        shdr[scount].sh_addr = 0;
        shdr[scount].sh_flags = 0;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_entsize = 0;
        shdr[scount].sh_size = 0;
        shdr[scount].sh_addralign = 0;
        shdr[scount].sh_name = 0;
        strcpy(&StringTable[stoffset], "");
        stoffset += 1;
        scount++;

 	/*
         * .interp
         */
        shdr[scount].sh_type = SHT_PROGBITS;
        shdr[scount].sh_offset = elfdesc->interpOffset;
        shdr[scount].sh_addr = elfdesc->interpVaddr;
        shdr[scount].sh_flags = SHF_ALLOC;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = 0;
        shdr[scount].sh_size = elfdesc->interpSize;
        shdr[scount].sh_addralign = 1;
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".interp");
        stoffset += strlen(".interp") + 1;
        scount++;

	
	 /*
         *.note
         */
	
        shdr[scount].sh_type = SHT_NOTE;
        shdr[scount].sh_offset = elfdesc->noteOffset;
        shdr[scount].sh_addr = elfdesc->noteVaddr;
        shdr[scount].sh_flags = SHF_ALLOC;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = 0;
        shdr[scount].sh_size = elfdesc->noteSize;
        shdr[scount].sh_addralign = 4;
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".note");
        stoffset += strlen(".note") + 1;
        scount++;
	
        /*
         * .hash
         */
        shdr[scount].sh_type = SHT_GNU_HASH; // use SHT_HASH?
        shdr[scount].sh_offset = smeta->hashOff; 
        shdr[scount].sh_addr = smeta->hashVaddr;
        shdr[scount].sh_flags = SHF_ALLOC;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = 0;
        shdr[scount].sh_size = global_hacks.hash_size <= 0 ? UNKNOWN_SHDR_SIZE : global_hacks.hash_size;
        shdr[scount].sh_addralign = 4;
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".hash");
        stoffset += strlen(".hash") + 1;
        scount++;
	
	 /*
         * .dynsym
         */
	dynsym_index = scount;
        shdr[scount].sh_type = SHT_DYNSYM;
        shdr[scount].sh_offset = smeta->dsymOff;
        shdr[scount].sh_addr = smeta->dsymVaddr;
        shdr[scount].sh_flags = SHF_ALLOC;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = scount + 1;
        shdr[scount].sh_entsize = sizeof(ElfW(Sym));
        shdr[scount].sh_size = smeta->dstrOff - smeta->dsymOff;
        shdr[scount].sh_addralign = sizeof(long);
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".dynsym");
        stoffset += strlen(".dynsym") + 1;
        scount++;

        /*
         * .dynstr
         */
        shdr[scount].sh_type = SHT_STRTAB;
        shdr[scount].sh_offset = smeta->dstrOff;
        shdr[scount].sh_addr = smeta->dstrVaddr;
        shdr[scount].sh_flags = SHF_ALLOC;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = sizeof(ElfW(Sym));
        shdr[scount].sh_size = smeta->strSiz;
        shdr[scount].sh_addralign = 1;
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".dynstr");
        stoffset += strlen(".dynstr") + 1;
        scount++;
	
	/*
         * rela.dyn
         */
        shdr[scount].sh_type = (__ELF_NATIVE_CLASS == 64) ? SHT_RELA : SHT_REL;
        shdr[scount].sh_offset = (__ELF_NATIVE_CLASS == 64) ? smeta->relaOff : smeta->relOff;
	shdr[scount].sh_addr = (__ELF_NATIVE_CLASS == 64) ? smeta->relaVaddr : smeta->relVaddr;
        shdr[scount].sh_flags = SHF_ALLOC;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = dynsym_index;
        shdr[scount].sh_entsize = (__ELF_NATIVE_CLASS == 64) ? sizeof(Elf64_Rela) : sizeof(Elf32_Rel);
        shdr[scount].sh_size = global_hacks.rela_size <= 0 ? UNKNOWN_SHDR_SIZE : global_hacks.rela_size;
        shdr[scount].sh_addralign = sizeof(long); 
        shdr[scount].sh_name = stoffset;
        if (__ELF_NATIVE_CLASS == 64) {
                strcpy(&StringTable[stoffset], ".rela.dyn");
                stoffset += strlen(".rela.dyn") + 1;
        } else {
                strcpy(&StringTable[stoffset], ".rel.dyn");
                stoffset += strlen(".rel.dyn") + 1;
        }
        scount++;
	
	/*
	 * rela.plt
	 */
	shdr[scount].sh_type = (__ELF_NATIVE_CLASS == 64) ? SHT_RELA : SHT_REL;
	log_msg(__LINE__, "assigning rela.plt offset: %lx\n", smeta->plt_relaOff);
        shdr[scount].sh_offset = (__ELF_NATIVE_CLASS == 64) ? smeta->plt_relaOff : smeta->plt_relOff;
        shdr[scount].sh_addr = (__ELF_NATIVE_CLASS == 64) ? smeta->plt_relaVaddr : smeta->plt_relVaddr;
        shdr[scount].sh_flags = SHF_ALLOC;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = dynsym_index;
        shdr[scount].sh_entsize = (__ELF_NATIVE_CLASS == 64) ? sizeof(Elf64_Rela) : sizeof(Elf32_Rel);
        shdr[scount].sh_size = global_hacks.plt_rela_size <= 0 ? UNKNOWN_SHDR_SIZE : global_hacks.plt_rela_size;
        shdr[scount].sh_addralign = sizeof(long);
        shdr[scount].sh_name = stoffset;
        if (__ELF_NATIVE_CLASS == 64) {
                strcpy(&StringTable[stoffset], ".rela.plt");
                stoffset += strlen(".rela.plt") + 1;
        } else {
                strcpy(&StringTable[stoffset], ".rel.plt");
                stoffset += strlen(".rel.plt") + 1;
        }
        scount++;


        /*
         * .init
         */
        shdr[scount].sh_type = SHT_PROGBITS;
        shdr[scount].sh_offset = smeta->initOff;
        shdr[scount].sh_addr = smeta->initVaddr;
        shdr[scount].sh_flags = SHF_ALLOC|SHF_EXECINSTR;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = 0;
        shdr[scount].sh_size = global_hacks.init_size <= 0 ? UNKNOWN_SHDR_SIZE : global_hacks.init_size;
        shdr[scount].sh_addralign = sizeof(long);
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".init");
        stoffset += strlen(".init") + 1;
        scount++;
	
	/*
	 * .plt
	 */
	shdr[scount].sh_type = SHT_PROGBITS;
	shdr[scount].sh_offset = smeta->initOff + (global_hacks.init_size <= 0 ? UNKNOWN_SHDR_SIZE : global_hacks.init_size);
	/* NOTE: plt has an align of 16, and needs to be aligned to that in the address, which sometimes leaves space between
	 * the end of .init and the beggining of plt. So we handle that alignment by increasing the sh_offset in an aligned
	 * way.
	 */
	shdr[scount].sh_offset += 
	((smeta->initVaddr + (global_hacks.init_size <= 0 ? UNKNOWN_SHDR_SIZE : global_hacks.init_size) + 16) & ~15) - 
	(smeta->initVaddr + (global_hacks.init_size <= 0 ? UNKNOWN_SHDR_SIZE : global_hacks.init_size));
	
	shdr[scount].sh_addr = global_hacks.plt_vaddr;
	shdr[scount].sh_flags = SHF_ALLOC|SHF_EXECINSTR;
	shdr[scount].sh_info = 0;
	shdr[scount].sh_link = 0;
	shdr[scount].sh_entsize = 16;
	shdr[scount].sh_size = global_hacks.plt_size <= 0 ? UNKNOWN_SHDR_SIZE : global_hacks.plt_size;
	shdr[scount].sh_addralign = 16;
	shdr[scount].sh_name = stoffset;
	strcpy(&StringTable[stoffset], ".plt");
	stoffset += strlen(".plt") + 1;
	scount++;

	 /*
         * .text
         */
	
        text_shdr_index = scount;
        shdr[scount].sh_type = SHT_PROGBITS;
        shdr[scount].sh_offset = elfdesc->textOffset;
        shdr[scount].sh_addr = elfdesc->textVaddr;
        shdr[scount].sh_flags = SHF_ALLOC|SHF_EXECINSTR;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = 0;
        shdr[scount].sh_size = elfdesc->textSize;
        shdr[scount].sh_addralign = 16;
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".text");
        stoffset += strlen(".text") + 1;
        scount++;

        
        /*
         * .fini
         */
        shdr[scount].sh_type = SHT_PROGBITS;
        shdr[scount].sh_offset = smeta->finiOff;
        shdr[scount].sh_addr = smeta->finiVaddr;
        shdr[scount].sh_flags = SHF_ALLOC|SHF_EXECINSTR;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = 0;
        shdr[scount].sh_size = global_hacks.fini_size <= 0 ? UNKNOWN_SHDR_SIZE : global_hacks.fini_size;
        shdr[scount].sh_addralign = 16;
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".fini");
        stoffset += strlen(".fini") + 1;
        scount++;

	/*
         * .eh_frame_hdr
         */
        shdr[scount].sh_type = SHT_PROGBITS;
        shdr[scount].sh_offset = elfdesc->ehframeOffset;
        shdr[scount].sh_addr = elfdesc->ehframe_Vaddr;    
        shdr[scount].sh_flags = SHF_ALLOC|SHF_EXECINSTR;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = 0;
        shdr[scount].sh_size = elfdesc->ehframe_Size;
        shdr[scount].sh_addralign = 4;
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".eh_frame_hdr");
        stoffset += strlen(".eh_frame_hdr") + 1;
        scount++;
        
        /*
         * .eh_frame
         */
        shdr[scount].sh_type = SHT_PROGBITS;
        
	// XXX workaround for an alignment bug where eh_frame has 4 bytes of zeroes
	// that should not be there at the beggining
	shdr[scount].sh_offset = elfdesc->ehframeOffset + elfdesc->ehframe_Size;
        if (*(uint32_t *)&elfdesc->mem[shdr[scount].sh_offset] == (uint32_t)0x00000000) {
		shdr[scount].sh_offset += 4;
		global_hacks.eh_frame_offset_workaround = 1; // XXX ugly hack
	}
	shdr[scount].sh_addr = elfdesc->ehframe_Vaddr + elfdesc->ehframe_Size;
        shdr[scount].sh_flags = SHF_ALLOC|SHF_EXECINSTR;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = 0;
        size_t ehsz = (ElfW(Off))((elfdesc->ehframe_Vaddr + elfdesc->ehframe_Size) - elfdesc->textVaddr);
        shdr[scount].sh_size = global_hacks.ehframe_size <= 0 ? ehsz : global_hacks.ehframe_size;
	shdr[scount].sh_addralign = 8;
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".eh_frame");
        stoffset += strlen(".eh_frame") + 1;
        scount++;

	 /*
         * .dynamic 
         */
        shdr[scount].sh_type = SHT_DYNAMIC;
        shdr[scount].sh_offset = elfdesc->dynOffset;
        shdr[scount].sh_addr = elfdesc->dynVaddr;
        shdr[scount].sh_flags = SHF_ALLOC|SHF_WRITE;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = (__ELF_NATIVE_CLASS == 64) ? 16 : 8;
        shdr[scount].sh_size = elfdesc->dynSize;
        shdr[scount].sh_addralign = sizeof(long);
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".dynamic");
        stoffset += strlen(".dynamic") + 1;
        scount++;

        /*
         * .got.plt
         */
        shdr[scount].sh_type = SHT_PROGBITS;
        shdr[scount].sh_offset = smeta->gotOff;
        shdr[scount].sh_addr = smeta->gotVaddr;
        shdr[scount].sh_flags = SHF_ALLOC|SHF_WRITE;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = sizeof(long);
	shdr[scount].sh_size = global_hacks.got_size <= 0 ? UNKNOWN_SHDR_SIZE : global_hacks.got_size;
        shdr[scount].sh_addralign = sizeof(long);
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".got.plt");
        stoffset += strlen(".got.plt") + 1;
        scount++;
	
	/*
	 * .data
         */
        shdr[scount].sh_type = SHT_PROGBITS;
        shdr[scount].sh_offset = elfdesc->dataOffset;
        shdr[scount].sh_addr = elfdesc->dataVaddr;
        shdr[scount].sh_flags = SHF_ALLOC|SHF_WRITE;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = 0;
        shdr[scount].sh_size = elfdesc->dataSize;
        shdr[scount].sh_addralign = sizeof(long);
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".data");
        stoffset += strlen(".data") + 1;
        scount++;

        /*
         * .bss
         */
        shdr[scount].sh_type = SHT_PROGBITS; // we change this to progbits cuz we want to be able to see data
        shdr[scount].sh_offset = elfdesc->bssOffset;
        shdr[scount].sh_addr = elfdesc->bssVaddr;
        shdr[scount].sh_flags = SHF_ALLOC|SHF_WRITE;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = 0;
        shdr[scount].sh_size = elfdesc->bssSize;
        shdr[scount].sh_addralign = sizeof(long);
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".bss");
        stoffset += strlen(".bss") + 1;
        scount++;

        /*
         * .heap
         */
        shdr[scount].sh_type = SHT_PROGBITS; // we change this to progbits cuz we want to be able to see data
        shdr[scount].sh_offset = get_internal_sh_offset(elfdesc, memdesc, HEAP);
        shdr[scount].sh_addr = memdesc->heap.base;
        shdr[scount].sh_flags = SHF_ALLOC|SHF_WRITE;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = 0;
        shdr[scount].sh_size = memdesc->heap.size;
        shdr[scount].sh_addralign = sizeof(long);
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".heap");
        stoffset += strlen(".heap") + 1;
        scount++;
	
	/*
	 * This next part is a loop that writes out all of the
	 * section headers for the shared libraries. libc.so.text,
	 * libc.so.data, .libc.so.relro, etc. (approx 3 mappings/sections for each lib)
	 */
	int data_count;
	char *str = NULL;
	for (data_count = 0, i = 0; i < notedesc->lm_files->libcount; i++) {
		shdr[scount].sh_type = notedesc->lm_files->libs[i].injected ? SHT_INJECTED : SHT_SHLIB;
		shdr[scount].sh_offset = notedesc->lm_files->libs[i].offset;
		shdr[scount].sh_addr = notedesc->lm_files->libs[i].addr;
		shdr[scount].sh_flags = SHF_ALLOC;
		shdr[scount].sh_info = 0;
		shdr[scount].sh_link = 0;
		shdr[scount].sh_entsize = 0;
		shdr[scount].sh_size = notedesc->lm_files->libs[i].size;
		shdr[scount].sh_addralign = 8;
		shdr[scount].sh_name = stoffset;
		switch(notedesc->lm_files->libs[i].flags) {
			case PF_R|PF_X:
				/* .text of library; i.e libc.so.text */
				str = xfmtstrdup("%s.text", notedesc->lm_files->libs[i].name);
				break;
			case PF_R|PF_W:
				str = xfmtstrdup("%s.data.%d", notedesc->lm_files->libs[i].name, data_count++);
				break;
			case PF_R:
				str = xfmtstrdup("%s.relro", notedesc->lm_files->libs[i].name);
				break;
			default:
				str = xfmtstrdup("%s.undef", notedesc->lm_files->libs[i].name);
				break;
		}
		strcpy(&StringTable[stoffset], str);
		stoffset += strlen(str) + 1;
		scount += 1;
		xfree(str);
	}
	
	/*
	 * .prstatus
	 */
	shdr[scount].sh_type = SHT_PROGBITS;
	shdr[scount].sh_offset = ecfs_file->prstatus_offset;
	shdr[scount].sh_addr = 0;
	shdr[scount].sh_flags = 0;
	shdr[scount].sh_info = 0;
	shdr[scount].sh_link = 0;
	shdr[scount].sh_entsize = sizeof(struct elf_prstatus);
	shdr[scount].sh_size = ecfs_file->prstatus_size;
	shdr[scount].sh_addralign = 4;
	shdr[scount].sh_name = stoffset;
	strcpy(&StringTable[stoffset], ".prstatus");
	stoffset += strlen(".prstatus") + 1;
	scount++;
	
	/*
	 * .fd_info
	 */
      	shdr[scount].sh_type = SHT_PROGBITS;
        shdr[scount].sh_offset = ecfs_file->fdinfo_offset;
        shdr[scount].sh_addr = 0;
        shdr[scount].sh_flags = 0;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = sizeof(fd_info_t);
        shdr[scount].sh_size = ecfs_file->fdinfo_size;
        shdr[scount].sh_addralign = 4;
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".fdinfo");
        stoffset += strlen(".fdinfo") + 1;
        scount++;

	/*
	 * siginfo_t
	 */
	shdr[scount].sh_type = SHT_PROGBITS;
        shdr[scount].sh_offset = ecfs_file->siginfo_offset;
        shdr[scount].sh_addr = 0;
        shdr[scount].sh_flags = 0;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = sizeof(siginfo_t);
        shdr[scount].sh_size = ecfs_file->siginfo_size;
        shdr[scount].sh_addralign = 4;
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".siginfo");
        stoffset += strlen(".siginfo") + 1;
        scount++;

	/*
	 * auxv
	 */
   	shdr[scount].sh_type = SHT_PROGBITS;
        shdr[scount].sh_offset = ecfs_file->auxv_offset;
        shdr[scount].sh_addr = 0;
        shdr[scount].sh_flags = 0;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = 8;
        shdr[scount].sh_size = ecfs_file->auxv_size;
        shdr[scount].sh_addralign = 8;
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".auxvector");
        stoffset += strlen(".auxvector") + 1;
        scount++;

	/*
	 * .exepath
	 */
	shdr[scount].sh_type = SHT_PROGBITS;
	shdr[scount].sh_offset = ecfs_file->exepath_offset;
	shdr[scount].sh_addr = 0;
        shdr[scount].sh_flags = 0;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = 8;
        shdr[scount].sh_size = ecfs_file->exepath_size;
        shdr[scount].sh_addralign = 1;
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".exepath");
        stoffset += strlen(".exepath") + 1;
        scount++;

	/*
	 * .personality
	 */
	shdr[scount].sh_type = SHT_PROGBITS;
        shdr[scount].sh_offset = ecfs_file->personality_offset;
        shdr[scount].sh_addr = 0;
        shdr[scount].sh_flags = 0;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = sizeof(elf_stat_t);
        shdr[scount].sh_size = ecfs_file->personality_size;
        shdr[scount].sh_addralign = 1;
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".personality");
        stoffset += strlen(".personality") + 1;
        scount++;

	/*
 	 * .arglist
	 */
	shdr[scount].sh_type = SHT_PROGBITS;
	shdr[scount].sh_offset = ecfs_file->arglist_offset;
	shdr[scount].sh_addr = 0;
	shdr[scount].sh_flags = 0;
	shdr[scount].sh_info = 0;
	shdr[scount].sh_link = 0;
	shdr[scount].sh_entsize = 1;
	shdr[scount].sh_size = ecfs_file->arglist_size;
	shdr[scount].sh_addralign = 1;
	shdr[scount].sh_name = stoffset;
	strcpy(&StringTable[stoffset], ".arglist");
	stoffset += strlen(".arglist") + 1;
	scount++;

	/*
         * .stack
         */
        shdr[scount].sh_type = SHT_PROGBITS; // we change this to progbits cuz we want to be able to see data
        shdr[scount].sh_offset = get_internal_sh_offset(elfdesc, memdesc, STACK);
        shdr[scount].sh_addr = memdesc->stack.base;
        shdr[scount].sh_flags = SHF_ALLOC|SHF_WRITE;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = 0;
        shdr[scount].sh_size = memdesc->stack.size;
        shdr[scount].sh_addralign = sizeof(long);
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".stack");
        stoffset += strlen(".stack") + 1;
        scount++;

        /*
         * .vdso
         */
        shdr[scount].sh_type = SHT_PROGBITS; // we change this to progbits cuz we want to be able to see data
        shdr[scount].sh_offset = get_internal_sh_offset(elfdesc, memdesc, VDSO);
        shdr[scount].sh_addr = memdesc->vdso.base;
        shdr[scount].sh_flags = SHF_ALLOC|SHF_WRITE;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = 0;
        shdr[scount].sh_size = memdesc->vdso.size;
        shdr[scount].sh_addralign = sizeof(long);
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".vdso");
        stoffset += strlen(".vdso") + 1;
        scount++;

        /*
         * .vsyscall
         */
        shdr[scount].sh_type = SHT_PROGBITS; // we change this to progbits cuz we want to be able to see data
        shdr[scount].sh_offset = get_internal_sh_offset(elfdesc, memdesc, VSYSCALL);
        shdr[scount].sh_addr = memdesc->vsyscall.base;
        shdr[scount].sh_flags = SHF_ALLOC|SHF_WRITE;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = 0;
        shdr[scount].sh_size = memdesc->vsyscall.size;
        shdr[scount].sh_addralign = sizeof(long);
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".vsyscall");
        stoffset += strlen(".vsyscall") + 1;
        scount++;

	 /*
         * .symtab
         */
        shdr[scount].sh_type = SHT_SYMTAB;
        shdr[scount].sh_offset = 0;
        shdr[scount].sh_addr = 0;
        shdr[scount].sh_flags = 0;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = scount + 1;
        shdr[scount].sh_entsize = sizeof(ElfW(Sym));
        shdr[scount].sh_size = 0;
        shdr[scount].sh_addralign = 4;
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".symtab");
        stoffset += strlen(".symtab") + 1;
        scount++;

        /*
         * .strtab
         */
        shdr[scount].sh_type = SHT_STRTAB;
        shdr[scount].sh_offset = 0;
        shdr[scount].sh_addr = 0;
        shdr[scount].sh_flags = 0;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = 0;
        shdr[scount].sh_size = 0;
        shdr[scount].sh_addralign = 1;
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".strtab");
        stoffset += strlen(".strtab") + 1;
        scount++;

        /*
         * .shstrtab
         */
        shdr[scount].sh_type = SHT_STRTAB;
        shdr[scount].sh_offset = e_shoff + (sizeof(ElfW(Shdr)) * (scount  + 1));
        shdr[scount].sh_addr = 0;
        shdr[scount].sh_flags = 0;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = 0;
        shdr[scount].sh_size = stoffset + strlen(".shstrtab") + 1; 
        shdr[scount].sh_addralign = 1;
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".shstrtab");
        stoffset += strlen(".shstrtab") + 1;
        scount++;

	 /* We will add the actual sections for .symtab and .strtab
         * after we write out the current section headers first and
         * use them to retrieve symtab info from eh_frame
         */
	const char *filepath = outfile;
        int e_shstrndx = scount - 1;
        for (i = 0; i < scount; i++) 
                if (write(fd, (char *)&shdr[i], sizeof(ElfW(Shdr))) < 0)
			log_msg(__LINE__, "write %s", strerror(errno));
        
        ssize_t b = write(fd, (char *)StringTable, stoffset);
	if (b < 0) {
		log_msg(__LINE__, "write %s", strerror(errno));
		exit(-1);
	}
        fsync(fd);
        close(fd);
        
	fd = xopen(filepath, O_RDWR);
        
        if (fstat(fd, &st) < 0) {
                log_msg(__LINE__, "fstat %s", strerror(errno));
                exit(-1);
        }

        uint8_t *mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if (mem == MAP_FAILED) {
                log_msg(__LINE__, "mmap %s", strerror(errno));
                exit(-1);
        }

        ElfW(Ehdr *)ehdr = (ElfW(Ehdr) *)mem;
        ehdr->e_entry = memdesc->o_entry; // this is unsigned
	ehdr->e_shoff = e_shoff;
        ehdr->e_shstrndx = e_shstrndx;
	ehdr->e_shentsize = sizeof(ElfW(Shdr));
        ehdr->e_shnum = scount;
        ehdr->e_type = ET_NONE;
	
	msync(mem, st.st_size, MS_SYNC);
        munmap(mem, st.st_size);

        close(fd);
	free(shdr);
	free(StringTable);

	return scount;
}


int core2ecfs(const char *outfile, handle_t *handle)
{
	struct stat st;
	int i;
	elfdesc_t *elfdesc = handle->elfdesc;
	memdesc_t *memdesc = handle->memdesc;
	notedesc_t *notedesc = handle->notedesc;
	ElfW(Ehdr) *ehdr = elfdesc->ehdr;
	uint8_t *mem = elfdesc->mem;
	ecfs_file_t *ecfs_file = heapAlloc(sizeof(ecfs_file_t));
	int fd, ret;

	fd = xopen(outfile, O_CREAT|O_TRUNC|O_RDWR);
	chmod(outfile, S_IRWXU|S_IRWXG);
	stat(elfdesc->path, &st); // stat the corefile
	
	ecfs_file->prstatus_offset = st.st_size;
	ecfs_file->prstatus_size = notedesc->thread_count * sizeof(struct elf_prstatus);
	ecfs_file->fdinfo_offset = ecfs_file->prstatus_offset + notedesc->thread_count * sizeof(struct elf_prstatus);
	ecfs_file->fdinfo_size = memdesc->fdinfo_size;
	ecfs_file->siginfo_offset = ecfs_file->fdinfo_offset + ecfs_file->fdinfo_size;
	ecfs_file->siginfo_size = sizeof(siginfo_t);
	ecfs_file->auxv_offset = ecfs_file->siginfo_offset + ecfs_file->siginfo_size;
	ecfs_file->auxv_size = notedesc->auxv_size;
	ecfs_file->exepath_offset = ecfs_file->auxv_offset + ecfs_file->auxv_size;
	ecfs_file->exepath_size = strlen(memdesc->exe_path) + 1;
	ecfs_file->personality_offset = ecfs_file->exepath_offset + ecfs_file->exepath_size;
	ecfs_file->personality_size = sizeof(elf_stat_t);
	ecfs_file->arglist_offset = ecfs_file->personality_offset + ecfs_file->personality_size;
	ecfs_file->arglist_size = ELF_PRARGSZ;
	ecfs_file->stb_offset = ecfs_file->arglist_offset + ecfs_file->arglist_size;
	
	/*
	 * write original body of core file
	 */	
	if (write(fd, elfdesc->mem, st.st_size) != st.st_size) {
		log_msg(__LINE__, "write %s", strerror(errno));
		exit(-1);
	}

	/*
	 * write prstatus structs
	 */
	if( write(fd, notedesc->prstatus, sizeof(struct elf_prstatus)) == -1 ) {
            log_msg(__LINE__, "write %s", strerror(errno));
            exit(-1);
        }
	for (i = 1; i < notedesc->thread_count; i++) {
		if( write(fd, notedesc->thread_core_info[i].prstatus, sizeof(struct elf_prstatus)) == -1) {
                    log_msg(__LINE__, "write %s", strerror(errno));
                    exit(-1);
                }
        }
	
	/*
	 * write fdinfo structs
	 */
	if( write(fd, memdesc->fdinfo, ecfs_file->fdinfo_size) == -1) {
            log_msg(__LINE__, "write %s", strerror(errno));
            exit(-1);
        }

	/*
	 * write siginfo_t struct
	 */
	if( write(fd, notedesc->siginfo, sizeof(siginfo_t)) == -1) {
            log_msg(__LINE__, "write %s", strerror(errno));
            exit(-1);
        }
	
	/*
 	 * write auxv data
	 */
	if( write(fd, notedesc->auxv, notedesc->auxv_size) == -1) {
            log_msg(__LINE__, "write %s", strerror(errno));
            exit(-1);
        }
	
	/*
	 * write exepath string
	 */
	if( write(fd, memdesc->exe_path, strlen(memdesc->exe_path) + 1) ) {
            log_msg(__LINE__, "write %s", strerror(errno));
            exit(-1);
        }

	/*
	 * write ELF personality
	 */
	build_elf_stats(handle);
	if( write(fd, &handle->elfstat, sizeof(elf_stat_t)) == -1) { 
            log_msg(__LINE__, "write %s", strerror(errno));
            exit(-1);
        }
	
	/*
	 * write .arglist section data
	 */
	if( write(fd, handle->arglist, ELF_PRARGSZ) == -1) {
            log_msg(__LINE__, "write %s", strerror(errno));
            exit(-1);
        }

	/*
	 * Build section header table
	 */
	int shnum = build_section_headers(fd, outfile, handle, ecfs_file);
	
	close(fd);
	
	/*
	 * Now remap our new file to make further edits.
	 */
	fd = xopen(outfile, O_RDWR);
	stat(outfile, &st);
	mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		log_msg(__LINE__, "mmap %s", strerror(errno));
		return -1;
	}

	ehdr = (ElfW(Ehdr) *)mem;
	ehdr->e_shoff = ecfs_file->stb_offset;
	ehdr->e_shnum = shnum;
	munmap(mem, st.st_size);
	close(fd);

	/*
	 * Now we remap our file one last time to fill in the .symtab
	 * section with our .eh_frame based symtab reconstruction
	 * technique which is a big part of the draw to ECFS format.
	 */
	
	ret = build_local_symtab_and_finalize(outfile, handle);
	if (ret < 0) 
		log_msg(__LINE__, "local symtab reconstruction failed");

	/* Open just once more to fill in the dynamic symbol table values */


	return 0;
}
	
/*
 * Get original entry point
 */
ElfW(Addr) get_original_ep(int pid)
{
	struct stat st;
	char *path = xfmtstrdup("/proc/%d/exe", pid);
	int fd = xopen(path, O_RDONLY);
	xfree(path);
	xfstat(fd, &st);
	uint8_t *mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		log_msg(__LINE__, "mmap");
		return -1;
	}
	ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)mem;
	return ehdr->e_entry;
}

void fill_in_pstatus(memdesc_t *memdesc, notedesc_t *notedesc)
{
                memdesc->task.uid = notedesc->psinfo->pr_uid;
                memdesc->task.gid = notedesc->psinfo->pr_gid;
                memdesc->task.ppid = notedesc->psinfo->pr_ppid;
                memdesc->task.exit_signal = notedesc->prstatus->pr_info.si_signo;
                memdesc->path = memdesc->comm = notedesc->psinfo->pr_fname;
}

void build_elf_stats(handle_t *handle)
{
	handle->elfstat.personality = 0;

	if (handle->elfdesc->dynlinked == 0) {
#if DEBUG
		log_msg(__LINE__, "personality of ELF: statically linked");
#endif
		handle->elfstat.personality |= ELF_STATIC;
	}
	if (handle->elfdesc->pie) {
#if DEBUG
		log_msg(__LINE__, "personality of ELF: position independent executable");
#endif
		handle->elfstat.personality |= ELF_PIE;
	}

	if (opts.heuristics) {
#if DEBUG
		log_msg(__LINE__, "personality of ELF: heuristics turned on");
#endif
		handle->elfstat.personality |= ELF_HEURISTICS;
	}
#if DEBUG
	if (!(handle->elfstat.personality & ELF_STATIC))
		log_msg(__LINE__, "personality of ELF: dynamically linked");
#endif
}

void pull_unknown_shdr_addrs(int pid)
{
	global_hacks.plt_vaddr = get_original_shdr_addr(pid, ".plt");
}
/*
 * Notice we read these and store them in global variables
 * this was an after-the-fact hack that is ugly and needs
 * changing.
 */
void pull_unknown_shdr_sizes(int pid)
{
	memset(&global_hacks, 0, sizeof(global_hacks));
	global_hacks.hash_size = get_original_shdr_size(pid, ".gnu.hash");
	global_hacks.rela_size = get_original_shdr_size(pid, ".rela.dyn");
	global_hacks.plt_rela_size = get_original_shdr_size(pid, ".rela.plt");
	global_hacks.init_size = get_original_shdr_size(pid, ".init");
	global_hacks.fini_size = get_original_shdr_size(pid, ".fini");
	global_hacks.got_size = get_original_shdr_size(pid, ".got.plt");
	global_hacks.plt_size = get_original_shdr_size(pid, ".plt");
	global_hacks.ehframe_size = get_original_shdr_size(pid, ".eh_frame");
}

/*
 * XXX This function calls pull_unknown_shdr_ functions
 * to fill up global_hacks structure with information
 * needed for section headers. This is ugly and temporary
 */
void fill_global_hacks(int pid)
{
	pull_unknown_shdr_sizes(pid);
	pull_unknown_shdr_addrs(pid);

}
int main(int argc, char **argv)
{
		
	struct rlimit limit_core = {0L, 0L};
	memdesc_t *memdesc = NULL;
	elfdesc_t *elfdesc = NULL;
	notedesc_t *notedesc = NULL;
	handle_t *handle = alloca(sizeof(handle_t));
	pid_t pid = 0;
	int i, j, ret, c, pie = 0;
	char *corefile = NULL;
	char *outfile = NULL;

	/*
	 * When testing use:
	 * ./ecfs -c corefile -o output.ecfs -p <pid>
	 *
	 * although when having run as automated with core pipes use
	 * the following command within /proc/sys/kernel/core_pattern
	 * ./ecfs -i -p %p -e %e
	 */
	if (argc < 2) {
		fprintf(stdout, "Usage: %s [-i] [-cpoe]\n", argv[0]);
		fprintf(stdout, "- Automated mode to be used with /proc/sys/kernel/core_pattern\n");
		fprintf(stdout, "[-i]	read core file from stdin; output file will be procname.pid\n");
		fprintf(stdout, "\n- Manual mode which allows for specifying existing core files (Debugging mode)\n");
		fprintf(stdout, "[-c]	corefile to be processed\n");
		fprintf(stdout, "[-p]	pid of process (Must respawn a process after it crashes)\n");
		fprintf(stdout, "[-e]	executable path (Supplied by %%e format arg in core_pattern)\n");
		fprintf(stdout, "[-o]	output ecfs file\n\n");
		exit(-1);
	}
	memset(&opts, 0, sizeof(opts));

	while ((c = getopt(argc, argv, "thc:io:p:e:")) != -1) {
		switch(c) {
			case 'c':	
				opts.use_stdin = 0;
				corefile = xstrdup(optarg);
				break;
			case 'i':
				opts.use_stdin = 1;
				break;
			case 'o':
				outfile = xstrdup(optarg);
				break;
			case 'e':
				exename = xstrdup(optarg);
				break;
			case 'p':
				pid = atoi(optarg);
				break;
			case 'h':
				opts.heuristics = 1;
				break;
			case 't':
				opts.text_all = 1;
				break;
			default:
				fprintf(stderr, "Unknown option\n");
				exit(0);
		}
	}
	
	if (opts.use_stdin == 0) {
		if (corefile == NULL) {
			log_msg(__LINE__, "Must specify a corefile with -c");
			exit(0);
		}
		if (pid == 0) {
			log_msg(__LINE__, "Must specify a pid with -p");
			exit(0);
		}
		if (outfile == NULL) {
			log_msg(__LINE__, "Did not specify an output file, defaulting to use 'ecfs.out'");
			outfile = xfmtstrdup("%s/ecfs.out", ECFS_CORE_DIR);		
		}
	}
	
	/*
	 * Don't allow itself to core in the event of a bug.
	 */
	
    	if (setrlimit(RLIMIT_CORE, &limit_core) < 0) {
		log_msg(__LINE__, "setrlimit %s", strerror(errno));
		exit(-1);
	}
	
	/*
	 * Prevents ecfs from coring itself
	 */
	prctl(PR_SET_DUMPABLE, 0);

	if (opts.use_stdin) {
		/*
		 * If we're reading from stdin we are probably waiting for the kernel
		 * to write the corefile to us. Until we have read the core file completely
		 * /proc/$pid/? will remain open to us, so we need to gather whatever we need
		 * from this area now while our process is in a stopped zombie state.
		 */
#if DEBUG
		log_msg(__LINE__, "Using stdin, outfile is:%s", outfile);
#endif
		/*
		 * If we are getting core directly from the kernel then we must
		 * read /proc/<pid>/ before we read the corefile. The process stays
		 * open as long as the corefile hasn't been read yet.
	  	 */
        	if (exename == NULL) {
			log_msg(__LINE__, "Must specify exename of process when using stdin mode; supplied by %%e of core_pattern");
			exit(-1);
		}
		if (pid == 0) {
                        log_msg(__LINE__, "Must specify a pid with -p");
                        exit(0);
                }
                if (outfile == NULL) {
                        log_msg(__LINE__, "Did not specify an output file, defaulting to use 'ecfs.out'");
                        outfile = xfmtstrdup("%s/ecfs.out", ECFS_CORE_DIR);
                }
		
		memdesc = build_proc_metadata(pid, notedesc);
        	if (memdesc == NULL) {
                	log_msg(__LINE__, "Failed to retrieve process metadata");
                	exit(-1);
        	}
		memdesc->task.pid = pid;
		pie = check_for_pie(pid);
		fill_global_hacks(pid);
		//pull_unknown_shdr_sizes(pid); // get size of certain shdrs from original exe
		memdesc->fdinfo_size = get_fd_links(memdesc, &memdesc->fdinfo) * sizeof(fd_info_t);
		memdesc->o_entry = get_original_ep(pid);
		if (opts.text_all)
			create_shlib_text_mappings(memdesc);
	}

#if DEBUG
	if (corefile)
		log_msg(__LINE__, "Loading core file: %s", corefile);
#endif
	switch(opts.use_stdin) {
		case 0:
			/*
			 * load the core file from a file
			 */
			elfdesc = load_core_file((const char *)corefile);
			if (elfdesc == NULL) {
				log_msg(__LINE__, "Failed to parse core file");
				exit(-1);
			}
			break;
		case 1:
			/*
			 * load the core file from stdin
			 */
			elfdesc = load_core_file_stdin();
			break;
	}
	
	/*
	 * Retrieve 'struct elf_prstatus' and other structures
	 * that contain vital information (Such as registers).
	 * These are all stored in the ELF notes area of the
	 * core file.
	 */
	notedesc = (notedesc_t *)parse_notes_area(elfdesc);
	if (notedesc == NULL) {
		log_msg(__LINE__, "Failed to parse ELF notes segment\n");
		exit(-1);
	}
	
	/*
	 * In real scenarios we will be receiving the core dump right as
	 * the kernel creates it and therefore the pid that we get from
	 * prstatus->pr_pid will still be an active pid until we are done
	 * processing the core and grabbing things from /proc. Although in
	 * test scenarios we may want to be able to specify which pid to
	 * use.
	 */
	if (opts.use_stdin == 0) {
		exename = notedesc->psinfo->pr_fname;
		memcpy(handle->arglist, notedesc->psinfo->pr_psargs, ELF_PRARGSZ); 
		pid = pid ? pid : notedesc->prstatus->pr_pid;
		memdesc = build_proc_metadata(pid, notedesc);
        	memdesc->o_entry = get_original_ep(pid); // get original entry point
		if (memdesc == NULL) {
                	log_msg(__LINE__, "Failed to retrieve process metadata");
                	exit(-1);
        	}
		memdesc->task.pid = pid;
		memdesc->fdinfo_size = get_fd_links(memdesc, &memdesc->fdinfo) * sizeof(fd_info_t);
		fill_global_hacks(pid);
		pie = check_for_pie(pid);
	}
	fill_in_pstatus(memdesc, notedesc);
#if DEBUG
	log_msg(__LINE__, "check_for_pie returned %d", pie);
#endif
	if (pie > 0) {
		unsigned long text_base = lookup_text_base(memdesc, notedesc->nt_files);
		if (text_base == 0) {
			log_msg(__LINE__, "Failed to locate text base address");
			goto done;
		}
		unsigned long hint = text_base;
		get_text_phdr_size_with_hint(elfdesc, hint);
	}
	
	/*
	 * XXX the linux kernel only dumps 4096 bytes of any code segment
	 * in order to save space, and this is generally OK since the code
	 * segment isn't suppose to change in memory. Unfortunatley for
 	 * our purposes we want this, so we have to retrieve the text from
	 * /proc/$pid/mem and merge it into our corefile which is a pain
	 * and after we do this, we must re-load the corefile again.
	 * if opts.text_all is enabled we do the same thing for the text images
	 * of every single shared library which becomes our biggest bottleneck
	 * in terms of performance.
	 */
	if (elfdesc->text_memsz > elfdesc->text_filesz) {
		corefile = tmp_corefile == NULL ? corefile : tmp_corefile;
#if DEBUG
		log_msg(__LINE__, "merging text into core");
#endif
		if (merge_exe_text_into_core((const char *)corefile, memdesc) < 0) {
			log_msg(__LINE__, "Failed to merge text into core file");
		}
		
        	elfdesc = reload_core_file(elfdesc);
        	if (elfdesc == NULL) {
        		log_msg(__LINE__, "Failed to parse text-merged core file");	
                	exit(-1);
        	} 
	}
	if (opts.text_all) {
#if DEBUG
		log_msg(__LINE__, "opts.text_all is enabled");
#endif
		/*
		 * opts.text_all is enabled which means that we are going to write
		 * out the entire text segment of each shared library. Whereas by
		 * default (As with regular core files) we only write out the first 4096
		 * bytes of each shared libraries text segment. 
		 */
		corefile = tmp_corefile == NULL ? corefile : tmp_corefile;
		if (merge_shlib_texts_into_core((const char *)corefile, memdesc) < 0) {
			log_msg(__LINE__, "Failed to merge shlib texts into core");
		}
		elfdesc = reload_core_file(elfdesc); // reload after our mods
		if (elfdesc == NULL) {
			log_msg(__LINE__, "Failed to parse shlib text merged core file");
			exit(-1);
		}
	}

	/*
	 * Which mappings are stored in actual phdr segments?
	 */
        for (i = 0; i < elfdesc->ehdr->e_phnum; i++) {
                for (j = 0; j < memdesc->mapcount; j++) 
                        if (memdesc->maps[j].base == (elfdesc->phdr + i)->p_vaddr)
                                memdesc->maps[j].has_pt_load++;
        }
	
	/*
	 * attach to process with ptrace and parse original phdr table
	 * to get more granular segment information.
	 */
#if DEBUG
	log_msg(__LINE__, "parsing original phdr's in memory");
#endif
	if (parse_orig_phdrs(elfdesc, memdesc, notedesc) < 0) {
		log_msg(__LINE__, "Failed to parse program headers in memory");
		exit(-1);
	}
	
	/*
	 * Combine all handles into 1 (Should work this into the code earlier on)
	 */
	handle->elfdesc = elfdesc;
	handle->memdesc = memdesc;
	handle->notedesc = notedesc;
#if DEBUG
	log_msg(__LINE__, "calling xref_phdrs_for_offsets()");
#endif
	/*
	 * Figure out where the offsets to certain parts of the
	 * file are, such as .dynamic, .interp, etc.
	 * in such cases where we got the original info from
	 * the original phdr table. The offsets will be different
	 * since the phdr's are all page aligned in the corefile.
	 */
	xref_phdrs_for_offsets(memdesc, elfdesc);
	

	/*
	 * Out of the parsed NT_FILES get a list of which ones are
	 * shared libraries so we can create shdrs for them.
	 */
#if DEBUG
	log_msg(__LINE__, "calling lookup_lib_maps()");
#endif
	notedesc->lm_files = (struct lib_mappings *)heapAlloc(sizeof(struct lib_mappings));
	lookup_lib_maps(elfdesc, memdesc, notedesc->nt_files, notedesc->lm_files);
	
#if DEBUG
	for (i = 0; i < notedesc->lm_files->libcount; i++)
		log_msg(__LINE__, "libname: %s addr: %lx\n", notedesc->lm_files->libs[i].name, notedesc->lm_files->libs[i].addr);
#endif
	/*
	 * Build elf stats into personality
	 */
#if DEBUG
	log_msg(__LINE__, "build_elf_stats() is being called");
#endif
	build_elf_stats(handle);

	/*
	 * We get a plethora of information about where certain
	 * data and code is from the dynamic segment by parsing
	 * it by D_TAG values.
	 */
#if DEBUG
	log_msg(__LINE__, "calling extract_dyntag_info()");
#endif
	ret = extract_dyntag_info(handle);
	if (ret < 0) {
		log_msg(__LINE__, "Failed to extract dynamic segment information");
		exit(-1);
	}

	/*
	 * Parse the symtab of each shared library and store its
	 * results in linked list. Each node holds a symentry_t vector
	 */
#if DEBUG
	log_msg(__LINE__, "calling fill_dynamic_symtab()");
#endif
	list_t *list_head;
	ret = fill_dynamic_symtab(&list_head, notedesc->lm_files);
	if (ret < 0) 
		log_msg(__LINE__, "Unable to load dynamic symbol table with runtime values");
	
	
	/*
	 * Before we call core2ecfs we need to make a list of which shared libraries
	 * were maliciously injected, so that section headers can be created of type
	 * SHT_INJECTED instead of SHT_SHLIB for those ones.
	 */
#if DEBUG
	log_msg(__LINE__, "calling mark_dll_injection()");
#endif
	 if (!(handle->elfstat.personality & ELF_STATIC))
		if (opts.heuristics)
	 		mark_dll_injection(notedesc, memdesc, elfdesc);

	/*
	 * Convert the core file into an actual ECFS file and write it
	 * to disk.
	 */
#if DEBUG
	log_msg(__LINE__, "calling core2ecfs()");
#endif
	ret = core2ecfs(outfile, handle);
	if (ret < 0) {
		log_msg(__LINE__, "Failed to transform core file '%s' into ecfs", argv[2]);
		exit(-1);
	}
	
	if (opts.use_stdin)
		unlink(elfdesc->path);
	if (tmp_corefile) // incase we had to re-write file and mege in text
		unlink(tmp_corefile);
#if DEBUG
	log_msg(__LINE__, "calling store_dynamic_symvals()");
#endif
	/*
	 * XXX should move into core2ecfs?
	 */
	ret = store_dynamic_symvals(list_head, outfile);
	if (ret < 0) 
		log_msg(__LINE__, "Unable to store runtime values into dynamic symbol table");
	
#if DEBUG
	log_msg(__LINE__, "finished storing symvals");
#endif
done: 
 	if (opts.use_stdin)
         	unlink(elfdesc->path);
        if (tmp_corefile) // incase we had to re-write file and mege in text
                unlink(tmp_corefile);

        return 0;
}




