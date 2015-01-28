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

#include "ecfs.h"

struct opts opts;

typedef struct handle {
	elfdesc_t *elfdesc;
	memdesc_t *memdesc;
	notedesc_t *notedesc;
	struct nt_file_struct *nt_files;
	struct section_meta smeta;
} handle_t;

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
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	ElfW(Nhdr) *nhdr; //notes
	uint8_t *mem;
	struct stat st;
	int i, j, fd;
	
	elfdesc->path = xstrdup(path);

	if ((fd = open(path, O_RDONLY)) < 0) {
		perror("open");
		return NULL;
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		return NULL;
	}

	mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}

	ehdr = (ElfW(Ehdr) *)mem;
	phdr = (ElfW(Phdr) *)&mem[ehdr->e_phoff];
	
	if (ehdr->e_type != ET_CORE) {
		fprintf(stderr, "File %s is not an ELF core file. exiting with failure\n", path);
		return NULL;
	}
	
	/*
	 * Setup notes pointer
	 */
	for (i = 0; i < ehdr->e_phnum; i++)
		if (phdr[i].p_type == PT_NOTE) {
			nhdr = (ElfW(Nhdr) *)&mem[phdr[i].p_offset];
			elfdesc->noteSize = phdr[i].p_filesz;
			break;
		}
	
	elfdesc->ehdr = ehdr;
	elfdesc->phdr = phdr;
	elfdesc->nhdr = nhdr;
	elfdesc->mem = mem;
	elfdesc->size = st.st_size;
	
	return elfdesc;
}


#define RBUF_LEN 4096 * 8

/*
 * This function will read the corefile from stdin
 * then write it to a temporary file which is then read
 * by the load_core_file() function above.
 */
elfdesc_t * load_core_file_stdin(void)
{
	elfdesc_t *elfdesc = (elfdesc_t *)heapAlloc(sizeof(elfdesc_t));
        ElfW(Ehdr) *ehdr;
        ElfW(Phdr) *phdr;
        ElfW(Nhdr) *nhdr; //notes
        uint8_t *mem;
        uint8_t *buf;
	struct stat st;
        ssize_t nread;
	ssize_t bytes, bw;
	int i = 0, j = 0;
	int file, fd;
	
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
			perror("write");
			exit(-1);
		}
		syncfs(file);
	}
	syncfs(file);
	close(file);
	
	return load_core_file(filepath);

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
		printf("%lx  %lx  %lx\n", file_maps->files[i].addr, 
					  file_maps->files[i].addr + file_maps->files[i].size, 
					  file_maps->files[i].pgoff);
		printf("\t%s\n", file_maps->files[i].path);
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
	size_t i, j, len;
	int tc, ret;
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
					notedesc->thread_core_info[tc].prstatus = (struct elf_prstatus *)heapAlloc(notes->n_descsz);
					memcpy(notedesc->thread_core_info[tc].prstatus, desc, notes->n_descsz);
					break;
				case 0:
					notedesc->prstatus = (struct elf_prstatus *)heapAlloc(sizeof(struct elf_prstatus));
					memcpy(notedesc->prstatus, desc, notes->n_descsz);
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
		}
		/*
		 * note entries are always word aligned (4 bytes)
		 */
		len = (notes->n_descsz + notes->n_namesz + sizeof(long) + 3) & ~3;
		notes = ELFNOTE_NEXT(notes);
	}

	return notedesc;
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
		if (!strcmp(memdesc->path, p))
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
                if (!strcmp(memdesc->path, p))
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
                if (!strcmp(memdesc->path, p)) {
			p = strrchr(fmaps->files[i + 1].path, '/') + 1;
			if (!strcmp(memdesc->path, p))
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
                if (!strcmp(memdesc->path, p)) {
                        p = strrchr(fmaps->files[i + 1].path, '/') + 1;
                        if (!strcmp(memdesc->path, p))
                                return fmaps->files[i + 1].size;
                }
        }
        return 0;
}

#define MAX_LIB_LEN 255
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
		p = strrchr(fmaps->files[i].path, '/') + 1;
		if (!strstr(p, ".so"))
			continue;
		for (j = 0; j < strlen(p); j++)
			tmp[j] = p[j];
		tmp[j] = '\0';
		strncpy(lm->libs[lm->libcount].name, tmp, MAX_LIB_LEN - 1);
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
        char mpath[256], buf[256], tmp[256], *p, *q = alloca(32);
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
		if (strstr(tmp, path)) {
                        if (!strstr(tmp, "---p"))
                                maps[lc].filename = xstrdup(strchr(tmp, '/'));
                                maps[lc].elfmap++;
				if (strstr(tmp, "r-xp") || strstr(tmp, "rwxp"))
					maps[lc].textbase++;
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

static int get_fd_links(memdesc_t *memdesc, fd_info_t **fdinfo)
{
	DIR *dp;
	struct dirent *dptr = NULL;
	char tmp[256];
	char *dpath = xfmtstrdup("/proc/%d/fd", memdesc->task.pid);
	*fdinfo = (fd_info_t *)heapAlloc(sizeof(fd_info_t) * 256);
	int fdcount;
 
        for (fdcount = 0, dp = opendir(dpath); dp != NULL;) {
                dptr = readdir(dp);
                if (dptr == NULL) 
                        break;
		snprintf(tmp, sizeof(tmp), "%s/%s", dpath, dptr->d_name); // i.e /proc/pid/fd/3
		readlink(tmp, (*fdinfo)[fdcount].path, MAX_PATH);
		(*fdinfo)[fdcount].fd = atoi(dptr->d_name);
		fdcount++;
	}
	return fdcount;
}

static int get_proc_status(notedesc_t *notedesc, memdesc_t *memdesc)
{


	if (opts.use_stdin == 0) {
		/*
		 * we are not reading from stdin which means we read
		 * the corefile first and can use some of the psinfo
		 * members that we parsed from notes.
		 */
		memdesc->task.uid = notedesc->psinfo->pr_uid;
		memdesc->task.gid = notedesc->psinfo->pr_gid;
		memdesc->task.ppid = notedesc->psinfo->pr_ppid;
		memdesc->task.pid = notedesc->psinfo->pr_pid;
		memdesc->task.exit_signal = notedesc->prstatus->pr_info.si_signo;
		memdesc->path = notedesc->psinfo->pr_fname;
	} // else; we get these values later.

	switch(notedesc->psinfo->pr_sname) {
        	case 'D':
                	memdesc->task.state |= PS_SLEEP_UNINTER;
                        break;
                case 'R':
                        memdesc->task.state |= PS_RUNNING;
                        break;
                case 'S':
                    	memdesc->task.state |= PS_SLEEP_INTER;
                       	break;
                case 'T':
                        memdesc->task.state |= PS_STOPPED;
                        break;
                case 'Z':
                        memdesc->task.state |= PS_DEFUNCT;
                        break;
                default:
                        memdesc->task.state |= PS_UNKNOWN;
                        break;
      	}
	return 0;

}


static int get_map_count(pid_t pid)
{
        FILE *pd;
        char cmd[256], buf[256];
        int lc;
  	      
        snprintf(cmd, sizeof(cmd), "/usr/bin/wc -l /proc/%d/maps", pid);
	if ((pd = popen(cmd, "r")) == NULL)
                return -1;
        fgets(buf, sizeof(buf), pd);
        lc = atoi(buf);
        pclose(pd);
        return lc;
}

char * get_exe_path(int pid)
{
	char *path = xfmtstrdup("/proc/%d/exe", pid);
	char *ret = (char *)heapAlloc(MAX_PATH);
	readlink(path, ret, MAX_PATH);
	free(path);
	return ret;
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
                printf("[!] failed to get mapcount from /proc/%d/maps\n", pid);
                return NULL;
        }
        memdesc->maps = (mappings_t *)heapAlloc(sizeof(mappings_t) * memdesc->mapcount);
        
        memset((void *)memdesc->maps, 0, sizeof(mappings_t) * memdesc->mapcount);
        
	memdesc->path = exename; // supplied by core_pattern %e
       
	memdesc->exe_path = get_exe_path(pid);

	printf("exe_path: %s\n", memdesc->exe_path);
	if (get_maps(pid, memdesc->maps, memdesc->path) < 0) {
                printf("[!] failed to get data from /proc/%d/maps\n", pid);
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
	int pid = memdesc->task.pid;
	int fd;
	uint8_t *mem;
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	ElfW(Addr) text_base = 0;
	int i;

	/*
	 * For debugging purposes since the core file on disk isn't
	 * going to match the exact one in the process image for PIE
	 * executables (Since we technically have to kill the process
	 * to get the core, then restart the process again)
	 * we won't use lookup_text_base() but instead get it from
	 * the maps. We can change this much later on.
	 */
	//text_base = lookup_text_base(memdesc, notedesc->nt_files);
	
	for (i = 0; i < memdesc->mapcount; i++)
		if (memdesc->maps[i].textbase)
			text_base = memdesc->maps[i].base;

	if (text_base == 0) {
		printf("Unable to locate executable base necessary to find phdr's\n");
		return -1;
	}
	
	/*
	 * We should avoid using ptrace and it won't work in conjunction with
	 * the kernels core_pattern piping feature.
	 */
	/*
	if (pid_attach_direct(pid) < 0) {
		ecfs_print("pid_attach failed\n");
		return -1;
	}
	
	if (pid_read(pid, (void *)mem, (void *)text_base, 4096) < 0)
		return -1;
	
	if (pid_detach_direct(pid) < 0)
		return -1;
	*/
	/* Instead we use mmap on the original executable file */
	fd = xopen(memdesc->exe_path, O_RDONLY);
	mem = mmap(NULL, 8192, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
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
				switch(!(!phdr[i].p_offset)) {
					case 0:
						/* text segment */
						elfdesc->textVaddr = text_base;
						elfdesc->textSize = lookup_text_size(memdesc, notedesc->nt_files);
						break;
					case 1:
						elfdesc->dataVaddr = lookup_data_base(memdesc, notedesc->nt_files);
						elfdesc->dataSize = lookup_data_size(memdesc, notedesc->nt_files);
						elfdesc->bssSize = phdr[i].p_memsz - phdr[i].p_filesz;
						elfdesc->o_datafsize = phdr[i].p_filesz;
						if (elfdesc->pie == 0)
							elfdesc->bssVaddr = phdr[i].p_vaddr + phdr[i].p_filesz;
						break;
				}
				break;
			case PT_DYNAMIC:
				elfdesc->dynVaddr = phdr[i].p_vaddr + (elfdesc->pie ? text_base : 0);
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
	notedesc_t *notedesc = handle->notedesc;
	ElfW(Phdr) *phdr = elfdesc->phdr;
	ElfW(Dyn) *dyn;
	ElfW(Off) dataOffset = elfdesc->dataOffset; // this was filled in from xref_phdrs_for_offsets
	elfdesc->dyn = NULL;
	struct section_meta smeta;
	char *p;
	
	for (i = 0; i < elfdesc->ehdr->e_phnum; i++) {
		if (phdr[i].p_vaddr == elfdesc->dataVaddr) {
			elfdesc->dyn = (ElfW(Dyn) *)&elfdesc->mem[phdr[i].p_offset + (elfdesc->dynVaddr - elfdesc->dataVaddr)];
			break;
		}
	}

	if (elfdesc->dyn == NULL) {
		fprintf(stderr, "Unable to find dynamic segment in core file, exiting...\n");
		return -1;
	}
	dyn = elfdesc->dyn;
	for (j = 0; dyn[j].d_tag != DT_NULL; j++) {
        	switch(dyn[j].d_tag) {
			case DT_REL:
                        	smeta.relVaddr = dyn[j].d_un.d_val;
                                smeta.relOff = smeta.relVaddr - elfdesc->textVaddr;
#if DEBUG
				printf("relVaddr: %lx relOff: %lx\n", smeta.relVaddr, smeta.relOff);
#endif
                        	break;
                        case DT_RELA:
                        	smeta.relaVaddr = dyn[j].d_un.d_val;
                                smeta.relaOff = smeta.relaVaddr - elfdesc->textVaddr; 
#if DEBUG
				printf("relaVaddr: %lx relaOffset: %lx\n", smeta.relaVaddr, smeta.relaOff);
#endif
                        	break;
                        case DT_PLTGOT:
                        	smeta.gotVaddr = dyn[j].d_un.d_val;
                                smeta.gotOff = dyn[j].d_un.d_val - elfdesc->dataVaddr;
                                smeta.gotOff += (ElfW(Off))dataOffset;
#if DEBUG
				printf("gotVaddr: %lx gotOffset: %lx\n", smeta.gotVaddr, smeta.gotOff);
#endif
                                break;
                        case DT_GNU_HASH:
                                smeta.hashVaddr = dyn[j].d_un.d_val;
                                smeta.hashOff = elfdesc->textOffset + smeta.hashVaddr - elfdesc->textVaddr;
#if DEBUG
				printf("hashVaddr: %lx hashOff: %lx\n", smeta.hashVaddr, smeta.hashOff);
#endif
                                break;
                        case DT_INIT: 
                                smeta.initVaddr = dyn[j].d_un.d_val + (memdesc->pie ? elfdesc->textVaddr : 0);
                                smeta.initOff = elfdesc->textOffset + smeta.initVaddr - elfdesc->textVaddr;
#if DEBUG
				printf("initVaddr: %lx initOff: %lx\n", smeta.initVaddr, smeta.initOff);
#endif
                                break;
                        case DT_FINI:
                                smeta.finiVaddr = dyn[j].d_un.d_val + (memdesc->pie ? elfdesc->textVaddr : 0);
                                smeta.finiOff = elfdesc->textOffset + smeta.finiVaddr - elfdesc->textVaddr;
#if DEBUG
				printf("finiVaddr: %lx finiOff: %lx\n", smeta.finiVaddr, smeta.finiOff);
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
                                break;
                        case DT_STRTAB:
                                smeta.dstrVaddr = dyn[j].d_un.d_ptr;
                                smeta.dstrOff = elfdesc->textOffset + smeta.dstrVaddr - elfdesc->textVaddr;
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
			printf("noteOffset: %lx\n", elfdesc->noteOffset);
#endif
		}
		if (elfdesc->interpVaddr >= phdr[i].p_vaddr && elfdesc->interpVaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
			elfdesc->interpOffset = phdr[i].p_offset + elfdesc->interpVaddr - phdr[i].p_vaddr;
#if DEBUG
			printf("interpOffset: %lx\n", elfdesc->interpOffset);
#endif
		}
		if (elfdesc->dynVaddr >= phdr[i].p_vaddr && elfdesc->dynVaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
			elfdesc->dynOffset = phdr[i].p_offset + elfdesc->dynVaddr - phdr[i].p_vaddr;
#if DEBUG
			printf("dynOffset: %lx\n", elfdesc->dynOffset);
#endif
		}
		if (elfdesc->ehframe_Vaddr >= phdr[i].p_vaddr && elfdesc->ehframe_Vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
			elfdesc->ehframeOffset = phdr[i].p_offset + elfdesc->ehframe_Vaddr - phdr[i].p_vaddr;
#if DEBUG
			printf("ehframeOffset: %lx\n", elfdesc->ehframeOffset);
#endif
		}
		if (elfdesc->textVaddr == phdr[i].p_vaddr) {
			elfdesc->textOffset = phdr[i].p_offset;
			elfdesc->textSize = phdr[i].p_memsz;
#if DEBUG
			printf("textOffset: %lx\n", elfdesc->textOffset);
#endif
		}
		if (elfdesc->dataVaddr == phdr[i].p_vaddr) {
			elfdesc->dataOffset = phdr[i].p_offset;
			if (elfdesc->pie)
				elfdesc->bssVaddr = elfdesc->dataVaddr + elfdesc->o_datafsize;
			printf("bssVaddr is: %lx\n", elfdesc->bssVaddr);
			elfdesc->bssOffset = phdr[i].p_offset + elfdesc->bssVaddr - elfdesc->dataVaddr;
#if DEBUG
			printf("bssOffset: %lx\n"
			       "dataOffset: %lx\n", elfdesc->bssOffset, elfdesc->dataOffset);
#endif
		}
	}
}

static ElfW(Off) get_internal_sh_offset(elfdesc_t *elfdesc, memdesc_t *memdesc, int type)
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
                                                if (phdr[j].p_vaddr == maps[i].base)
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
                        return 0;
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
	elfdesc_t *elfdesc = handle->elfdesc;
        memdesc_t *memdesc = handle->memdesc;
        notedesc_t *notedesc = handle->notedesc;
        struct section_meta *smeta = &handle->smeta;
	struct fde_func_data *fndata, *fdp;
        int fncount, i, fd;
        struct stat st;
	uint8_t *mem;
	ElfW(Ehdr) *ehdr;
	ElfW(Shdr) *shdr;

	char *StringTable;
        fncount = get_all_functions(outfile, &fndata);
 	if (fncount < 0)
		fncount = 0;             	

#if DEBUG
	printf("Found %d local functions from .eh_frame\n", fncount);
#endif
        ElfW(Sym) *symtab = (ElfW(Sym) *)alloca(sizeof(ElfW(Sym)) * fncount);
        fdp = (struct fde_func_data *)fndata; 
        char *strtab = alloca(8192);
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
        size_t symtab_size = fncount * sizeof(ElfW(Sym));
 	 /*
         * We append symbol table sections last 
         */
        if ((fd = open(outfile, O_RDWR)) < 0) {
                perror("open");
                exit(-1);
        }

        if (fstat(fd, &st) < 0) {
                perror("fstat");
                exit(-1);
        }

        mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if (mem == MAP_FAILED) {
                perror("mmap");
                exit(-1);
        }
        ehdr = (ElfW(Ehdr) *)mem;
        shdr = (ElfW(Shdr) *)&mem[ehdr->e_shoff];

        if (lseek(fd, 0, SEEK_END) < 0) {
                perror("open");
                exit(-1);
        }
	
        uint64_t symtab_offset = lseek(fd, 0, SEEK_CUR);
        for (i = 0; i < symcount; i++) 
                write(fd, (char *)&symtab[i], sizeof(ElfW(Sym))); 
        
      	StringTable = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset];
        /* Write section hdr string table */
        uint64_t stloff = lseek(fd, 0, SEEK_CUR);
        write(fd, strtab, symstroff);
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
	ElfW(Shdr) *shdr = alloca(sizeof(ElfW(Shdr)) * MAX_SHDR_COUNT);
        char *StringTable = (char *)alloca(MAX_SHDR_COUNT * 16);
	struct stat st;
        unsigned int stoffset = 0;
        int scount = 0;
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
        shdr[scount].sh_size = smeta->interpSiz;
        shdr[scount].sh_addralign = 1;
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".interp");
        stoffset += strlen(".interp") + 1;
        scount++;

	 /*
         * .note
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
        shdr[scount].sh_size = UNKNOWN_SHDR_SIZE;
        shdr[scount].sh_addralign = 4;
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".hash");
        stoffset += strlen(".hash") + 1;
        scount++;
	
	 /*
         * .dynsym
         */
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
        shdr[scount].sh_link = scount - 1;
        shdr[scount].sh_entsize = (__ELF_NATIVE_CLASS == 64) ? sizeof(Elf64_Rela) : sizeof(Elf32_Rel);
        shdr[scount].sh_size = UNKNOWN_SHDR_SIZE;
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
         * .init
         */
        shdr[scount].sh_type = SHT_PROGBITS;
        shdr[scount].sh_offset = smeta->initOff;
        shdr[scount].sh_addr = smeta->initVaddr;
        shdr[scount].sh_flags = SHF_ALLOC|SHF_EXECINSTR;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = 0;
        shdr[scount].sh_size = UNKNOWN_SHDR_SIZE;
        shdr[scount].sh_addralign = sizeof(long);
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".init");
        stoffset += strlen(".init") + 1;
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
        shdr[scount].sh_size = UNKNOWN_SHDR_SIZE;
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
        shdr[scount].sh_addralign = 16;
        shdr[scount].sh_name = stoffset;
        strcpy(&StringTable[stoffset], ".eh_frame_hdr");
        stoffset += strlen(".eh_frame_hdr") + 1;
        scount++;
        
        /*
         * .eh_frame
         */
        shdr[scount].sh_type = SHT_PROGBITS;
        shdr[scount].sh_offset = elfdesc->ehframeOffset + elfdesc->ehframe_Size;
        shdr[scount].sh_addr = elfdesc->ehframe_Vaddr + elfdesc->ehframe_Size;
        shdr[scount].sh_flags = SHF_ALLOC|SHF_EXECINSTR;
        shdr[scount].sh_info = 0;
        shdr[scount].sh_link = 0;
        shdr[scount].sh_entsize = 0;
        shdr[scount].sh_size = (ElfW(Off))((elfdesc->ehframe_Vaddr + elfdesc->ehframe_Size) - elfdesc->textVaddr);
        shdr[scount].sh_addralign = 16;
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
        shdr[scount].sh_size = UNKNOWN_SHDR_SIZE;
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
	
	int data_count;
	char *str = NULL;
	for (data_count = 0, i = 0; i < notedesc->lm_files->libcount; i++) {
		shdr[scount].sh_type = SHT_SHLIB;
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
        shdr[scount].sh_size;
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
                write(fd, (char *)&shdr[i], sizeof(ElfW(Shdr)));
        
        write(fd, (char *)StringTable, stoffset);
        fsync(fd);
        close(fd);
        
	fd = xopen(filepath, O_RDWR);
        
        if (fstat(fd, &st) < 0) {
                perror("fstat");
                exit(-1);
        }

        uint8_t *mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if (mem == MAP_FAILED) {
                perror("mmap");
                exit(-1);
        }

        ElfW(Ehdr *)ehdr = (ElfW(Ehdr) *)mem;
        ehdr->e_shoff = e_shoff;
        ehdr->e_shstrndx = e_shstrndx;
	ehdr->e_shentsize = sizeof(ElfW(Shdr));
        ehdr->e_shnum = scount;
        ehdr->e_type = ET_NONE;
	
	msync(mem, st.st_size, MS_SYNC);
        munmap(mem, st.st_size);

        close(fd);

	
	return scount;
}


int core2ecfs(const char *outfile, handle_t *handle)
{
	struct stat st;
	int i, j, no_dynamic = 0;
	ElfW(Dyn) *dyn = NULL;
	elfdesc_t *elfdesc = handle->elfdesc;
	memdesc_t *memdesc = handle->memdesc;
	notedesc_t *notedesc = handle->notedesc;
	struct section_meta *smeta = &handle->smeta;
	ElfW(Ehdr) *ehdr = elfdesc->ehdr;
	ElfW(Phdr) *phdr = elfdesc->phdr;
	uint8_t *mem = elfdesc->mem;
	fd_info_t *fdinfo = NULL;
	ecfs_file_t *ecfs_file = heapAlloc(sizeof(ecfs_file_t));
	int fd, ret;

	fd = xopen(outfile, O_CREAT|O_TRUNC|O_RDWR);
	chmod(outfile, S_IRWXU|S_IRWXG);
 	
	stat(elfdesc->path, &st); // stat the corefile
	ecfs_file->prstatus_offset = st.st_size;
	ecfs_file->prstatus_size = notedesc->thread_count * sizeof(struct elf_prstatus);
	ecfs_file->fdinfo_offset = ecfs_file->prstatus_offset + notedesc->thread_count * sizeof(struct elf_prstatus);
	ecfs_file->fdinfo_size = get_fd_links(memdesc, &fdinfo) * sizeof(fd_info_t);
	ecfs_file->siginfo_offset = ecfs_file->fdinfo_offset + ecfs_file->fdinfo_size;
	ecfs_file->siginfo_size = sizeof(siginfo_t);
	ecfs_file->auxv_offset = ecfs_file->siginfo_offset + ecfs_file->siginfo_size;
	ecfs_file->auxv_size = notedesc->auxv_size;
	ecfs_file->stb_offset = ecfs_file->auxv_offset + ecfs_file->auxv_size;
	
	/*
	 * write original body of core file
	 */	
	if (write(fd, elfdesc->mem, st.st_size) != st.st_size) {
		perror("write");
		exit(-1);
	}

	/*
	 * write prstatus structs
	 */
	write(fd, notedesc->prstatus, sizeof(struct elf_prstatus));
	for (i = 0; i < notedesc->thread_count; i++)	
		write(fd, notedesc->thread_core_info[i].prstatus, sizeof(struct elf_prstatus));
	
	/*
	 * write fdinfo structs
	 */
	write(fd, fdinfo, ecfs_file->fdinfo_size);

	/*
	 * write siginfo_t struct
	 */
	write(fd, notedesc->siginfo, sizeof(siginfo_t));
	
	/*
 	 * write auxv data
	 */
	write(fd, notedesc->auxv, notedesc->auxv_size);
	
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
		perror("mmap");
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
#if DEBUG
		fprintf(stderr, "local symtab reconstruction failed\n");
#endif	

	return 0;
}
	
void fill_in_pstatus(memdesc_t *memdesc, notedesc_t *notedesc)
{
                memdesc->task.uid = notedesc->psinfo->pr_uid;
                memdesc->task.gid = notedesc->psinfo->pr_gid;
                memdesc->task.ppid = notedesc->psinfo->pr_ppid;
                //memdesc->task.pid = notedesc->psinfo->pr_pid;
                memdesc->task.exit_signal = notedesc->prstatus->pr_info.si_signo;
                memdesc->path = notedesc->psinfo->pr_fname;
}

int main(int argc, char **argv)
{
		
	struct rlimit limit_core = {0L, 0L};
	memdesc_t *memdesc;
	elfdesc_t *elfdesc;
	notedesc_t *notedesc = NULL;
	handle_t *handle = alloca(sizeof(handle_t));
	pid_t pid = 0;
	int i, j, ret, c;
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
	
	while ((c = getopt(argc, argv, "c:io:p:e:")) != -1) {
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
			default:
				fprintf(stderr, "Unknown option\n");
				exit(0);
		}
	}
	FILE *fdesc = fopen("/tmp/core.test", "w");	
	char *pfile = xfmtstrdup("/proc/%d/maps", pid);
	FILE *fr = fopen(pfile, "r");
	char tmp[8192];
	fgets(tmp, sizeof(tmp), fr);
	fclose(fr);
	ecfs_print("exename: %s\n", exename);
	printf("pid: %d\n", pid);
	fprintf(fdesc, "exename: %s pid: %d\n%s", exename, pid, tmp);
	fclose(fdesc);
	
	opts.logfile = LOGGING_PATH;

	if (opts.use_stdin == 0) {
		if (corefile == NULL) {
			printf("Must specify a corefile with -c\n");
			exit(0);
		}
		if (pid == 0) {
			printf("Must specify a pid with -p\n");
			exit(0);
		}
		if (outfile == NULL) {
			printf("Did not specify an output file, defaulting to use 'ecfs.out'\n");
			outfile = xfmtstrdup("%s/ecfs.out", ECFS_CORE_DIR);		
		}
	}
	
	/*
	 * Don't allow itself to core in the event of a bug.
	 */
	/*
    	if (setrlimit(RLIMIT_CORE, &limit_core) < 0) {
		perror("setrlimit");
		exit(-1);
	}
	*/
	if (opts.use_stdin) {
		printf("Using stdin, outfile is:%s\n", outfile);
		/*
		 * If we are getting core directly from the kernel then we must
		 * read /proc/<pid>/ before we read the corefile. The process stays
		 * open as long as the corefile hasn't been read yet.
	  	 */
        	if (exename == NULL) {
			ecfs_print("must specify exename\n");
			fprintf(stderr, "Must specify exename of process when using stdin mode; supplied by %%e of core_pattern\n");
			exit(-1);
		}
		if (pid == 0) {
			ecfs_print("must specify a pid\n");
                        printf("Must specify a pid with -p\n");
                        exit(0);
                }
                if (outfile == NULL) {
                        printf("Did not specify an output file, defaulting to use 'ecfs.out'\n");
                        outfile = xfmtstrdup("%s/ecfs.out", ECFS_CORE_DIR);
                }

		ecfs_print("calling build_proc_metadata\n");
		memdesc = build_proc_metadata(pid, notedesc);
        	if (memdesc == NULL) {
                	fprintf(stderr, "Failed to retrieve process metadata\n");
                	exit(-1);
        	}
		ecfs_print("succeeded in calling proc_metadata\n");
		memdesc->task.pid = pid;
	}

#if DEBUG
	if (corefile)
		printf("Loading core file: %s\n", corefile);
#endif
	switch(opts.use_stdin) {
		case 0:
			/*
			 * load the core file from a file
			 */
			elfdesc = load_core_file((const char *)corefile);
			if (elfdesc == NULL) {
				fprintf(stderr, "Failed to parse core file\n");
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
		ecfs_print("Failed to parse notes\n");
		fprintf(stderr, "Failed to parse ELF notes segment\n");
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
		pid = pid ? pid : notedesc->prstatus->pr_pid;
		memdesc = build_proc_metadata(pid, notedesc);
        	if (memdesc == NULL) {
                	fprintf(stderr, "Failed to retrieve process metadata\n");
                	exit(-1);
        	}
		memdesc->task.pid = pid;
	}
	fill_in_pstatus(memdesc, notedesc);
		
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
	if (parse_orig_phdrs(elfdesc, memdesc, notedesc) < 0) {
		fprintf(stderr, "Failed to parse program headers in memory\n");
		exit(-1);
	}

	/*
	 * Combine all handles into 1 (Should work this into the code earlier on)
	 */
	handle->elfdesc = elfdesc;
	handle->memdesc = memdesc;
	handle->notedesc = notedesc;
	
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
	ecfs_print("lookup_lib_maps\n");
	notedesc->lm_files = (struct lib_mappings *)heapAlloc(sizeof(struct lib_mappings));
	lookup_lib_maps(elfdesc, memdesc, notedesc->nt_files, notedesc->lm_files);
	
#if DEBUG
	for (i = 0; i < notedesc->lm_files->libcount; i++)
		printf("libname: %s addr: %lx\n", notedesc->lm_files->libs[i].name, notedesc->lm_files->libs[i].addr);
#endif
	/*
	 * We get a plethora of information about where certain
	 * data and code is from the dynamic segment by parsing
	 * it by D_TAG values.
	 */
	ecfs_print("extracting dyninfo\n");
	ret = extract_dyntag_info(handle);
	if (ret < 0) {
		fprintf(stderr, "Failed to extract dynamic segment information\n");
		exit(-1);
	}
	/*
	 * Convert the core file into an actual ECFS file and write it
	 * to disk.
	 */
	ecfs_print("core2ecfs\n");
	ret = core2ecfs(outfile, handle);
	if (ret < 0) {
		fprintf(stderr, "Failed to transform core file '%s' into ecfs\n", argv[2]);
		exit(-1);
	}
	
	if (opts.use_stdin)
		unlink(elfdesc->path);
}





