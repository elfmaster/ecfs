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
		(*nt_files)->files[i].size = fmp->start - fmp->end;
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

static int get_proc_status(notedesc_t *notedesc, memdesc_t *memdesc)
{


	memdesc->task.uid = notedesc->psinfo->pr_uid;
	memdesc->task.gid = notedesc->psinfo->pr_gid;
	memdesc->task.ppid = notedesc->psinfo->pr_ppid;
	memdesc->task.pid = notedesc->psinfo->pr_pid;
	memdesc->task.exit_signal = notedesc->prstatus->pr_info.si_signo;
	memdesc->path = notedesc->psinfo->pr_fname;

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

/*
 * Get /proc/pid/maps info to create data
 * about stack, heap etc. This can then be
 * merged with the info retrieved from the
 * core files phdr's.
 */

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
        
        if (get_proc_status(notedesc, memdesc) < 0) {
                printf("[!] failed to get data from /proc/%d/status\n", pid);
                return NULL;
        }
        
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

static int parse_orig_phdrs(elfdesc_t *elfdesc, memdesc_t *memdesc, notedesc_t *notedesc)
{
	int pid = memdesc->task.pid;
	uint8_t *mem = alloca(8192);
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
	
	if (pid_attach_direct(pid) < 0)
		return -1;
	
	if (pid_read(pid, (void *)mem, (void *)text_base, 4096) < 0)
		return -1;
	
	/*
	 * Now get text_base again but from the core file. During a real crashdump
	 * these values will be the exact same either way.
	 */
	text_base = lookup_text_base(memdesc, notedesc->nt_files);

	ehdr = (ElfW(Ehdr) *)mem;
	phdr = (ElfW(Phdr) *)(mem + ehdr->e_phoff);
	if (ehdr->e_type == ET_DYN)
		elfdesc->pie++;
	
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
				elfdesc->noteVaddr = phdr[i].p_vaddr + (elfdesc->pie ? text_base : 0);
				elfdesc->noteSize = phdr[i].p_filesz;
				break;
			case PT_INTERP:
				elfdesc->dynlinked++;
				break;
		}
	}

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
	ElfW(Off) dataOffset;
	elfdesc->dyn = NULL;
	struct section_meta smeta;

	for (i = 0; i < elfdesc->ehdr->e_phnum; i++) {
		if (phdr[i].p_vaddr = elfdesc->dataVaddr) {
			elfdesc->dyn = &elfdesc->mem[phdr[i].p_offset + (elfdesc->dynVaddr - elfdesc->dataVaddr)];
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
                        	break;
                        case DT_RELA:
                        	smeta.relaVaddr = dyn[j].d_un.d_val;
                                smeta.relaOff = smeta.relaVaddr - elfdesc->textVaddr;
                        	break;
                        case DT_PLTGOT:
                        	smeta.gotVaddr = dyn[j].d_un.d_val;
                                smeta.gotOff = dyn[j].d_un.d_val - elfdesc->dataVaddr;
                                smeta.gotOff += (ElfW(Off))dataOffset;
                                break;
                        case DT_GNU_HASH:
                                smeta.hashVaddr = dyn[j].d_un.d_val;
                                smeta.hashOff = smeta.hashVaddr - elfdesc->textVaddr;
                                break;
                        case DT_INIT: 
                                smeta.initVaddr = dyn[j].d_un.d_val + (memdesc->pie ? elfdesc->textVaddr : 0);
                                smeta.initOff = smeta.initVaddr - elfdesc->textVaddr;
                                break;
                        case DT_FINI:
                                smeta.finiVaddr = dyn[j].d_un.d_val + (memdesc->pie ? elfdesc->textVaddr : 0);
                                smeta.finiOff = smeta.finiVaddr - elfdesc->textVaddr;
                                break;
                        case DT_STRSZ:
                                smeta.strSiz = dyn[j].d_un.d_val;
                                break;  
                        case DT_PLTRELSZ:
                                smeta.pltSiz = dyn[j].d_un.d_val;
                                break;
                        case DT_SYMTAB:
                                smeta.dsymVaddr = dyn[j].d_un.d_ptr;
                                smeta.dsymOff = smeta.dsymVaddr - elfdesc->textVaddr;
                                break;
                        case DT_STRTAB:
                                smeta.dstrVaddr = dyn[j].d_un.d_ptr;
                                smeta.dstrOff = smeta.dstrVaddr - elfdesc->textVaddr;
                                break;

		}
	}
	memcpy((void *)&handle->smeta, (void *)&smeta, sizeof(struct section_meta));
	return 0;
}

/*
 * ET_CORE files have all phdr segments as type PT_LOAD (except for 1 single PT_NOTE)
 * but this causes us some problems since we need to specifically know where PT_DYNAMIC,
 * PT_GNU_EH_FRAME, and PT_NOTE(from original executable) are located in the core file.
 * To solve this we briefly use ptrace to retrive and parse the phdr table from the actual
 * process image, which has the original in-tact phdr before it was dumped into a core phdr
 * table. We then go through in this next function and mark up our core file phdr's with
 * the proper p_type's.
 */
static void update_corefile_phdrs(memdesc_t *memdesc, elfdesc_t *elfdesc)
{
	ElfW(Phdr) *phdr = elfdesc->phdr;
	int i;

	for (i = 0; i < elfdesc->ehdr->e_phnum; i++) {
		if (phdr[i].p_vaddr == elfdesc->dynVaddr) {
			phdr[i].p_type = PT_DYNAMIC;
#if DEBUG
			printf("Found PT_DYNAMIC and marking it in core file\n");
#endif
		}
		else
		if (phdr[i].p_vaddr == elfdesc->ehframe_Vaddr) {
			phdr[i].p_type = PT_GNU_EH_FRAME;
#if DEBUG
			printf("Found PT_GNU_EH_FRAME and marking it in core file\n");
#endif
		}
		else
		if (phdr[i].p_vaddr == elfdesc->noteVaddr) {
			phdr[i].p_type = PT_NOTE;
#if DEBUG
			printf("Found PT_NOTE and am marking it in core file\n");
#endif
		}
	}	
}


int core2ecfs(const char *outfile, memdesc_t *memdesc, elfdesc_t *elfdesc, notedesc_t *notedesc)
{
	int i, j, no_dynamic = 0;
	ElfW(Dyn) *dyn = NULL;
	ElfW(Ehdr) *ehdr = elfdesc->ehdr;
	ElfW(Phdr) *phdr = elfdesc->phdr;
	uint8_t *mem = elfdesc->mem;
	
	for (i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_vaddr == PAGE_ALIGN(elfdesc->dataVaddr)) {
			dyn = (ElfW(Dyn) *)&mem[elfdesc->dynVaddr - elfdesc->dataVaddr];
			break;
		}
	}
	return 0;
}
	
int main(int argc, char **argv)
{
		
	struct rlimit limit_core = {0L, 0L};
	memdesc_t *memdesc;
	elfdesc_t *elfdesc;
	notedesc_t *notedesc = NULL;
	handle_t *handle = alloca(sizeof(handle_t));
	pid_t pid;
	int i, j, ret;
	
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <corefile(input)> <ecfsfile(output)> <pid(optional)>\n", argv[0]);
		exit(-1);
	}
	
    	if (setrlimit(RLIMIT_CORE, &limit_core) < 0) {
		perror("setrlimit");
		exit(-1);
	}
#if DEBUG
	printf("Loading core file: %s\n", argv[1]);
#endif
	elfdesc = load_core_file((const char *)argv[1]);
	if (elfdesc == NULL) {
		fprintf(stderr, "Failed to parse core file\n");
		exit(-1);
	}

	notedesc = (notedesc_t *)parse_notes_area(elfdesc);
	if (notedesc == NULL) {
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
	pid = argc > 3 ? atoi(argv[3]) : notedesc->prstatus->pr_pid;
	memdesc = build_proc_metadata(pid, notedesc);
        if (memdesc == NULL) {
                fprintf(stderr, "Failed to retrieve process metadata\n");
                exit(-1);
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
	if (parse_orig_phdrs(elfdesc, memdesc, notedesc) < 0) {
		fprintf(stderr, "Failed to parse program headers in memory\n");
		exit(-1);
	}

	handle->elfdesc = elfdesc;
	handle->memdesc = memdesc;
	handle->notedesc = notedesc;
	
	ret = extract_dyntag_info(handle);
	
	/*
	 * Convert the core file into an actual ECFS file and write it
	 * to disk.
	 */
	ret = core2ecfs(argv[2], memdesc, elfdesc, notedesc);
	if (ret < 0) {
		fprintf(stderr, "Failed to transform core file '%s' into ecfs\n", argv[2]);
		exit(-1);
	}

}






