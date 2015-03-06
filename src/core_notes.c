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

static void parse_nt_files(struct nt_file_struct **nt_files, void *data, size_t size)
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
				log_msg(__LINE__, "Collecting PRSTATUS struct for thread #%d", notedesc->thread_count);
#endif
				if (notes->n_descsz != (size_t)sizeof(struct elf_prstatus)) {
#if DEBUG
					log_msg(__LINE__, "error: The ELF note entry for NT_PRSTATUS is not the correct size");
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
					log_msg(__LINE__, "error: The ELF note entry for NT_PRPSINFO is not the correct size");	
#endif
					break;
				}
				notedesc->psinfo = (struct elf_prpsinfo *)heapAlloc(sizeof(struct elf_prpsinfo));
				memcpy(notedesc->psinfo, desc, notes->n_descsz);
				break;
			case NT_SIGINFO:
				if (notes->n_descsz != sizeof(siginfo_t)) {
#if DEBUG
					log_msg(__LINE__, "error: the ELF note entry for NT_SIGINFO is not the correct size");
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
					log_msg(__LINE__, "error: The ELF note entry for NT_PRPSINFO is not the correct size\n");
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

void fill_in_pstatus(memdesc_t *memdesc, notedesc_t *notedesc)
{
                memdesc->task.uid = notedesc->psinfo->pr_uid;
                memdesc->task.gid = notedesc->psinfo->pr_gid;
                memdesc->task.ppid = notedesc->psinfo->pr_ppid;
                memdesc->task.exit_signal = notedesc->prstatus->pr_info.si_signo;
                memdesc->path = memdesc->comm = notedesc->psinfo->pr_fname;
}
