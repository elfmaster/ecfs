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

ElfW(Addr) lookup_text_base(memdesc_t *memdesc, struct nt_file_struct *fmaps)
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

int parse_orig_phdrs(elfdesc_t *elfdesc, memdesc_t *memdesc, notedesc_t *notedesc)
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
				elfdesc->dynSize = phdr[i].p_memsz;
				break;
			case PT_GNU_EH_FRAME:
				elfdesc->ehframe_Vaddr = phdr[i].p_vaddr + (elfdesc->pie ? text_base : 0);
				elfdesc->ehframe_Size = phdr[i].p_memsz;
				break;
			case PT_NOTE:
				/*
				 * We don't want the original executables note, but the corefile
				 * notes so we don't fill these in at this point, hence the comments
				 *
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
		case DT_HASH:
			smeta.hashVaddr = dyn[j].d_un.d_val;
			smeta.hashOff = elfdesc->textOffset + smeta.hashVaddr - elfdesc->textVaddr;
#if DEBUG
			log_msg(__LINE__, "HASH: hashVaddr: %#lx hashOff: #%lx",
			smeta.hashVaddr, smeta.hashOff);
#endif
			break;
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
			log_msg(__LINE__, "DYNSEGMENT: relaOffset = %lx + %lx - %lx",
			    elfdesc->textOffset, smeta.plt_relaVaddr, elfdesc->textVaddr);
			log_msg(__LINE__, "DYNSEGMENT: plt_relaVaddr: %lx plt_relaOffset: %lx",
			    smeta.plt_relaVaddr, smeta.plt_relaOff);
#endif
			break;
		case DT_PLTGOT:
			smeta.gotVaddr = dyn[j].d_un.d_val;
			smeta.gotOff = dyn[j].d_un.d_val - elfdesc->dataVaddr;
			smeta.gotOff += (ElfW(Off))dataOffset;
#if DEBUG
			log_msg(__LINE__, "DYNSEGMENT: gotVaddr: %lx gotOffset: %lx",
			    smeta.gotVaddr, smeta.gotOff);
#endif
			break;
		case DT_GNU_HASH:
			smeta.hashVaddr = dyn[j].d_un.d_val;
			smeta.hashOff = elfdesc->textOffset + smeta.hashVaddr - elfdesc->textVaddr;
#if DEBUG
			log_msg(__LINE__, "DYNSEGMENT: hashVaddr: %lx hashOff: %lx",
			    smeta.hashVaddr, smeta.hashOff);
#endif
			break;
		case DT_INIT: 
			smeta.initVaddr = dyn[j].d_un.d_val + (memdesc->pie ? elfdesc->textVaddr : 0);
			smeta.initOff = elfdesc->textOffset + smeta.initVaddr - elfdesc->textVaddr;
#if DEBUG
			log_msg(__LINE__, "DYNSEGMENT: initVaddr: %lx initOff: %lx",
			    smeta.initVaddr, smeta.initOff);
#endif
			break;
		case DT_FINI:
			smeta.finiVaddr = dyn[j].d_un.d_val + (memdesc->pie ? elfdesc->textVaddr : 0);
			smeta.finiOff = elfdesc->textOffset + smeta.finiVaddr - elfdesc->textVaddr;
#if DEBUG
			log_msg(__LINE__, "DYNSEGMENT: finiVaddr: %lx finiOff: %lx",
			    smeta.finiVaddr, smeta.finiOff);
#endif
			break;
		case DT_INIT_ARRAY:
			smeta.ctors_vaddr = dyn[j].d_un.d_val + (memdesc->pie ? elfdesc->textVaddr : 0);
			log_msg(__LINE__, "CTORS: %lx\n", smeta.ctors_vaddr);
				break;
		case DT_INIT_ARRAYSZ:
			log_msg(__LINE__, "CTORSSZ: %lx\n", smeta.ctors_size);
			smeta.ctors_size = dyn[j].d_un.d_val;
			break;
		case DT_FINI_ARRAY:
			smeta.dtors_vaddr = dyn[j].d_un.d_val + (memdesc->pie ? elfdesc->textVaddr : 0);
			break;
		case DT_FINI_ARRAYSZ:
			smeta.dtors_size = dyn[j].d_un.d_val;
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
#if DEBG
			log_msg(__LINE__, "DYNSEGMENT: .dynsym addr: %lx offset: %lx",
			    smeta.dsymVaddr, smeta.dsymOff);
#endif
			break;
		case DT_STRTAB:
			smeta.dstrVaddr = dyn[j].d_un.d_ptr;
			smeta.dstrOff = elfdesc->textOffset + smeta.dstrVaddr - elfdesc->textVaddr;
#if DEBUG
			log_msg(__LINE__, "DYNSEGMENT: .dynstr addr: %lx  offset: %lx (%lx + (%lx - %lx)",
			    smeta.dstrVaddr, smeta.dstrOff, elfdesc->textOffset, smeta.dstrVaddr,
			    elfdesc->textVaddr); 
#endif
			break;
		}
	}
	memcpy((void *)&handle->smeta, (void *)&smeta, sizeof(struct section_meta));
	return 0;
}

void xref_phdrs_for_offsets(memdesc_t *memdesc, elfdesc_t *elfdesc)
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
	
		/*
		 * We handle eh_frame in two different ways based on whether or not the executable
		 * is statically or dynamically linked.
		 */
		if (elfdesc->dynlinked) {
			if (elfdesc->ehframe_Vaddr >= phdr[i].p_vaddr && elfdesc->ehframe_Vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
				elfdesc->ehframeOffset = phdr[i].p_offset + elfdesc->ehframe_Vaddr - phdr[i].p_vaddr;
#if DEBUG
			log_msg(__LINE__, "ehframeOffset: %lx\n", elfdesc->ehframeOffset);
#endif
			}
		} else {
			if (global_hacks.ehframe_vaddr >= phdr[i].p_vaddr && global_hacks.ehframe_vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
				elfdesc->ehframeOffset = phdr[i].p_offset + global_hacks.ehframe_vaddr - phdr[i].p_vaddr;
#if DEBUG
			log_msg(__LINE__, "ehframeOffset: %lx\n", elfdesc->ehframeOffset);
#endif
			}
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

