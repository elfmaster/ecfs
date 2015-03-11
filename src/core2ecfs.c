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
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
 */

#include "../include/ecfs.h"
#include "../include/util.h"
#include "../include/eh_frame.h"

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
	if (global_hacks.stripped) {
#if DEBUG
		log_msg(__LINE__, "personality of ELF: section header table is stripped");
#endif
		handle->elfstat.personality |= ELF_STRIPPED_SHDRS;
	}
#if DEBUG
	if (!(handle->elfstat.personality & ELF_STATIC))
		log_msg(__LINE__, "personality of ELF: dynamically linked");
#endif
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
                exit_failure(-1);
        }

        if (fstat(fd, &st) < 0) {
                log_msg(__LINE__, "fstat %s", strerror(errno));
                exit_failure(-1);
        }

        mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if (mem == MAP_FAILED) {
                log_msg(__LINE__, "mmap %s : this will result in failure of reconstructing .symtab", strerror(errno));
                exit_failure(-1);
        }
        ehdr = (ElfW(Ehdr) *)mem;
        shdr = (ElfW(Shdr) *)&mem[ehdr->e_shoff];

        if (lseek(fd, 0, SEEK_END) < 0) {
                log_msg(__LINE__, "lseek %s", strerror(errno));
                exit_failure(-1);
        }
	
        uint64_t symtab_offset = lseek(fd, 0, SEEK_CUR);
        for (i = 0; i < symcount; i++) {
                if( write(fd, (char *)&symtab[i], sizeof(ElfW(Sym))) == -1 ) {
                    log_msg(__LINE__, "write %s", strerror(errno));
                    exit_failure(-1);
                }
        }
      	StringTable = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset];
        /* Write section hdr string table */
        uint64_t stloff = lseek(fd, 0, SEEK_CUR);
        if( write(fd, strtab, symstroff) == -1) {
            log_msg(__LINE__, "write %s", strerror(errno));
            exit_failure(-1);
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
	int i, dynamic;

	dynamic = !(handle->elfstat.personality & ELF_STATIC);
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
	
	if (dynamic) {
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
	}
	
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
	
	if (dynamic) {
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
	}

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

        
	if (dynamic) {
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
       } 
       	/*
       	 * .eh_frame
	 */
        shdr[scount].sh_type = SHT_PROGBITS;
	/*
	 * For dynamically linked case:
 	 * .eh_frame starts safter .eh_frame_hdr, so we that's why to get the offset
	 * we do sh_offset = elfdesc->ehFrameOffset + elfdesc->ehframe_size;
	 * in other words, elfdesc->ehframeOffset points to eh_frame_hdr not eh_frame
	 */
	shdr[scount].sh_offset = dynamic ? (elfdesc->ehframeOffset + elfdesc->ehframe_Size) : elfdesc->ehframeOffset;
        // XXX workaround for an alignment bug where eh_frame has 4 bytes of zeroes
        // that should not be there at the beggining
	if (*(uint32_t *)&elfdesc->mem[shdr[scount].sh_offset] == (uint32_t)0x00000000) {
		shdr[scount].sh_offset += 4;
		global_hacks.eh_frame_offset_workaround = 1; // XXX ugly hack
	}
	shdr[scount].sh_addr = dynamic ? (elfdesc->ehframe_Vaddr + elfdesc->ehframe_Size) : global_hacks.ehframe_vaddr;
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

	if (dynamic) {
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
	}
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
	
	if (dynamic) {
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
		log_msg(__LINE__, "FATAL: write %s", strerror(errno));
		exit_failure(-1);
	}
        fsync(fd);
        close(fd);
        
	fd = xopen(filepath, O_RDWR);
        
        if (fstat(fd, &st) < 0) {
                log_msg(__LINE__, "FATAL: fstat %s", strerror(errno));
                exit_failure(-1);
        }

        uint8_t *mem = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if (mem == MAP_FAILED) {
                log_msg(__LINE__, "FATAL: mmap %s (%lx bytes)", strerror(errno), st.st_size);
                exit_failure(-1);
        }

        ElfW(Ehdr *)ehdr = (ElfW(Ehdr) *)mem;
        ehdr->e_entry = memdesc->o_entry; // this is unsigned
	ehdr->e_shoff = e_shoff;
        ehdr->e_shstrndx = e_shstrndx;
	ehdr->e_shentsize = sizeof(ElfW(Shdr));
        ehdr->e_shnum = scount;
        ehdr->e_type = ET_NONE;
	
	msync(mem, 4096, MS_SYNC);
        munmap(mem, 4096);

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
	/*
	 * It is possible that a single write could be huge
	 * i.e. larger than 2GB and will cause write to fail.
	 * therefore lets do this in incremental writes.
	 */	
	const int CHUNK_SIZE = 0x100000;
	size_t foffset = 0;
	ssize_t len = st.st_size;
	
	do {
		if (len < CHUNK_SIZE) {
			if (write(fd, &elfdesc->mem[foffset], len) != len) {
				log_msg(__LINE__, "write failed: %s", strerror(errno));
				exit_failure(-1);
			}
			break;
		}
		if (write(fd, &elfdesc->mem[foffset], CHUNK_SIZE) < 0) {
			log_msg(__LINE__, "write failed: %s", strerror(errno));
			exit_failure(-1);
		}
		foffset += CHUNK_SIZE;
		len -= CHUNK_SIZE;
	} while(len > 0);

	/*
	 * write prstatus structs
	 */
	if( write(fd, notedesc->prstatus, sizeof(struct elf_prstatus)) == -1 ) {
            log_msg(__LINE__, "write %s", strerror(errno));
            exit_failure(-1);
        }
	for (i = 1; i < notedesc->thread_count; i++) {
		if( write(fd, notedesc->thread_core_info[i].prstatus, sizeof(struct elf_prstatus)) == -1) {
                    log_msg(__LINE__, "write %s", strerror(errno));
                    exit_failure(-1);
                }
        }
	
	/*
	 * write fdinfo structs
	 */
	if( write(fd, memdesc->fdinfo, ecfs_file->fdinfo_size) == -1) {
            log_msg(__LINE__, "write %s", strerror(errno));
        }

	/*
	 * write siginfo_t struct
	 */
	if( write(fd, notedesc->siginfo, sizeof(siginfo_t)) == -1) {
            log_msg(__LINE__, "write %s", strerror(errno));
        }
	
	/*
 	 * write auxv data
	 */
	if( write(fd, notedesc->auxv, notedesc->auxv_size) == -1) {
            log_msg(__LINE__, "write %s", strerror(errno));
        }
	
	/*
	 * write exepath string
	 */
	if( write(fd, memdesc->exe_path, strlen(memdesc->exe_path) + 1) == -1) {
            log_msg(__LINE__, "write %s", strerror(errno));
        }

	/*
	 * write ELF personality
	 */
	build_elf_stats(handle);
	if( write(fd, &handle->elfstat, sizeof(elf_stat_t)) == -1) { 
            log_msg(__LINE__, "write %s", strerror(errno));
        }
	
	/*
	 * write .arglist section data
	 */
	if( write(fd, handle->arglist, ELF_PRARGSZ) == -1) {
            log_msg(__LINE__, "write %s", strerror(errno));
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
	mem = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		log_msg(__LINE__, "mmap %s", strerror(errno));
		return -1;
	}

	ehdr = (ElfW(Ehdr) *)mem;
	ehdr->e_shoff = ecfs_file->stb_offset;
	ehdr->e_shnum = shnum;
	munmap(mem, 4096);
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
	
