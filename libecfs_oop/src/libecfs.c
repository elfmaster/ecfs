
/*
 * libecfs.cpp
 * This source code was directly transcribed from libecfs.c. Therefore because the original code was
 * written in C, there is still a great deal of C code.
 */

#include "../include/libecfs.h"
#include "../include/util.h"

int Ecfs::load(const char *path)
{	
	Ecfs *ecfs = this;
	uint8_t *mem;
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	ElfW(Shdr) *shdr;
	int fd, i;
	struct stat st;

	fd = xopen(path, O_RDONLY);
	xfstat(fd, &st);
	ecfs->filesize = st.st_size;
	mem = (uint8_t *)mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	
	if (memcmp(mem, "\x7f\x45\x4c\x46", 4) != 0)
		return -1;
	
	ehdr = (ElfW(Ehdr) *)mem;
	
	if (ehdr->e_type != ET_NONE && ehdr->e_type != ET_CORE) 
		return -1;
	
	if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0 || ehdr->e_shstrndx == SHN_UNDEF) 
		return -1;
	
	phdr = (ElfW(Phdr) *)(mem + ehdr->e_phoff);
	shdr = (ElfW(Shdr) *)(mem + ehdr->e_shoff);
	
	/*
	 * setup section header string table
	 */
	ecfs->shstrtab = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset];
	
	/*
	 * setup .dynsym symbols, .symtab symbols, and .dynstr and .strtab string table
	 */
	for (ecfs->dynstr = NULL, i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".dynstr")) 
			ecfs->dynstr = (char *)&mem[shdr[i].sh_offset];
		else
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".strtab"))
			ecfs->strtab = (char *)&mem[shdr[i].sh_offset];
		else
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".dynsym")) 
			ecfs->dynsym = (ElfW(Sym) *)&mem[shdr[i].sh_offset];
		else
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".symtab"))
			ecfs->symtab = (ElfW(Sym) *)&mem[shdr[i].sh_offset];
	}
	
	
	/*
	 * Find .dynamic, .text, and .data segment/section
	 */
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".dynamic")) {
			ecfs->dynVaddr = shdr[i].sh_addr;
			ecfs->dynSize = shdr[i].sh_size;
			ecfs->dynOff = shdr[i].sh_offset;
			ecfs->dyn = (ElfW(Dyn) *)&mem[shdr[i].sh_offset];
		} else
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], "._DATA")) {
			ecfs->dataVaddr = shdr[i].sh_addr;
			ecfs->dataSize = shdr[i].sh_size;
			ecfs->dataOff = shdr[i].sh_offset;
		} else
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], "._TEXT")) {
			ecfs->textVaddr = shdr[i].sh_addr;
			ecfs->textSize = shdr[i].sh_size;
			ecfs->textOff = shdr[i].sh_offset;
		}
	}
	/*
	 * Get dynamic relocation sections
	 */
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".rela.dyn")) {
			ecfs->dyn_rela = (ElfW(Rela) *)&mem[shdr[i].sh_offset];
			ecfs->dyn_rela_count = shdr[i].sh_size / shdr[i].sh_entsize;
			break;
		}
	}

	/*
	 * Get plt relocation sections
	 */
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".rela.plt")) {
			ecfs->plt_rela = (ElfW(Rela) *)&mem[shdr[i].sh_offset];
			ecfs->plt_rela_count = shdr[i].sh_size / shdr[i].sh_entsize;
			break;
		}
	}
	
	/*
	 * set the pltgot pointer
	 */
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".got.plt")) {
			ecfs->pltgot = (unsigned long *)&mem[shdr[i].sh_offset];
			break;
		}
	}
	
	/*
	 * Get plt addr and size
	 */
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".plt")) {
			ecfs->pltVaddr = shdr[i].sh_addr;
			ecfs->pltSize = shdr[i].sh_size;
			break;
		}
	}

	/*
	 * Get .personality info
	 */
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".personality")) {
			ecfs->elfstats = (elf_stat_t *)&mem[shdr[i].sh_offset];
			break;
		}
	}
	if (ecfs->elfstats->personality & ELF_PIE)
		ecfs->pie = 1;

	ecfs->ehdr = ehdr;
	ecfs->phdr = phdr;
	ecfs->shdr = shdr;
	ecfs->mem = mem;
	
	return 0;
}	

void Ecfs::unload(void)
{
	munmap(this->mem, this->filesize);
}


std::vector<fdinfo> Ecfs::get_fdinfo(void)
{
	Ecfs *desc = this;
	char *StringTable = desc->shstrtab;
	ElfW(Shdr) *shdr = desc->shdr;
	struct fdinfo *fdinfo_ptr;
	
	/*
	 * By default std::vector uses an allocator for the heap so we
	 * can return the fdinfo_vec by reference, but we will go ahead
	 * and do it by value
	 */
	std::vector <fdinfo> fdinfo_vec;
	size_t items;

	for (int i = 0; i < desc->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".fdinfo")) {
			fdinfo_ptr = (struct fdinfo *)alloca(shdr[i].sh_size);
			memcpy(fdinfo_ptr, &desc->mem[shdr[i].sh_offset], shdr[i].sh_size);
			items = shdr[i].sh_size / sizeof(struct fdinfo);
			fdinfo_vec.assign(fdinfo_ptr, &fdinfo_ptr[items]);
		}
	}
    	/*
       	 * In addition to returning a vector we assign the internal
         * copy as well that can be used at any time until the Ecfs object is
         * destructed.
         */
	//this->fdinfo_vector = fdinfo_vec;
	return fdinfo_vec;
}

std::vector<elf_prstatus>  Ecfs::get_prstatus(void)
{
	char *StringTable = this->shstrtab;
	ElfW(Shdr) *shdr = this->shdr;
	struct elf_prstatus *prstatus;
	std::vector <elf_prstatus> prstatus_vec;
	size_t items;

	for (int i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".prstatus")) {
			prstatus = (struct elf_prstatus *)alloca(shdr[i].sh_size);
			memcpy(prstatus, &this->mem[shdr[i].sh_offset], shdr[i].sh_size);
			items = shdr[i].sh_size / sizeof(struct elf_prstatus);
			prstatus_vec.assign(prstatus, &prstatus[items]);
		}
	}
	/*
	 * In addition to returning a vector we assign the internal
	 * copy as well that can be used at any time until the Ecfs object is
	 * destructed.
	 */
	//this->prstatus_vector = prstatus_vec;
	return prstatus_vec;
}

int Ecfs::get_thread_count(void)
{
	char *StringTable = this->shstrtab;
	ElfW(Shdr) *shdr = this->shdr;
	int i;

	for (i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".prstatus")) 
			return shdr[i].sh_size / shdr[i].sh_entsize;
	}
	return -1;
}
	
char * Ecfs::get_exe_path(void)
{
	
	char *StringTable = this->shstrtab;
	ElfW(Shdr) *shdr = this->shdr;
	char *ret;
	
	for (int i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".exepath")) {
			ret = (char *)heapAlloc(shdr[i].sh_size);
			strcpy(ret, (char *)&this->mem[shdr[i].sh_offset]);
			return ret;	
		}
	}
	return NULL;
}

vector <ecfs_sym> Ecfs::get_dynamic_symbols(void)
{
	int i, j;
	ElfW(Ehdr) *ehdr = this->ehdr;
	ElfW(Shdr) *shdr = this->shdr;
	ssize_t symcount;
	ElfW(Sym) *dynsym = this->dynsym;
	vector <ecfs_sym> ecfs_sym_vec;
	ecfs_sym_t *syms;
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (shdr[i].sh_type == SHT_DYNSYM) {
			symcount = shdr[i].sh_size / sizeof(ElfW(Sym));
			size_t alloc_len = symcount * sizeof(ecfs_sym_t);
			syms = (ecfs_sym_t *)alloca(alloc_len);
			for (j = 0; j < symcount; j++) {
				syms[j].strtab = this->dynstr;
				syms[j].symval = dynsym[j].st_value;
				syms[j].size = dynsym[j].st_size;
				syms[j].type = ELF32_ST_TYPE(dynsym[j].st_info);
				syms[j].binding = ELF32_ST_BIND(dynsym[j].st_info);
				syms[j].nameoffset = dynsym[j].st_name;
			}
			ecfs_sym_vec.assign(syms, &syms[symcount]);
		}
	}
	return ecfs_sym_vec; // by value
}

int Ecfs::get_siginfo(siginfo_t *siginfo)
{
	char *StringTable = this->shstrtab;
	ElfW(Shdr) *shdr = this->shdr;
	int i;

	for (i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".siginfo")) {
			memcpy(siginfo, &this->mem[shdr[i].sh_offset], shdr[i].sh_size);
			return 0;
		}
	}

	return -1;
}

/*
 * This function takes a pointer passed by reference 
 * and assigns it to point at the given section. It also
 * returns the size of that section. This is a nice way to
 * do it so that the user can get both the section pointer
 * and size all in one. On failure -1 is returned
 * or *ptr = NULL
 */
ssize_t Ecfs::get_stack_ptr(uint8_t **ptr)
{
	char *StringTable = this->shstrtab;
	ElfW(Shdr) *shdr = this->shdr;
	int i, j;
	uint8_t *p;
	for (i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".stack")) {
			*ptr = &this->mem[shdr[i].sh_offset];
			p = *ptr;
			printf("found .stack\n");
			for (j = 0; j < shdr[i].sh_size; j++)
				printf("%02x", p[j]);
			return shdr[i].sh_size;
		}
	}

	*ptr = NULL;
	return -1;
}

#if 0
ssize_t get_heap_ptr(ecfs_elf_t *desc, uint8_t **ptr)
{
	char *StringTable = desc->shstrtab;
	ElfW(Shdr) *shdr = desc->shdr;
	int i;

	for (i = 0; i < desc->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".heap")) {
			*ptr = &desc->mem[shdr[i].sh_offset];
			return shdr[i].sh_size;
		}
	}
	
	*ptr = NULL;
	return -1;
}


int get_local_symbols(ecfs_elf_t *desc, ecfs_sym_t **syms)
{
	int i, j;
	ElfW(Ehdr) *ehdr = desc->ehdr;
	ElfW(Shdr) *shdr = desc->shdr;
	ssize_t symcount;
	ElfW(Sym) *locsym = desc->symtab;

	for (i = 0; i < ehdr->e_shnum; i++) {
		if (shdr[i].sh_type == SHT_SYMTAB) {
			symcount = shdr[i].sh_size / sizeof(ElfW(Sym));
			size_t alloc_len = symcount * sizeof(ecfs_sym_t);
			*syms = (ecfs_sym_t *)heapAlloc(alloc_len);
			for (j = 0; j < symcount; j++) {
				(*syms)[j].strtab = desc->dynstr;
				(*syms)[j].symval = locsym[j].st_value;
				(*syms)[j].size = locsym[j].st_size;
				(*syms)[j].type = ELF32_ST_TYPE(locsym[j].st_info);
				(*syms)[j].binding = ELF32_ST_BIND(locsym[j].st_info);
				(*syms)[j].nameoffset = locsym[j].st_name;
			}
			return symcount;
		}
	}
	return 0;
}
						

ssize_t get_ptr_for_va(ecfs_elf_t *desc, unsigned long vaddr, uint8_t **ptr)
{
	ElfW(Ehdr) *ehdr = desc->ehdr;
	ElfW(Phdr) *phdr = desc->phdr;
	ssize_t len;
	int i;
	
	for (i = 0; i < ehdr->e_phnum; i++) {
		if (vaddr >= phdr[i].p_vaddr && vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
			*ptr = (uint8_t *)&desc->mem[phdr[i].p_offset + (vaddr - phdr[i].p_vaddr)];
			len = phdr[i].p_vaddr + phdr[i].p_memsz - vaddr;
			return len;
		}
	}
	*ptr = NULL;
	return -1;
	
}

/*
 * i.e. len = get_section_pointer(desc, ".bss", &ptr);
 */
ssize_t get_section_pointer(ecfs_elf_t *desc, const char *name, uint8_t **ptr)
{
	char *StringTable = desc->shstrtab;
	ElfW(Shdr) *shdr = desc->shdr;
	ssize_t len;
	int i;

	for (i = 0; i < desc->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], name)) {
			*ptr = (uint8_t *)&desc->mem[shdr[i].sh_offset];
			len = shdr[i].sh_size;
			return len;
		}		
	}
	*ptr = NULL;
	return -1;
}

/*
 * i.e len = get_section_size(desc, ".bss");
 */
ssize_t get_section_size(ecfs_elf_t *desc, const char *name)
{
	char *StringTable = desc->shstrtab;
	ElfW(Shdr) *shdr = desc->shdr;
	ssize_t len;
	int i;

	for (i = 0; i < desc->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], name)) {
			len = shdr[i].sh_size;
			return len;
		}
	}
	return -1;
}

unsigned long get_section_va(ecfs_elf_t *desc, const char *name)
{
	char *StringTable = desc->shstrtab;
	ElfW(Shdr) *shdr = desc->shdr;
	int i;
	unsigned long addr;

	for (i = 0; i < desc->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], name)) {
			addr = shdr[i].sh_addr;
			return addr;
		}
	}
	return 0;
}



unsigned long get_text_va(ecfs_elf_t *desc)
{
	return desc->textVaddr;
}

unsigned long get_data_va(ecfs_elf_t *desc)
{
	return desc->dataVaddr;
}

size_t get_text_size(ecfs_elf_t *desc)
{
	return desc->textSize;
}

size_t get_data_size(ecfs_elf_t *desc)
{
	return desc->dataSize;
}

unsigned long get_plt_va(ecfs_elf_t *desc)
{
	return desc->pltVaddr;
}

unsigned long get_plt_size(ecfs_elf_t *desc)
{
	return desc->pltSize;
}

int get_auxiliary_vector32(ecfs_elf_t *desc, Elf32_auxv_t **auxv)
{
	ElfW(Ehdr) *ehdr = desc->ehdr;
	ElfW(Shdr) *shdr = desc->shdr;
	char *shstrtab = (char *)&desc->mem[shdr[ehdr->e_shstrndx].sh_offset];
	int i, ac = 0;

	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&shstrtab[shdr[i].sh_name], ".auxvector")) {
			ac = shdr[i].sh_size / sizeof(**auxv);
			*auxv = (Elf32_auxv_t *)&desc->mem[shdr[i].sh_offset];
			break;
		}
	}
	return ac;
}

int get_auxiliary_vector64(ecfs_elf_t *desc, Elf64_auxv_t **auxv)
{
	ElfW(Ehdr) *ehdr = desc->ehdr;
	ElfW(Shdr) *shdr = desc->shdr;
	char *shstrtab = (char *)&desc->mem[shdr[ehdr->e_shstrndx].sh_offset];
	int i, ac = 0;

	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&shstrtab[shdr[i].sh_name], ".auxvector")) {
			ac = shdr[i].sh_size / sizeof(**auxv);
			*auxv = (Elf64_auxv_t *)&desc->mem[shdr[i].sh_offset];
			break;
		}
	}
	return ac;
}
	
int get_shlib_mapping_names(ecfs_elf_t *desc, char ***shlvec)
{
	int i, count, c;	
	char *shstrtab = desc->shstrtab;
	ElfW(Shdr) *shdr = desc->shdr;
	
	for (count = 0, i = 0; i < desc->ehdr->e_shnum; i++) 
		if (shdr[i].sh_type == SHT_SHLIB || shdr[i].sh_type == SHT_INJECTED || shdr[i].sh_type == SHT_PRELOADED)
			count++;
	if (count == 0)
		return 0;
	
	*shlvec = (char **)calloc(count + 1, sizeof(char *));
	for (c = 0, i = 0; i < desc->ehdr->e_shnum; i++) {
		if (shdr[i].sh_type == SHT_SHLIB || shdr[i].sh_type == SHT_INJECTED || shdr[i].sh_type == SHT_PRELOADED) 
			*((*shlvec) + c++) = strdup(&shstrtab[shdr[i].sh_name]);
	}	
	return count;
}


/*
 * This function fills in this struct:
   typedef struct pltgotinfo {
		unsigned long got_site; // address of where the GOT entry exists
		unsigned long got_entry_va; // address that is in the GOT entry (the pointer address)
		unsigned long plt_entry_va; // the PLT address that the GOT entry should point to if not yet resolved
		unsigned long shl_entry_va; // the shared library address the GOT should point to if it has been resolved
} pltgot_info_t;
*/
ssize_t get_pltgot_info(ecfs_elf_t *desc, pltgot_info_t **pginfo)
{	
	int i;
	unsigned long *GOT = NULL;
	ElfW(Sym) *symtab = desc->dynsym;
	ElfW(Sym) *sym;
	ElfW(Addr) pltVaddr;
	size_t pltSize;
	
	if ((pltVaddr = get_plt_va(desc)) == 0)
		return -1;
	if ((pltSize = get_plt_size(desc)) == 0)
		return -1;
	if (desc->plt_rela_count == 0 || desc->plt_rela == NULL || symtab == NULL)
		return -1;
	
	*pginfo = (pltgot_info_t *)heapAlloc(desc->plt_rela_count * sizeof(pltgot_info_t));
	GOT = &desc->pltgot[3]; // the first 3 entries are reserved
	pltVaddr += 16; // we want to start at the PLT entry after what is called PLT-0
	for (i = 0; i < desc->plt_rela_count; i++) {
		(*pginfo)[i].got_site = desc->plt_rela[i].r_offset;
		(*pginfo)[i].got_entry_va = (unsigned long)GOT[i];
		 sym = (ElfW(Sym) *)&symtab[ELF64_R_SYM(desc->plt_rela[i].r_info)];
		(*pginfo)[i].shl_entry_va = sym->st_value;
		 // the + 6 is because it must point to the push instruction in the plt entry
		(*pginfo)[i].plt_entry_va = (pltVaddr + 6); // + (desc->pie ? desc->textVaddr : 0); 
		pltVaddr += 16;
	}
	return i;
}

unsigned long get_fault_location(ecfs_elf_t *desc)
{
	siginfo_t siginfo;
	
	if (get_siginfo(desc, &siginfo) < 0)
		return 0;

	return (unsigned long)siginfo.si_addr;
}

/*
 * Returns argc and allocated and fills argv
 */
int get_arg_list(ecfs_elf_t *desc, char ***argv)
{
	unsigned int i, argc, c;
	ElfW(Ehdr) *ehdr = desc->ehdr;
	ElfW(Shdr) *shdr = desc->shdr;
	uint8_t *mem = desc->mem;
	char *shstrtab = desc->shstrtab;
	char *p = NULL;
	char *q = NULL;

	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&shstrtab[shdr[i].sh_name], ".arglist")) {
			*argv = (char **)heapAlloc(sizeof(char *) * MAX_ARGS);		
			p = (char *)&mem[shdr[i].sh_offset];
			for (argc = 0, c = 0; c < shdr[i].sh_size; ) {
				*((*argv) + argc++) = xstrdup(p);
				 q = strchr(p, '\0') + 1;
				 c += (q - p);
				 p = q;
			}
			return argc;
		}
	}
	**argv = NULL;
	return -1;
}

char * get_section_name_by_addr(ecfs_elf_t *desc, unsigned long addr)
{
	ElfW(Ehdr) *ehdr = desc->ehdr;
	ElfW(Shdr) *shdr = desc->shdr;
	char *shstrtab = desc->shstrtab;
	int i;

	for (i = 0; i < ehdr->e_shnum; i++) 
		if (shdr[i].sh_addr == addr)
			return &shstrtab[shdr[i].sh_name];
	return NULL;
}
#endif
