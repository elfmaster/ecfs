#include "../include/libecfs.hpp"


/*
 * NOTE:
 * Since the template type 'ecfs_type' is not passed as any arguments
 * to Ecfs::load(), we have to atleast specify it in the declaration of
 * the function template, hence the int Ecfs<ecfs_type>::load()
 */
template <class ecfs_type> int Ecfs<ecfs_type>::load(const string path)
{	
	Ecfs *ecfs = this;
	uint8_t *mem;
	int fd, i;
	struct stat st;
	Ecfs::Ehdr *ehdr;
	Ecfs::Phdr *phdr;
	Ecfs::Shdr *shdr;

	fd = xopen(path.c_str(), O_RDONLY);
	xfstat(fd, &st);
	ecfs->filesize = st.st_size;
	mem = (uint8_t *)mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	
	if (memcmp(mem, "\x7f\x45\x4c\x46", 4) != 0)
		return -1;
	
	ehdr = (Ehdr *)mem;
	
	if (ehdr->e_type != ET_NONE && ehdr->e_type != ET_CORE) 
		return -1;
	
	if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0 || ehdr->e_shstrndx == SHN_UNDEF) 
		return -1;
	
	phdr = (Phdr *)(mem + ehdr->e_phoff);
	shdr = (Shdr *)(mem + ehdr->e_shoff);
	
	/*
	 * setup section header string table
	 */
	ecfs->shstrtab = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset];
	ecfs->m_shstrtab = ecfs->shstrtab;
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
			ecfs->dynsym = (Ecfs::Sym *)&mem[shdr[i].sh_offset];
		else
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".symtab"))
			ecfs->symtab = (Ecfs::Sym *)&mem[shdr[i].sh_offset];
	}
	
	
	/*
	 * Find .dynamic, .text, and .data segment/section
	 */
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".dynamic")) {
			ecfs->dynVaddr = shdr[i].sh_addr;
			ecfs->dynSize = shdr[i].sh_size;
			ecfs->dynOff = shdr[i].sh_offset;
			ecfs->dyn = (Ecfs::Dyn *)&mem[shdr[i].sh_offset];
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
			ecfs->dyn_rela = (Ecfs::Rela *)&mem[shdr[i].sh_offset];
			ecfs->dyn_rela_count = shdr[i].sh_size / shdr[i].sh_entsize;
			break;
		}
	}

	/*
	 * Get plt relocation sections
	 */
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".rela.plt")) {
			ecfs->plt_rela = (Ecfs::Rela *)&mem[shdr[i].sh_offset];
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
	ecfs->filepath = path;
	
	/*
	 * Now that we have assigned all of the private pointers and variables
	 * lets set the internal vectors.
	 */
	this->get_fdinfo(this->m_fdinfo);
	this->get_pltgot_info(this->m_pltgot);
	this->gen_dynamic_symbols();
	this->gen_local_symbols();
	this->gen_prstatus();
	this->get_auxv(this->m_auxv);
	this->get_shlib_maps(this->m_shlib);
	this->get_phdrs(this->m_phdr);
	this->get_shdrs(this->m_shdr);

	/*
	 * set argv
	 */
	this->gen_argv();

	return 0;
}	

template int Ecfs<ecfs_type32>::load(const string);
template int Ecfs<ecfs_type64>::load(const string);





template <class ecfs_type> 
void Ecfs<ecfs_type>::unload(void)
{
	munmap(this->mem, this->filesize);
}

template void Ecfs<ecfs_type32>::unload(void);
template void Ecfs<ecfs_type64>::unload(void);

/*
 * Use like:
 *       Ecfs <ecfs_type64>ecfs(argv[1]);
 *       vector <fdinfo_64> fdinfo_vector;
 *       if (ecfs.get_fdinfo(fdinfo_vector) < 0) {
 *               printf("Getting fdinfo failed\n");
 *       }
 *	 for (i = 0; i < fdinfo_vector.size(); i++)
 * 	 	printf("filepath: %s\n", fdinfo_vector[i].path);
 *
*/
template <class ecfs_type>
int Ecfs<ecfs_type>::get_fdinfo(std::vector<Ecfs::fdinfo> &fdinfo_vec)
{
	Ecfs *desc = this;
	char *StringTable = desc->shstrtab;
	Ecfs::Shdr *shdr = desc->shdr;
	Ecfs::fdinfo *fdinfo_ptr;
	
	/*
	 * By default std::vector uses an allocator for the heap so we
	 * can return the fdinfo_vec by reference, but we will go ahead
	 * and do it by value
	 */
	//std::vector <Ecfs::fdinfo> fdinfo_vec;
	size_t items;

	for (int i = 0; i < desc->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".fdinfo")) {
			fdinfo_ptr = (Ecfs::fdinfo *)alloca(shdr[i].sh_size);
			memcpy(fdinfo_ptr, &desc->mem[shdr[i].sh_offset], shdr[i].sh_size);
			items = shdr[i].sh_size / sizeof(Ecfs::fdinfo);
			fdinfo_vec.assign(fdinfo_ptr, &fdinfo_ptr[items]);
			return fdinfo_vec.size();
		}
	}
	return -1; // failed if we got here
}

template int Ecfs<ecfs_type32>::get_fdinfo(std::vector<Ecfs::fdinfo> &);
template int Ecfs<ecfs_type64>::get_fdinfo(std::vector<Ecfs::fdinfo> &);


template <class ecfs_type>
void Ecfs<ecfs_type>::gen_prstatus()
{
	char *StringTable = this->shstrtab;
	Ecfs::Shdr *shdr = this->shdr;
	std::vector<Ecfs::prstatus> prstatus_vec;
	Ecfs::prstatus *prstatus;
	uint64_t items;

	for (int i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".prstatus")) {
			prstatus = (Ecfs::prstatus *)&this->mem[shdr[i].sh_offset];
			items = shdr[i].sh_size / sizeof(Ecfs::prstatus);
			prstatus_vec.assign(prstatus, &prstatus[items]);
			break;
		}
	}
	this->m_prstatus = prstatus_vec;
}

template void Ecfs<ecfs_type32>::gen_prstatus();
template void Ecfs<ecfs_type64>::gen_prstatus();

template <class ecfs_type>
int Ecfs<ecfs_type>::get_thread_count(void)
{
	char *StringTable = this->shstrtab;
	Ecfs::Shdr *shdr = this->shdr;
	int i;

	for (i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".prstatus")) 
			return shdr[i].sh_size / shdr[i].sh_entsize;
	}
	return -1;
}
	

template int Ecfs<ecfs_type32>::get_thread_count(void);
template int Ecfs<ecfs_type64>::get_thread_count(void);

template <class ecfs_type>
char * Ecfs<ecfs_type>::get_exe_path(void)
{
	
	char *StringTable = this->shstrtab;
	Ecfs::Shdr *shdr = this->shdr;
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

template char * Ecfs<ecfs_type32>::get_exe_path(void);
template char * Ecfs<ecfs_type64>::get_exe_path(void);


template <class ecfs_type>
void Ecfs<ecfs_type>::gen_dynamic_symbols()
{
	int i, j;
	ssize_t symcount;
	Ecfs::Ehdr *ehdr = this->ehdr;
	Ecfs::Shdr *shdr = this->shdr;
	Ecfs::Sym *dynsym = this->dynsym;
	
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (shdr[i].sh_type == SHT_DYNSYM) {
			symcount = shdr[i].sh_size / sizeof(Ecfs::Sym);

			for (j = 0; j < symcount; j++) {
				ecfs_sym_t sym;

				sym.strtab = this->dynstr;
				sym.symval = dynsym[j].st_value;
				sym.size = dynsym[j].st_size;
				sym.type = ELF32_ST_TYPE(dynsym[j].st_info);
				sym.binding = ELF32_ST_BIND(dynsym[j].st_info);
				sym.nameoffset = dynsym[j].st_name;
				sym.name = &this->dynstr[sym.nameoffset];

				this->m_symtab.emplace_back(sym);
			}
			return;
		}
	}
}
template void Ecfs<ecfs_type32>::gen_dynamic_symbols();
template void Ecfs<ecfs_type64>::gen_dynamic_symbols();


/*
 * We only use a 64bit version if siginfo_t with this
 * function. There are too many oddities with this struct
 * and glibc to redefine it as both 32bit and 64bit I have
 * tried. This isn't a blocker however though because the first
 * 6 members are the same whether it be in 64bit or 32bit and
 * that's typically all we need from this structure to get the
 * most interesting data, including signal numbers etc.
 * In the future I may fix this by storing a custom siginfo_t
 * structure within the .siginfo section of an ECFS file but I will
 * have to change the ecfs code itself. This custom siginfo_t will
 * contain only the first few members, similar to elf_siginfo struct.
 *
 */
template <class ecfs_type>
int Ecfs<ecfs_type>::get_siginfo(siginfo_t &siginfo)
{
	char *StringTable = this->shstrtab;
	Ecfs::Shdr *shdr = this->shdr;
	int i;

	for (i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".siginfo")) {
			siginfo = *(siginfo_t *)(&this->mem[shdr[i].sh_offset]);
			return 0;
		}
	}

	return -1;
}
template int Ecfs<ecfs_type32>::get_siginfo(siginfo_t &);
template int Ecfs<ecfs_type64>::get_siginfo(siginfo_t &);

/*
 * This function takes a pointer passed by reference 
 * and assigns it to point at the given section. It also
 * returns the size of that section. This is a nice way to
 * do it so that the user can get both the section pointer
 * and size all in one. On failure -1 is returned
 * or *ptr = NULL
 *
 * Example:
 * uint8_t *ptr;
 * ssize_t stack_size = ecfs.get_stack_ptr(ptr);
 * for(; stack_size != -1 && stack_size > 0; stack_size--)
 *	printf("stack_byte: %02x\n", *ptr);
 *
 */
template <class ecfs_type>
ssize_t Ecfs<ecfs_type>::get_stack_ptr(uint8_t *&ptr)
{
	char *StringTable = this->shstrtab;
	Ecfs::Shdr *shdr = this->shdr;
	int i;
	for (i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".stack")) {
			ptr = &this->mem[shdr[i].sh_offset];
			return shdr[i].sh_size;
		}
	}

	ptr = NULL;
	return -1;
}
template ssize_t Ecfs<ecfs_type32>::get_stack_ptr(uint8_t *&);
template ssize_t Ecfs<ecfs_type64>::get_stack_ptr(uint8_t *&);



template <class ecfs_type>
ssize_t Ecfs<ecfs_type>::get_heap_ptr(uint8_t *&ptr)
{
	char *StringTable = this->shstrtab;
	Ecfs::Shdr *shdr = this->shdr;
	int i;

	for (i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".heap")) {
			ptr = &this->mem[shdr[i].sh_offset];
			return shdr[i].sh_size;
		}
	}
	
	ptr = NULL;
	return -1;
}
template ssize_t Ecfs<ecfs_type32>::get_heap_ptr(uint8_t *&);
template ssize_t Ecfs<ecfs_type64>::get_heap_ptr(uint8_t *&);


template <class ecfs_type>
void Ecfs<ecfs_type>::gen_local_symbols()
{
	int i, j;
	Ecfs::Sym *symtab = this->symtab;
	Ecfs::Ehdr *ehdr = this->ehdr;
	Ecfs::Shdr *shdr = this->shdr;
	ssize_t symcount;

	for (i = 0; i < ehdr->e_shnum; i++) {
		if (shdr[i].sh_type == SHT_SYMTAB) {
			symcount = shdr[i].sh_size / sizeof(Ecfs::Sym);
			for (j = 0; j < symcount; j++) {
				ecfs_sym_t sym;

				sym.strtab = this->strtab;
				sym.symval = symtab[j].st_value;
				sym.size = symtab[j].st_size;
				sym.type = ELF32_ST_TYPE(symtab[j].st_info);
				sym.binding = ELF32_ST_BIND(symtab[j].st_info);
				sym.nameoffset = symtab[j].st_name;
				sym.name = &this->strtab[sym.nameoffset];

				this->m_symtab.emplace_back(sym);
			}
			return;
		}
	}
}
template void Ecfs<ecfs_type32>::gen_local_symbols();
template void Ecfs<ecfs_type64>::gen_local_symbols();


/*
 * Example of using get_ptr_for_va(). Lets zero out part of a segment
 * starting at an arbitrary address within the segment.
 *
 * uint8_t *ptr;
 * ssize_t bytes_left_in_segment = ecfs.get_ptr_for_va(0x4000ff, ptr);
 * if (ptr) 
 * 	for (int i = 0; i < bytes_left_in_segment; i++) 
 * 		ptr[i] = 0;
 * 
 */
template <class ecfs_type>
ssize_t Ecfs<ecfs_type>::get_ptr_for_va(unsigned long vaddr, uint8_t *&ptr)
{
	Ecfs::Ehdr *ehdr = this->ehdr;
	Ecfs::Phdr *phdr = this->phdr;
	ssize_t len;
	int i;
	
	for (i = 0; i < ehdr->e_phnum; i++) {
		if (vaddr >= phdr[i].p_vaddr && vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
			ptr = (uint8_t *)&this->mem[phdr[i].p_offset + (vaddr - phdr[i].p_vaddr)];
			len = phdr[i].p_vaddr + phdr[i].p_memsz - vaddr;
			return len;
		}
	}
	ptr = NULL;
	return -1;
	
}

template ssize_t Ecfs<ecfs_type32>::get_ptr_for_va(unsigned long, uint8_t *&ptr);
template ssize_t Ecfs<ecfs_type64>::get_ptr_for_va(unsigned long, uint8_t *&ptr);

/*
 * Example of us printing out the uninitialized data memory
 * from .bss section:
 *
 * len = ecfs.get_section_pointer(".bss", ptr);
 * for (int i = 0; i < len; i++)
 * 	printf("%02x\n", ptr[i]);
 *
 */
template <class ecfs_type>
ssize_t Ecfs<ecfs_type>::get_section_pointer(const char *name, uint8_t *&ptr)
{
	char *StringTable = this->shstrtab;
	Ecfs::Shdr *shdr = this->shdr;
	ssize_t len;
	int i;

	for (i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], name)) {
			ptr = (uint8_t *)&this->mem[shdr[i].sh_offset];
			len = shdr[i].sh_size;
			return len;
		}		
	}
	ptr = NULL;
	return -1;
}

template ssize_t Ecfs<ecfs_type32>::get_section_pointer(const char *, uint8_t *&);
template ssize_t Ecfs<ecfs_type64>::get_section_pointer(const char *, uint8_t *&);

/*
 * i.e len = get_section_size(desc, ".bss");
 */
template <class ecfs_type>
ssize_t Ecfs<ecfs_type>::get_section_size(const char *name)
{
	char *StringTable = this->shstrtab;
	Ecfs::Shdr *shdr = this->shdr;
	ssize_t len;
	int i;

	for (i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], name)) {
			len = shdr[i].sh_size;
			return len;
		}
	}
	return -1;
}
template ssize_t Ecfs<ecfs_type32>::get_section_size(const char *);
template ssize_t Ecfs<ecfs_type64>::get_section_size(const char *);







template <class ecfs_type>
unsigned long Ecfs<ecfs_type>::get_section_va(const char *name)
{
	char *StringTable = this->shstrtab;
	Ecfs::Shdr *shdr = this->shdr;
	int i;
	unsigned long addr;

	for (i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], name)) {
			addr = shdr[i].sh_addr;
			return addr;
		}
	}
	return 0;
}

template unsigned long Ecfs<ecfs_type32>::get_section_va(const char *);
template unsigned long Ecfs<ecfs_type64>::get_section_va(const char *);

template <class ecfs_type>
unsigned long Ecfs<ecfs_type>::get_text_va(void)
{
	return this->textVaddr;
}

template unsigned long Ecfs<ecfs_type32>::get_text_va(void);
template unsigned long Ecfs<ecfs_type64>::get_text_va(void);

template <class ecfs_type>
unsigned long Ecfs<ecfs_type>::get_data_va(void)
{
	return this->dataVaddr;
}


template unsigned long Ecfs<ecfs_type32>::get_data_va(void);
template unsigned long Ecfs<ecfs_type64>::get_data_va(void);

template <class ecfs_type>
size_t Ecfs<ecfs_type>::get_text_size(void) 
{
	return this->textSize;
}

template size_t Ecfs<ecfs_type32>::get_text_size(void);
template size_t Ecfs<ecfs_type64>::get_text_size(void);

template <class ecfs_type>
size_t Ecfs<ecfs_type>::get_data_size(void)
{
	return this->dataSize;
}

template size_t Ecfs<ecfs_type32>::get_data_size(void);
template size_t Ecfs<ecfs_type64>::get_data_size(void);

template <class ecfs_type>
unsigned long Ecfs<ecfs_type>::get_plt_va(void)
{
	return this->pltVaddr;
}

template unsigned long Ecfs<ecfs_type32>::get_plt_va(void);
template unsigned long Ecfs<ecfs_type64>::get_plt_va(void);

template <class ecfs_type>
size_t Ecfs<ecfs_type>::get_plt_size(void)
{
	return this->pltSize;
}

template size_t Ecfs<ecfs_type32>::get_plt_size(void);
template size_t Ecfs<ecfs_type64>::get_plt_size(void);



/*
 * Use a vector, why not? We are afterall dealing
 * with the 'auxiliary vector'
 */
template <class ecfs_type>
int Ecfs<ecfs_type>::get_auxv(vector <auxv_t> &auxv)
{
	Ecfs::Ehdr *ehdr = this->ehdr;
	Ecfs::Shdr *shdr = this->shdr;
	char *shstrtab = this->shstrtab;
	int i, ac = 0;
	Ecfs::auxv_t *auxp;

	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&shstrtab[shdr[i].sh_name], ".auxvector")) {
			ac = shdr[i].sh_size / sizeof(Ecfs::auxv_t);
			auxp = (Ecfs::auxv_t *)&this->mem[shdr[i].sh_offset];
			auxv.assign(auxp, auxp + ac);
			break;
		}
	}
	return ac;
}

template int Ecfs<ecfs_type32>::get_auxv(vector <auxv_t>&);
template int Ecfs<ecfs_type64>::get_auxv(vector <auxv_t>&);


template <class ecfs_type>
ssize_t Ecfs<ecfs_type>::get_shlib_maps(vector <ecfs_map *> &shlib)
{
	ssize_t i, count;	
	char *shstrtab = this->shstrtab;
	Ecfs::Shdr *shdr = this->shdr;
	ecfs_map shlibp;

	for (count = 0, i = 0; i < this->ehdr->e_shnum; i++) {
		switch(shdr[i].sh_type) {
			case SHT_SHLIB:
			case SHT_INJECTED:
			case SHT_PRELOADED:
				count++;
				shlibp.name = std::string(&shstrtab[shdr[i].sh_name]);
				shlibp.vaddr = shdr[i].sh_addr;
				shlibp.offset = shdr[i].sh_offset;
				shlibp.size = shdr[i].sh_size;
				shlib.emplace_back(&shlibp);
				break;
			default:
				continue;
		}
	}

	return count;
}

template ssize_t Ecfs<ecfs_type32>::get_shlib_maps(vector <ecfs_map *>&);
template ssize_t Ecfs<ecfs_type64>::get_shlib_maps(vector <ecfs_map *>&);


/*
 * XXX FALSE POSITIVES BUG
 * I'm not sure if this function is the culprit, or if its a problem with the
 * symbol resolution against certain shared libraries, but in really big GOT's
 * such as with sshd, there are incorrect values showing up, such as pginfo[N].got_entry_va
 * might have an address that doesn't match the proper shared library address, or the PLT address
 * which normally indicates a PLT/GOT hooks, but in this case, its verified that there are no
 * hooks, thus resulting in FALSE POSITIVES
*/

template <class ecfs_type>
ssize_t Ecfs<ecfs_type>::get_pltgot_info(vector <pltgotinfo_t> &pginfo)
{	
	ssize_t i;
	unsigned long *GOT = NULL;
	Ecfs::Sym *symtab = this->dynsym;
	Ecfs::Sym *sym;
	Ecfs::Addr pltVaddr;
	size_t pltSize;
	pltgotinfo_t *pginfo_ptr;

	if ((pltVaddr = this->get_plt_va()) == 0)
		return -1;
	if ((pltSize = this->get_plt_size()) == 0)
		return -1;
	if (this->plt_rela_count == 0 || this->plt_rela == NULL || symtab == NULL)
		return -1;
	pginfo_ptr = (pltgot_info_t *)alloca(this->plt_rela_count * sizeof(pltgotinfo_t));
	GOT = &this->pltgot[3]; // the first 3 entries are reserved
	pltVaddr += 16; // we want to start at the PLT entry after what is called PLT-0
	for (i = 0; i < this->plt_rela_count; i++) {
		pginfo_ptr[i].got_site = this->plt_rela[i].r_offset;
		pginfo_ptr[i].got_entry_va = (unsigned long)GOT[i];
		sym = (Ecfs::Sym *)&symtab[ELF64_R_SYM(this->plt_rela[i].r_info)];
		pginfo_ptr[i].shl_entry_va = sym->st_value;
		 // the + 6 is because it must point to the push instruction in the plt entry
		pginfo_ptr[i].plt_entry_va = (pltVaddr + 6); // + (desc->pie ? desc->textVaddr : 0); 
		pltVaddr += 16;
		pginfo.push_back(pginfo_ptr[i]);
	}
	return i;
}

template ssize_t Ecfs<ecfs_type32>::get_pltgot_info(vector <pltgotinfo_t> &);
template ssize_t Ecfs<ecfs_type64>::get_pltgot_info(vector <pltgotinfo_t> &);



template <class ecfs_type>
unsigned long Ecfs<ecfs_type>::get_fault_location()
{
	siginfo_t siginfo;
	
	if (this->get_siginfo(siginfo) < 0)
		return 0;

	return (unsigned long)siginfo.si_addr;
}

template unsigned long Ecfs<ecfs_type32>::get_fault_location();
template unsigned long Ecfs<ecfs_type64>::get_fault_location();


template <class ecfs_type>
void Ecfs<ecfs_type>::gen_argv()
{
	uint64_t i;
	Ecfs::Ehdr *ehdr = this->ehdr;
	Ecfs::Shdr *shdr = this->shdr;
	uint8_t *mem = this->mem;
	char *shstrtab = this->shstrtab;

	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&shstrtab[shdr[i].sh_name], ".arglist")) {
			std::string cur_string(reinterpret_cast<char *>(&mem[shdr[i].sh_offset]));

			// split the string on spaces
			std::string item;
			std::istringstream ss(cur_string);
			while (std::getline(ss, item, ' ')) {
				this->m_argv.push_back(item);
		    }

			break;
		}
	}
}
template void Ecfs<ecfs_type32>::gen_argv();
template void Ecfs<ecfs_type64>::gen_argv();

/*
 * Give an address as a parameter and return the name of the
 * section that the address resides in. 
 */
template <class ecfs_type>
char * Ecfs<ecfs_type>::get_section_name_by_addr(unsigned long addr)
{
	Ecfs::Ehdr *ehdr = this->ehdr;
	Ecfs::Shdr *shdr = this->shdr;
	char *shstrtab = this->shstrtab;
	int i;

	for (i = 0; i < ehdr->e_shnum; i++) 
		if (addr >= shdr[i].sh_addr && addr < shdr[i].sh_addr + shdr[i].sh_size)
			return &shstrtab[shdr[i].sh_name];
	return NULL;
}

template char * Ecfs<ecfs_type32>::get_section_name_by_addr(unsigned long);
template char * Ecfs<ecfs_type64>::get_section_name_by_addr(unsigned long);

/*
 * Example:
 * vector <Elf64_Phdr> phdr;
 * int phnum = ecfs.get_phdrs(phdr);
 * for (auto &ph : phdr) {
 * 	printf("Vaddr: %lx\n", ph.p_vaddr);
 * }
 */
template <class ecfs_type>
int Ecfs<ecfs_type>::get_phdrs(std::vector <Phdr> &phdr_vec)
{
	Ecfs::Phdr *phdr_ptr = this->phdr;
	phdr_vec.assign(phdr_ptr, &phdr_ptr[this->ehdr->e_phnum]);
	return this->ehdr->e_phnum;
}
template int Ecfs<ecfs_type32>::get_phdrs(std::vector <Phdr> &);
template int Ecfs<ecfs_type64>::get_phdrs(std::vector <Phdr> &);


template <class ecfs_type>
int Ecfs <ecfs_type>::get_shdrs(std::vector <Shdr> &shdr_vec)
{
	Ecfs::Shdr *shdr_ptr = this->shdr;
	shdr_vec.assign(shdr_ptr, &shdr_ptr[this->ehdr->e_shnum]);
	return this->ehdr->e_shnum;
}

template int Ecfs<ecfs_type32>::get_shdrs(std::vector <Shdr>&);
template int Ecfs<ecfs_type64>::get_shdrs(std::vector <Shdr>&);


template <class ecfs_type>
std::string Ecfs <ecfs_type>::get_filepath()
{
	return this->filepath;
}

template std::string Ecfs<ecfs_type32>::get_filepath();
template std::string Ecfs<ecfs_type64>::get_filepath();


