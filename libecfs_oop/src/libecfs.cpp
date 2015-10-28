#include "../include/libecfs.hpp"


template <class ecfs_type> bool Ecfs<ecfs_type>::fail(void)
{
	return this->error ? true : false;
}

template bool Ecfs<ecfs_type32>::fail(void);
template bool Ecfs<ecfs_type64>::fail(void);
	
/*
 * Is invoked in the constructor, or can be called by itself
 *
 */
template <class ecfs_type> int Ecfs<ecfs_type>::load(const char *path)
{	
	Ecfs *ecfs = this;
	uint8_t *mem;
	int fd, i;
	struct stat st;
	Ecfs::Ehdr *ehdr;
	Ecfs::Phdr *phdr;
	Ecfs::Shdr *shdr;

	fd = xopen(path, O_RDONLY);
	xfstat(fd, &st);
	ecfs->filesize = st.st_size;
	mem = (uint8_t *)mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	
	if (memcmp(mem, "\x7f\x45\x4c\x46", 4) != 0) {
		this->m_errmsg = xfmtstrdup("File: %s is not an ELF executable", path);
		this->error = true;
		return -1;
	}
	
	ehdr = (Ehdr *)mem;
	
	if (ehdr->e_type != ET_NONE && ehdr->e_type != ET_CORE) {
		this->m_errmsg = xfmtstrdup("File: %s does not appear to be an ECFS file (marked by ET_NONE or ET_CORE)", path);
		this->error = true;
		return -1;
	}
	
	if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0 || ehdr->e_shstrndx == SHN_UNDEF) {
		this->m_errmsg = xfmtstrdup("File: %s has a section header table that is out of bounds or undefined\n");
		this->error = true;
		return -1;
	}
	
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
	
	/*
	 * Now that we have assigned all of the private pointers and variables
	 * lets set the internal vectors.
	 */
	if (this->get_fdinfo(this->m_fdinfo) == -1) {
		this->m_errmsg = xstrdup("Unable to load .fdinfo section");
		this->error = true;
		return -1;
	}

	if (this->get_pltgot_info(this->m_pltgot) == -1) {
		this->m_errmsg = xstrdup("Unable to load .got.plt section");
		this->error = true;
		return -1;
	}

	if (this->get_dynamic_symbols(this->m_dynsym) == -1) {
		this->m_errmsg = xstrdup("Unable to load .dynsym symbol table");
		this->error = true;
		return -1;
	}
	
	if (this->get_local_symbols(this->m_symtab) == -1) {
		this->m_errmsg = xstrdup("Unable to load .symtab symbol table");
		this->error = true;
		return -1;
	}

	if (this->get_prstatus(this->m_prstatus) == -1) {
		this->m_errmsg = xstrdup("Unable to load .prstatus section");
		this->error = true;
		return -1;
	}
	
	if (this->get_auxv(this->m_auxv) == -1) {
		this->m_errmsg = xstrdup("Unable to load .auxv section");
		this->error = true;
		return -1;
	}

	if (this->get_shlib_maps(this->m_shlib) == -1) {
		this->m_errmsg = xstrdup("Unable to load shared library mappings");
		this->error = true;
		return -1;
	}

	if (this->get_phdrs(this->m_phdr) == -1) {
		this->m_errmsg = xstrdup("Unable to load program headers");
		this->error = true;
		return -1;
	}

	if (this->get_shdrs(this->m_shdr) == -1) {
		this->m_errmsg = xstrdup("Unable to load section headers");
		this->error = true;
		return -1;
	}


	/*
	 * set argv
	 */
	char **argvp;
	this->m_argc = this->get_argv(&argvp);
	this->m_argv.assign(argvp, (argvp + this->m_argc)); 
	return 0;
}	

template int Ecfs<ecfs_type32>::load(const char *);
template int Ecfs<ecfs_type64>::load(const char *);





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



/*
 example:
 	vector <prstatus_64> prstatus_vector;
        if (ecfs.get_prstatus(prstatus_vector) < 0)
                printf("Getting prstatus failed\n");
	for (i = 0; i < prstatus_vector.size(); i++)
		printf("%d\n", prstatus_vector[i].pr_pid);
*/

template <class ecfs_type>
int Ecfs<ecfs_type>::get_prstatus(std::vector<Ecfs::prstatus> &prstatus_vec)
{
	char *StringTable = this->shstrtab;
	Ecfs::Shdr *shdr = this->shdr;
	Ecfs::prstatus *prstatus_ptr;
	size_t items;

	for (int i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".prstatus")) {
			prstatus_ptr = (Ecfs::prstatus *)alloca(shdr[i].sh_size);
			memcpy(prstatus_ptr, &this->mem[shdr[i].sh_offset], shdr[i].sh_size);
			items = shdr[i].sh_size / sizeof(Ecfs::prstatus);
			prstatus_vec.assign(prstatus_ptr, &prstatus_ptr[items]);
			return prstatus_vec.size();
		}
	}
	/*
	 * In addition to returning a vector we assign the internal
	 * copy as well that can be used at any time until the Ecfs object is
	 * destructed.
	 */
	//this->prstatus_vector = prstatus_vec;
	return -1;
}

template int Ecfs<ecfs_type32>::get_prstatus(std::vector<Ecfs::prstatus> &);
template int Ecfs<ecfs_type64>::get_prstatus(std::vector<Ecfs::prstatus> &);


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
int Ecfs<ecfs_type>::get_dynamic_symbols(vector <ecfs_sym_t>&sym_vec)
{
	int i, j;
	Ecfs::Ehdr *ehdr = this->ehdr;
	Ecfs::Shdr *shdr = this->shdr;
	ssize_t symcount;
	Ecfs::Sym *dynsym = this->dynsym;
	ecfs_sym_t *syms;
	
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (shdr[i].sh_type == SHT_DYNSYM) {
			symcount = shdr[i].sh_size / sizeof(Ecfs::Sym);
			size_t alloc_len = symcount * sizeof(ecfs_sym_t);
			syms = (ecfs_sym_t *)alloca(alloc_len);
			for (j = 0; j < symcount; j++) {
				syms[j].strtab = this->dynstr;
				syms[j].symval = dynsym[j].st_value;
				syms[j].size = dynsym[j].st_size;
				syms[j].type = ELF32_ST_TYPE(dynsym[j].st_info);
				syms[j].binding = ELF32_ST_BIND(dynsym[j].st_info);
				syms[j].nameoffset = dynsym[j].st_name;
				syms[j].name = &syms[j].strtab[syms[j].nameoffset];
			}
			sym_vec.assign(syms, &syms[symcount]);
			return sym_vec.size();
		}
	}
	return -1; // failed if we got here
}
template int Ecfs<ecfs_type32>::get_dynamic_symbols(vector <ecfs_sym_t>&);
template int Ecfs<ecfs_type64>::get_dynamic_symbols(vector <ecfs_sym_t>&);

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
int Ecfs<ecfs_type>::get_local_symbols(vector <ecfs_sym_t>&sym_vec)
{
        int i, j;
        Ecfs::Ehdr *ehdr = this->ehdr;
        Ecfs::Shdr *shdr = this->shdr;
        ssize_t symcount;
        Ecfs::Sym *symtab = this->symtab;
        ecfs_sym_t *syms;

        for (i = 0; i < ehdr->e_shnum; i++) {
                if (shdr[i].sh_type == SHT_SYMTAB) {
                        symcount = shdr[i].sh_size / sizeof(Ecfs::Sym);
                        size_t alloc_len = symcount * sizeof(ecfs_sym_t);
                        syms = (ecfs_sym_t *)alloca(alloc_len);
                        for (j = 0; j < symcount; j++) {
                                syms[j].strtab = this->strtab;
                                syms[j].symval = symtab[j].st_value;
                                syms[j].size = symtab[j].st_size;
                                syms[j].type = ELF32_ST_TYPE(symtab[j].st_info);
                                syms[j].binding = ELF32_ST_BIND(symtab[j].st_info);
                                syms[j].nameoffset = symtab[j].st_name;
                                syms[j].name = &syms[j].strtab[syms[j].nameoffset];
                        }
                        sym_vec.assign(syms, &syms[symcount]);
                        return sym_vec.size();
                }
        }
        return -1; // failed if we got here
}
template int Ecfs<ecfs_type32>::get_local_symbols(vector <ecfs_sym_t>&);
template int Ecfs<ecfs_type64>::get_local_symbols(vector <ecfs_sym_t>&);

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
ssize_t Ecfs<ecfs_type>::get_shlib_maps(vector <shlibmap_t> &shlib)
{
	ssize_t i, count;	
	char *shstrtab = this->shstrtab;
	Ecfs::Shdr *shdr = this->shdr;
	shlibmap_t *shlibp = (shlibmap_t *)alloca(sizeof(shlibmap_t));

	for (count = 0, i = 0; i < this->ehdr->e_shnum; i++) {
		switch(shdr[i].sh_type) {
			case SHT_SHLIB:
			case SHT_INJECTED:
			case SHT_PRELOADED:
				count++;
				shlibp->name = xstrdup(&shstrtab[shdr[i].sh_name]);
				shlibp->vaddr = shdr[i].sh_addr;
				shlibp->offset = shdr[i].sh_offset;
				shlibp->size = shdr[i].sh_size;
				shlib.push_back(*shlibp);
			default:
				continue;
		}
	}
	return count;
}

template ssize_t Ecfs<ecfs_type32>::get_shlib_maps(vector <shlibmap_t>&);
template ssize_t Ecfs<ecfs_type64>::get_shlib_maps(vector <shlibmap_t>&);


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
unsigned long Ecfs<ecfs_type>::get_fault_location(void)
{
	siginfo_t siginfo;
	
	if (this->get_siginfo(siginfo) < 0)
		return 0;

	return (unsigned long)siginfo.si_addr;
}

template unsigned long Ecfs<ecfs_type32>::get_fault_location(void);
template unsigned long Ecfs<ecfs_type64>::get_fault_location(void);

/*
 * Will change to vector of strings, for now use
 * the good ole C way:
 * char **argv;
 * int argc = get_argv(&argv);
 * while(argc--) printf("%s\n", *argv++);
 * XXX
 * ECFS currently uses the pr_psargs buffer form
 * struct prpsinfo.
 */
template <class ecfs_type>
int Ecfs<ecfs_type>::get_argv(char ***argv)
{
        int i, argc, c;
        Ecfs::Ehdr *ehdr = this->ehdr;
        Ecfs::Shdr *shdr = this->shdr;
        uint8_t *mem = this->mem;
        char *shstrtab = this->shstrtab;
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
template int Ecfs<ecfs_type32>::get_argv(char ***);
template int Ecfs<ecfs_type64>::get_argv(char ***);



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


