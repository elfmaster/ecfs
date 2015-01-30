#include "libecfs.h"

ecfs_elf_t * load_ecfs_file(const char *path)
{
	ecfs_elf_t *ecfs = (ecfs_elf_t *)heapAlloc(sizeof(ecfs_elf_t));
	uint8_t *mem;
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	ElfW(Shdr) *shdr;
	int fd, i, j;
	struct stat st;

	fd = xopen(path, O_RDONLY);
	xfstat(fd, &st);
	ecfs->filesize = st.st_size;
	mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}
	ehdr = (ElfW(Ehdr) *)mem;
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
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".data")) {
                        ecfs->dataVaddr = shdr[i].sh_addr;
                        ecfs->dataSize = shdr[i].sh_size;
                        ecfs->dataOff = shdr[i].sh_offset;
                } else
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".text")) {
                        ecfs->textVaddr = shdr[i].sh_addr;
                        ecfs->textSize = shdr[i].sh_size;
                        ecfs->textOff = shdr[i].sh_offset;
                }

	}
	ecfs->ehdr = ehdr;
	ecfs->phdr = phdr;
	ecfs->shdr = shdr;
	ecfs->mem = mem;
	return ecfs;
}	

int get_fd_info(ecfs_elf_t *desc, struct fdinfo **fdinfo)
{
	char *StringTable = desc->shstrtab;
	ElfW(Shdr) *shdr = desc->shdr;
	int i;
	for (i = 0; i < desc->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".fdinfo")) {
			*fdinfo = (struct fdinfo *)heapAlloc(shdr[i].sh_size);
			memcpy(*fdinfo, &desc->mem[shdr[i].sh_offset], shdr[i].sh_size);
			return shdr[i].sh_size / sizeof(struct fdinfo);
		}
	}
	return -1;
}

int get_prstatus_structs(ecfs_elf_t *desc, struct elf_prstatus **prstatus)
{
	char *StringTable = desc->shstrtab;
        ElfW(Shdr) *shdr = desc->shdr;
        int i;
        for (i = 0; i < desc->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".prstatus")) {
			*prstatus = (struct elf_prstatus *)heapAlloc(shdr[i].sh_size);
			memcpy(*prstatus, &desc->mem[shdr[i].sh_offset], shdr[i].sh_size);
			return shdr[i].sh_size / sizeof(struct elf_prstatus);
		}
	}
	return -1;
}

int get_thread_count(ecfs_elf_t *desc)
{
	char *StringTable = desc->shstrtab;
	ElfW(Shdr) *shdr = desc->shdr;
	int i;

	for (i = 0; i < desc->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".prstatus")) 
			return shdr[i].sh_size / shdr[i].sh_entsize;
	}
	return -1;
}
		
char * get_exe_path(ecfs_elf_t *desc)
{
        char *StringTable = desc->shstrtab;
        ElfW(Shdr) *shdr = desc->shdr;
	int i, c;
	char *ret;

        for (i = 0; i < desc->ehdr->e_shnum; i++) {
                if (!strcmp(&StringTable[shdr[i].sh_name], ".exepath")) {
			ret = (char *)heapAlloc(shdr[i].sh_size);
			strcpy(ret, (char *)&desc->mem[shdr[i].sh_offset]);
			return ret;	
        	}
	}
        return NULL;
}


	

