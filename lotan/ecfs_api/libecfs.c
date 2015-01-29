#include "libecfs.h"

ecfs_file_t * load_ecfs_file(const char *path)
{
	ecfs_file_t *ecfs = (ecfs_file_t *)heapAlloc(sizeof(ecfs_file_t));
	uint8_t *mem;
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	ElfW(Shdr) *shdr;
	int fd, i, j;
	struct stat st;

	fd = xopen(path, O_RDONLY);
	xfstat(fd, &st);
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
	 * setup dynamic string table
	 */
	for (ecfs->dynstr = NULL, i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".dynstr")) {
			ecfs->dynstr = (char *)&mem[shdr[i].sh_offset];
			break;
		}
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
	
			
}


