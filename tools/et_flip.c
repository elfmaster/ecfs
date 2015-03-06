/*
 * This program switches a binary back and forth from being 
 * type ET_NONE or ET_CORE. In some cases you will want it to be
 * ET_CORE so you can use it with GDB. In other cases you may want
 * objdump to be able to use the section headers so it should be
 * an ET_NONE.
 */

#include "../include/ecfs.h"

int main(int argc, char **argv)
{
	struct stat st;
	int fd;
	char *mem;
	Elf32_Ehdr *ehdr; //a 32bit elf header will work for the first 16 bytes of a 32bit or 64bit file

	if (argc < 2) {
		printf("Usage: %s <ecfs_file>\n", argv[0]);
		exit(0);
	}
	
	fd = xopen(argv[1], O_RDWR);
	xfstat(fd, &st);
	mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}
	ehdr = (Elf32_Ehdr *)mem;
	ehdr->e_type = (ehdr->e_type == ET_NONE) ? ET_CORE : ET_NONE;
	msync((void *)mem, st.st_size, MS_SYNC);
	munmap(mem, st.st_size);
		
	return 0;
}

