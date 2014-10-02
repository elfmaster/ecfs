#include "vv.h"

ElfW(Off) lookup_shdr_offset(uint8_t *mem, const char *name)
{
	ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)mem;
	ElfW(Shdr) *shdr = (ElfW(Shdr) *)(mem + ehdr->e_shoff);
	int i;

	char *StringTable = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset];
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], name))
			return shdr[i].sh_offset;
	}
	return 0;
}


