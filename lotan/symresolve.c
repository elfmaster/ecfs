#include "ecfs.h"


typedef struct symentry {
	ElfW(Addr) value;
	size_t size;
	char *name;
} symentry_t;
	
int resolve_symbols(list_t **list, const char *path, unsigned long base)
{
	struct stat st;
	int fd;
	uint8_t *mem;
	ElfW(Ehdr) *ehdr;
	ElfW(Shdr) *shdr;
	ElfW(Sym) *symtab;
	char *StringTable, *dynstr;
	size_t i, symcount;
	symentry_t *symvector;

	fd = xopen(path, O_RDONLY);
	xfstat(fd, &st);
	mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		return -1;
	} 
	
	ehdr = (ElfW(Ehdr) *)mem;	
	shdr = (ElfW(Shdr) *)&mem[ehdr->e_shoff];
	StringTable = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset];

 	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable, ".dynsym")) {
			symcount = shdr[i].sh_size / sizeof(shdr[i].sh_entsize);
			symtab = (ElfW(Sym) *)&mem[shdr[i].sh_offset];
		} else
		if (!strcmp(&StringTable, ".dynstr")) 
			dynstr = (char *)&mem[shdr[i].sh_offset];
	}

	symvector = (symentry_t *)heapAlloc(symcount * sizeof(symentry_t));
	for (i = 0; i < symcount; i++) {
		symvector[i].value = symtab[i].st_value;
		symvector[i].size = symtab[i].st_size;
		symvector[i].name = xstrdup(&dynstr[symtab[i].st_name]);
	}
	
		

}


int fill_dynamic_symtab(list_t **list, memdesc_t *memdesc, struct lib_mappings *lm)
{
        /*
         * The .dynsym section is in the output ecfs executable and does not exist
         * yet when this function is called. We therefore 
         */ 
	*list = (list_t *)heapAlloc(sizeof(**list));
	for (i = 0; i < lm->libcount; i++) {
		resolve_symbols((&(*list)), lm->libs[i].path, lm->libs[i].addr);
 	       

}

