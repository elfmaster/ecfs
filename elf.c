#include "vv.h"


size_t sizeof_note(const char *name, int descsz)
{
        return (sizeof(ElfW(Note)) +
            ELFNOTE_ALIGN(strlen(name)+1) +
            ELFNOTE_ALIGN(descsz));
}


void setup_note(ElfW(Note) *n, const char *name, int type, const void *desc, int descsz)
{
        int l = strlen(name) + 1;
        n->namesz = l;
        strcpy(ELFNOTE_NAME(n), name);
        
        n->descsz = descsz;
        memcpy((void *)ELFNOTE_DESC(n), desc, descsz);
        
        n->type = type;
}


void elf_note_info_init(struct elf_note_info *ni)
{
	memset((struct elf_note_info *)ni, 0, sizeof(struct elf_note_info) * MAX_THREADS);
	ni->notes = (struct memelfnote *)heapAlloc(sizeof(struct memelfnote));
	ni->psinfo = (struct elf_prpsinfo *)heapAlloc(sizeof(struct elf_prpsinfo));
	ni->prstatus = (struct elf_prstatus *)heapAlloc(sizeof(struct elf_prstatus));
	ni->fpu = (elf_fpregset_t *)heapAlloc(sizeof(elf_fpregset_t));
}

void fill_psinfo(struct elf_prpsinfo *psinfo, memdesc_t *memdesc)
{
	char *args; // stack args
	int i, len;

	memset(psinfo, 0, sizeof(struct elf_prpsinfo));
	memcpy(psinfo->pr_psargs, memdesc->stack_args, memdesc->stack_args_len);
	for(i = 0; i < len; i++)
        	if (psinfo->pr_psargs[i] == 0)
                	psinfo->pr_psargs[i] = ' ';
        psinfo->pr_psargs[len] = 0;


}

void fill_prstatus(struct elf_prstatus *prstatus, memdesc_t *memdesc)
{
	prstatus->pr_info.si_signo = SIGUSR1;
	prstatus->pr_sigpend = 0;
	prstatus->pr_sighold = 0;
	prstatus->pr_ppid = memdesc->task.leader;
	prstatus->pr_pgrp = memdesc->task.leader;
	prstatus->pr_sid = 0;
	
}

		
int fill_note_info(desc_t *desc, long signr, struct pt_regs *regs)
{	
	elfdesc_t *elf = &desc->binary;
	memdesc_t *memdesc = &desc->memory;
	struct elf_note_info *info = desc->info;
	
	
	elf_note_info_init(info);
	
	memset(info->prstatus, 0, sizeof(struct elf_prstatus));
	fill_prstatus(info->prstatus, memdesc);

}

	
	
int build_notes_area(const char *filepath, struct elf_note_info *ni)
{
	int fd;
	uint8_t *mem;
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	ElfW(Note) *np, *notes;
	size_t len = 0, noteSize;
	struct stat st;
	int i;

	fd = open(filepath, O_RDWR);
	fstat(fd, &st);
	mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}
	ehdr = (ElfW(Ehdr) *)mem;
	phdr = (ElfW(Phdr) *)(mem + ehdr->e_phoff);
	
	for (i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_NOTE) {
			np = (ElfW(Note) *)&mem[phdr[i].p_offset];
			noteSize = phdr[i].p_filesz;
			break;
		}
	}
	
	notes = (ElfW(Note) *)heapAlloc(sizeof(ElfW(Note)) * 256);
	
	
	for (i = 0; i < noteSize; i += len) {
			

	}
}


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


