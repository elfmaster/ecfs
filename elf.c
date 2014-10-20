#include "ecfs.h"


#define MAX_NOTES 256

/*
 * Modified version of the kernel macro
 * we copy struct user_regs_struct to pr_regs
 * in elf_prstatus
 */
#define ELF_CORE_COPY_REGS(pr_reg, regs)                        \
do {                                                            \
         unsigned v;                                             \
         (pr_reg)[0] = (regs)->r15;                              \
         (pr_reg)[1] = (regs)->r14;                              \
         (pr_reg)[2] = (regs)->r13;                              \
         (pr_reg)[3] = (regs)->r12;                              \
         (pr_reg)[4] = (regs)->rbp;                               \
         (pr_reg)[5] = (regs)->rbx;                               \
         (pr_reg)[6] = (regs)->r11;                              \
         (pr_reg)[7] = (regs)->r10;                              \
         (pr_reg)[8] = (regs)->r9;                               \
         (pr_reg)[9] = (regs)->r8;                               \
         (pr_reg)[10] = (regs)->rax;                              \
         (pr_reg)[11] = (regs)->rcx;                              \
         (pr_reg)[12] = (regs)->rdx;                              \
         (pr_reg)[13] = (regs)->rsi;                              \
         (pr_reg)[14] = (regs)->rdi;                              \
         (pr_reg)[15] = (regs)->orig_rax;                         \
         (pr_reg)[16] = (regs)->rip;                              \
         (pr_reg)[17] = (regs)->cs;                              \
         (pr_reg)[18] = (regs)->eflags;                           \
         (pr_reg)[19] = (regs)->rsp;                              \
         (pr_reg)[20] = (regs)->ss;                              \
         (pr_reg)[21] = (regs)->fs;                     \
         (pr_reg)[22] = (regs)->gs;                 \
         asm("movl %%ds,%0" : "=r" (v)); (pr_reg)[23] = v;       \
         asm("movl %%es,%0" : "=r" (v)); (pr_reg)[24] = v;       \
         asm("movl %%fs,%0" : "=r" (v)); (pr_reg)[25] = v;       \
         asm("movl %%gs,%0" : "=r" (v)); (pr_reg)[26] = v;       \
} while (0);


static size_t sizeof_note(const char *name, int descsz)
{
        return (sizeof(ElfW(Note)) +
            ELFNOTE_ALIGN(strlen(name)+1) +
            ELFNOTE_ALIGN(descsz));
}

static int notesize(struct memelfnote *en)
{
        int sz;

        sz = sizeof(ElfW(Note));
        sz += ELFNOTE_ALIGN(strlen(en->name) + 1);
        sz += ELFNOTE_ALIGN(en->datasz);

        return sz;
}


static size_t get_note_info_size(struct elf_note_info *info)
{
        int sz = 0;
        int i;

        for (i = 0; i < info->numnote; i++)
                sz += notesize(info->notes + i);

        //sz += info->thread_status_size;

        return sz;
}

static int do_write(int fd, void *data, size_t len, loff_t *offset)
{
	loff_t off = *offset;
	if (lseek(fd, off, SEEK_SET) < 0)
		return 0;
	if (write(fd, data, len) < 0)
		return 0;
	return 1;
}

#define DUMP_WRITE(fd, data, len, offset) \
        do { if (!do_write(fd, data, len, offset)) return 0; *offset += (len); } while(0)

static int writenote(struct memelfnote *men, int fd,
                        loff_t *foffset)
{
        ElfW(Note) en;
        en.namesz = strlen(men->name) + 1;
        en.descsz = men->datasz;
        en.type = men->type;
	
	printf("Dumping note at %lx\n", *foffset);
        DUMP_WRITE(fd, &en, sizeof(en), foffset);
        DUMP_WRITE(fd, (char *)men->name, en.namesz, foffset);
	DUMP_WRITE(fd, men->data, en.descsz, foffset);
	
        return 1;
}

static void fill_note(struct memelfnote *note, const char *name, int type, 
                unsigned int sz, void *data)
{
        note->name = name;
        note->type = type;
        note->datasz = sz;
        note->data = data;
        return;
}

void elf_note_info_init(struct elf_note_info *ni)
{
	memset((struct elf_note_info *)ni, 0, sizeof(struct elf_note_info) * MAX_THREADS);
	ni->notes = (struct memelfnote *)heapAlloc(sizeof(struct memelfnote) * MAX_NOTES);
	ni->psinfo = (struct elf_prpsinfo *)heapAlloc(sizeof(struct elf_prpsinfo));
	ni->prstatus = (struct elf_prstatus *)heapAlloc(sizeof(struct elf_prstatus));
	ni->fpu = (elf_fpregset_t *)heapAlloc(sizeof(elf_fpregset_t));
}

static void fill_auxv_note(struct memelfnote *note, memdesc_t *memdesc)
{
        ElfW(Addr) *auxv = (ElfW(Addr) *) memdesc->saved_auxv;
        int i = 0;

        do {
                i += 2;
        } while (auxv[i - 2] != AT_NULL);
        fill_note(note, "CORE", NT_AUXV, i * sizeof(ElfW(Addr)), auxv);
}

void fill_psinfo(struct elf_prpsinfo *psinfo, memdesc_t *memdesc)
{
	char *args; // stack args
	int i, len = memdesc->stack_args_len;

	memset(psinfo, 0, sizeof(struct elf_prpsinfo));
	memcpy(psinfo->pr_psargs, memdesc->stack_args, memdesc->stack_args_len);
	for(i = 0; i < len; i++)
        	if (psinfo->pr_psargs[i] == 0)
                	psinfo->pr_psargs[i] = ' ';
        psinfo->pr_psargs[len] = 0;


}

void fill_prstatus(struct elf_prstatus *prstatus, memdesc_t *memdesc)
{
	struct user_regs_struct *pt_regs = (struct user_regs_struct *)&memdesc->pt_regs;

	prstatus->pr_info.si_signo = SIGUSR1;
	prstatus->pr_sigpend = 0;
	prstatus->pr_sighold = 0;
	prstatus->pr_ppid = memdesc->task.leader;
	prstatus->pr_pgrp = memdesc->task.leader;
	prstatus->pr_sid = 0;

	ELF_CORE_COPY_REGS(prstatus->pr_reg, pt_regs);
}

		
size_t fill_note_info(desc_t *desc, struct user_regs_struct *regs, int thread_count)
{	
	elfdesc_t *elf = &desc->binary;
	memdesc_t *memdesc = &desc->memory;
	struct elf_note_info *info = &desc->info[thread_count];
	
	elf_note_info_init(info);
	
	memset(info->prstatus, 0, sizeof(struct elf_prstatus));
	fill_prstatus(info->prstatus, memdesc);
	fill_psinfo(info->psinfo, memdesc);

	fill_note(info->notes + 0, "CORE", NT_PRSTATUS,
                  sizeof(*info->prstatus), info->prstatus);
        fill_note(info->notes + 1, "CORE", NT_PRPSINFO,
                  sizeof(*info->psinfo), info->psinfo);
	fill_auxv_note(info->notes + 2, memdesc);
	info->numnote += 3;
	
	return get_note_info_size(info);
}

	
	
loff_t build_notes_area(const char *filepath, desc_t *desc)
{
	int fd;
	uint8_t *mem;
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	ElfW(Note) *np;
	size_t len = 0, noteSize;
	struct stat st;
	int i;
	loff_t notes_offset;

	fd = open(filepath, O_RDWR);
	fstat(fd, &st);
	mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}
	notes_offset = lseek(fd, 0, SEEK_END);
	if (notes_offset < 0) {
		perror("lseek");
		exit(-1);
	}

	ehdr = (ElfW(Ehdr) *)mem;
	phdr = (ElfW(Phdr) *)(mem + ehdr->e_phoff);
	
	int thread_count = 0;
	noteSize = fill_note_info(desc, &desc->memory.pt_regs, thread_count);
        struct memelfnote *notes = desc->info[thread_count].notes;
	
        for (i = 0; i < desc->info[thread_count].numnote ; i++)  {
                writenote(notes + i, fd, &notes_offset);
	}

	for (i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_NOTE) {
			phdr[i].p_vaddr = desc->memory.data_base + st.st_size;
			phdr[i].p_paddr = desc->memory.data_base + st.st_size;
			phdr[i].p_filesz = phdr[i].p_memsz = noteSize;
			loff_t notes_offset = phdr[i].p_offset = st.st_size;
			break;
		}
	}
	
	//notes = (ElfW(Note) *)heapAlloc(sizeof(ElfW(Note)) * 256);
	munmap(mem, st.st_size);
	close(fd);
		
	return notes_offset;
	
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


