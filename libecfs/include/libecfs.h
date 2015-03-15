#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <elf.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <errno.h>
#include <link.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <time.h>
#include <locale.h>
#include <signal.h>
#include <sys/user.h>
#include <sys/procfs.h>         /* struct elf_prstatus */
#include <sys/resource.h>
#include <stdio.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * Custom shdr type
 */
#define SHT_INJECTED 0x200000

/*
 * Socket protocol
 */
#define NET_TCP 1
#define NET_UDP 2

typedef struct elf_stats {
#define ELF_STATIC (1 << 1) // if its statically linked (instead of dynamically)
#define ELF_PIE (1 << 2)    // if its position indepdendent executable
#define ELF_LOCSYM (1 << 3) // local symtab exists?
#define ELF_HEURISTICS (1 << 4) // were detection heuristics used by ecfs?
#define ELF_STRIPPED_SHDRS (1 << 8)
        unsigned int personality; // if (personality & ELF_STATIC)
} elf_stat_t;

typedef struct ecfs_elf {
         uint8_t *mem;          /* raw memory pointer */
         char *shstrtab;        /* shdr string table */
         char *strtab;          /* .symtab string table */
         char *dynstr;          /* .dynstr string table */
	 unsigned long *pltgot;	/* pointer to .plt.got */
	 ElfW(Ehdr) * ehdr;     /* ELF Header pointer */
         ElfW(Phdr) * phdr;     /* Program header table pointer */
         ElfW(Shdr) * shdr;     /* Section header table pointer */
         ElfW(Nhdr) * nhdr;     /* ELF Notes section pointer */
         ElfW(Dyn)  *dyn;       /* Dynamic segment pointer */
         ElfW(Sym)  *symtab;    /* Pointer to array of symtab symbol structs */
         ElfW(Sym)  *dynsym;    /* Pointer to array of dynsym symbol structs */
         ElfW(Addr) textVaddr;  /* Text segment virtual address */
         ElfW(Addr) dataVaddr;  /* data segment virtual address */
         ElfW(Addr) dynVaddr;   /* dynamic segment virtual address */
         ElfW(Addr) pltVaddr;
	 ElfW(Off) textOff;
	 ElfW(Off) dataOff;
	 ElfW(Off) dynOff;
	 ElfW(Rela) *plt_rela;  /* points to .rela.plt section */
	 ElfW(Rela) *dyn_rela;  /* points to .rela.dyn section */
	 ssize_t plt_rela_count; /* number of .rela.plt entries */
	 ssize_t dyn_rela_count; /* number of .rela.dyn entries */
	 size_t filesize;       /* total file size              */
         size_t dataSize;       /* p_memsz of data segment      */
         size_t textSize;       /* p_memsz of text segment      */
         size_t dynSize;        /* p_memsz of dynamnic segment  */
	 size_t pltSize;	/* size of .plt section */
         int fd;                /* A copy of the file descriptor to the file */
	 int pie;		/* is the process from a PIE executable? */
	 elf_stat_t *elfstats;
} ecfs_elf_t;

#define MAX_SYM_LEN 255

typedef struct ecfs_sym {
	ElfW(Addr) symval; /* Symbol value (address/offset) */
        size_t size;       /* size of object/function       */
        uint8_t type;      /* symbol type, i.e STT_FUNC, STT_OBJECT */
        uint8_t binding;   /* symbol bind, i.e STB_GLOBAL, STB_LOCAL */
        char *strtab; /* pointer to the symbols associated string table */
        int nameoffset;    /* Offset of symbol name into symbol strtab */
} ecfs_sym_t;

#ifndef MAX_PATH
#define MAX_PATH 512
#endif
typedef struct fdinfo {
        int fd;
        char path[MAX_PATH];
        loff_t pos;
	unsigned int perms;
	struct {
                struct in_addr src_addr;
                struct in_addr dst_addr;
                uint16_t src_port;
                uint16_t dst_port;
        } socket;
        char net;
} fd_info_t;

typedef struct pltgotinfo {
	unsigned long got_site; // address of where the GOT entry exists
	unsigned long got_entry_va; // address that is in the GOT entry (the pointer address)
	unsigned long plt_entry_va; // the PLT address that the GOT entry should point to if not yet resolved
	unsigned long shl_entry_va; // the shared library address the GOT should point to if it has been resolved
} pltgot_info_t;


int get_shlib_mapping_names(ecfs_elf_t *, char ***);
ecfs_elf_t * load_ecfs_file(const char *);
int unload_ecfs_file(ecfs_elf_t *desc);
char * get_exe_path(ecfs_elf_t *desc);
int get_fd_info(ecfs_elf_t *desc, struct fdinfo **fdinfo);
int get_thread_count(ecfs_elf_t *desc);
int get_prstatus_structs(ecfs_elf_t *desc, struct elf_prstatus **prstatus);
int get_dynamic_symbols(ecfs_elf_t *desc, ecfs_sym_t **);
int get_siginfo(ecfs_elf_t *desc, siginfo_t *siginfo);
ssize_t get_stack_ptr(ecfs_elf_t *desc, uint8_t **ptr);
ssize_t get_heap_ptr(ecfs_elf_t *desc, uint8_t **ptr);
int get_local_symbols(ecfs_elf_t *desc, ecfs_sym_t **syms);
ssize_t get_ptr_for_va(ecfs_elf_t *desc, unsigned long vaddr, uint8_t **ptr);
ssize_t get_section_pointer(ecfs_elf_t *desc, const char *name, uint8_t **ptr);
int get_auxiliary_vector(ecfs_elf_t *, Elf64_auxv_t **);
ssize_t get_pltgot_info(ecfs_elf_t *desc, pltgot_info_t **pginfo);
int get_auxiliary_vector64(ecfs_elf_t *desc, Elf64_auxv_t **auxv);
unsigned long get_fault_location(ecfs_elf_t *desc);
