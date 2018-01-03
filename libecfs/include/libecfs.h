#pragma once

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
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_ARGS 256 // for .arglist
/*
 * Custom shdr type
 */
#define SHT_INJECTED 0x200000
#define SHT_PRELOADED 0x300000
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

typedef enum ecfs_iter {
	ECFS_ITER_OK,
	ECFS_ITER_DONE,
	ECFS_ITER_ERROR
} ecfs_iter_t;

typedef struct elf_phdr {
	uint32_t type;
	uint32_t flags;
	ElfW(Off) offset;
	ElfW(Addr) vaddr;
	ElfW(Addr) paddr;
	size_t filesz;
	size_t memsz;
	ElfW(Word) align;
} elf_phdr_t;

typedef struct elf_phdr_node {
	uint32_t type;
	uint32_t flags;
	ElfW(Off) offset;
	ElfW(Addr) vaddr;
	ElfW(Addr) paddr;
	size_t filesz;
	size_t memsz;
	ElfW(Word) align;
	SLIST_ENTRY(elf_phdr_node) _linkage;
} elf_phdr_node_t;

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
	struct {
		SLIST_HEAD(elf_phdr_list, elf_phdr_node) phdrs;
		//TODO SLIST_HEAD(elf_shdr_list, elf_shdr_node) shdrs;
	} slists;
} ecfs_elf_t;

typedef struct ecfs_phdr_iter {
	struct elf_phdr_node *current;
        ecfs_elf_t *obj;
} ecfs_phdr_iter_t;

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
ssize_t get_stack_ptr(ecfs_elf_t *desc, uint8_t **ptr, uint64_t *);
ssize_t get_heap_ptr(ecfs_elf_t *desc, uint8_t **ptr, uint64_t *);
int get_local_symbols(ecfs_elf_t *desc, ecfs_sym_t **syms);
ssize_t get_ptr_for_va(ecfs_elf_t *desc, unsigned long vaddr, uint8_t **ptr);
ssize_t get_section_pointer(ecfs_elf_t *desc, const char *name, uint8_t **ptr);
int get_auxiliary_vector(ecfs_elf_t *, Elf64_auxv_t **);
ssize_t get_pltgot_info(ecfs_elf_t *desc, pltgot_info_t **pginfo);
int get_auxiliary_vector64(ecfs_elf_t *desc, Elf64_auxv_t **auxv);
int get_auxiliary_vector32(ecfs_elf_t *desc, Elf32_auxv_t **auxv);
unsigned long get_fault_location(ecfs_elf_t *desc);
int get_arg_list(ecfs_elf_t *desc, char ***argv);
unsigned long get_section_va(ecfs_elf_t *desc, const char *name);
char * get_section_name_by_addr(ecfs_elf_t *desc, unsigned long addr);
void ecfs_phdr_iterator_init(ecfs_elf_t *, ecfs_phdr_iter_t *);
ecfs_iter_t ecfs_phdr_iterator_next(ecfs_phdr_iter_t *, elf_phdr_t *);
#ifdef __cplusplus
}
#endif
