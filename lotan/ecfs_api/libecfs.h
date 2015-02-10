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

typedef struct ecfs_elf {
         uint8_t *mem;          /* raw memory pointer */
         char *shstrtab;        /* shdr string table */
         char *strtab;          /* .symtab string table */
         char *dynstr;          /* .dynstr string table */
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
         ElfW(Off) textOff;
	 ElfW(Off) dataOff;
	 ElfW(Off) dynOff;
	 size_t filesize;       /* total file size              */
         size_t dataSize;       /* p_memsz of data segment      */
         size_t textSize;       /* p_memsz of text segment      */
         size_t dynSize;        /* p_memsz of dynamnic segment  */
         int fd;                /* A copy of the file descriptor to the file */
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
        struct {
                int src_port;
                int dst_port;
                struct in_addr src_addr;
                struct in_addr dst_addr;
        } socket;
        char net;
} fd_info_t;

void * heapAlloc(size_t);

ecfs_elf_t * load_ecfs_file(const char *);
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
