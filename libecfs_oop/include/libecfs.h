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
#include "util.h"

#include <iostream>
#include <fstream>
#include <vector>

using namespace std;


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

#ifndef MAX_PATH
#define MAX_PATH 512
#endif

typedef struct ecfs_sym {
        ElfW(Addr) symval; /* Symbol value (address/offset) */
        size_t size;       /* size of object/function       */
        uint8_t type;      /* symbol type, i.e STT_FUNC, STT_OBJECT */
        uint8_t binding;   /* symbol bind, i.e STB_GLOBAL, STB_LOCAL */
        char *strtab; /* pointer to the symbols associated string table */
        int nameoffset;    /* Offset of symbol name into symbol strtab */
} ecfs_sym_t;


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
} fdinfo_t;

typedef struct pltgotinfo {
        unsigned long got_site; // address of where the GOT entry exists
        unsigned long got_entry_va; // address that is in the GOT entry (the pointer address)
        unsigned long plt_entry_va; // the PLT address that the GOT entry should point to if not yet resolved
        unsigned long shl_entry_va; // the shared library address the GOT should point to if it has been resolved
} pltgotinfo_t;


class Ecfs {
	private:
 		uint8_t *mem;          /* raw memory pointer */
    		char *shstrtab;        /* shdr string table */
    		char *strtab;          /* .symtab string table */
    		char *dynstr;          /* .dynstr string table */
    		unsigned long *pltgot;  /* pointer to .plt.got */
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
    		size_t pltSize; /* size of .plt section */
    		int fd;                /* A copy of the file descriptor to the file */
    		int pie;        /* is the process from a PIE executable? */
    		
		elf_stat_t *elfstats;
		char *filepath;
	public:
                std::vector <pltgotinfo> pltgot_vector;
                std::vector <fdinfo> fdinfo_vector;
                std::vector <elf_prstatus> prstatus_vector;

		/*
		 * Constructor
		 */
		Ecfs(const char *path) {
			if (Ecfs::load(path) < 0) 
				fprintf(stderr, "Unable to load ecfs-core file '%s' into Ecfs object\n", path);
		}
		int load (const char *); // invokes all other primary methods
		void unload(void);	// free up all data structures of ecfs object
		std::vector<fdinfo> get_fdinfo(void);	// get vector of fdinfo structs
		std::vector<elf_prstatus> get_prstatus(void); // get vector of elf_prstatus structs
		int get_thread_count(void);	// get number of threads in process
		char * get_exe_path(void);	// get path to original executable that spawned the process
		std::vector<ecfs_sym> get_dynamic_symbols(void);	// get a vector of the complete .dynsym symbol table
		int get_siginfo(siginfo_t *);
		

		
};		
		
#define MAX_SYM_LEN 255



