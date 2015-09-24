#ifndef _LIBECFS_H
#define _LIBECFS_H


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

/*
 ********** linux system headers *****************
 * XXX must make sure we have ones that work for both 32bit and 64bit
 *
 */
typedef struct elf_timeval {    /* Time value with microsecond resolution    */
  long tv_sec;                  /* Seconds                                   */
  long tv_usec;                 /* Microseconds                              */
} elf_timeval;

typedef struct elf_siginfo_ {    /* Information about signal (unused)         */
  int32_t si_signo;             /* Signal number                             */
  int32_t si_code;              /* Extra code                                */
  int32_t si_errno;             /* Errno                                     */
} elf_siginfo_t;

typedef struct prstatus {       /* Information about thread; includes CPU reg*/
  elf_siginfo_t    pr_info;       /* Info associated with signal               */
  uint16_t       pr_cursig;     /* Current signal                            */
  unsigned long  pr_sigpend;    /* Set of pending signals                    */
  unsigned long  pr_sighold;    /* Set of held signals                       */
  pid_t          pr_pid;        /* Process ID                                */
  pid_t          pr_ppid;       /* Parent's process ID                       */
  pid_t          pr_pgrp;       /* Group ID                                  */
  pid_t          pr_sid;        /* Session ID                                */
  elf_timeval    pr_utime;      /* User time                                 */
  elf_timeval    pr_stime;      /* System time                               */
  elf_timeval    pr_cutime;     /* Cumulative user time                      */
  elf_timeval    pr_cstime;     /* Cumulative system time                    */
  user_regs_struct pr_reg;      /* CPU registers                             */
  uint32_t       pr_fpvalid;    /* True if math co-processor being used      */
} prstatus;


/*
 * This particular struct is created by libecfs and is not stored
 * within the ecfs file itself. Therefore we DONT need both a 64bit
 * and 32bit version of this struct.
 */
typedef struct ecfs_sym {
        long symval; /* Symbol value (address/offset) */
        size_t size;       /* size of object/function       */
        uint8_t type;      /* symbol type, i.e STT_FUNC, STT_OBJECT */
        uint8_t binding;   /* symbol bind, i.e STB_GLOBAL, STB_LOCAL */
        char *strtab; /* pointer to the symbols associated string table */
        int nameoffset;    /* Offset of symbol name into symbol strtab */
	char *name;  /* A pointer into the string table, to the symbol name */
} ecfs_sym_t;


/*
 * This struct is stored within ecfs files. A 32bit ecfs file
 * is going to have an fdinfo that is of 32bit values whereas
 * a 64bit ecfs file will have one that is of 64bit values.
 */
typedef struct fdinfo_64 {
        int fd;				// always 32bit
        char path[MAX_PATH];		// always MAX_PATH bytes
        uint64_t pos;			// XXX this changes from 64bit to 32bit depending
        unsigned int perms;		// always 32bit
        struct {
                struct in_addr src_addr; // in_addr is always uint32_t
                struct in_addr dst_addr; // in addr is always uint32_t
                uint16_t src_port; // always 16bit
                uint16_t dst_port; // always 16bit
        } socket;
        char net;			// always 1 byte
} fdinfo_64_t;

typedef struct fdinfo_32 {
        int fd;                         // always 32bit
        char path[MAX_PATH];            // always MAX_PATH bytes
        uint32_t pos;                   // XXX this changes from 64bit to 32bit depending
        unsigned int perms;             // always 32bit
        struct {
                struct in_addr src_addr; // in_addr is always uint32_t
                struct in_addr dst_addr; // in addr is always uint32_t
                uint16_t src_port; // always 16bit
                uint16_t dst_port; // always 16bit
        } socket;
        char net;                       // always 1 byte
} fdinfo_32_t;




struct ecfs_type32 {
	typedef fdinfo_32_t fdinfo;
	typedef Elf32_Ehdr Ehdr;
        typedef Elf32_Shdr Shdr;
        typedef Elf32_Phdr Phdr;
        typedef Elf32_Nhdr Nhdr;
        typedef Elf32_Dyn Dyn;
        typedef Elf32_Sym Sym;
        typedef Elf32_Rela Rela;
        typedef Elf32_Rel Rel;
        typedef Elf32_Addr Addr;
        typedef Elf32_Off Off;

	// add siginfo here as well
	// add prstatus
	// add prpsinfo
};
struct ecfs_type64 {
	typedef fdinfo_64_t fdinfo;
	typedef Elf64_Ehdr Ehdr;
        typedef Elf64_Shdr Shdr;
        typedef Elf64_Phdr Phdr;
        typedef Elf64_Nhdr Nhdr;
        typedef Elf64_Dyn Dyn;
        typedef Elf64_Sym Sym;
        typedef Elf64_Rela Rela;
        typedef Elf64_Rel Rel;
        typedef Elf64_Addr Addr;
        typedef Elf64_Off Off;

};

/*
 * This struct is NOT stored in the ecfs file so we don't need
 * both a 32bit and 64bit version of it kept internally.
 */
typedef struct pltgotinfo {
        unsigned long got_site; // address of where the GOT entry exists
        unsigned long got_entry_va; // address that is in the GOT entry (the pointer address)
        unsigned long plt_entry_va; // the PLT address that the GOT entry should point to if not yet resolved
        unsigned long shl_entry_va; // the shared library address the GOT should point to if it has been resolved
} pltgotinfo_t;


/******************
 * Main ECFS class that is used for loading and parsing ECFS files
 ****
 ****************<elfmaster>******************************
 */

template <class ecfs_type> 
class Ecfs {
		typedef typename ecfs_type::Ehdr Ehdr;
		typedef typename ecfs_type::Shdr Shdr;
		typedef typename ecfs_type::Phdr Phdr;
		typedef typename ecfs_type::Nhdr Nhdr;
		typedef typename ecfs_type::Dyn Dyn;
		typedef typename ecfs_type::Sym Sym;
		typedef typename ecfs_type::Rela Rela;
		typedef typename ecfs_type::Rel Rel; 
		typedef typename ecfs_type::Addr Addr;
		typedef typename ecfs_type::Off Off;
		
		/*
		 * Non ELF types
		 */
		typedef typename ecfs_type::fdinfo fdinfo;	
		/*
		 * Private members for encapsulation
		 */
	private:
		
 		uint8_t *mem;          /* raw memory pointer */
    		char *shstrtab;        /* shdr string table */
    		char *strtab;          /* .symtab string table */
    		char *dynstr;          /* .dynstr string table */
    		unsigned long *pltgot;  /* pointer to .plt.got */
    		Ehdr * ehdr;     /* ELF Header pointer */
    		Phdr * phdr;     /* Program header table pointer */
    		Shdr * shdr;     /* Section header table pointer */
    		Nhdr * nhdr;     /* ELF Notes section pointer */
    		Dyn  *dyn;       /* Dynamic segment pointer */
    		Sym  *symtab;    /* Pointer to array of symtab symbol structs */
    		Sym  *dynsym;    /* Pointer to array of dynsym symbol structs */
    		Addr textVaddr;  /* Text segment virtual address */
    		Addr dataVaddr;  /* data segment virtual address */
   		Addr dynVaddr;   /* dynamic segment virtual address */
    		Addr pltVaddr;
    		Off textOff;
    		Off dataOff;
    		Off dynOff;
    		Rela *plt_rela;  /* points to .rela.plt section */
    		Rela *dyn_rela;  /* points to .rela.dyn section */
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
		/*
		 * To maintain an internal copy of the vectors for various structure arrays
		 */
                std::vector <pltgotinfo> pltgot_vector;
                std::vector <fdinfo> fdinfo_vector;
                std::vector <prstatus> prstatus_vector;

		/*
		 * Constructor
		 */
		Ecfs(const char *path) {
			if (Ecfs::load(path) < 0) 
				fprintf(stderr, "Unable to load ecfs-core file '%s' into Ecfs object\n", path);
		}
		
		int load (const char *); // invokes all other primary methods
		void unload(void);	// free up all data structures of ecfs object
		
		int get_fdinfo(std::vector<fdinfo>&);	// get vector of fdinfo structs
		int get_prstatus(std::vector<prstatus>&); // get vector of elf_prstatus structs
		int get_thread_count(void);	// get number of threads in process
		char * get_exe_path(void);	// get path to original executable that spawned the process
		std::vector<ecfs_sym> get_dynamic_symbols(void);	// get a vector of the complete .dynsym symbol table
		std::vector<ecfs_sym> get_local_symbols(void);
		int get_siginfo(siginfo_t *);	// will fill siginfo_t with the signal struct
		ssize_t get_stack_ptr(uint8_t **); // will set pointer at .stack section and return the size
		ssize_t get_heap_ptr(uint8_t **); // will set pointer at .heap section and return the size
		ssize_t get_ptr_for_va(unsigned long, uint8_t **); // will set ptr to the segment address specified, and return the size of bytes left
		ssize_t get_section_pointer(const char *, uint8_t **); // set ptr to a given ELF section within a binary and return section size
		ssize_t get_section_size(const char *); // return the size of a section by name
		unsigned long get_section_va(const char *); // return the vaddr of a section by name
		unsigned long get_text_va(void);	// get vaddr of text segment
		unsigned long get_data_va(void);	// get vaddr of data segment
		size_t get_text_size(void); 		// get size of text segment
		size_t get_data_size(void);		// get size of data segment
		unsigned long get_plt_va(void);		// get vaddr of the .plt
		unsigned long get_plt_size(void);	// get size of the .plt 
		

		
};		
		
#define MAX_SYM_LEN 255


#endif
