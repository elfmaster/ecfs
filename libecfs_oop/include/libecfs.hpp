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
#include <netinet/in.h>
#include <arpa/inet.h>

#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <vector>
#include <iterator>

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

/* We need this to differentiate user_regs_struct on 64bit systems
 */
typedef struct user_regs_struct_32
{
  int32_t ebx;
  int32_t ecx;
  int32_t edx;
  int32_t esi;
  int32_t edi;
  int32_t ebp;
  int32_t eax;
  int32_t xds;
  int32_t xes;
  int32_t xfs;
  int32_t xgs;
  int32_t orig_eax;
  int32_t eip;
  int32_t xcs;
  int32_t eflags;
  int32_t esp;
  int32_t xss;
} user_regs_struct_32;

typedef struct elf_timeval {    /* Time value with microsecond resolution    */
  long tv_sec;                  /* Seconds                                   */
  long tv_usec;                 /* Microseconds                              */
} elf_timeval;

typedef struct elf_siginfo_ {    /* Information about signal (unused)         */
  int32_t si_signo;             /* Signal number                             */
  int32_t si_code;              /* Extra code                                */
  int32_t si_errno;             /* Errno                                     */
} elf_siginfo_t;

/*
 * This struct is exactly the same on 32bit and 64bit systems
 * except for the user_regs_struct
 */
typedef struct prstatus_64 {       /* Information about thread; includes CPU reg*/
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
} prstatus_64;


typedef struct prstatus_32 {       /* Information about thread; includes CPU reg*/
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
	user_regs_struct_32 pr_reg;      /* CPU registers                             */
uint32_t       pr_fpvalid;    /* True if math co-processor being used      */
} prstatus_32;



/* *************************** A BITCH
 * siginfo we must have a 32bit and 64bit version
 * at some point maybe we should modify the actual ecfs
 * software so that it writes only elf_siginfo_t which
 * is architecture agnostic since it just uses int32_t's.
 */

typedef union sigval32 {
       	int sival_int;
       	uint32_t sival_ptr; // XXX changed from void * to a uint32_t
} sigval32_t;

typedef union sigval64 {
	int sival_int;
	void *sival_ptr;
} sigval64_t;


/*
 * XXX
 * because of defines like this in glibc headers
 *
 *   #define si_pid		_sifields._kill._pid
 * we cannot name the members of this struct si_* it causes
 * conflicts. We must use _si_* instead
 */
typedef struct siginfo32 {
	int      _si_signo;    /* Signal number */
	int      _si_errno;    /* An errno value */
	int      _si_code;     /* Signal code */
	int      _si_trapno;   /* Trap number that caused */
	int      _si_pid;      /* Sending process ID */
	int      _si_uid;      /* Real user ID of sending process */
	int      _si_status;   /* Exit value or signal */
	uint32_t  _si_utime;    /* User time consumed */
	uint32_t  _si_stime;    /* System time consumed */
	sigval32_t _si_value;    /* Signal value */
	int      _si_interrupt;      /* POSIX.1b signal */
	uint32_t _si_ptr;      /* POSIX.1b signal */
	int      _si_overrun;  /* Timer overrun count; POSIX.1b timers */
	int      _si_timerid;  /* Timer ID; POSIX.1b timers */
	uint32_t _si_addr;     /* Memory location which caused fault */
	uint32_t _si_band;     /* Band event (was int in
								   glibc 2.3.2 and earlier) */
	int      _si_fd;       /* File descriptor */
	short    _si_addr_lsb; /* Least significant bit of address
                                        (since Linux 2.6.32) */
} siginfo32_t;

typedef struct siginfo64 {
	int      _si_signo;    /* Signal number */
	int      _si_errno;    /* An errno value */
	int      _si_code;     /* Signal code */
	int      _si_trapno;   /* Trap number that caused
                                        hardware-generated signal
                                        (unused on most architectures) */
	pid_t    _si_pid;      /* Sending process ID */
	uid_t    _si_uid;      /* Real user ID of sending process */
	int      _si_status;   /* Exit value or signal */
	clock_t  _si_utime;    /* User time consumed */
	clock_t  _si_stime;    /* System time consumed */
	sigval64_t _si_value;    /* Signal value */
	int      _si_interrupt;      /* POSIX.1b signal */
	void * _si_ptr;      /* POSIX.1b signal */
	int      _si_overrun;  /* Timer overrun count; POSIX.1b timers */
	int      _si_timerid;  /* Timer ID; POSIX.1b timers */
	void *_si_addr;     /* Memory location which caused fault */
	long _si_band;     /* Band event (was int in
						   glibc 2.3.2 and earlier) */
	int      _si_fd;       /* File descriptor */
	short    _si_addr_lsb; /* Least significant bit of address
                                        (since Linux 2.6.32) */
} siginfo64_t;




typedef struct shlibmap {
	std::string name;
	loff_t offset;
	unsigned long vaddr;
	size_t size;
} shlibmap_t;

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
	typedef prstatus_32 prstatus;
	typedef fdinfo_32_t fdinfo;
	typedef Elf32_auxv_t auxv_t;
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
	typedef prstatus_64 prstatus;
	typedef fdinfo_64_t fdinfo;
	typedef Elf64_auxv_t auxv_t;
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

typedef pltgotinfo_t pltgot_info_t; // for backwards compatibility

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
		typedef typename ecfs_type::prstatus prstatus;
		typedef typename ecfs_type::auxv_t auxv_t;

		/*
		 * Private members for encapsulation
		 */
	private:

		void gen_prstatus();
		void gen_argv();
		void gen_local_symbols();
		
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
		std::string filepath;
		
		char *m_shstrtab; // incase anyone wants to publicly access the section string table
		/*
		 * To maintain an internal copy of the vectors for various structure arrays
		 */
		std::vector <pltgotinfo> m_pltgot;
		std::vector <fdinfo> m_fdinfo;
		std::vector <prstatus> m_prstatus;
		std::vector <ecfs_sym_t> m_dynsym; //dynamic symbols
		std::vector <ecfs_sym_t> m_symtab; //symtab vector
		std::vector <auxv_t> m_auxv;
		std::vector <string> m_argv;
		std::vector <shlibmap_t *> m_shlib;
		std::vector <Phdr> m_phdr;
		std::vector <Shdr> m_shdr;

	public:

		/*
		 * Constructor
		 */
		Ecfs() {
		}
		~Ecfs() {
			m_pltgot.clear();
			m_fdinfo.clear();
			m_prstatus.clear();
			m_dynsym.clear();
		}
		
		int load (const string); // invokes all other primary methods
		void unload(void);	// free up all data structures of ecfs object
		
		int get_fdinfo(std::vector<fdinfo>&);	// get vector of fdinfo structs
		std::vector<prstatus> &get_prstatus(); // get vector of elf_prstatus structs
		std::vector<prstatus> const &get_prstatus() const;

		int get_thread_count(void);	// get number of threads in process
		char * get_exe_path(void);	// get path to original executable that spawned the process
		int get_dynamic_symbols(vector <ecfs_sym_t>&);	// get a vector of the complete .dynsym symbol table
		int get_local_symbols(vector <ecfs_sym_t>&);
		std::vector<ecfs_sym_t> &get_local_symbols();
		std::vector<ecfs_sym_t> const &get_local_symbols() const;
		int get_siginfo(siginfo_t &);	// will fill siginfo_t with the signal struct
		ssize_t get_stack_ptr(uint8_t *&); // will set pointer at .stack section and return the size
		ssize_t get_heap_ptr(uint8_t *&); // will set pointer at .heap section and return the size
		ssize_t get_ptr_for_va(unsigned long, uint8_t *&); // will set ptr to the segment address specified, and return the size of bytes left
		ssize_t get_section_pointer(const char *, uint8_t *&); // set ptr to a given ELF section within a binary and return section size
		ssize_t get_section_size(const char *); // return the size of a section by name
		unsigned long get_section_va(const char *); // return the vaddr of a section by name
		unsigned long get_text_va(void);	// get vaddr of text segment
		unsigned long get_data_va(void);	// get vaddr of data segment
		size_t get_text_size(void); 		// get size of text segment
		size_t get_data_size(void);		// get size of data segment
		unsigned long get_plt_va(void);		// get vaddr of the .plt
		size_t get_plt_size(void);	// get size of the .plt 
		int get_auxv(vector <auxv_t>&);	// get auxiliary vector
		ssize_t get_shlib_maps(vector <shlibmap_t *>&); // get vector of shlibmap_t structs
		ssize_t get_pltgot_info(vector <pltgotinfo_t>&); // get vector of pltgotinfo_t structs
		unsigned long get_fault_location();	// get address that the fault happened on (taken from siginfo_t)
		std::vector<std::string> &get_argv();	// get the argument vector
		std::vector<std::string> const &get_argv() const;
		char * get_section_name_by_addr(unsigned long); // return pointer to section name
		int get_phdrs(vector <Phdr>&); // to get physical access to the program headers
		int get_shdrs(vector <Shdr>&); // to get physical access to the section headers
		std::string get_filepath();
};		
		
#define MAX_SYM_LEN 255

static inline int xopen(const char *path, int flags)
{
        int fd = open(path, flags);
        if (fd < 0) {
                fprintf(stderr, "opening path: %s failed\n", path);
                exit(-1);
        }
        return fd;
}

static inline int xfstat(int fd, struct stat *st)
{
        int ret = fstat(fd, st);
        if (ret < 0) {
                perror("fstat");
                exit(-1);
        }
        return 0;
}

static inline void * heapAlloc(size_t len)
{
        void *p = malloc(len);
        if (p == NULL) {
                perror("malloc");
                exit(-1);
        }
        memset(p, 0, len);
        return p;
}


static inline char * xstrdup(const char *s)
{
        char *p = strdup(s);
        if (p == NULL) {
                perror("strdup");
                exit(-1);
        }
        return p;
}

		
		
