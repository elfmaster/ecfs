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
	char *name;
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
		int get_dynamic_symbols(vector <ecfs_sym_t>&);	// get a vector of the complete .dynsym symbol table
		int get_local_symbols(vector <ecfs_sym_t>&);
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
		unsigned long get_plt_size(void);	// get size of the .plt 
		int get_auxv(vector <auxv_t>&);	// get auxiliary vector
		ssize_t get_shlib_maps(vector <shlibmap_t>&);
		ssize_t get_pltgot_info(vector <pltgotinfo_t>&);
		
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




/*
 * NOTE:
 * Since the template type 'ecfs_type' is not passed as any arguments
 * to Ecfs::load(), we have to atleast specify it in the declaration of
 * the function template, hence the int Ecfs<ecfs_type>::load()
 */
template <class ecfs_type> int Ecfs<ecfs_type>::load(const char *path)
{	
	Ecfs *ecfs = this;
	uint8_t *mem;
	//typename ecfs_type::Ehdr *ehdr;
	//typename ecfs_type::Phdr *phdr;
	//typename ecfs_type::Shdr *shdr;
	int fd, i;
	struct stat st;
	Ecfs::Ehdr *ehdr;
	Ecfs::Phdr *phdr;
	Ecfs::Shdr *shdr;

	fd = xopen(path, O_RDONLY);
	xfstat(fd, &st);
	ecfs->filesize = st.st_size;
	mem = (uint8_t *)mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	
	if (memcmp(mem, "\x7f\x45\x4c\x46", 4) != 0)
		return -1;
	
	ehdr = (Ehdr *)mem;
	
	if (ehdr->e_type != ET_NONE && ehdr->e_type != ET_CORE) 
		return -1;
	
	if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0 || ehdr->e_shstrndx == SHN_UNDEF) 
		return -1;
	
	phdr = (Phdr *)(mem + ehdr->e_phoff);
	shdr = (Shdr *)(mem + ehdr->e_shoff);
	
	/*
	 * setup section header string table
	 */
	ecfs->shstrtab = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset];
	
	/*
	 * setup .dynsym symbols, .symtab symbols, and .dynstr and .strtab string table
	 */
	for (ecfs->dynstr = NULL, i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".dynstr")) 
			ecfs->dynstr = (char *)&mem[shdr[i].sh_offset];
		else
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".strtab"))
			ecfs->strtab = (char *)&mem[shdr[i].sh_offset];
		else
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".dynsym")) 
			ecfs->dynsym = (Ecfs::Sym *)&mem[shdr[i].sh_offset];
		else
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".symtab"))
			ecfs->symtab = (Ecfs::Sym *)&mem[shdr[i].sh_offset];
	}
	
	
	/*
	 * Find .dynamic, .text, and .data segment/section
	 */
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".dynamic")) {
			ecfs->dynVaddr = shdr[i].sh_addr;
			ecfs->dynSize = shdr[i].sh_size;
			ecfs->dynOff = shdr[i].sh_offset;
			ecfs->dyn = (Ecfs::Dyn *)&mem[shdr[i].sh_offset];
		} else
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], "._DATA")) {
			ecfs->dataVaddr = shdr[i].sh_addr;
			ecfs->dataSize = shdr[i].sh_size;
			ecfs->dataOff = shdr[i].sh_offset;
		} else
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], "._TEXT")) {
			ecfs->textVaddr = shdr[i].sh_addr;
			ecfs->textSize = shdr[i].sh_size;
			ecfs->textOff = shdr[i].sh_offset;
		}
	}
	/*
	 * Get dynamic relocation sections
	 */
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".rela.dyn")) {
			ecfs->dyn_rela = (Ecfs::Rela *)&mem[shdr[i].sh_offset];
			ecfs->dyn_rela_count = shdr[i].sh_size / shdr[i].sh_entsize;
			break;
		}
	}

	/*
	 * Get plt relocation sections
	 */
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".rela.plt")) {
			ecfs->plt_rela = (Ecfs::Rela *)&mem[shdr[i].sh_offset];
			ecfs->plt_rela_count = shdr[i].sh_size / shdr[i].sh_entsize;
			break;
		}
	}
	
	/*
	 * set the pltgot pointer
	 */
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".got.plt")) {
			ecfs->pltgot = (unsigned long *)&mem[shdr[i].sh_offset];
			break;
		}
	}
	
	/*
	 * Get plt addr and size
	 */
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".plt")) {
			ecfs->pltVaddr = shdr[i].sh_addr;
			ecfs->pltSize = shdr[i].sh_size;
			break;
		}
	}

	/*
	 * Get .personality info
	 */
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&ecfs->shstrtab[shdr[i].sh_name], ".personality")) {
			ecfs->elfstats = (elf_stat_t *)&mem[shdr[i].sh_offset];
			break;
		}
	}
	if (ecfs->elfstats->personality & ELF_PIE)
		ecfs->pie = 1;

	ecfs->ehdr = ehdr;
	ecfs->phdr = phdr;
	ecfs->shdr = shdr;
	ecfs->mem = mem;
	
	return 0;
}	
template <class ecfs_type> 
void Ecfs<ecfs_type>::unload(void)
{
	munmap(this->mem, this->filesize);
}


/*
 * Use like:
 *       Ecfs <ecfs_type64>ecfs(argv[1]);
 *       vector <fdinfo_64> fdinfo_vector;
 *       if (ecfs.get_fdinfo(fdinfo_vector) < 0) {
 *               printf("Getting fdinfo failed\n");
 *       }
 *	 for (i = 0; i < fdinfo_vector.size(); i++)
 * 	 	printf("filepath: %s\n", fdinfo_vector[i].path);
 *
*/
template <class ecfs_type>
int Ecfs<ecfs_type>::get_fdinfo(std::vector<Ecfs::fdinfo> &fdinfo_vec)
{
	Ecfs *desc = this;
	char *StringTable = desc->shstrtab;
	Ecfs::Shdr *shdr = desc->shdr;
	Ecfs::fdinfo *fdinfo_ptr;
	
	/*
	 * By default std::vector uses an allocator for the heap so we
	 * can return the fdinfo_vec by reference, but we will go ahead
	 * and do it by value
	 */
	//std::vector <Ecfs::fdinfo> fdinfo_vec;
	size_t items;

	for (int i = 0; i < desc->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".fdinfo")) {
			fdinfo_ptr = (Ecfs::fdinfo *)alloca(shdr[i].sh_size);
			memcpy(fdinfo_ptr, &desc->mem[shdr[i].sh_offset], shdr[i].sh_size);
			items = shdr[i].sh_size / sizeof(Ecfs::fdinfo);
			fdinfo_vec.assign(fdinfo_ptr, &fdinfo_ptr[items]);
			this->fdinfo_vector = fdinfo_vec;
			return fdinfo_vec.size();
		}
	}
	return -1; // failed if we got here
}

/*
 example:
 	vector <prstatus_64> prstatus_vector;
        if (ecfs.get_prstatus(prstatus_vector) < 0)
                printf("Getting prstatus failed\n");
	for (i = 0; i < prstatus_vector.size(); i++)
		printf("%d\n", prstatus_vector[i].pr_pid);
*/

template <class ecfs_type>
int Ecfs<ecfs_type>::get_prstatus(std::vector<Ecfs::prstatus> &prstatus_vec)
{
	char *StringTable = this->shstrtab;
	Ecfs::Shdr *shdr = this->shdr;
	Ecfs::prstatus *prstatus_ptr;
	size_t items;

	for (int i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".prstatus")) {
			prstatus_ptr = (Ecfs::prstatus *)alloca(shdr[i].sh_size);
			memcpy(prstatus_ptr, &this->mem[shdr[i].sh_offset], shdr[i].sh_size);
			items = shdr[i].sh_size / sizeof(Ecfs::prstatus);
			prstatus_vec.assign(prstatus_ptr, &prstatus_ptr[items]);
			this->prstatus_vector = prstatus_vec;
			return prstatus_vec.size();
		}
	}
	/*
	 * In addition to returning a vector we assign the internal
	 * copy as well that can be used at any time until the Ecfs object is
	 * destructed.
	 */
	//this->prstatus_vector = prstatus_vec;
	return -1;
}

template <class ecfs_type>
int Ecfs<ecfs_type>::get_thread_count(void)
{
	char *StringTable = this->shstrtab;
	Ecfs::Shdr *shdr = this->shdr;
	int i;

	for (i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".prstatus")) 
			return shdr[i].sh_size / shdr[i].sh_entsize;
	}
	return -1;
}
	
template <class ecfs_type>
char * Ecfs<ecfs_type>::get_exe_path(void)
{
	
	char *StringTable = this->shstrtab;
	Ecfs::Shdr *shdr = this->shdr;
	char *ret;
	
	for (int i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".exepath")) {
			ret = (char *)heapAlloc(shdr[i].sh_size);
			strcpy(ret, (char *)&this->mem[shdr[i].sh_offset]);
			return ret;	
		}
	}
	return NULL;
}

template <class ecfs_type>
int Ecfs<ecfs_type>::get_dynamic_symbols(vector <ecfs_sym_t>&sym_vec)
{
	int i, j;
	Ecfs::Ehdr *ehdr = this->ehdr;
	Ecfs::Shdr *shdr = this->shdr;
	ssize_t symcount;
	Ecfs::Sym *dynsym = this->dynsym;
	ecfs_sym_t *syms;
	
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (shdr[i].sh_type == SHT_DYNSYM) {
			symcount = shdr[i].sh_size / sizeof(Ecfs::Sym);
			size_t alloc_len = symcount * sizeof(ecfs_sym_t);
			syms = (ecfs_sym_t *)alloca(alloc_len);
			for (j = 0; j < symcount; j++) {
				syms[j].strtab = this->dynstr;
				syms[j].symval = dynsym[j].st_value;
				syms[j].size = dynsym[j].st_size;
				syms[j].type = ELF32_ST_TYPE(dynsym[j].st_info);
				syms[j].binding = ELF32_ST_BIND(dynsym[j].st_info);
				syms[j].nameoffset = dynsym[j].st_name;
				syms[j].name = &syms[j].strtab[syms[j].nameoffset];
			}
			sym_vec.assign(syms, &syms[symcount]);
			return sym_vec.size();
		}
	}
	return -1; // failed if we got here
}

/*
 * We only use a 64bit version if siginfo_t with this
 * function. There are too many oddities with this struct
 * and glibc to redefine it as both 32bit and 64bit I have
 * tried. This isn't a blocker however though because the first
 * 6 members are the same whether it be in 64bit or 32bit and
 * that's typically all we need from this structure to get the
 * most interesting data, including signal numbers etc.
 * In the future I may fix this by storing a custom siginfo_t
 * structure within the .siginfo section of an ECFS file but I will
 * have to change the ecfs code itself. This custom siginfo_t will
 * contain only the first few members, similar to elf_siginfo struct.
 *
 */
template <class ecfs_type>
int Ecfs<ecfs_type>::get_siginfo(siginfo_t &siginfo)
{
	char *StringTable = this->shstrtab;
	Ecfs::Shdr *shdr = this->shdr;
	int i;

	for (i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".siginfo")) {
			siginfo = *(siginfo_t *)(&this->mem[shdr[i].sh_offset]);
			return 0;
		}
	}

	return -1;
}

/*
 * This function takes a pointer passed by reference 
 * and assigns it to point at the given section. It also
 * returns the size of that section. This is a nice way to
 * do it so that the user can get both the section pointer
 * and size all in one. On failure -1 is returned
 * or *ptr = NULL
 *
 * Example:
 * uint8_t *ptr;
 * ssize_t stack_size = ecfs.get_stack_ptr(ptr);
 * for(; stack_size != -1 && stack_size > 0; stack_size--)
 *	printf("stack_byte: %02x\n", *ptr);
 *
 */
template <class ecfs_type>
ssize_t Ecfs<ecfs_type>::get_stack_ptr(uint8_t *&ptr)
{
	char *StringTable = this->shstrtab;
	Ecfs::Shdr *shdr = this->shdr;
	int i;
	for (i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".stack")) {
			ptr = &this->mem[shdr[i].sh_offset];
			return shdr[i].sh_size;
		}
	}

	ptr = NULL;
	return -1;
}

template <class ecfs_type>
ssize_t Ecfs<ecfs_type>::get_heap_ptr(uint8_t *&ptr)
{
	char *StringTable = this->shstrtab;
	ElfW(Shdr) *shdr = this->shdr;
	int i;

	for (i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".heap")) {
			ptr = &this->mem[shdr[i].sh_offset];
			return shdr[i].sh_size;
		}
	}
	
	ptr = NULL;
	return -1;
}

template <class ecfs_type>
int Ecfs<ecfs_type>::get_local_symbols(vector <ecfs_sym_t>&sym_vec)
{
        int i, j;
        Ecfs::Ehdr *ehdr = this->ehdr;
        Ecfs::Shdr *shdr = this->shdr;
        ssize_t symcount;
        Ecfs::Sym *symtab = this->symtab;
        ecfs_sym_t *syms;

        for (i = 0; i < ehdr->e_shnum; i++) {
                if (shdr[i].sh_type == SHT_SYMTAB) {
                        symcount = shdr[i].sh_size / sizeof(Ecfs::Sym);
                        size_t alloc_len = symcount * sizeof(ecfs_sym_t);
                        syms = (ecfs_sym_t *)alloca(alloc_len);
                        for (j = 0; j < symcount; j++) {
                                syms[j].strtab = this->strtab;
                                syms[j].symval = symtab[j].st_value;
                                syms[j].size = symtab[j].st_size;
                                syms[j].type = ELF32_ST_TYPE(symtab[j].st_info);
                                syms[j].binding = ELF32_ST_BIND(symtab[j].st_info);
                                syms[j].nameoffset = symtab[j].st_name;
                                syms[j].name = &syms[j].strtab[syms[j].nameoffset];
                        }
                        sym_vec.assign(syms, &syms[symcount]);
                        return sym_vec.size();
                }
        }
        return -1; // failed if we got here
}

/*
 * Example of using get_ptr_for_va(). Lets zero out part of a segment
 * starting at an arbitrary address within the segment.
 *
 * uint8_t *ptr;
 * ssize_t bytes_left_in_segment = ecfs.get_ptr_for_va(0x4000ff, ptr);
 * if (ptr) 
 * 	for (int i = 0; i < bytes_left_in_segment; i++) 
 * 		ptr[i] = 0;
 * 
 */
template <class ecfs_type>
ssize_t Ecfs<ecfs_type>::get_ptr_for_va(unsigned long vaddr, uint8_t *&ptr)
{
	Ecfs::Ehdr *ehdr = this->ehdr;
	Ecfs::Phdr *phdr = this->phdr;
	ssize_t len;
	int i;
	
	for (i = 0; i < ehdr->e_phnum; i++) {
		if (vaddr >= phdr[i].p_vaddr && vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
			ptr = (uint8_t *)&this->mem[phdr[i].p_offset + (vaddr - phdr[i].p_vaddr)];
			len = phdr[i].p_vaddr + phdr[i].p_memsz - vaddr;
			return len;
		}
	}
	ptr = NULL;
	return -1;
	
}

/*
 * Example of us printing out the uninitialized data memory
 * from .bss section:
 *
 * len = ecfs.get_section_pointer(".bss", ptr);
 * for (int i = 0; i < len; i++)
 * 	printf("%02x\n", ptr[i]);
 *
 */
template <class ecfs_type>
ssize_t Ecfs<ecfs_type>::get_section_pointer(const char *name, uint8_t *&ptr)
{
	char *StringTable = this->shstrtab;
	Ecfs::Shdr *shdr = this->shdr;
	ssize_t len;
	int i;

	for (i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], name)) {
			ptr = (uint8_t *)&this->mem[shdr[i].sh_offset];
			len = shdr[i].sh_size;
			return len;
		}		
	}
	ptr = NULL;
	return -1;
}

/*
 * i.e len = get_section_size(desc, ".bss");
 */
template <class ecfs_type>
ssize_t Ecfs<ecfs_type>::get_section_size(const char *name)
{
	char *StringTable = this->shstrtab;
	ElfW(Shdr) *shdr = this->shdr;
	ssize_t len;
	int i;

	for (i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], name)) {
			len = shdr[i].sh_size;
			return len;
		}
	}
	return -1;
}

template <class ecfs_type>
unsigned long Ecfs<ecfs_type>::get_section_va(const char *name)
{
	char *StringTable = this->shstrtab;
	Ecfs::Shdr *shdr = this->shdr;
	int i;
	unsigned long addr;

	for (i = 0; i < this->ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], name)) {
			addr = shdr[i].sh_addr;
			return addr;
		}
	}
	return 0;
}

template <class ecfs_type>
unsigned long Ecfs<ecfs_type>::get_text_va(void)
{
	return this->textVaddr;
}

template <class ecfs_type>
unsigned long Ecfs<ecfs_type>::get_data_va(void)
{
	return this->dataVaddr;
}

template <class ecfs_type>
size_t Ecfs<ecfs_type>::get_text_size(void) 
{
	return this->textSize;
}

template <class ecfs_type>
size_t Ecfs<ecfs_type>::get_data_size(void)
{
	return this->dataSize;
}

template <class ecfs_type>
unsigned long Ecfs<ecfs_type>::get_plt_va(void)
{
	return this->pltVaddr;
}

template <class ecfs_type>
unsigned long Ecfs<ecfs_type>::get_plt_size(void)
{
	return this->pltSize;
}


/*
 * Use a vector, why not? We are afterall dealing
 * with the 'auxiliary vector'
 */
template <class ecfs_type>
int Ecfs<ecfs_type>::get_auxv(vector <auxv_t> &auxv)
{
	Ecfs::Ehdr *ehdr = this->ehdr;
	Ecfs::Shdr *shdr = this->shdr;
	char *shstrtab = this->shstrtab;
	int i, ac = 0;
	Ecfs::auxv_t *auxp;

	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&shstrtab[shdr[i].sh_name], ".auxvector")) {
			ac = shdr[i].sh_size / sizeof(Ecfs::auxv_t);
			auxp = (Ecfs::auxv_t *)&this->mem[shdr[i].sh_offset];
			auxv.assign(auxp, auxp + ac);
			break;
		}
	}
	return ac;
}

template <class ecfs_type>
ssize_t Ecfs<ecfs_type>::get_shlib_maps(vector <shlibmap_t> &shlib)
{
	ssize_t i, count;	
	char *shstrtab = this->shstrtab;
	Ecfs::Shdr *shdr = this->shdr;
	shlibmap_t *shlibp = (shlibmap_t *)alloca(sizeof(shlibmap_t));

	for (count = 0, i = 0; i < this->ehdr->e_shnum; i++) {
		switch(shdr[i].sh_type) {
			case SHT_SHLIB:
			case SHT_INJECTED:
			case SHT_PRELOADED:
				count++;
				shlibp->name = xstrdup(&shstrtab[shdr[i].sh_name]);
				shlibp->vaddr = shdr[i].sh_addr;
				shlibp->offset = shdr[i].sh_offset;
				shlibp->size = shdr[i].sh_size;
				shlib.push_back(*shlibp);
			default:
				continue;
		}
	}
	return count;
}


/*
 * XXX FALSE POSITIVES BUG
 * I'm not sure if this function is the culprit, or if its a problem with the
 * symbol resolution against certain shared libraries, but in really big GOT's
 * such as with sshd, there are incorrect values showing up, such as pginfo[N].got_entry_va
 * might have an address that doesn't match the proper shared library address, or the PLT address
 * which normally indicates a PLT/GOT hooks, but in this case, its verified that there are no
 * hooks, thus resulting in FALSE POSITIVES
*/

template <class ecfs_type>
ssize_t Ecfs<ecfs_type>::get_pltgot_info(vector <pltgotinfo_t> &pginfo)
{	
	ssize_t i;
	unsigned long *GOT = NULL;
	Ecfs::Sym *symtab = this->dynsym;
	Ecfs::Sym *sym;
	Ecfs::Addr pltVaddr;
	size_t pltSize;
	pltgotinfo_t *pginfo_ptr;

	printf("Getting PLT info, sizes and address\n");
	if ((pltVaddr = this->get_plt_va()) == 0)
		return -1;
	if ((pltSize = this->get_plt_size()) == 0)
		return -1;
	if (this->plt_rela_count == 0 || this->plt_rela == NULL || symtab == NULL)
		return -1;
	printf("Building PLT vector\n");
	pginfo_ptr = (pltgot_info_t *)alloca(this->plt_rela_count * sizeof(pltgotinfo_t));
	GOT = &this->pltgot[3]; // the first 3 entries are reserved
	pltVaddr += 16; // we want to start at the PLT entry after what is called PLT-0
	for (i = 0; i < this->plt_rela_count; i++) {
		pginfo_ptr[i].got_site = this->plt_rela[i].r_offset;
		pginfo_ptr[i].got_entry_va = (unsigned long)GOT[i];
		 sym = (Ecfs::Sym *)&symtab[ELF64_R_SYM(this->plt_rela[i].r_info)];
		pginfo_ptr[i].shl_entry_va = sym->st_value;
		 // the + 6 is because it must point to the push instruction in the plt entry
		pginfo_ptr[i].plt_entry_va = (pltVaddr + 6); // + (desc->pie ? desc->textVaddr : 0); 
		pltVaddr += 16;
		printf("adding entry\n");
		pginfo.push_back(pginfo_ptr[i]);
	}
	return i;
}

#if 0
unsigned long get_fault_location(ecfs_elf_t *desc)
{
	siginfo_t siginfo;
	
	if (get_siginfo(desc, &siginfo) < 0)
		return 0;

	return (unsigned long)siginfo.si_addr;
}

/*
 * Returns argc and allocated and fills argv
 */
int get_arg_list(ecfs_elf_t *desc, char ***argv)
{
	unsigned int i, argc, c;
	ElfW(Ehdr) *ehdr = desc->ehdr;
	ElfW(Shdr) *shdr = desc->shdr;C++ **&
	uint8_t *mem = desc->mem;
	char *shstrtab = desc->shstrtab;
	char *p = NULL;
	char *q = NULL;

	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&shstrtab[shdr[i].sh_name], ".arglist")) {
			*argv = (char **)heapAlloc(sizeof(char *) * MAX_ARGS);		
			p = (char *)&mem[shdr[i].sh_offset];
			for (argc = 0, c = 0; c < shdr[i].sh_size; ) {
				*((*argv) + argc++) = xstrdup(p);
				 q = strchr(p, '\0') + 1;
				 c += (q - p);
				 p = q;
			}
			return argc;
		}
	}
	**argv = NULL;
	return -1;
}

char * get_section_name_by_addr(ecfs_elf_t *desc, unsigned long addr)
{
	ElfW(Ehdr) *ehdr = desc->ehdr;
	ElfW(Shdr) *shdr = desc->shdr;
	char *shstrtab = desc->shstrtab;
	int i;

	for (i = 0; i < ehdr->e_shnum; i++) 
		if (shdr[i].sh_addr == addr)
			return &shstrtab[shdr[i].sh_name];
	return NULL;
}
#endif
#endif
