#include <stdio.h>
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
#include <sys/procfs.h>		/* struct elf_prstatus */
#include <sys/resource.h>
#include "dwarf.h"
#include "libdwarf.h"

#define LOGGING_PATH "/home/ryan/bin/logging.txt"
#define ECFS_CORE_DIR "/home/ryan/bin" // XXX change this?
#define UNKNOWN_SHDR_SIZE 64
#define PAGE_ALIGN(x) (x & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(x) (PAGE_ALIGN(x) + PAGE_SIZE)

#define MAX_TID 256
#define PT_ATTACHED 1
#define PT_DETACHED 2

#define PARTIAL_SNAPSHOT 1
#define COMPLETE_SNAPSHOT 0

#define MAXFD 255

#define PS_TRACED 1
#define PS_STOPPED 2
#define PS_SLEEP_UNINTER 4
#define PS_SLEEP_INTER 8
#define PS_DEFUNCT 16
#define PS_RUNNING 32
#define PS_UNKNOWN 64

#define MAX_THREADS 256		// for each threads prstatus

#define ELFNOTE_NAME(_n_) ((char*)(_n_) + sizeof(*(_n_)))
#define ELFNOTE_ALIGN(_n_) (((_n_)+3)&~3)
#define ELFNOTE_NAME(_n_) ((char*)(_n_) + sizeof(*(_n_)))
#define ELFNOTE_DESC(_n_) (ELFNOTE_NAME(_n_) + ELFNOTE_ALIGN((_n_)->n_namesz))
#define ELFNOTE_NEXT(_n_) ((ElfW(Nhdr) *)(ELFNOTE_DESC(_n_) + ELFNOTE_ALIGN((_n_)->n_descsz)))

#define MAX_SHDR_COUNT 2048

struct opts {
	int use_stdin;
	char *logfile;
};

typedef struct {
	Elf64_Word namesz;
	Elf64_Word descsz;
	Elf64_Word type;
} ElfW(Note);

struct fde_func_data {		/* For eh_frame.c */
	uint64_t addr;
	size_t size;
};

#ifndef MAX_PATH
#define MAX_PATH 512
#endif

typedef struct fd_info {
	int fd;
	char path[MAX_PATH];
} fd_info_t;

struct section_meta {
	ElfW(Addr) bssVaddr, dynVaddr, relVaddr, relaVaddr, ehframeVaddr,
	    textVaddr, o_textVaddr, dataVaddr, o_dataVaddr, gotVaddr, noteVaddr,
	    hashVaddr, initVaddr, finiVaddr, pltVaddr, dsymVaddr, dstrVaddr,
	    interpVaddr, tlsVaddr;
	ElfW(Off) bssOff, dynOff, relOff, relaOff, noteOff, ehframeOff,
	    textOffset, dataOffset, gotOff, hashOff, initOff, finiOff, pltOff,
	    dsymOff, dstrOff, interpOff, tlsOff;
	ElfW(Word) bssSiz, dynSiz, hashSiz, ehframeSiz, textfSize, textSize,
	    dataSize, strSiz, pltSiz, interpSiz, tlsSiz, noteSiz, dsymSiz,
	    dstrSiz;
};

struct elf_thread_core_info {
	struct elf_prstatus *prstatus;
	struct elf_prpsinfo *psinfo;
	struct user_regs_struct *regs;
	siginfo_t *siginfo;
	 ElfW(Nhdr) * notes;
};

typedef struct ecfs_file_fmt {
	loff_t prstatus_offset; 
	loff_t prpsinfo_offset;
	loff_t fdinfo_offset;
	loff_t siginfo_offset;
	loff_t auxv_offset;
	loff_t exepath_offset;
	loff_t stb_offset;
	size_t prstatus_size;
	size_t prpsinfo_size;
	size_t fdinfo_size;
	size_t siginfo_size;
	size_t auxv_size;
	size_t exepath_size;
	int thread_count;
} ecfs_file_t;

struct nt_file_struct {
	struct {
		unsigned long addr;
		size_t size;
		size_t pgoff;
		char path[512];
	} files[4096];
	int fcount;
	int page_size;
};

struct lib_mappings {
	struct {
		unsigned long addr;
		unsigned long offset;
		size_t size;
		uint32_t flags; // PF_W|PF_R etc.
		char name[255];
	} libs[4096];
	int libcount;
};

typedef struct notedesc {
	ElfW(Nhdr) * notes;
	struct elf_prstatus *prstatus;	/* NT_PRSTATUS */
	struct elf_prpsinfo *psinfo;	/* NT_PRPSINFO */
#if __x86_64__
	Elf64_auxv_t *auxv;
#else
	Elf32_auxv_t *auxv;
#endif
	struct siginfo_t *siginfo;
	struct elf_thread_core_info thread_core_info[MAX_THREADS];
	elf_fpregset_t *fpu;
	int thread_count;
	int thread_status_size;
	int numnote;
	size_t auxv_size;
	struct nt_file_struct *nt_files;
	struct lib_mappings *lm_files;
} notedesc_t;

struct coredump_params {
	siginfo_t *siginfo;
	struct pt_regs *regs;
	unsigned long limit;
	unsigned long mm_flags;
};

typedef struct elfdesc {
	uint8_t *mem;
	 ElfW(Ehdr) * ehdr;
	 ElfW(Phdr) * phdr;
	 ElfW(Shdr) * shdr;
	 ElfW(Nhdr) * nhdr;
	 ElfW(Dyn)  *dyn;
	 ElfW(Addr) textVaddr;
	 ElfW(Addr) dataVaddr;
	 ElfW(Addr) dynVaddr;
	 ElfW(Addr) ehframe_Vaddr;
	 ElfW(Addr) noteVaddr;
	 ElfW(Addr) bssVaddr;
	 ElfW(Addr) interpVaddr;
	 ElfW(Off) textOffset;
	 ElfW(Off) dataOffset;
	 ElfW(Off) ehframeOffset;
	 ElfW(Off) dynOffset;
	 ElfW(Off) bssOffset;
	 ElfW(Off) interpOffset;
	 ElfW(Off) noteOffset;
	char *StringTable;
	char *path;
	size_t size;
	size_t noteSize;
	size_t gnu_noteSize;
	size_t textSize;
	size_t dataSize;
	size_t dynSize;
	size_t ehframe_Size;
	size_t bssSize;
	size_t interpSize;
	size_t o_datafsize; // data filesz of executable (not core)
	int dynlinked;
	int pie;
} elfdesc_t;

typedef struct mappings {
	uint8_t *mem;
	char *filename;
	unsigned long base;
	size_t size;
	int elfmap;
	int textbase;		// is the text segment base of the processes exe
	int stack;
	int thread_stack;
	int heap;
	int shlib;
	int padding;
	int special;
	int anonmap_exe;
	int filemap;
	int filemap_exe;
	int vdso;
	int vsyscall;
	int stack_tid;
	size_t sh_offset;
	uint32_t p_flags;
	int has_pt_load;
} mappings_t;

typedef struct memdesc {
	pid_t pid;
	uint8_t *exe;		/* Points to /proc/<pid>/exe */
	char *path;		// path to executable
	char *exe_path;
	char *comm;		//name of executable
	int mapcount;		// overall # of memory maps
	int type;		// ET_EXEC or ET_DYN
	 ElfW(Addr) base, data_base;
	struct {
		unsigned long sh_offset;
		unsigned long base;
		unsigned int size;
	} stack;
	struct {
		unsigned long sh_offset;
		unsigned long base;
		unsigned int size;
	} vdso;
	struct {
		unsigned long sh_offset;
		unsigned long base;
		unsigned int size;
	} vsyscall;
	struct {
		unsigned long sh_offset;
		unsigned long base;
		unsigned int size;
	} heap;
	struct {
		int fds[MAXFD];
		int pid;
		int ppid;
		int uid;
		int gid;
		int tidcount;
		int exit_signal;
		pid_t tid[MAX_TID];
		pid_t leader;
		pid_t tracer;	// the pid of the tracer
		unsigned int state;
	} task;
	mappings_t *maps;
	struct user_regs_struct pt_regs;
	char *stack_args;
	size_t stack_args_len;
	uint8_t *saved_auxv;
	int pie;
} memdesc_t;

typedef struct descriptor {
	elfdesc_t binary;
	memdesc_t memory;
	notedesc_t info[MAX_THREADS];
	int exe_type;
	int dynlinking;
	char *snapdir;
} desc_t;

typedef struct node {
	struct node *next;
	struct node *prev;
	desc_t *desc;
} node_t;

typedef struct list {
	node_t *head;
	node_t *tail;
} list_t;

void *heapAlloc(size_t);
char *xstrdup(const char *);
char *xfmtstrdup(char *fmt, ...);
int get_all_functions(const char *filepath, struct fde_func_data **funcs);
void ecfs_print(char *, ...);
int xopen(const char *, int);
