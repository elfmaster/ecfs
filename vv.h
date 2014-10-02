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
#include <sys/procfs.h> /* struct elf_prstatus */

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

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

struct elf_note_info {
        struct memelfnote *notes;
        struct elf_prstatus *prstatus;  /* NT_PRSTATUS */
        struct elf_prpsinfo *psinfo;    /* NT_PRPSINFO */
        struct list_head thread_list;
        elf_fpregset_t *fpu;
//#ifdef ELF_CORE_COPY_XFPREGS
//        elf_fpxregset_t *xfpu;
//#endif
        int thread_status_size;
        int numnote;
};

struct coredump_params {
        siginfo_t *siginfo;
	struct pt_regs *regs;
        unsigned long limit;
        unsigned long mm_flags;
};

typedef struct elfdesc {
	uint8_t *mem;
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	ElfW(Shdr) *shdr;
	ElfW(Addr) textVaddr;
	ElfW(Addr) dataVaddr;
	ElfW(Off) textOffset;
	ElfW(Off) dataOffset;
	ElfW(Off) dynamicOffset;
	char *StringTable;
} elfdesc_t;

typedef struct mappings {
	uint8_t *mem;
	char *filename;
	unsigned long base;
	size_t size;
	int elfmap;
	int stack;
	int heap;
	int shlib;
	int padding;
	int anonmap_exe;
	int filemap;
	int filemap_exe;
	int vdso;
	int vsyscall;
	size_t sh_offset;
	uint32_t p_flags;
} mappings_t;

typedef struct memdesc {
	pid_t pid;	
	uint8_t *exe; /* Points to /proc/<pid>/exe */
	char *path;   // path to executable
	char *comm; //name of executable
	int mapcount; // overall # of memory maps
	int type; // ET_EXEC or ET_DYN
	
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
		int uid, gid; 
		int tidcount;
		pid_t tid[MAX_TID];
		pid_t leader;
		pid_t tracer; // the pid of the tracer
		unsigned int state;
	} task;
	mappings_t *maps;
	struct user_regs_struct pt_regs;
} memdesc_t;
	
		
	
typedef struct descriptor {
	elfdesc_t binary;
	memdesc_t memory;
	int exe_type;
	int dynlinking;
	char *snapdir;
} desc_t;


typedef struct node {
        struct node *next;
        struct node *prev;
        pid_t item;
        desc_t *desc;
} node_t;

typedef struct list {
        node_t *head;
        node_t *tail;
} list_t;



memdesc_t * take_process_snapshot(pid_t);
void * heapAlloc(size_t);
char * xstrdup(const char *);
char * xfmtstrdup(char *fmt, ...);

