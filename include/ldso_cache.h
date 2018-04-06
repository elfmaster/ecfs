/*
 * Taken from libelfmasters internal.h which is where I originally designed
 * the code for transitive resolution of shared library dependencies.
 */
#pragma once
#include <search.h>
#include <ctype.h>
#include <sys/queue.h>

#include "ecfs.h"

#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

#define CACHEMAGIC "ld.so-1.7.0"
struct file_entry {
	int flags;
	uint32_t key;
	uint32_t value;
};

struct cache_file {
	char magic[sizeof CACHEMAGIC - 1];
	uint32_t nlibs;
	struct file_entry libs[0];
};

#define CACHEMAGIC_NEW "glibc-ld.so.cache"
#define CACHE_VERSION "1.1"

#define ELF_LDSO_CACHE_OLD (1 << 0)
#define ELF_LDSO_CACHE_NEW (1 << 1)

struct file_entry_new {
        int32_t flags;
        uint32_t key;
        uint32_t value;
        uint32_t osversion;
        uint64_t hwcap;
};

struct cache_file_new {
	char magic[sizeof CACHEMAGIC_NEW - 1];
	char version[sizeof CACHE_VERSION - 1];
	uint32_t nlibs;         /* number of entries */
	uint32_t len_strings;   /* size of string table */
	uint32_t unused[5];     /* space for future extension */
	struct file_entry_new libs[0]; /* Entries describing libraries */
        /* After this the string table of size len_strings is found */
};

typedef struct elf_malloc_node {
	void *ptr;
	LIST_ENTRY(elf_malloc_node) _linkage;
} elf_malloc_node_t;

/*
 * Resolve basenames to full paths using ld.so.cache parsing
 */

#define ELF_SO_RESOLVE_F (1 << 0)
/*
 * Get all dependencies recursively
 */
#define ELF_SO_RESOLVE_ALL_F (1 << 1)

typedef struct elfdesc elfdesc_t;

typedef struct elf_shared_object {
        const char *basename;
        char *path;
} elf_shared_object_t;

typedef struct elf_shared_object_node {
        const char *basename;
        char *path;
        unsigned int index; // used by elf_shared_object iterator
        LIST_ENTRY(elf_shared_object_node) _linkage;
} elf_shared_object_node_t;

typedef struct elf_shared_object_iterator {
	unsigned int index;
	elfdesc_t *obj;
	int fd;
	void *mem;
        struct stat st;
        struct cache_file *cache;
        struct cache_file_new *cache_new;
        char *cache_data;
        size_t cache_size;
        uint32_t flags;
        uint32_t cache_flags;
        bool resolve;
        struct elf_shared_object_node *current;
        struct elf_shared_object_node *yield;
        struct hsearch_data yield_cache;
        LIST_HEAD(ldso_cache_yield_list, elf_shared_object_node) yield_list;
        LIST_HEAD(ldso_malloc_list, elf_malloc_node) malloc_list;
} elf_shared_object_iterator_t;

typedef enum elf_iterator_res elf_iterator_res_t;

elf_iterator_res_t
elf_shared_object_iterator_next(struct elf_shared_object_iterator *iter,
    struct elf_shared_object *entry);

bool elf_shared_object_iterator_init(elfdesc_t *obj, struct elf_shared_object_iterator *iter,
    const char *cache_path, uint32_t flags);
