/*
 * NOTE: This code was adapted from my other project libelfmaster.
 */
#include "../include/ecfs.h"
#include "../include/ldso_cache.h"
#include "../include/util.h"

#define MAX_SO_COUNT 1024
#define CACHE_FILE "/etc/ld.so.cache"
#define CACHEMAGIC_VERSION_NEW CACHEMAGIC_NEW CACHE_VERSION

#define ALIGN_CACHE(addr)                               \
	(((addr) + __alignof__ (struct cache_file_new) -1)      \
	    & (~(__alignof__ (struct cache_file_new) - 1)))

bool
elf_shared_object_iterator_init(elfdesc_t *obj, struct elf_shared_object_iterator *iter,
    const char *cache_path, uint32_t flags)
{
	const char *cache_file = cache_path == NULL ? CACHE_FILE : cache_path;

	LIST_INIT(&iter->yield_list);
	LIST_INIT(&iter->malloc_list);

	iter->flags = flags;
	iter->cache_flags = 0;
	iter->index = 0;
	iter->obj = obj;

	if ((flags & ELF_SO_RESOLVE_F) == 0 &&
	    (flags & ELF_SO_RESOLVE_ALL_F) == 0)
		goto finish;
	if (flags & ELF_SO_RESOLVE_ALL_F) {
		iter->flags |= ELF_SO_RESOLVE_F;
		memset(&iter->yield_cache, 0, sizeof(struct hsearch_data));
		if (hcreate_r(MAX_SO_COUNT, &iter->yield_cache) == 0) {
			log_msg2(__LINE__, __FILE__, "hcreate_r: %s",
			    strerror(errno));
			return false;
		}
	}
	iter->fd = open(cache_file, O_RDONLY);
	if (iter->fd < 0) {
		log_msg2(__LINE__, __FILE__, "open cache_file: %s\n",
		    strerror(errno));
		return false;
	}
	if (fstat(iter->fd, &iter->st) < 0) {
		log_msg2(__LINE__, __FILE__, "fstat: %s\n", strerror(errno));
		return false;
	}
	iter->mem = mmap(NULL, iter->st.st_size, PROT_READ, MAP_PRIVATE,
	    iter->fd, 0);
	if (iter->mem == MAP_FAILED) {
		log_msg2(__LINE__, __FILE__, "mmap %s: %s\n",
		    CACHE_FILE, strerror(errno));
		return false;
	}
	iter->cache = iter->mem;

	if (memcmp(iter->mem, CACHEMAGIC, strlen(CACHEMAGIC))) {
		size_t offset;

		iter->cache_flags |= ELF_LDSO_CACHE_OLD;
		offset = ALIGN_CACHE(sizeof(struct cache_file)
		    + iter->cache->nlibs * sizeof(struct file_entry));
		iter->cache_new = (struct cache_file_new *)
		    ((char *)iter->cache + offset);
		if ((size_t)iter->st.st_size < (offset + sizeof(struct cache_file_new))
		    || memcmp(iter->cache_new->magic, CACHEMAGIC_VERSION_NEW,
		    strlen(CACHEMAGIC_VERSION_NEW)) != 0) {
			iter->cache_new = (void *)-1;
		} else {
			iter->cache_flags |= ELF_LDSO_CACHE_NEW;
		}
	} else if (memcmp(iter->mem, CACHEMAGIC_VERSION_NEW,
	    strlen(CACHEMAGIC_VERSION_NEW)) == 0) {
		iter->cache_new = iter->mem;
		iter->cache_flags |= ELF_LDSO_CACHE_NEW;
	}
	if (iter->cache_flags & ELF_LDSO_CACHE_NEW) {
		iter->cache_data = (char *)iter->cache_new;
		iter->cache_size = (char *)iter->cache + iter->st.st_size -
		    iter->cache_data;
		log_msg2(__LINE__, __FILE__,
		    "using new cache, size: %lu\n", iter->cache_size);
	} else {
		iter->cache_data =
		    (char *)&iter->cache->libs[iter->cache->nlibs];
		iter->cache_size = (char *)iter->cache + iter->st.st_size -
		    iter->cache_data;
		log_msg2(__LINE__, __FILE__,
		    "using old cache size: %lu\n", iter->cache_size);
	}
finish:
	iter->current = LIST_FIRST(&obj->list.shared_objects);
	return true;
}

elf_iterator_res_t
elf_shared_object_iterator_next(struct elf_shared_object_iterator *iter,
    struct elf_shared_object *entry)
{
	bool result;

	if (iter->current == NULL && LIST_EMPTY(&iter->yield_list)) {
		ldso_cleanup(iter);
		return ELF_ITER_DONE;
	}

        if ((iter->flags & ELF_SO_RESOLVE_F) == 0)
                goto next_basename;

        if (iter->flags & ELF_SO_RESOLVE_ALL_F) {
                if (LIST_EMPTY(&iter->yield_list) == 0) {
			iter->yield = LIST_FIRST(&iter->yield_list);
			entry->path = iter->yield->path;
			entry->basename = iter->yield->basename;
			LIST_REMOVE(iter->yield, _linkage);
			free(iter->yield);
			return ELF_ITER_OK;
		}
		result = ldso_recursive_cache_resolve(iter, iter->current->basename);
		if (!result) {
			log_msg2(__LINE__, __FILE__,
			    "ldso_recursive_cache_resolve failed\n");
			goto err;
		}
		if (result) {
			entry->path = (char *)ldso_cache_bsearch(iter, iter->current->basename);
			entry->basename = iter->current->basename;
			iter->current = LIST_NEXT(iter->current, _linkage);

			if (entry->path == NULL)
				return ELF_ITER_NOTFOUND;

			if (ldso_insert_yield_cache(iter, entry->path) == false) {
				log_msg2(__LINE__, __FILE__,
				    "ldso_insert_yield_cache failed\n");
				goto err;
			}
			return ELF_ITER_OK;
		}
	}
	entry->path = (char *)ldso_cache_bsearch(iter, iter->current->basename);
	if (entry->path == NULL) {
		log_msg2(__LINE__, __FILE__,
		    "ldso_cache_bsearch: %s failed\n", iter->current->basename);
		goto err;
	}

next_basename:
	entry->basename = iter->current->basename;
	iter->current = LIST_NEXT(iter->current, _linkage);
	return ELF_ITER_OK;
err:
	ldso_cleanup(iter);
	return ELF_ITER_ERROR;
}
