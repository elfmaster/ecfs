/*
 * NOTE: This code was adapted from libelfmaster's ldso resolution
 * iterator.
 */
#include "../include/ecfs.h"
#include "../include/ldso_cache.h"
#include "../include/util.h"
#include "../include/misc.h"

#define MAX_SO_COUNT 1024
#define CACHE_FILE "/etc/ld.so.cache"
#define CACHEMAGIC_VERSION_NEW CACHEMAGIC_NEW CACHE_VERSION

#define ALIGN_CACHE(addr)                               \
	(((addr) + __alignof__ (struct cache_file_new) -1)      \
	    & (~(__alignof__ (struct cache_file_new) - 1)))

static bool ldso_parse_dynamic_segment(elfdesc_t *);

list_t *needed_list;

/*
 * NOTE: This function doesn't fill in an entire elfdesc_t. This is because
 * the code in this file was adapted from libelfmaster, and so we had
 * to do some hacks to get it working since ECFS doesn't use libelfmaster
 * for parsing, and that is because libelfmaster only builds on x64 which
 * diverts from our goals with building on 32bit systems.
 */
static bool
ldso_elf_open_object(char *path, elfdesc_t *elfdesc)
{
	int fd, i;
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	struct stat st;
	uint8_t *mem;
	ElfW(Dyn) *dyn;
	/*
	 * TODO, we shouldn't assume all PIE (ET_DYN) will have a base of 0
	 * since you can have an ET_DYN that has an absolute address range
	 * but for now we will keep it.
	 */
	uint64_t text_base = elfdesc->pie ? 0 : elfdesc->textVaddr;

	fd = xopen(path, O_RDONLY);
	xfstat(fd, &st);
	elfdesc->mmap_size = st.st_size;

	log_msg2(__LINE__, __FILE__, "calling ldso_elf_open_object: arch: %lx text_base: %lx\n",
	    elfdesc->arch, text_base);

	mem = elfdesc->mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (elfdesc->mem == MAP_FAILED) {
		log_msg2(__LINE__, __FILE__, "mmap: %s\n", strerror(errno));
		return false;
	}

	ehdr = elfdesc->ehdr = (ElfW(Ehdr) *)mem;
	phdr = elfdesc->phdr = (ElfW(Phdr) *)&mem[ehdr->e_phoff];

	for (i = 0; i < elfdesc->ehdr->e_phnum; i++) {
		if (elfdesc->phdr[i].p_type == PT_DYNAMIC) {
			dyn = elfdesc->dyn = (ElfW(Dyn) *)&mem[elfdesc->phdr[i].p_offset];
		}
	}

	for (i = 0; dyn[i].d_tag != DT_NULL; i++) {
		if (dyn[i].d_tag != DT_STRTAB)
			continue;
		elfdesc->dynstr = (char *)&mem[dyn[i].d_un.d_val - text_base];
	}
	/*
	 * Setup the first pass of basenames for DT_NEEDED entries
	 * in a linked list.
	 */
	return ldso_parse_dynamic_segment(elfdesc);
}

static bool
ldso_elf_close_object(elfdesc_t *elfdesc)
{

	if (munmap(elfdesc->mem, elfdesc->mmap_size) < 0)
		return false;
	return true;
}

static bool
ldso_parse_dynamic_segment(elfdesc_t *obj)
{
	struct elf_shared_object_node *so;
	ElfW(Phdr) *phdr = obj->phdr;
	ElfW(Dyn) *dyn = obj->dyn;
	int i, j;

	LIST_INIT(&obj->list.shared_objects);

	/*
	 * This should already be filled in by extract_dyntag_info
	 * but just incase lets perform a sanity check because we
	 * might use this code in other places within the state of
	 * the ECFS software. Such as with ecfs exec.
	 */
	if (obj->dyn == NULL) {
		for (i = 0; i < obj->ehdr->e_phnum; i++) {
			if (phdr[i].p_type != PT_DYNAMIC)
				continue;
			obj->dyn = (ElfW(Dyn) *)&obj->mem[phdr[i].p_offset];
			break;
		}
	}
	if (obj->dyn == NULL)
		return false;

	for (j = 0, dyn = obj->dyn; dyn[j].d_tag != DT_NULL; j++) {
		switch(dyn[j].d_tag) {
		case DT_NEEDED:
			so = heapAlloc(sizeof(*so));
			so->basename = (char *)&obj->dynstr[dyn[j].d_un.d_val];
			log_msg2(__LINE__, __FILE__, "Inserting: %s\n", so->basename);
			LIST_INSERT_HEAD(&obj->list.shared_objects, so, _linkage);
			break;
		default:
			break;
		}
	}
	return true;
}

static int
ldso_cache_cmp(const char *p1, const char *p2)
{

	while (*p1) {
		if (isdigit(*p1) && isdigit(*p2)) {
			int v1, v2;

			v1 = strtoul(p1, (char **)&p1, 10);
			v2 = strtoul(p2, (char **)&p2, 10);
			if (v1 != v2)
				return v1 - v2;
		}
		else if (isdigit(*p1) && !isdigit(*p2)) {
			return 1;
		} else if (!isdigit(*p1) && isdigit(*p2)) {
			return -1;
		} else if (*p1 != *p2) {
			return *p1 - *p2;
		} else {
			p1++, p2++;
		}
	}
	return *p1 - *p2;
}

#define ldso_cache_verify_offset(offset) (offset < iter->cache_size)

static inline bool
ldso_cache_check_flags(struct elf_shared_object_iterator *iter,
    uint32_t flags)
{
	if (iter->obj->arch == i386__) {
		if (flags == 0x803)
			return true;
	} else if (iter->obj->arch == x64__) {
		if (flags == 0x303) {
			return true;
		}
	}
	log_msg2(__LINE__, __FILE__, "returing false\n");
	return false;
}

const char *
ldso_cache_bsearch(struct elf_shared_object_iterator *iter,
    const char *name)
{
	int ret;
	uint64_t value;
	uint32_t middle, flags;
	uint32_t left = 0;
	uint32_t right = (iter->cache_flags & ELF_LDSO_CACHE_NEW) ?
	    iter->cache_new->nlibs - 1 : iter->cache->nlibs - 1;
	const char *best = NULL;

	while (left <= right) {
		uint32_t key;

		middle = (left + right) / 2;
		if (iter->cache_flags & ELF_LDSO_CACHE_NEW) {
			key = iter->cache_new->libs[middle].key;
		} else {
			key = iter->cache->libs[middle].key;
		}
		ret = ldso_cache_cmp(name, iter->cache_data + key);
		if (ret == 0) {
			left = middle;
			while (middle > 0) {
				if (iter->cache_flags & ELF_LDSO_CACHE_NEW) {
					key = iter->cache_new->libs[middle - 1].key;
				} else {
					key = iter->cache->libs[middle - 1].key;
				}
				if (ldso_cache_cmp(name,
				    iter->cache_data + key) != 0) {
					break;
				}
				--middle;
			}
			do {
				uint32_t new_key;

				if (iter->cache_flags & ELF_LDSO_CACHE_NEW) {
					new_key = iter->cache_new->libs[middle].key;
					value = iter->cache_new->libs[middle].value;
					flags = iter->cache_new->libs[middle].flags;
				} else {
					new_key = iter->cache->libs[middle].key;
					value = iter->cache->libs[middle].value;
					flags = iter->cache->libs[middle].flags;
				}
				if (middle > left && (ldso_cache_cmp(name,
				    iter->cache_data + new_key) != 0))
					break;
				if (ldso_cache_check_flags(iter, flags) &&
				    ldso_cache_verify_offset(value)) {
					if (best == NULL) {
						best = iter->cache_data + value;
						break;
					}
				}
			} while (++middle <= right);
			break;
		}
		if (ret < 0) {
			left = middle + 1;
		} else {
			right = middle - 1;
		}
	}
	return best;
}

static void *
ldso_malloc(struct elf_shared_object_iterator *iter, size_t size)
{
	void *p;
	struct elf_malloc_node *n;

	p = malloc(size);
	if (p == NULL)
		return NULL;
	n = malloc(sizeof(*n));
	if (n == NULL)
		return NULL;
	n->ptr = p;
	LIST_INSERT_HEAD(&iter->malloc_list, n, _linkage);
	return n->ptr;
}

void
ldso_free_malloc_list(struct elf_shared_object_iterator *iter)
{
	struct elf_malloc_node *next, *current;

	LIST_FOREACH_SAFE(current, &iter->malloc_list, _linkage, next) {
		free(current->ptr);
		free(current);
	}
	return;
}

void
ldso_cleanup(struct elf_shared_object_iterator *iter)
{

	ldso_free_malloc_list(iter);
	if (iter->flags & ELF_SO_RESOLVE_ALL_F)
		hdestroy_r(&iter->yield_cache);
	(void) munmap(iter->mem, iter->st.st_size);
}


static char *
ldso_strdup(struct elf_shared_object_iterator *iter, const char *s)
{

        char *string;

	string = ldso_malloc(iter, strlen(s) + 1);
	if (string == NULL)
		return NULL;
	strcpy(string, s);
	return string;
}

static bool
ldso_insert_yield_entry(struct elf_shared_object_iterator *iter,
    const char *path)
{
	struct elf_shared_object_node *so = malloc(sizeof(*so));
	ENTRY e = {(char *)path, (char *)path}, *ep;

	if (so == NULL)
		return false;
	/*
	 * If we find the item in the cache then don't add it
	 * to the list again.
	 */
	if (hsearch_r(e, FIND, &ep, &iter->yield_cache) != 0) {
		free(so);
		return true;
	}
	/*
	 * Add path to cache.
	 */
	if (hsearch_r(e, ENTER, &ep, &iter->yield_cache) == 0)
		return false;
	/*
	 * Add path to yield list.
	 */
	so->path = (char *)path;
	so->basename = strrchr(path, '/') + 1;
	LIST_INSERT_HEAD(&iter->yield_list, so, _linkage);
	iter->yield = LIST_FIRST(&iter->yield_list);
	return true;
}

bool
ldso_insert_yield_cache(struct elf_shared_object_iterator *iter,
    const char *path)
{
        ENTRY e = {(char *)path, (char *)path}, *ep;

        if (hsearch_r(e, FIND, &ep, &iter->yield_cache) != 0)
                return true;
        if (hsearch_r(e, ENTER, &ep, &iter->yield_cache) == 0)
                return false;
        return true;
}

bool
ldso_recursive_cache_resolve(struct elf_shared_object_iterator *iter,
    const char *bname)
{
        const char *path = ldso_cache_bsearch(iter, bname);
        struct elf_shared_object_node *current;
        elfdesc_t obj = { .exe_path = (char *)path, .arch = iter->obj->arch};

	log_msg2(__LINE__, __FILE__, "basename: %s, path: %s\n", bname, path);

	if (path == NULL) {
                return true;
        }
        if (ldso_elf_open_object((char *)path, &obj) == false) {
                return false;
        }
        if (LIST_EMPTY(&obj.list.shared_objects))
                goto done;

        LIST_FOREACH(current, &obj.list.shared_objects, _linkage) {

		if (current->basename == NULL) {
			log_msg(__LINE__, "basename == NULL fail\n");
                        goto err;
                }
                path = (char *)ldso_cache_bsearch(iter, current->basename);
                if (path == NULL) {
                        log_msg2(__LINE__, __FILE__,
			    "cannot resolve %s\n", current->basename);
                        goto err;
                }
                /*
                 * We update the existing object list to now contain the
                 * full path. That way any subsequent calls to the shared
                 * object iterator will use the linked list cache.
                 */
                current->path = ldso_strdup(iter, path);
                if (current->path == NULL) {
                        goto err;
                }
                if (ldso_insert_yield_entry(iter, current->path) == false)
                        goto err;
		if (ldso_recursive_cache_resolve(iter, current->basename) == false)
			goto err;

        }
done:
        ldso_elf_close_object(&obj);
        return true;
err:
        ldso_elf_close_object(&obj);
        return false;
}

bool
elf_shared_object_iterator_init(elfdesc_t *obj, struct elf_shared_object_iterator *iter,
    const char *cache_path, uint32_t flags)
{
	const char *cache_file = cache_path == NULL ? CACHE_FILE : cache_path;
	elfdesc_t *nobj = heapAlloc(sizeof(*nobj));

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
	/*
	 * XXX This is a hack. We are creating a new object who's sole purpose is
	 * to contain a list of first-level DT_NEEDED entries. So we have to
	 * first copy a few values we need from the original elfdesc obj.
	 * We may be able to go back to using the original object I'm currently
	 * forgetting why we had to do it this way.
	 */
	nobj->runtime_base = obj->runtime_base;
	nobj->textVaddr = obj->textVaddr;
	nobj->pie = obj->pie;
	if (ldso_elf_open_object(obj->exe_path, nobj) == false) {
		log_msg2(__LINE__, __FILE__, "ldso_elf_open_object failed inside iterator init\n");
		return false;
	}
	iter->current = LIST_FIRST(&nobj->list.shared_objects);
	return true;
}

elf_iterator_res_t
elf_shared_object_iterator_next(struct elf_shared_object_iterator *iter,
    struct elf_shared_object *entry)
{
	bool result;

	if (iter->current == NULL && LIST_EMPTY(&iter->yield_list)) {
		ldso_cleanup(iter);
		log_msg2(__LINE__, __FILE__, "iterator done\n");
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

		log_msg2(__LINE__, __FILE__, "passing %s to ldso_recursive_cache_resolve()\n",
		    iter->current->basename);

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
