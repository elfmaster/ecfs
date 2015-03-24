/*
 * Copyright (c) 2015, Ryan O'Neill
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * XXX
 * THIS CODE IS BASICALLY main/ecfs.c but has been modified to work with 
 * snapshots of processes and does not rely on /proc/sys/kernel/core_pattern
 * the same way that ecfs and ecfs_handler do.  
*/

#include "../include/ecfs.h"
#include "../include/util.h"
#include "../include/ptrace.h"
#include "../include/symresolve.h"
#include "../include/heuristics.h"
#include "../include/core_text.h"
#include "../include/core_notes.h"
#include "../include/proc.h"
#include "../include/core_headers.h"
#include "../include/personality.h"
#include "../include/core2ecfs.h"
#include "../include/core_accessors.h"


/*
 * XXX stay out of habit of using global variables
 * this was put in  because I had to perform a hack
 * after the code had already been designed in order
 * to merge the entire text segment into the corefile
 * prior to processing it into an ECFS file.
 */

/*
 * Get /proc/pid/maps info to create data
 * about stack, heap etc. This can then be
 * merged with the info retrieved from the
 * core files phdr's.
 */

char *exename = NULL;

static memdesc_t * build_proc_metadata(pid_t pid, notedesc_t *notedesc)
{
	int i;
	memdesc_t *memdesc = (memdesc_t *)heapAlloc(sizeof(memdesc_t));
	
	memdesc->mapcount = get_map_count(pid);
        if (memdesc->mapcount < 0) {
                log_msg(__LINE__, "failed to get mapcount from /proc/%d/maps", pid);
                return NULL;
        }
        memdesc->maps = (mappings_t *)heapAlloc(sizeof(mappings_t) * memdesc->mapcount);
        
        memset((void *)memdesc->maps, 0, sizeof(mappings_t) * memdesc->mapcount);
        
	/*
	 * comm and path should be different. comm should be just the filename
	 * whereas path should be the complete filepath. Although due to an early
	 * on coding mistake I named comm, as path. There was no comm. path contained
	 * the filename, and exe_path contained the file path. Then came in a complication
	 * where some executable paths are actually symbolic links. So I had to make
	 * some changes, but still need to clear some things up. Currently memdesc->comm
	 * and memdesc->path both contain the filename (Which might just be a symbolic link)
	 * and exe_path and exe_comm contain the path and filename of the real file that
	 * the link points to.
	 */
	memdesc->comm = memdesc->path = exename; // supplied by core_pattern %e
	memdesc->exe_path = get_executable_path(pid); 
	memdesc->exe_comm = strrchr(memdesc->exe_path, '/') + 1;
	if (get_maps(pid, memdesc->maps, memdesc->exe_comm) < 0) {
                log_msg(__LINE__, "failed to get data from /proc/%d/maps", pid);
                return NULL;
        }
        
        memdesc->task.pid = memdesc->pid = pid;
	

        for (i = 0; i < memdesc->mapcount; i++) {
                if (memdesc->maps[i].heap) {
                        memdesc->heap.base = memdesc->maps[i].base;
                        memdesc->heap.size = memdesc->maps[i].size;
                } else
                if (memdesc->maps[i].stack) {
                        memdesc->stack.base = memdesc->maps[i].base;
                        memdesc->stack.size = memdesc->maps[i].size;
                } else
                if (memdesc->maps[i].vdso) {
                        memdesc->vdso.base = memdesc->maps[i].base;
                        memdesc->vdso.size = memdesc->maps[i].size;
                } else
                if (memdesc->maps[i].vsyscall) {
                        memdesc->vsyscall.base = memdesc->maps[i].base;
                        memdesc->vsyscall.size = memdesc->maps[i].size;
                }
		if (memdesc->maps[i].textbase) {
			memdesc->text.base = memdesc->maps[i].base;
			memdesc->text.size = memdesc->maps[i].size;
		}
        }
#if DEBUG
	log_msg(__LINE__, "executable text base: %lx\n", memdesc->text.base);
#endif
	ssize_t tlen = get_segment_from_pmem(memdesc->text.base, memdesc, &memdesc->textseg);
        if (tlen < 0) {
		log_msg(__LINE__, "get_segment_from_pmem() failed: %s\n", strerror(errno));
        	/* NOTE: Do not return NULL here. If we fail to get this, then the
		 * result should NOT be to fail, but rather produce an ecfs-core file
		 * that has truncated text segments (like a regular core file.
		 */
	}
	return memdesc;
	
}

static char * itoa(long x, char *t)
{
        int i;
        int j;

        i = 0;
        do
        {
                t[i] = (x % 10) + '0';
                x /= 10;
                i++;
        } while (x!=0);

        t[i] = 0;

        for (j=0; j < i / 2; j++) {
                t[j] ^= t[i - j - 1];
                t[i - j - 1] ^= t[j];
                t[j] ^= t[i - j - 1];
        }

        return t;
}

static char * get_exe_name(int pid)
{
	FILE *fp;
	char *comm = (char *)heapAlloc(32);
	char *path, *p;
	
	asprintf(&path, "/proc/%d/comm", pid);
	
	if ((fp = fopen(path, "r"))  == NULL) {
		perror("fopen");
		return NULL;
	}

	fgets(comm, sizeof(comm), fp);
	if ((p = strchr(comm, '\n')) != NULL)
		*p = '\0';
	comm[sizeof(comm) - 1] = '\0';
	fclose(fp);
	return comm;
}

static int launch_gcore_utility(int pid, const char *filename)
{
	int ret, status;
	char *gcore_path = NULL;
	char *tmp = malloc(16);
	char *args[5];
	
	if (access("/usr/bin/gcore", F_OK) == 0)
		gcore_path = "/usr/bin/gcore";
	else
	if (access("/bin/gcore", F_OK) == 0)
		gcore_path = "/bin/gcore";
	else {
		fprintf(stderr, "Unable to find GDB corefile utility 'gcore' in /bin or /usr/bin\n");
		return -1;
	}
	
	args[0] = gcore_path;
	args[1] = "-o";
	args[2] = (char *)filename;
	args[3] = itoa(pid, tmp);
	args[4] = NULL;

	if ((pid = fork()) < 0) {
		perror("fork()");
		return -1;
	}

	if (pid == 0) {
		ret = execve(gcore_path, args, NULL);
		if (ret < 0) {
			perror("execve");
			exit(-1);
		}
		exit(0);
	}
	wait(&status);

	return 0;
}

/* 
 * the gcore utility creates blank section headers for
 * the core files. Since ecfs creates a complete section 
 * header table itself, we remove the one created by gcore
 */
static int strip_section_header_table(const char *corefile)
{
	int fd, tfd, tval;
	uint8_t *mem;
	uint8_t *copy;
	struct timeval tv;
	char *tmpfile;
	struct stat st;

	fd = xopen(corefile, O_RDONLY);
	xfstat(fd, &st);
	mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("1st. mmap");
		exit(-1);
	}
	ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)mem;
	if (ehdr->e_shoff == 0)
		return 0;
	
	gettimeofday(&tv, NULL);
	srand(tv.tv_usec);
	tval = rand() & 0xffff;
	asprintf(&tmpfile, "tmp.%s", corefile);
	tfd = xopen(tmpfile, O_CREAT|O_WRONLY);
	printf("doing mmap\n");
	copy = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (copy == MAP_FAILED) {
		perror("2nd. mmap");
		return -1;
	}
	printf("Copying from mem to copy %d bytes from %p to %p\n", ehdr->e_shoff, mem, copy);
	memcpy(copy, mem, ehdr->e_shoff);
	//unlink(corefile);
	printf("Writing %d bytes\n", ehdr->e_shoff);
	if (write(tfd, copy, ehdr->e_shoff) < 0) {
		perror("write");
		return -1;
	}
	fsync(tfd);
	close(tfd);
	munmap(copy, st.st_size);
	printf("renaming %s to %s\n", tmpfile, corefile);
	rename(tmpfile, corefile);
	return 0;
}

	
int main(int argc, char **argv)
{
		
	struct rlimit limit_core = {0L, 0L};
	memdesc_t *memdesc = NULL;
	elfdesc_t *elfdesc = NULL;
	notedesc_t *notedesc = NULL;
	handle_t *handle = alloca(sizeof(handle_t));
	pid_t pid = 0;
	int i, j, ret, c, pie = 0;
	char *corefile = NULL;
	char *outfile = NULL;
	list_t *list_head;
	
	if (argc < 5) {
		fprintf(stdout, "ECFS - Snapshotting tool by elfmaster[at]zoho.com\n");
		fprintf(stdout, "Usage: %s -p <pid> -o <outfile>\n", argv[0]);
		fprintf(stdout, "[-p]	pid of process (Must respawn a process after it crashes)\n");
		fprintf(stdout, "[-o]	output ecfs file\n");
		fprintf(stdout, "[-e]	(Optional) otherwise its grabbed from /proc/$pid/comm\n");
		fprintf(stdout, "[-h]	(Optional) turns heuristics on for detecting dll injection and PLT hooks\n");
		fprintf(stdout, "[-t]	(Optional) recommended, grabs entire text segment of exe and shlibs\n");
		exit(-1);
	}
	memset(&opts, 0, sizeof(opts));

	while ((c = getopt(argc, argv, "th:o:p:e:")) != -1) {
		switch(c) {
			case 'o':
				outfile = xstrdup(optarg);
				break;
			case 'e':
				exename = xstrdup(optarg);
				break;
			case 'p':
				pid = atoi(optarg);
				break;
			case 'h':
				opts.heuristics = 1;
				break;
			case 't':
				opts.text_all = 1;
				break;
			default:
				fprintf(stderr, "Unknown option\n");
				exit(0);
		}
	}
	
	/*
	 * Don't allow itself to core in the event of a bug.
	 */
	
    	if (setrlimit(RLIMIT_CORE, &limit_core) < 0) {
		log_msg(__LINE__, "setrlimit %s", strerror(errno));
		exit(-1);
	}
	
	/*
	 * Prevents ecfs from coring itself
	 */
	prctl(PR_SET_DUMPABLE, 0);
	
#if DEBUG
	fprintf(stderr, "options: text_all: %d heuristics: %d outfile: %s exename: %s pid: %d\n", 
			opts.text_all, opts.heuristics, outfile, exename, pid);
#endif
	if (opts.text_all) {
		/*
		 * text_all requires alot more disk operations and 
		 * the time it takes becomes infeasable. We use a
		 * tmpfs ramdisk (of 1 GIG which can be tweaked up to 4GIG)
		 * to fix this problem. Even the hugest processes only
		 * take ~3 seconds now.
		 */
		printf("Creating ramdisk\n");
		int ramdisk_size = inquire_meminfo();
		printf("ramdisk_size: %d\n", ramdisk_size);
		if (ramdisk_size <= 0)
			ramdisk_size = 1;
		if (create_tmp_ramdisk(ramdisk_size) < 0) {
			fprintf(stderr, "create_tmp_ramdisk failed\n");
		} else
			opts.use_ramdisk = 1;
 	}

       	if (exename == NULL) {
		exename = get_exe_name(pid);
		if (exename == NULL) {
			log_msg(__LINE__, "Must specify exename of process when using stdin mode; supplied by %%e of core_pattern");
			exit(-1);
		}
	}
	if (pid == 0) {
        	log_msg(__LINE__, "Must specify a pid with -p");
            	exit(0);
        }
        if (outfile == NULL) {
              	outfile = xfmtstrdup("%s/%s.%d", ECFS_CORE_DIR, exename, pid);
       		fprintf(stdout, "Did not specify -o: writing to file %s\n", outfile);
	}
		
	memdesc = build_proc_metadata(pid, notedesc);
       	if (memdesc == NULL) {
		fprintf(stderr, "build_proc_metadata() failed\n");
               	exit(-1);
       	}
	memdesc->task.pid = pid;
	pie = check_for_pie(pid);
	global_hacks.stripped = check_for_stripped_shdr(pid);
	memdesc->pie = pie;
	fill_global_hacks(pid, memdesc);
	memdesc->fdinfo_size = get_fd_links(memdesc, &memdesc->fdinfo) * sizeof(fd_info_t);
	memdesc->o_entry = get_original_ep(pid);
	if (opts.text_all) {
		create_shlib_text_mappings(memdesc);
	}
	/*
	 * load the core file from stdin (Passed by the kernel via core_pattern)
	 */
	
		
	asprintf(&corefile, "core.%s", exename);
	
	if (launch_gcore_utility(pid, corefile) < 0) {
		fprintf(stderr, "ecfs-snapshot utility requires that the GDB gcore script is present on your system\n");
		exit(-1);
	}
	/*
	 * gcore actually will create core.%s.<pid> based on us passing it
	 * core.%s, so we need to modify our filename so that we then open
	 * that filename.
	 */
	xfree(corefile);
	asprintf(&corefile, "core.%s.%d", exename, pid);
	
	if (strip_section_header_table(corefile) < 0) {
		fprintf(stderr, "Unable to strip the section header table (created by gcore) on %s\n", corefile);
		exit(-1);
	}

	elfdesc = load_core_file(corefile);
	if (elfdesc == NULL) {
		fprintf(stderr, "load_core_file failed\n");
		exit(-1);
	}
#if DEBUG
	fprintf(stdout, "Successfully created temporary corefile: %s\n", corefile);
#endif
	/*
	 * Retrieve 'struct elf_prstatus' and other structures
	 * that contain vital information (Such as registers).
	 * These are all stored in the ELF notes area of the
	 * core file.
	 */
#if DEBUG
	log_msg(__LINE__, "Parsing notes area");
#endif
	notedesc = (notedesc_t *)parse_notes_area(elfdesc);
	if (notedesc == NULL) {
		fprintf(stderr, "Failed to parse ELF notes segment\n");
		exit(-1);
	}
	
#if DEBUG
	fprintf(stderr, "check_for_pie returned %d", pie);
#endif
	fill_in_pstatus(memdesc, notedesc);

	if (pie > 0) {
		unsigned long text_base = lookup_text_base(memdesc, notedesc->nt_files);
		if (text_base == 0) {
			fprintf(stderr, "Failed to locate text base address");
			goto done;
		}
		unsigned long hint = text_base;
		get_text_phdr_size_with_hint(elfdesc, hint);
	}
	
	/*
	 * XXX the linux kernel only dumps 4096 bytes of any code segment
	 * in order to save space, and this is generally OK since the code
	 * segment isn't suppose to change in memory. Unfortunatley for
 	 * our purposes we want this, so we have to retrieve the text from
	 * /proc/$pid/mem and merge it into our corefile which is a pain
	 * and after we do this, we must re-load the corefile again.
	 * if opts.text_all is enabled we do the same thing for the text images
	 * of every single shared library which becomes our biggest bottleneck
	 * in terms of performance.
	 */
	if (elfdesc->text_memsz > elfdesc->text_filesz) {
		fprintf(stderr, "merging text into core\n");
		if (merge_exe_text_into_core((const char *)corefile, memdesc) < 0) {
			log_msg(__LINE__, "Failed to merge text into core file");
		}
		
        	elfdesc = reload_core_file(elfdesc);
        	if (elfdesc == NULL) {
        		log_msg(__LINE__, "Failed to parse text-merged core file");	
                	exit(-1);
        	} 
	}
	if (opts.text_all) {
#if DEBUG
		log_msg(__LINE__, "opts.text_all is enabled");
#endif
		/*
		 * opts.text_all is enabled which means that we are going to write
		 * out the entire text segment of each shared library. Whereas by
		 * default (As with regular core files) we only write out the first 4096
		 * bytes of each shared libraries text segment. 
		 */
		if (merge_shlib_texts_into_core((const char *)corefile, memdesc) < 0) {
			log_msg(__LINE__, "Failed to merge shlib texts into core");
		}
		elfdesc = reload_core_file(elfdesc); // reload after our mods
		if (elfdesc == NULL) {
			log_msg(__LINE__, "Failed to parse shlib text merged core file");
			exit(-1);
		}
	}

#if DEBUG
	log_msg(__LINE__, "parsing original phdr's from /proc/$pid/exe");
#endif
	if (parse_orig_phdrs(elfdesc, memdesc, notedesc) < 0) {
		log_msg(__LINE__, "Failed to parse program headers in memory");
		exit(-1);
	}
	
	/*
	 * Combine all handles into 1 (Should work this into the code earlier on)
	 */
	handle->elfdesc = elfdesc;
	handle->memdesc = memdesc;
	handle->notedesc = notedesc;
#if DEBUG
	log_msg(__LINE__, "calling xref_phdrs_for_offsets()");
#endif
	/*
	 * Figure out where the offsets to certain parts of the
	 * file are, such as .dynamic, .interp, etc.
	 * in such cases where we got the original info from
	 * the original phdr table. The offsets will be different
	 * since the phdr's are all page aligned in the corefile.
	 */
	xref_phdrs_for_offsets(memdesc, elfdesc);
	

	/*
	 * Is this binary dynamically linked (not statically?)
	 * Out of the parsed NT_FILES get a list of which ones are
	 * shared libraries so we can create shdrs for them.
	 */
	if (elfdesc->dynlinked) {
#if DEBUG
		log_msg(__LINE__, "calling lookup_lib_maps()");
#endif
		notedesc->lm_files = (struct lib_mappings *)heapAlloc(sizeof(struct lib_mappings));
		lookup_lib_maps(elfdesc, memdesc, notedesc->nt_files, notedesc->lm_files);
	
#if DEBUG
		for (i = 0; i < notedesc->lm_files->libcount; i++)
			log_msg(__LINE__, "libname: %s addr: %lx\n", notedesc->lm_files->libs[i].name, notedesc->lm_files->libs[i].addr);
#endif
	}
	/*
	 * Build elf stats into personality
	 */
#if DEBUG
	log_msg(__LINE__, "build_elf_stats() is being called");
#endif
	build_elf_stats(handle);

	/*
	 * If we aren't dealing with a statically-compiled-only
	 * binary then we need to extract dynamic infoz:
	 * We get a plethora of information about where certain
	 * data and code is from the dynamic segment by parsing
	 * it by D_TAG values.
	 */
	if (!(handle->elfstat.personality & ELF_STATIC)) {
#if DEBUG
		log_msg(__LINE__, "calling extract_dyntag_info()");
#endif
		ret = extract_dyntag_info(handle);
		if (ret < 0) {
			log_msg(__LINE__, "Failed to extract dynamic segment information");
			exit(-1);
		}
	}

	/*
	 * If we aren't dealing with a statically-compiled-only
	 * binary then we need to fill in its dynamic symtab.
	 * Parse the symtab of each shared library and store its
	 * results in linked list. Each node holds a symentry_t vector
	 */
	if (!(handle->elfstat.personality & ELF_STATIC)) {
#if DEBUG
		log_msg(__LINE__, "calling fill_dynamic_symtab()");
#endif
		ret = fill_dynamic_symtab(&list_head, notedesc->lm_files);
		if (ret < 0) 
			log_msg(__LINE__, "Unable to load dynamic symbol table with runtime values");
	}
	
	/*
	 * Before we call core2ecfs we need to make a list of which shared libraries
	 * were maliciously injected, so that section headers can be created of type
	 * SHT_INJECTED instead of SHT_SHLIB for those ones.
	 */
	 if (!(handle->elfstat.personality & ELF_STATIC))
		if (opts.heuristics) {
#if DEBUG
			log_msg(__LINE__, "calling mark_dll_injection()");
#endif
	 		mark_dll_injection(notedesc, memdesc, elfdesc);
		}
	memset(handle->arglist, 0xff, ELF_PRARGSZ);
	memcpy(handle->arglist, (char *)notedesc->psinfo->pr_psargs, ELF_PRARGSZ);
	/*
	 * Convert the core file into an actual ECFS file and write it
	 * to disk.
	 */
#if DEBUG
	log_msg(__LINE__, "calling core2ecfs()");
#endif
	ret = core2ecfs(outfile, handle);
	if (ret < 0) {
		log_msg(__LINE__, "Failed to transform core file '%s' into ecfs", argv[2]);
		exit(-1);
	}
	
	unlink(elfdesc->path); //unlink a tmp file
	if (corefile) // incase we had to re-write file and merge in text
		unlink(corefile);

	if (!(handle->elfstat.personality & ELF_STATIC)) {
#if DEBUG
		log_msg(__LINE__, "calling store_dynamic_symvals() on outfile: %s", outfile);
#endif
		ret = store_dynamic_symvals(list_head, outfile);
		if (ret < 0) 
			log_msg(__LINE__, "Unable to store runtime values into dynamic symbol table");
	}
#if DEBUG
	log_msg(__LINE__, "finished storing symvals");
#endif
done: 
        
	unlink(elfdesc->path); // unlink tmp file
        if (corefile) {// incase we had to re-write file and mege in text
#if DEBUG
		log_msg(__LINE__, "unlink(%s)", corefile);	
#endif
        	unlink(corefile);
	}
#if DEBUG
	log_msg(__LINE__, "umount %s", ECFS_RAMDISK_DIR);
#endif
	umount(ECFS_RAMDISK_DIR);
	/*
	 * XXX add line to umount ramdisk
	 */
        return 0;
}

