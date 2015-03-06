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
 * This function will read the corefile from stdin
 * then write it to a temporary file which is then read
 * by the load_core_file() function above.
 */
#define RBUF_LEN 4096 * 8
elfdesc_t * load_core_file_stdin(char **corefile)
{
        uint8_t *buf = NULL;
        ssize_t nread;
	ssize_t bytes = 0, bw;
	int i = 0;
	int file;
	
	char *tmp_dir = opts.use_ramdisk ? ECFS_RAMDISK_DIR : ECFS_CORE_DIR;
	
	char *filepath = xfmtstrdup("%s/.tmp_core", tmp_dir);
        do {
                if (access(filepath, F_OK) == 0) {
                        free(filepath);
                        filepath = xfmtstrdup("%s/.tmp_core.%d", tmp_dir, ++i);
                } else
                        break;
                        
        } while(1);
	
	/*
	 * Open tmp file for writing
	 */
	file = xopen(filepath, O_CREAT|O_RDWR);
	buf = alloca(RBUF_LEN);
	while ((nread = read(STDIN_FILENO, buf, RBUF_LEN)) > 0) {
        	bytes += nread;
		bw = write(file, buf, nread);
		if (bw < 0) {
			log_msg(__LINE__, "write %s", strerror(errno));
			exit(-1);
		}
	}
	syncfs(file);
	close(file);
	*corefile = xstrdup(filepath);
	return load_core_file(filepath);

}		
#undef RBUF_LEN

/*
 * Get /proc/pid/maps info to create data
 * about stack, heap etc. This can then be
 * merged with the info retrieved from the
 * core files phdr's.
 */

char *exename = NULL;

memdesc_t * build_proc_metadata(pid_t pid, notedesc_t *notedesc)
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
                return NULL;
        }
	return memdesc;
	
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
	fd_info_t *fdinfo = NULL;
	list_t *list_head;
	/*
	 * When testing use:
	 * ./ecfs -c corefile -o output.ecfs -p <pid>
	 *
	 * although when having run as automated with core pipes use
	 * the following command within /proc/sys/kernel/core_pattern
	 * ./ecfs -i -p %p -e %e
	 */
	if (argc < 2) {
		fprintf(stdout, "Usage: %s [-peo]\n", argv[0]);
		fprintf(stdout, "- Automated mode to be used with /proc/sys/kernel/core_pattern\n");
		fprintf(stdout, "\n- Manual mode which allows for specifying existing core files (Debugging mode)\n");
		fprintf(stdout, "[-p]	pid of process (Must respawn a process after it crashes)\n");
		fprintf(stdout, "[-e]	executable path (Supplied by %%e format arg in core_pattern)\n");
		fprintf(stdout, "[-o]	output ecfs file\n\n");
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
	log_msg(__LINE__, "options: text_all: %d heuristics: %d outfile: %s exename: %s pid: %d", 
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
		if (create_tmp_ramdisk(1) < 0) {
			log_msg(__LINE__, "create_tmp_ramdisk failed");
		} else
			opts.use_ramdisk = 1;
 	}

	/*
	 * If we're reading from stdin we are probably waiting for the kernel
	 * to write the corefile to us. Until we have read the core file completely
	 * /proc/$pid/? will remain open to us, so we need to gather whatever we need
	 * from this area now while our process is in a stopped zombie state.
	 */
#if DEBUG
	log_msg(__LINE__, "Using stdin, outfile is: %s", outfile);
#endif
	/*
	 * If we are getting core directly from the kernel then we must
	 * read /proc/<pid>/ before we read the corefile. The process stays
	 * open as long as the corefile hasn't been read yet.
  	 */
       	if (exename == NULL) {
		log_msg(__LINE__, "Must specify exename of process when using stdin mode; supplied by %%e of core_pattern");
		exit(-1);
	}
	if (pid == 0) {
        	log_msg(__LINE__, "Must specify a pid with -p");
            	exit(0);
        }
        if (outfile == NULL) {
        	log_msg(__LINE__, "Did not specify an output file, defaulting to use 'ecfs.out'");
              	outfile = xfmtstrdup("%s/ecfs.out", ECFS_CORE_DIR);
       	}
		
	memdesc = build_proc_metadata(pid, notedesc);
       	if (memdesc == NULL) {
               	log_msg(__LINE__, "Failed to retrieve process metadata");
               	exit(-1);
       	}
	memdesc->task.pid = pid;
	pie = check_for_pie(pid);
	global_hacks.stripped = check_for_stripped_shdr(pid);
	fill_global_hacks(pid);
	pie = check_for_pie(pid);
	memdesc->fdinfo_size = get_fd_links(memdesc, &memdesc->fdinfo) * sizeof(fd_info_t);
	memdesc->o_entry = get_original_ep(pid);
	if (opts.text_all)
		create_shlib_text_mappings(memdesc);

	/*
	 * load the core file from stdin (Passed by the kernel via core_pattern)
	 */
	elfdesc = load_core_file_stdin(&corefile);
	
#if DEBUG
	log_msg(__LINE__, "Successfully read core from stdin and created temporary corefile path: %s", corefile);
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
		log_msg(__LINE__, "Failed to parse ELF notes segment\n");
		exit(-1);
	}
	
#if DEBUG
	log_msg(__LINE__, "check_for_pie returned %d", pie);
#endif
	fill_in_pstatus(memdesc, notedesc);

	if (pie > 0) {
		unsigned long text_base = lookup_text_base(memdesc, notedesc->nt_files);
		if (text_base == 0) {
			log_msg(__LINE__, "Failed to locate text base address");
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
#if DEBUG
		log_msg(__LINE__, "merging text into core");
#endif
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

	/*
	 * Which mappings are stored in actual phdr segments?
	 */
        for (i = 0; i < elfdesc->ehdr->e_phnum; i++) {
                for (j = 0; j < memdesc->mapcount; j++) 
                        if (memdesc->maps[j].base == (elfdesc->phdr + i)->p_vaddr)
                                memdesc->maps[j].has_pt_load++;
        }
	
	/*
	 * attach to process with ptrace and parse original phdr table
	 * to get more granular segment information.
	 */
#if DEBUG
	log_msg(__LINE__, "parsing original phdr's in memory");
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
#if DEBUG
	log_msg(__LINE__, "calling mark_dll_injection()");
#endif
	 if (!(handle->elfstat.personality & ELF_STATIC))
		if (opts.heuristics)
	 		mark_dll_injection(notedesc, memdesc, elfdesc);

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
		log_msg(__LINE__, "calling store_dynamic_symvals()");
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
	log_msg(__LINE__, "Going to remove: %s", corefile);
        if (corefile) // incase we had to re-write file and mege in text
        	unlink(corefile);

        return 0;
}

