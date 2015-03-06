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

void build_elf_stats(handle_t *);


/*
 * This function will not read directly from vaddr unless vaddr marks
 * the beggining of a segment; otherwise this function finds where the
 * segment begins (The segment range that vaddr fits in) and reads from there.
 */
ssize_t get_segment_from_pmem(unsigned long vaddr, memdesc_t *memdesc, uint8_t **ptr);

/*
 * This function simply mmap's the core file into memory
 * and sets up pointers to the ELF header, and the program
 * headers. It also sets up Elf notes pointer (ElfW(Nhdr) *nhdr).
 * after this function is called you may then parse the notes
 * and operate on the core file in any other way.
 */
elfdesc_t * load_core_file(const char *path);

elfdesc_t * reload_core_file(elfdesc_t *old);

/*
 * The complete text segment of executables and shared library
 * is not included in core files. Only 4096 bytes are written
 * to save space; this is generally fine since the text presumably
 * doesn't ever change, and can be remarkably big. For our case
 * though we want the complete text of the main executable and
 * its shared libaries. This function merges the executables complete
 * text segment into the core file. And merge_shlib_texts_into_core
 * will do the ones for each shared library.
 */
int merge_exe_text_into_core(const char *path, memdesc_t *memdesc);

/*
 * This function is called by merge_shlib_texts_into_core() and merges a text segment
 * from a given shared library into the core file.
 */

void create_shlib_text_mappings(memdesc_t *memdesc);

int merge_shlib_texts_into_core(const char *corefile, memdesc_t *memdesc);

/*
 * Parse the ELF notes to extract info such as struct prpsinfo
 * and struct prstatus. These structs hold information about the
 * process, and task state.
 */
notedesc_t * parse_notes_area(elfdesc_t *elfdesc);

int check_for_pie(int pid);
	
int check_for_stripped_shdr(int pid);

void get_text_phdr_size_with_hint(elfdesc_t *elfdesc, unsigned long hint);

/*
 * There should be 3 mappings for each lib
 * .text, relro, and .data.
 */
void lookup_lib_maps(elfdesc_t *elfdesc, memdesc_t *memdesc, struct nt_file_struct *fmaps, struct lib_mappings *lm);

/*
 * Since the process is paused, all /proc data is still available.
 * get_maps() simply extracts all of the memory mapping information
 * including details such as stack, heap, .so's, vdso etc.
 * eventually we pair this info up with the program headers (PT_LOAD's)
 * in the core file to determine where to build certain section headers.
 */
int get_maps(pid_t pid, mappings_t *maps, const char *path);

int get_fd_links(memdesc_t *memdesc, fd_info_t **fdinfo);

int get_map_count(pid_t pid);

/*
 * Handle the case where say: /bin/someprog is a symbolic link
 */
char * get_exe_path(int pid);

/*
 * Can only be called after the notes file has been parsed.
 * We really only need these for PIE executables since getting
 * the base address data and text can only otherwise be gotten
 * from maps. The phdr's of a PIE executable won't reflect the
 * actual load addresses.
 */
ElfW(Addr) lookup_text_base(memdesc_t *memdesc, struct nt_file_struct *fmaps);

/*
 * This function parses the original phdr's which it must get using
 * ptrace. This is the only part where we use ptrace() and we should
 * possibly change this to using /proc/self/mem instead. In any case
 * we get the original phdr locations so that we can then find them
 * in relation to the corefile that was dumped.
 *
 * NOTE:
 * The dataVaddr is taken from the core file which gives the page aligned
 * segment address, which is not the same as the original data segment address.
 * In our case we use the page aligned dataVaddr which we retrieve with our
 * lookup_data_base() function.
 */
int parse_orig_phdrs(elfdesc_t *elfdesc, memdesc_t *memdesc, notedesc_t *notedesc);

/*
 * Parse the dynamic segment to get 
 * a whole lot of needed information
 */

int extract_dyntag_info(handle_t *handle);

/*
 * The offsets from when a file is an executable to a corefile
 * change durastically because the phdr table is so much bigger
 * pushing everything else forward. We must find the offsets of
 * certain old phdr's like PT_DYNAMIC and figure out what the offset
 * is in the core file for it. That way we can build appropriate shdrs.
 */
void xref_phdrs_for_offsets(memdesc_t *memdesc, elfdesc_t *elfdesc);

/*
 * This function treats type as either HEAP/STACK/VDSO/VSYSCALL. But if it
 * is none of these, then it is treated as an index into the 'mappings_t maps[]'
 * array.
 */
ElfW(Off) get_internal_sh_offset(elfdesc_t *elfdesc, memdesc_t *memdesc, int type);

int core2ecfs(const char *outfile, handle_t *handle);
	
/*
 * Get original entry point
 */
void fill_in_pstatus(memdesc_t *memdesc, notedesc_t *notedesc);

/*
 * XXX This function calls pull_unknown_shdr_ functions
 * to fill up global_hacks structure with information
 * needed for section headers. This is ugly and temporary
 */
void fill_global_hacks(int pid);
