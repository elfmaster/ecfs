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
#ifndef _ECFS_CORE_TEXT_H
#define _ECFS_CORE_TEXT_H

/*
 * This function will not read directly from vaddr unless vaddr marks
 * the beggining of a segment; otherwise this function finds where the
 * segment begins (The segment range that vaddr fits in) and reads from there.
 */
ssize_t get_segment_from_pmem(unsigned long vaddr, memdesc_t *memdesc, uint8_t **ptr);

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

#endif
