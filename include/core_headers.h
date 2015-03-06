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

#ifndef _ECFS_CORE_HEADERS_H
#define _ECFS_CORE_HEADERS_H

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

#endif
