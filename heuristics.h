

/* 
 * ECFS performs certain heuristics to help aid in forensics analysis.
 * one of these heuristics is showing shared libraries that have been
 * injected vs. loaded by the linker/dlopen/preloaded
 */
#ifndef _ECFS_HEURISTICS_H
#define _ECFS_HEURISTICS_H

int build_rodata_strings(char ***stra, uint8_t *rodata_ptr, size_t rodata_size);

/* 
 * From DT_NEEDED (We pass the executable and each shared library to this function)
 */
int get_dt_needed_libs(const char *bin_path, struct needed_libs **needed_libs);
/*
 * Get dlopen libs
 */
int get_dlopen_libs(const char *exe_path, struct dlopen_libs **dl_libs);

void mark_dll_injection(notedesc_t *notedesc, memdesc_t *memdesc, elfdesc_t *elfdesc);

#endif
