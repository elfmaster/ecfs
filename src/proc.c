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

static ElfW(Addr) get_mapping_flags(ElfW(Addr) addr, memdesc_t *memdesc)
{
	int i;
	for (i = 0; i < memdesc->mapcount; i++) 
		if (memdesc->maps[i].base == addr)
			return memdesc->maps[i].p_flags;
	return -1;
}

static ElfW(Off) get_mapping_offset(ElfW(Addr) addr, elfdesc_t *elfdesc)
{
	ElfW(Ehdr) *ehdr = elfdesc->ehdr;
	ElfW(Phdr) *phdr = elfdesc->phdr;
	int i;

	for (i = 0; i < ehdr->e_phnum; i++)
		if (phdr[i].p_vaddr == addr)
			return phdr[i].p_offset;
	return 0;
}

void lookup_lib_maps(elfdesc_t *elfdesc, memdesc_t *memdesc, struct nt_file_struct *fmaps, struct lib_mappings *lm)
{
	int i, j;
	char *p, *tmp = alloca(256);
	memset(lm, 0, sizeof(struct lib_mappings));

	for (i = 0; i < fmaps->fcount; i++) {
#if DEBUG	
		log_msg(__LINE__, "filepath: %s", fmaps->files[i].path);
#endif
		p = strrchr(fmaps->files[i].path, '/') + 1;
		if (!strstr(p, ".so"))
			continue;
		for (j = 0; j < strlen(p); j++)
			tmp[j] = p[j];
		tmp[j] = '\0';
		/*
	 	 * path and name are MAX_LIB_N + 1 in size hence no need
		 * to take byte for null terminator into account with strncpy
	 	 */
		strncpy(lm->libs[lm->libcount].path, fmaps->files[i].path, MAX_LIB_PATH);
		strncpy(lm->libs[lm->libcount].name, tmp, MAX_LIB_NAME);
#if DEBUG
		log_msg(__LINE__, "libname: %s", lm->libs[lm->libcount].name);
#endif
		lm->libs[lm->libcount].addr = fmaps->files[i].addr;
		lm->libs[lm->libcount].size = fmaps->files[i].size;
		lm->libs[lm->libcount].flags = get_mapping_flags(lm->libs[lm->libcount].addr, memdesc);
		lm->libs[lm->libcount].offset = get_mapping_offset(lm->libs[lm->libcount].addr, elfdesc);
		lm->libcount++;
	}
		
}

int get_maps(pid_t pid, mappings_t *maps, const char *path)
{
        char mpath[256], buf[256], tmp[256], *p, *chp, *q = alloca(32);
        FILE *fd;
        int lc, i;
        
        snprintf(mpath, sizeof(mpath), "/proc/%d/maps", pid);
        if ((fd = fopen(mpath, "r")) == NULL) 
                return -1;

        for (lc = 0; (fgets(buf, sizeof(buf), fd) != NULL); lc++) {
                strcpy(tmp, buf); //tmp and buf are same sized buffers
                p = strchr(buf, '-');
                *p = '\0';
                p++;
                maps[lc].elfmap = 0;
                maps[lc].base = strtoul(buf, NULL, 16);
                maps[lc].size = strtoul(p, NULL, 16) - maps[lc].base;
		chp = strrchr(tmp, '/'); 
		if (chp) 
			*(char *)strchr(chp, '\n') = '\0';
		if (chp && !strcmp(&chp[1], path)) {
                        if (!strstr(tmp, "---p")) {
                                maps[lc].filename = xstrdup(strchr(tmp, '/'));
                                maps[lc].elfmap++;
				if (strstr(tmp, "r-xp") || strstr(tmp, "rwxp")) //sometimes text is polymorphic
					maps[lc].textbase++;
			}
                }
                else
                if (strstr(tmp, "[heap]")) 
                        maps[lc].heap++;
                else
                if (strstr(tmp, "[stack]"))
                        maps[lc].stack++;
                else
                if (strstr(tmp, "[stack:")) { /* thread stack */
                        for (i = 0, p = strchr(tmp, ':') + 1; *p != ']'; p++, i++)
                                q[i] = *p;
                        maps[i].thread_stack++;
                        maps[i].stack_tid = atoi(q);
                }
                else 
                if (strstr(tmp, "---p")) 
                        maps[lc].padding++;
                else
                if (strstr(tmp, "[vdso]")) 
                        maps[lc].vdso++; 
                else
                if (strstr(tmp, "[vsyscall]"))
                        maps[lc].vsyscall++;
                else
                if ((p = strrchr(tmp, '/'))) {
                        if (strstr(p, ".so")) {
#if DEBUG
				log_msg(__LINE__, "marked %s as shared library", p);
#endif
                                maps[lc].shlib++;
                                maps[lc].filename = xstrdup(strchr(tmp, '/'));
                        }
                        else
                        if (strstr(p, "rwxp") || strstr(p, "r-xp")) {
                                maps[lc].filename = xstrdup(strchr(tmp, '/'));
                                maps[lc].filemap_exe++; // executable file mapping
                        }
                        else {
                                maps[lc].filename = xstrdup(strchr(tmp, '/'));
                                maps[lc].filemap++; // regular file mapping
                        }       
                } else
                if (strstr(tmp, "rwxp") || strstr(tmp, "r-xp")) 
                        maps[lc].anonmap_exe++; // executable anonymous mapping
                
                /*      
                 * Set segment permissions (Or is it a special file?)
                 */
                if (strstr(tmp, "r--p")) 
                        maps[lc].p_flags = PF_R;
                else
                if (strstr(tmp, "rw-p"))
                        maps[lc].p_flags = PF_R|PF_W;
                else
                if (strstr(tmp, "-w-p"))
                        maps[lc].p_flags = PF_W;
                else
                if (strstr(tmp, "--xp"))
                        maps[lc].p_flags = PF_X;
                else
                if (strstr(tmp, "r-xp"))
                        maps[lc].p_flags = PF_X|PF_R;
                else
                if (strstr(tmp, "-wxp"))
                        maps[lc].p_flags = PF_X|PF_W;
 		else
                if (strstr(tmp, "rwxp"))
                        maps[lc].p_flags = PF_X|PF_W|PF_R;
                else
                if (strstr(tmp, "r--s"))
                        maps[lc].special++;
                else
                if (strstr(tmp, "rw-s"))
                        maps[lc].special++;
                else
                if (strstr(tmp, "-w-s"))
                        maps[lc].special++;
                else
                if (strstr(tmp, "--xs"))
                        maps[lc].special++;
                else
                if (strstr(tmp, "r-xs"))
                        maps[lc].special++;
                else
                if (strstr(tmp, "-wxs"))
                        maps[lc].special++;
                else
                if (strstr(tmp, "rwxs"))
                        maps[lc].special++;
                
        }
        fclose(fd);

        return 0;
}

static void fill_sock_info(fd_info_t *fdinfo, unsigned int inode)
{
	FILE *fp = fopen("/proc/net/tcp", "r");
	char buf[512], local_addr[64], rem_addr[64];
	char more[512];
	int local_port, rem_port, d, state, timer_run, uid, timeout;
	unsigned long rxq, txq, time_len, retr, _inode;
	if( fgets(buf, sizeof(buf), fp) == NULL ) {
		log_msg(__LINE__, "fgets %s", strerror(errno));
		exit(-1);
        }
	while (fgets(buf, sizeof(buf), fp)) {
		sscanf(buf, "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %ld %512s\n",
			&d, local_addr, &local_port, rem_addr, &rem_port, &state,
			&txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &_inode, more);
		if (_inode == inode) {
#if DEBUG
			log_msg(__LINE__, "socket (TCP) inode match");
#endif
			sscanf(local_addr, "%X", &(fdinfo->socket.src_addr.s_addr));
			sscanf(rem_addr, "%X", &(fdinfo->socket.dst_addr.s_addr));
			fdinfo->socket.src_port = local_port;
			fdinfo->socket.dst_port = rem_port;
			fdinfo->net = NET_TCP;
		}
	}	/* Try for UDP if we don't find the socket inode in TCP */
	
	fclose(fp);
	fp = fopen("/proc/net/udp", "r");
	if( fgets(buf, sizeof(buf), fp) == NULL ) {
		log_msg(__LINE__, "fgets %s", strerror(errno));
		exit(-1);
        }
        while (fgets(buf, sizeof(buf), fp)) {
                sscanf(buf, "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %ld %512s\n",
                        &d, local_addr, &local_port, rem_addr, &rem_port, &state,
                        &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &_inode, more);
                if (_inode == inode) {
#if DEBUG
                        log_msg(__LINE__, "socket (UDP) inode match");
#endif
                        sscanf(local_addr, "%X", &(fdinfo->socket.src_addr.s_addr));
                        sscanf(rem_addr, "%X", &(fdinfo->socket.dst_addr.s_addr));
                        fdinfo->socket.src_port = local_port;
                        fdinfo->socket.dst_port = rem_port;
                        fdinfo->net = NET_UDP;
                        log_msg(__LINE__, "setting net UDP");
                }
        }

	fclose(fp);
}

int get_fd_links(memdesc_t *memdesc, fd_info_t **fdinfo)
{
	FILE *fp;
	DIR *dp;
	struct dirent *dptr = NULL;
	char tmp[256];
	char *dpath = xfmtstrdup("/proc/%d/fd", memdesc->task.pid);
	char *fdinfo_path = xfmtstrdup("/proc/%d/fdinfo", memdesc->task.pid);
	*fdinfo = (fd_info_t *)heapAlloc(sizeof(fd_info_t) * 256);
	fd_info_t fdinfo_tmp;
	unsigned int inode;
	char *p, tmp_path[512], none[16];
	int fdcount, pos;
	unsigned int perms;
 	
        for (fdcount = 0, dp = opendir(dpath); dp != NULL;) {
                dptr = readdir(dp);
                if (dptr == NULL) 
                        break;
		if (dptr->d_name[0] == '.')
			continue;
		snprintf(tmp, sizeof(tmp), "%s/%s", dpath, dptr->d_name); // i.e /proc/pid/fd/3
		if( readlink(tmp, (*fdinfo)[fdcount].path, MAX_PATH) == -1 ) {
                    log_msg(__LINE__, "readlink %s", strerror(errno));
                    exit(-1);
                }
		if (strstr((*fdinfo)[fdcount].path, "socket")) {
			p = strchr((*fdinfo)[fdcount].path, ':') + 2;
			if (p == NULL) {
				fdcount++;
				continue;
			}
			
			inode = atoi(p);
			fill_sock_info(&fdinfo_tmp, inode);
			if (fdinfo_tmp.net) {
				(*fdinfo)[fdcount].net = fdinfo_tmp.net;
				(*fdinfo)[fdcount].socket = fdinfo_tmp.socket;
			}
		}
		(*fdinfo)[fdcount].fd = atoi(dptr->d_name);
		snprintf(tmp_path, sizeof(tmp_path), "%s/%d", fdinfo_path, (*fdinfo)[fdcount].fd);
		fp = fopen(tmp_path, "r");
		fscanf(fp, "%s	%d", none, &pos);
		(*fdinfo)[fdcount].pos = (loff_t)pos;
		fscanf(fp, "%s	%d", none, &perms);
		(*fdinfo)[fdcount].perms = (unsigned int)octal2decimal(perms);
		fclose(fp);
		fdcount++;
	}
	xfree(dpath);
	xfree(fdinfo_path);
	return fdcount;
}

int get_map_count(pid_t pid)
{
        FILE *pd;
        char cmd[256], buf[256];
        int lc;
  	      
        snprintf(cmd, sizeof(cmd), "/usr/bin/wc -l /proc/%d/maps", pid);
	if ((pd = popen(cmd, "r")) == NULL) {
            	log_msg(__LINE__, "popen %s", strerror(errno));
		return -1;
        }
        if( fgets(buf, sizeof(buf), pd) == NULL ) {
            log_msg(__LINE__, "fgets %s", strerror(errno));
            exit(-1);
        }
        lc = atoi(buf);
        pclose(pd);
        return lc;
}

char * get_executable_path(int pid)
{
	char *path = xfmtstrdup("/proc/%d/exe", pid);
	char *ret = (char *)heapAlloc(MAX_PATH);
	char *ret2 = (char *)heapAlloc(MAX_PATH);
	
	memset(ret, 0, MAX_PATH); // for null termination padding
	if( readlink(path, ret, MAX_PATH) == -1) {
            log_msg(__LINE__, "readlink %s", strerror(errno));
            exit(-1);
        }
	free(path);
	/* Now is our new path also a symbolic link? */
	int rval = readlink(ret, ret2, MAX_PATH);
	return rval < 0 ? ret : ret2;
}

/*
 * Get original entry point
 */
ElfW(Addr) get_original_ep(int pid)
{
        struct stat st;
        char *path = xfmtstrdup("/proc/%d/exe", pid);
        int fd = xopen(path, O_RDONLY);
        xfree(path);
        xfstat(fd, &st);
        uint8_t *mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (mem == MAP_FAILED) {
                log_msg(__LINE__, "mmap");
                return -1;
        }
        ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)mem;
        return ehdr->e_entry;
}
