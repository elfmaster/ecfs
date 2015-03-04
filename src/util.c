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
#include <syslog.h>

struct opts opts;

void log_msg(unsigned int lineno, char *fmt, ...);

void deliver_signal(int pid, int signo)
{
	kill(pid, signo);
}

void * heapAlloc(size_t len)
{
	void *p = malloc(len);
	if (p == NULL) {
		perror("malloc");
		exit(-1);
	}
	memset(p, 0, len);
	return (void *)(uintptr_t)p;
}

char * xstrdup(const char *s)
{
        char *p = strdup(s);
        if (p == NULL) {
                perror("strdup");
                exit(-1);
        }
        return p;
}
        
char * xfmtstrdup(char *fmt, ...)
{
        char *s, buf[512];
        va_list va;
        
        va_start (va, fmt);
        vsnprintf (buf, sizeof(buf), fmt, va);
        s = (char *)(uintptr_t)xstrdup(buf);
        
        return s;
}

int xopen(const char *path, int flags)
{
	int fd = open(path, flags);
	if (fd < 0) {
		log_msg(__LINE__, "xopen() failed opening path: %s: %s", path, strerror(errno));
		exit(-1);
	}
	return fd;
}

int xlseek(int fd, off_t offset, int whence)
{
	off_t ret = lseek(fd, offset, whence);
	if (ret < 0) {
		perror("lseek");
		exit(-1);
	}
	return ret;
}

	
int xfstat(int fd, struct stat *st)
{
	int ret = fstat(fd, st);
	if (ret < 0) {
		perror("fstat");
		exit(-1);
	}
	return 0;
}

void xfree(void *p)
{
#if DEBUG
	log_msg(__LINE__, "xfree() called");
#endif
	if (p)
		free(p);
#if DEBUG
	log_msg(__LINE__, "xfree() returning");
#endif
}

/*
 * Used for debugging
 */
#define LOGFILE "/home/ryan/bin/logging.txt"
void ecfs_print(char *fmt, ...)
{
	FILE *fp;
        va_list va;
	
	va_start (va, fmt);
	if ((fp = fopen(LOGFILE, "w")) == NULL) {
		perror("fopen");
		exit(-1);
	}
        vfprintf (fp, fmt, va);
 	fflush (fp);
	va_end(va);
	fclose(fp);
}

void log_msg(unsigned int lineno, char *fmt, ...)
{
        char buf[512];
	va_list va;
        va_start (va, fmt);
	vsnprintf(buf, sizeof(buf), fmt, va);
	va_end(va);
	syslog(LOG_MAKEPRI(LOG_USER, LOG_WARNING), "%s [line: %i]", buf, lineno);

}

int create_tmp_ramdisk(size_t gigs)
{
	int ret;

	if (gigs > MAX_RAMDISK_GIGS) {
		log_msg(__LINE__, "create_tmp_ramdisk(): should not exceed %d gigs\n", MAX_RAMDISK_GIGS);
		return -1;
	}
	if (access(ECFS_RAMDISK_DIR, F_OK) != 0) 
		mkdir(ECFS_RAMDISK_DIR, S_IRWXU|S_IRWXG);

	char *cmd = xfmtstrdup("mount -o size=%dG -t tmpfs none %s", gigs, ECFS_RAMDISK_DIR);
	ret = system(cmd);
	if (ret == -1)
		return -1;
	return 0;
}
