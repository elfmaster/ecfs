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
	if (p)
		free(p);
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

int octal2decimal(int n)
{
	int decimal=0, i=0, rem;
    	while (n != 0) {
        	rem = n%10;
        	n/=10;
        	decimal += rem*pow(8,i);
        	++i;
    	}
    	return decimal;
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

void exit_failure(int code)
{
	umount(ECFS_RAMDISK_DIR);
	exit(code);
}

int inquire_meminfo(void)
{
        FILE *fp;
        int kbytes, gbytes;
	char s1[32], s2[32];
	
        fp = fopen("/proc/meminfo", "r");
        if (fp == NULL) {       
                perror("fopen");
                return -1;
        }
        fscanf(fp, "%s %u %s", s1, &kbytes, s2);
        fclose(fp);
        if (kbytes < 1048576)
                return 0;
	gbytes = kbytes / 1024 / 1024;
	return gbytes;
}

int create_tmp_ramdisk(size_t gigs)
{
	int ret;

	if (access(ECFS_RAMDISK_DIR, F_OK) != 0) {
#if DEBUG
		log_msg(__LINE__, "%s did not exist, so creating it.");
#endif
		mkdir(ECFS_RAMDISK_DIR, S_IRWXU|S_IRWXG);
	}
	
#if DEBUG
	log_msg(__LINE__, "mount -o size=%dG -t tmpfs none %s", gigs, ECFS_RAMDISK_DIR);
#endif
	char *cmd = xfmtstrdup("mount -o size=%dG -t tmpfs none %s", gigs, ECFS_RAMDISK_DIR);
	ret = system(cmd);
	if (ret == -1)
		return -1;
	return 0;
}
