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


#include "ecfs.h"
#include <syslog.h>

struct opts opts;

void ffperror(const char *, int);

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
	char *str = xfmtstrdup("xopen failed on %s", path);
	int fd = open(path, flags);
	if (fd < 0) {
		fprintf(stderr, "opening path: %s failed\n", path);
		ffperror(str, 0);
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
        char buf[512];
	
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
	int fd;
        char buf[512];
	va_list va;
        va_start (va, fmt);
	vsnprintf(buf, sizeof(buf), fmt, va);
	va_end(va);
	syslog(LOG_MAKEPRI(LOG_USER, LOG_WARNING), "%s [line: %i]", buf, lineno);

}
void ffperror(const char *s, int lineno)
{
	system("touch /tmp/ecfs.debug");
	FILE *fp = fopen("/tmp/ecfs.debug", "w");
	fprintf(fp, "%s failed on code line [%d]: %s\n", s, lineno, strerror(errno));
	fclose(fp);
}



