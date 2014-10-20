/*
 * ECFS (Extended core file snapshot) utility (C) 2014 Ryan O'Neill
 * http://www.bitlackeys.org/#research
 * elfmaster@zoho.com
 */


#include "ecfs.h"

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

