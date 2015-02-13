/*
 * ECFS (Extended core file snapshot) utility (C) 2014 Ryan O'Neill
 * http://www.bitlackeys.org/#research
 * elfmaster@zoho.com
 */

#include "ecfs.h"

int waitpid2(pid_t pid, int *status, int options)
{
        pid_t ret;

        do {
                ret = waitpid(pid, status, options);
        } while (ret == -1 && errno == EINTR);

        return ret;
}


void toggle_ptrace_state(desc_t *h, int state)
{
        switch (state) {
                case PT_ATTACHED:
                        h->memory.task.state &= ~PT_DETACHED;
                        h->memory.task.state |= PT_ATTACHED;
                        break;
                case PT_DETACHED:
                        h->memory.task.state &= ~PT_ATTACHED;
                        h->memory.task.state |= PT_DETACHED;
                        break;
        }
}

int pid_attach(desc_t *h)
{
        int status;
        pid_t pid = h->memory.task.pid;
        
        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
                if (errno) {
                        fprintf(stderr, "ptrace: pid_attach() failed: %s\n", strerror(errno));
                        return -1;
                }
        }
        do {
                if (waitpid2(pid, &status, 0) < 0) 
                        goto detach;
                
                if (!WIFSTOPPED(status))
                        goto detach;
                
                if (WSTOPSIG(status) == SIGSTOP)
                        break;
        
                if (ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status)) == -1 )
                        goto detach;
        } while(1);
        
        toggle_ptrace_state(h, PT_ATTACHED);
        return 0;


detach:
        fprintf(stderr, "pid_attach() -> waitpid(): %s\n", strerror(errno));
        pid_detach(h);
        return -1;
}

int pid_attach_stateful(desc_t *h)
{
        if(h->memory.task.state & PT_ATTACHED)
                return 0;
        
        if (pid_attach(h) < 0)
                return -1;

}

int pid_read(int pid, void *dst, const void *src, size_t len)
{

        int sz = len / sizeof(void *);
        unsigned char *s = (unsigned char *)src;
        unsigned char *d = (unsigned char *)dst;
        long word;

        while (sz-- != 0) {
                word = ptrace(PTRACE_PEEKTEXT, pid, s, NULL);
                if (word == -1 && errno) {
                        fprintf(stderr, "pid_read failed, pid: %d: %s\n", pid, strerror(errno));
                        return -1;
                }
                *(long *)d = word;
                s += sizeof(long);
                d += sizeof(long);
        }
        
        return 0;
}

int pid_write(int pid, void *dest, const void *src, size_t len)
{
        size_t rem = len % sizeof(void *);
        size_t quot = len / sizeof(void *);
        unsigned char *s = (unsigned char *) src;
        unsigned char *d = (unsigned char *) dest;
        
        while (quot-- != 0) {
                if (ptrace(PTRACE_POKEDATA, pid, d, *(void **)s) == -1 )
                        goto out_error;
                s += sizeof(void *);
                d += sizeof(void *);
        }

        if (rem != 0) {
                long w;
                unsigned char *wp = (unsigned char *)&w;

                w = ptrace(PTRACE_PEEKDATA, pid, d, NULL);
                if (w == -1 && errno != 0) {
                        d -= sizeof(void *) - rem;

                        w = ptrace(PTRACE_PEEKDATA, pid, d, NULL);
                        if (w == -1 && errno != 0)
                                goto out_error;

                        wp += sizeof(void *) - rem;
                }

                while (rem-- != 0)
                        wp[rem] = s[rem];

                if (ptrace(PTRACE_POKEDATA, pid, (void *)d, (void *)w) == -1)
                        goto out_error;
        }

        return 0;

out_error:
        fprintf(stderr, "pid_write() failed, pid: %d: %s\n", pid, strerror(errno));
        return -1;
}

int pid_detach_direct(pid_t pid)
{
        if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
                if (errno) {
                        fprintf(stderr, "ptrace: pid_detach() failed: %s\n", strerror(errno));
                        return -1;
                }
        }
#if DEBUG
        printf("[+] PT_TID_DETACHED -> %d\n", pid);
#endif
        return 0;
}

int pid_detach(desc_t *h)
{
        pid_t pid = h->memory.task.pid;
        
        if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
                if (errno) {
                        fprintf(stderr, "ptrace: pid_detach() failed: %s\n", strerror(errno));
                        return -1;
                }
        }
        toggle_ptrace_state(h, PT_DETACHED);
        return 0;
}

int pid_detach_stateful(desc_t *h)
{
        if (h->memory.task.state & PT_DETACHED)
                return 0;
        if (pid_detach(h) < 0)
                return -1;
}


int pid_attach_direct(pid_t pid)
{
        int status;

        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
                if (errno) {
                        fprintf(stderr, "ptrace: pid_attach() failed: %s\n", strerror(errno));
                        return -1;
                }
        }
        do {
                if (waitpid2(pid, &status, 0) < 0)
                        goto detach;

                if (!WIFSTOPPED(status))
                        goto detach;

                if (WSTOPSIG(status) == SIGSTOP)
                        break;

                if ( ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status)) == -1 )
                        goto detach;
        } while(1);

#if DEBUG
        printf("[+] PT_TID_ATTACHED -> %d\n", pid);
#endif
        return 0;


detach:
        fprintf(stderr, "pid_attach_direct() -> waitpid(): %s\n", strerror(errno));
        pid_detach_direct(pid);
        return -1;
}


