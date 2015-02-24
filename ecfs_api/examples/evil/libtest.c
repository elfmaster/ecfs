/*
 * This is our evil shared library, it must be position independent. 
 * syscalls should be called directly using the method below and need
 * to be static
 */

#include <sys/types.h>
#include <sys/syscall.h>
#include <stdio.h>



long evil_write(long fd, char *buf, unsigned long len)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $1, %%rax\n"
                        "syscall" : : "g"(fd), "g"(buf), "g"(len));
        asm("mov %%rax, %0" : "=r"(ret));
        return ret;
}

char * evil_fgets(char *buf, size_t len, FILE *fp)
{
	evil_write(1, buf, len);
}

int main(void) { }
/*
void
_init ()
{
}
void
_fini ()
{
}
*/
