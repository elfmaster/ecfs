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

#include "../include/ecfs_handler.h"
#include <syslog.h>
#include <stdarg.h>

static void log_msg(unsigned int lineno, char *fmt, ...)
{
        char buf[512];
        va_list va;
        va_start (va, fmt);
        vsnprintf(buf, sizeof(buf), fmt, va);
        va_end(va);
        syslog(LOG_MAKEPRI(LOG_USER, LOG_WARNING), "%s [line: %i]", buf, lineno);

}

static void load_ecfs_worker(char **argv, char **envp, const char *ecfs_worker_path)
{
	int status, pid;
	int ret;

	argv[0] = ecfs_worker_path;
	pid = fork();
	
	if (pid < 0) {
		log_msg(__LINE__, "FATAL: fork() failed: %s", strerror(errno));
		exit(-1);
	}
	if (pid == 0) {
		ret = execve(ecfs_worker_path, argv, envp);
		if (ret < 0) {
			log_msg(__LINE__, "execve() failed: %s", strerror(errno));
			exit(-1);
		}
		exit(0);
	}
	wait(&status); 

}

/*
 * If we cannot get architecture this way its probably
 * because the executable no longer exists? In this case
 * we will try another approach.
 */

static int check_binary_arch(const char *path)
{
	int ret;
	Elf32_Ehdr *ehdr; // doesn't matter if its 32bit or 64bit in this case
	struct stat st;
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	ret = fstat(fd, &st);
	if (ret < 0)
		return -1;
	uint8_t *mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED)
		return -1;
	ehdr = (Elf32_Ehdr *)mem;
	switch(ehdr->e_machine) {
		case EM_386:
			ret = 32;
			break;
		case EM_X86_64:
			ret = 64;
			break;
		default:
			ret = -1;
			break;
	}
	return ret;
}


int main(int argc, char **argv, char **envp)
{
	int c;
	int pid = 0;
	int heuristics = 0;
	int text_all = 0;
	char *outfile;
	char *exename;
	char *exepath;
	char *ecfs_worker;

  	if (argc < 2) {
                fprintf(stdout, "Usage: %s [-peo]\n", argv[0]);
                fprintf(stdout, "- To be used with /proc/sys/kernel/core_pattern\n");
                fprintf(stdout, "[-p]   pid of process (Supplied by %%p format arg in core_pattern)\n");
                fprintf(stdout, "[-e]   executable path (Supplied by %%e format arg in core_pattern)\n");
                fprintf(stdout, "[-o]   output ecfs file\n\n");
		fprintf(stdout, "[-t]	Write complete text image of all shlibs (vs. the default 4096 bytes)\n");
		fprintf(stdout, "[-h]	Turn on heuristics for detecting .so injection attacks\n");
                exit(0);
        }
        while ((c = getopt(argc, argv, "th:o:p:e:")) != -1) {
                switch(c) {
                        case 'o':
                                outfile = strdup(optarg);
                                break;
                        case 'e':
                                exename = strdup(optarg);
                                break;
                        case 'p':
                                pid = atoi(optarg);
                                break;
                        case 'h':
                                heuristics = 1;
                                break;
                        case 't':
                                text_all = 1;
                                break;
                        default:
                                fprintf(stderr, "Unknown option\n");
                                exit(0);
                }
        }
	
	if (pid == 0 || exename == NULL || outfile == NULL) {
		log_msg(__LINE__, "invalid command line args being used - pid: %d exename: %p outfile: %p", pid, exename, outfile);
		exit(-1);
	}
	
	exepath = alloca(512);
	snprintf(exepath, 512, "/proc/%d/exe", pid);
	
	int arch = check_binary_arch(exepath);
	if (arch == -1) {
		log_msg(__LINE__, "FATAL: Could not detect if process was using 32bit or 64bit ELF, bailing out...");
		exit(-1);
	}
	switch(arch) {
		case 32:
#if DEBUG
			log_msg(__LINE__, "launching %s", ECFS_WORKER_32);
#endif
			ecfs_worker = strdup(ECFS_WORKER_32);
			break;
		case 64:
#if DEBUG
			log_msg(__LINE__, "launching %s", ECFS_WORKER_64);
#endif
			ecfs_worker = strdup(ECFS_WORKER_64);
			break;
	}
	
	load_ecfs_worker(argv, envp, ecfs_worker);

	exit(0);
}






