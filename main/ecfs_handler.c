#include "../include/ecfs_handler.h"

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
		case E_386:
			ret = 32;
			break;
		case E_X86_64:
			ret = 64;
			break;
		default:
			ret = -1;
			break;
	}
	return ret;
}


int main(int argc, char **argv)
{
	int pid = 0;
	int heuristics = 0;
	int text_all = 0;
	char *outfile;
	char *exename;

	Elf32_Ehdr *ehdr; // doesn't matter if its 32bit or 64bit.
	char *exepath;

	option_struct_t options;
	
	void *handle;
	void (*ecfs_transform)(options_struct_t *);
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
                                outfile = xstrdup(optarg);
                                break;
                        case 'e':
                                exename = xstrdup(optarg);
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
	
	exepath = xfmtstrdup("/proc/%d/exe", pid);
	arch = check_binary_arch(exepath);
	if (arch == -1) {
		log_msg(__LINE__, "FATAL: Could not detect if process was using 32bit or 64bit ELF, bailing out...");
		exit(-1);
	}
	switch(arch) {
		case 32:
			ecfs_worker = xstrdup(ECFS_WORKER_32);
			break;
		case 64:
			ecfs_worker = xstrdup(ECFS_WORKER_64);
			break;
	}
	/*
	 * Store command line options in option_struct_t
	 * structure so that we can pass it to the entry
	 * point of ecfs_transform() function which exists
	 * in the ecfs-base shared library
	 */
	options.text_all = text_all;
	options.heuristics = heuristics;
	options.pid = pid;
	strncpy(options.outfile, outfile, sizeof(options.outfile));
	options.outfile[sizeof(options.outfile) - 1] = '\0';
	strncpy(options.exename, exename, sizeof(options.exename));
	options.exename[sizeof(options.exename) - 1] = '\0';
	
	/*
	 * Load the appropriate ecfs worker for our process
	 * either 32bit or 64bit, and transfer control over
	 * to it.
	 */
	handle = dlopen(ecfs_worker, RTLD_NOW);
	if (handle == NULL) {
		log_msg(__LINE__, "FATAL: dlopen failed to load ecfs worker '%s': %s", ecfs_worker, strerror(errno));
		exit(-1);
	}
	ecfs_transform = dlsym(handle, ECFS_ENTRY_POINT);
	

}




