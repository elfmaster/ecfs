#include "../include/ecfs_handler.h"


int main(int argc, char **argv)
{
	char *outfile;
	char *exename;
	int pid;
	int text_all;
	int heuristics;

	options_struct_t options;
	void *ecfs_handle;
	void (*ecfs_transform)(options_struct_t *);

	if (argc < 2) {
                fprintf(stdout, "Usage: %s [-peoth]\n", argv[0]);
                fprintf(stdout, "- To be used with /proc/sys/kernel/core_pattern only (Never called directly)\n");
                fprintf(stdout, "[-p]   pid of process (Supplied by %%p format arg in core_pattern)\n");
                fprintf(stdout, "[-e]   executable name (Supplied by %%e format arg in core_pattern)\n");
                fprintf(stdout, "[-o]   output ecfs file\n\n");
		fprintf(stdout, "[-t]   Write complete text images into ecfs-core files\n");
		fprintf(stdout, "[-h]   Enable heuristics for detecting .so injection attacks\n");
                exit(-1);
        }
        memset(&opts, 0, sizeof(opts));

        while ((c = getopt(argc, argv, "th:o:p:e:")) != -1) {
                switch(c) {
                        case 'o':
                                opts.outfile = xstrdup(optarg);
                                break;
                        case 'e':
                                opts.exename = xstrdup(optarg);
                                break;
                        case 'p':
                                pid = atoi(optarg);
                                break;
                        case 'h':
                                opts.heuristics = 1;
                                break;
                        case 't':
                                opts.text_all = 1;
                                break;
                        default:
                                fprintf(stderr, "Unknown option\n");
                                exit(0);
                }
        }





}




