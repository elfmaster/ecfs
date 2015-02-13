#include "ecfs.h"
#include <dirent.h>

struct opts opts; 

struct linux_dirent {
        long d_ino;
        off_t d_off;
        unsigned short d_reclen;
        char d_name[];
};

static int get_pid_uid(pid_t pid)
{
	FILE *fd;
	char *path = alloca(128);
	char tmp[32], buf[256];
	int uid, t1, t2, t3;

	snprintf(path, 128, "/proc/%d/status", pid);
	if ((fd = fopen(path, "r")) == NULL) 
		return -1;
	while (!(feof(fd))) {
		fgets(buf, sizeof(buf), fd);
		if (strncasecmp(buf, "Uid:", 4) == 0) {
			sscanf(buf, "%s %d %d %d %d", tmp, &uid, &t1, &t2, &t3);
			return uid;
		}
	}
	return -1;	
}

int main(int argc, char **argv)
{
	desc_t desc;
	int c;	
	
	if (argc < 2) {
		printf("Usage: %s [-ca] [-s snapshot_dir] [-p pid]\n", argv[0]);
		exit(0);
	}
	
	memset((void *)&opts, 0, sizeof(opts));

	while((c = getopt(argc, argv, "cap:s:")) != -1) {
		switch(c) {
			case 'c':
				opts.coretype++;
				break;
			case 'a':
				opts.all++;
				break;
			case 'p':
				opts.pid = atoi(optarg);
				break;
			case 's':
				opts.snapdir = strdup(optarg);
				break;
			default:
				printf("unknown option\n");
				break;
		}
	}

	
	if (opts.snapdir == NULL) {
		printf("Using default snapshot directory $CWD/.snapshot\n");
		desc.snapdir = xstrdup(".snapshot");
		mkdir(desc.snapdir, 0700);
	} else {
		printf("Using directory %s for snapshots\n", opts.snapdir);
		desc.snapdir = xstrdup(opts.snapdir);
		mkdir(desc.snapdir, 0700);
	}
		
	if (opts.pid) {
		memdesc_t *memdesc = (memdesc_t *)take_process_snapshot(opts.pid);
		if (memdesc == NULL) {
			printf("[!] Taking process snapshot failed\n");
			exit(-1);
		}
		memcpy((void *)&desc.memory, (void *)memdesc, sizeof(memdesc_t));
		dump_process_snapshot((desc_t *)&desc);
	} else
	if (opts.all) {
		pid_t pid;
		int myuid;
		size_t nread;
		int dd, bpos;
		char buf[4096], *p;
		struct linux_dirent *d;
        	list_t *list = (list_t *)heapAlloc(sizeof(list_t));
        	node_t *current;
        	list->head = NULL;
        	list->tail = NULL;
		
                if ((dd = open("/proc", O_RDONLY | O_DIRECTORY)) == -1) {
                        perror("open dir /proc");
                        exit(-1);
                }

		for (;;) {
			
			if ((nread = syscall(SYS_getdents, dd, buf, 4096)) == -1) {
                                perror("getdents");
                                exit(-1);
                        }
                        
			if (nread == 0)
                                break;

		        for (bpos = 0; bpos < nread;) {
                        	d = (struct linux_dirent *)(buf + bpos);
                                bpos += d->d_reclen; 
                                if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
                                        continue; 
				for (p = d->d_name; *p != '\0'; p++)
					if (*p < '0' || *p > '9')
						continue; //we are only interested in pid directories
				
				pid = atoi(d->d_name);
				if ((myuid = getuid()) != 0) 
					if (get_pid_uid(pid) != myuid) {
						printf("[!] pid %d not owned by uid: %d, continuing...\n", pid, myuid);
						continue;		
					}
		                memdesc_t *memdesc = (memdesc_t *)take_process_snapshot(pid);
                		if (memdesc == NULL) {
                        		printf("[!] Taking process snapshot of %d failed; check process ownership?\n", pid);
					continue;
                		} 
                		memcpy((void *)&desc.memory, (void *)memdesc, sizeof(memdesc_t));
		                dump_process_snapshot((desc_t *)&desc);
				free_snapshot_maps(memdesc);
				insert_front(&list, &desc);
				sleep(1);
			}
		} 
		for (current = list->tail; current != NULL; current = current->prev) 
			printf("Successfully dumped process %d\n", current->desc->memory.pid);		
	  	

	}
				
}
