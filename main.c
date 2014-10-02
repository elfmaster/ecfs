#include "vv.h"

int main(int argc, char **argv)
{
	desc_t desc;
		
	if (argc < 2) {
		printf("Usage: %s <pid>\n", argv[0]);
		exit(0);
	}

	pid_t pid = atoi(argv[1]);
	
	desc.snapdir = xstrdup(".snapshot");
	mkdir(desc.snapdir, 0700);

	memdesc_t *memdesc = (memdesc_t *)take_process_snapshot(pid);
	memcpy((void *)&desc.memory, (void *)memdesc, sizeof(memdesc_t));
	dump_process_snapshot(&desc, COMPLETE_SNAPSHOT);

	
}
