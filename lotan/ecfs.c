/*
 * ECFS (C) Ryan O'Neill 2014 - 2015
 */

#include "ecfs.h"

static int get_maps(pid_t pid, mappings_t *maps, const char *path)
{
        char mpath[256], buf[256], tmp[256], *p, *q = alloca(32);
        FILE *fd;
        int lc, i;
        
        snprintf(mpath, sizeof(mpath), "/proc/%d/maps", pid);
        
        if ((fd = fopen(mpath, "r")) == NULL) 
                return -1;

        for (lc = 0; (fgets(buf, sizeof(buf), fd) != NULL); lc++) {
                strcpy(tmp, buf); //tmp and buf are same sized buffers
                p = strchr(buf, '-');
                *p = '\0';
                p++;
                maps[lc].elfmap = 0;
                maps[lc].base = strtoul(buf, NULL, 16);
                maps[lc].size = strtoul(p, NULL, 16) - maps[lc].base;
                if (strstr(tmp, path)) {
                        if (!strstr(tmp, "---p"))
                                maps[lc].filename = xstrdup(strchr(tmp, '/'));
                                maps[lc].elfmap++;
                }
                else
                if (strstr(tmp, "[heap]")) 
                        maps[lc].heap++;
                else
                if (strstr(tmp, "[stack]"))
                        maps[lc].stack++;
                else
                if (strstr(tmp, "[stack:")) { /* thread stack */
                        for (i = 0, p = strchr(tmp, ':') + 1; *p != ']'; p++, i++)
                                q[i] = *p;
                        maps[i].thread_stack++;
                        maps[i].stack_tid = atoi(q);
                }
                else 
                if (strstr(tmp, "---p")) 
                        maps[lc].padding++;
                else
                if (strstr(tmp, "[vdso]")) 
                        maps[lc].vdso++; 
                else
                if (strstr(tmp, "[vsyscall]"))
                        maps[lc].vsyscall++;
                else
                if ((p = strrchr(tmp, '/'))) {
                        if (strstr(p, ".so")) {
                                maps[lc].shlib++;
                                maps[lc].filename = xstrdup(strchr(tmp, '/'));
                        }
                        else
                        if (strstr(p, "rwxp") || strstr(p, "r-xp")) {
                                maps[lc].filename = xstrdup(strchr(tmp, '/'));
                                maps[lc].filemap_exe++; // executable file mapping
                        }
                        else {
                                maps[lc].filename = xstrdup(strchr(tmp, '/'));
                                maps[lc].filemap++; // regular file mapping
                        }       
                } else
                if (strstr(tmp, "rwxp") || strstr(tmp, "r-xp")) 
                        maps[lc].anonmap_exe++; // executable anonymous mapping
                
                /*      
                 * Set segment permissions (Or is it a special file?)
                 */
                if (strstr(tmp, "r--p")) 
                        maps[lc].p_flags = PF_R;
                else
                if (strstr(tmp, "rw-p"))
                        maps[lc].p_flags = PF_R|PF_W;
                else
                if (strstr(tmp, "-w-p"))
                        maps[lc].p_flags = PF_W;
                else
                if (strstr(tmp, "--xp"))
                        maps[lc].p_flags = PF_X;
                else
                if (strstr(tmp, "r-xp"))
                        maps[lc].p_flags = PF_X|PF_R;
                else
                if (strstr(tmp, "-wxp"))
                        maps[lc].p_flags = PF_X|PF_W;
 		else
                if (strstr(tmp, "rwxp"))
                        maps[lc].p_flags = PF_X|PF_W|PF_R;
                else
                if (strstr(tmp, "r--s"))
                        maps[lc].special++;
                else
                if (strstr(tmp, "rw-s"))
                        maps[lc].special++;
                else
                if (strstr(tmp, "-w-s"))
                        maps[lc].special++;
                else
                if (strstr(tmp, "--xs"))
                        maps[lc].special++;
                else
                if (strstr(tmp, "r-xs"))
                        maps[lc].special++;
                else
                if (strstr(tmp, "-wxs"))
                        maps[lc].special++;
                else
                if (strstr(tmp, "rwxs"))
                        maps[lc].special++;
                
        }
        fclose(fd);

        return 0;
}

static int proc_status(pid_t pid, memdesc_t *memdesc)
{
        FILE *fd;
        char path[256], buf[256], *p, *tp;
        int i;

        snprintf(path, sizeof(path), "/proc/%d/status", pid);
        if ((fd = fopen(path, "r")) == NULL)
                return -1;
        
        while (fgets(buf, sizeof(buf), fd)) {
                p = strchr(buf, ':');
                *p++ = '\0';
                while (*p == 0x20 || *p == '\t')
                        p++;
                if (strcasecmp(buf, "name") == 0) {
                        memdesc->comm = strdup(p);
                        if ((tp = strchr(memdesc->comm, '\n')))
                                *tp = '\0';
                }
                else
                if (strcasecmp(buf, "ppid") == 0)
                        memdesc->task.leader = atoi(p);
                else
                if (strcasecmp(buf, "uid") == 0)
                        memdesc->task.uid = atoi(p);
                else
                if (strcasecmp(buf, "gid") == 0)
                        memdesc->task.gid = atoi(p);
                else
                if (strcasecmp(buf, "tracerpid") == 0) {
                        memdesc->task.tracer = atoi(p); 
                        if (memdesc->task.tracer)
                                memdesc->task.state |= PS_TRACED;
                } 
                else
                if (strcasecmp(buf, "state") == 0) {
                        switch(*p) {
                                case 'D': 
                                        memdesc->task.state |= PS_SLEEP_UNINTER;
                                        break;
                                case 'R':
                                        memdesc->task.state |= PS_RUNNING;
				           break;
                                case 'S':
                                        memdesc->task.state |= PS_SLEEP_INTER;
                                        break;
                                case 'T':
                                        memdesc->task.state |= PS_STOPPED;
                                        break;
                                case 'Z':
                                        memdesc->task.state |= PS_DEFUNCT;
                                        break; 
                                default:
                                        memdesc->task.state |= PS_UNKNOWN;      
                                        break;
                        }
                }
                
        }

        return 0;
}


char * get_exe_path(pid_t pid, const char *name)
{
        FILE *fd;
        char buf[256];
        char mpath[256];
        char *p, *ret = NULL;
        
        snprintf(mpath, sizeof(mpath), "/proc/%d/maps", pid);
        
        if ((fd = fopen(mpath, "r")) == NULL)
                return NULL;
        while (fgets(buf, sizeof(buf), fd)) {
                if ((p = strrchr(buf, '/')) == NULL)
                        continue;
                p++;
                if (strncmp(p, name, strlen(name)) == 0) {      
                        p = strchr(buf, '/');
                        ret = strdup(p);        
                        if ((p = strchr(ret, '\n')))
                                *p = '\0';
                        break;
                }
        }
        return ret;
}

static int get_map_count(pid_t pid)
{
        FILE *pd;
        char cmd[256], buf[256];
        int lc;
        
        snprintf(cmd, sizeof(cmd), "/usr/bin/wc -l /proc/%d/maps", pid);
        if ((pd = popen(cmd, "r")) == NULL)
                return -1;
        fgets(buf, sizeof(buf), pd);
        lc = atoi(buf);
        pclose(pd);
        return lc;
}

memdesc_t * build_proc_metadata(pid_t pid)
{
	memdesc_t *memdesc = (memdesc_t *)heapAlloc(sizeof(memdesc_t));
	
	memdesc->mapcount = get_map_count(pid);
        if (memdesc->mapcount < 0) {
                printf("[!] failed to get mapcount from /proc/%d/maps\n", pid);
                return NULL;
        }
        memdesc->maps = (mappings_t *)heapAlloc(sizeof(mappings_t) * memdesc->mapcount);
        
        memset((void *)memdesc->maps, 0, sizeof(mappings_t) * memdesc->mapcount);
        
        if (proc_status(pid, memdesc) < 0) {
                printf("[!] failed to get data from /proc/%d/status\n", pid);
                return NULL;
        }
        
        if ((memdesc->path = get_exe_path(pid, memdesc->comm)) == NULL) {
                printf("[!] Unable to find executable file path associated with pid: %d\n", pid);
                return NULL;
        }

        if (get_maps(pid, memdesc->maps, memdesc->path) < 0) {
                printf("[!] failed to get data from /proc/%d/maps\n", pid);
                return NULL;
        }
        
        memdesc->task.pid = memdesc->pid = pid;
	
	return memdesc;

}


	
int main(int argc, char **argv)
{
		
	struct rlimit limit_core = {0L, 0L};
	
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <pid> <corefile(input)> <ecfsfile(output)>\n", argv[0]);
		exit(-1);
	}
	
    	if (setrlimit(RLIMIT_CORE, &limit_core) < 0) {
		perror("setrlimit");
		exit(-1);
	}
	
	



}




