#include <stdio.h>
#include "../src/libecfs.hpp"

static void print_registers(struct user_regs_struct *reg)
{
        struct user_regs_struct pt_reg;
        memcpy(&pt_reg, reg, sizeof(struct user_regs_struct));

#ifdef __x86_64__
        printf("r15:\t%llx\n"
                        "r14:\t%llx\n"
                        "r13:\t%llx\n" 
                        "r12:\t%llx\n"
                        "rbp:\t%llx\n"
                        "rbx:\t%llx\n"   
                        "r11:\t%llx\n"
                        "r10:\t%llx\n"
                        "r9: \t%llx\n"
                        "r8: \t%llx\n"
                        "rax:\t%llx\n"
                        "rcx:\t%llx\n"
                        "rdx:\t%llx\n"
                        "rsi:\t%llx\n"
                        "rdi:\t%llx\n"
                        "rip:\t%llx\n"
                        "rsp:\t%llx\n"
                        "cs: \t%llx\n"
                        "ss: \t%llx\n"
                        "ds: \t%llx\n"
                        "es: \t%llx\n"
                        "fs: \t%llx\n" 
                        "gs: \t%llx\n"
                        "eflags: %llx\n", 
        pt_reg.r15, pt_reg.r14, pt_reg.r13, pt_reg.r12, pt_reg.rbp, pt_reg.rbx, pt_reg.r11,
        pt_reg.r10, pt_reg.r9, pt_reg.r8, pt_reg.rax, pt_reg.rcx, pt_reg.rdx, pt_reg.rsi, pt_reg.rdi,
        pt_reg.rip, pt_reg.rsp, pt_reg.cs, pt_reg.ss, pt_reg.ds, pt_reg.es, pt_reg.fs, pt_reg.gs, pt_reg.eflags);
#endif
/* must add 32bit support */
}


int main(int argc, char **argv)
{
	if (argc < 2) {
		printf("%s file\n", argv[0]);
		exit(0);
	}
	unsigned int i, ret;
	
	printf("Creating ecfs object on %s\n", argv[1]);
	Ecfs <ecfs_type64>ecfs(argv[1]);
	for (i = 0; i < ecfs.fdinfo_vector.size(); i++)
		printf("fd path: %s\n", ecfs.fdinfo_vector[i].path);
	for (i = 0; i < ecfs.symtab_vector.size(); i++)
		printf("symbol name: %s value: %lx\n", ecfs.symtab_vector[i].name, ecfs.symtab_vector[i].symval);

#if 0
	/*
	 * Get fdinfo
	 */
	vector <fdinfo_64> fdinfo_vector;
	if (ecfs.get_fdinfo(fdinfo_vector) < 0) {
		printf("Getting fdinfo failed\n");
	}
	for (i = 0; i < fdinfo_vector.size(); i++)
		printf("%s\n", fdinfo_vector[i].path);
	
	
	/*
	 * Get prstatus 
	 */
	vector <prstatus_64> prstatus_vector;
	if (ecfs.get_prstatus(prstatus_vector) < 0)
		printf("Getting prstatus failed\n");
	
	for (i = 0; i < prstatus_vector.size(); i++) {
		printf("pid: %d\n", prstatus_vector[i].pr_pid);
		print_registers(&prstatus_vector[i].pr_reg);
	}

	/* 
	 * Get thread count and exepath
	 */
	printf("There are %d threads in for %s\n",
	ecfs.get_thread_count(), ecfs.get_exe_path());
	
	/*
	 * Get local symbols
	 */
	vector <ecfs_sym> symtab;
	ssize_t symcount = ecfs.get_local_symbols(symtab);
	for (i = 0; i < symcount; i++)
		printf("Name: %s Value: %lx\n",  symtab[i].name,symtab[i].symval);
	
	/*
	 * Get the dynamic symbols
	 */
	vector <ecfs_sym> dynsyms;
	if (ecfs.get_dynamic_symbols(dynsyms) < 0) {
		printf("get_dynamic_symbols() failed\n");
	}
	for (i = 0; i < dynsyms.size(); i++)
		printf("Name: %s value: %lx\n",
		dynsyms[i].name, dynsyms[i].symval);
	
	
	/*
	 * Get signal info (Will only work for 64bit ECFS files for now :(
	 */
	siginfo_t siginfo;
	ecfs.get_siginfo(siginfo);
	printf("\nSignal number: %d\n", siginfo.si_signo);

	/*
	 * Get heap pointer
	 */
	uint8_t *heap_ptr, *stack_ptr;
	ecfs.get_heap_ptr(heap_ptr);
	
	/*
	 * Get stack pointer
	 */
	ecfs.get_stack_ptr(stack_ptr);
	
	/*
	 * Print first 16 bytes of heap and stack
	 */
	printf("16 bytes of heap data\n");
	for (i = 0; i < 16; i++)
		printf("%02x", heap_ptr[i]);
	printf("\n\n");
	printf("16 bytes of stack data\n");
	for (i = 0; i < 16; i++)
		printf("%02x", stack_ptr[i]);
	
	/*
	 * Get and Show size of text segment
	 */
	printf("text size: %d bytes\n", ecfs.get_text_size());
	
	/*
	 * Get and print auxiliary vector
	 */
	vector <Elf64_auxv_t> auxv;
	unsigned int asz = ecfs.get_auxv(auxv);
	for (i = 0; i < asz; i++)
		printf("auxv type: %d\n", auxv[i].a_type);
	
	/*
	 * Get the shared library mappings
	 */
	printf("Getting shlib maps\n");
	vector <shlibmap_t> shlibs;
	ecfs.get_shlib_maps(shlibs);
	for (i = 0; i < shlibs.size(); i++)
		printf("%s : %lx\n", shlibs[i].name, shlibs[i].vaddr);
	
	/*
	 * Get PLT/GOT info
	 */
	printf("Getting PLTGOT\n");
	vector <pltgotinfo_t> pltgot;
	ret = ecfs.get_pltgot_info(pltgot);
	for (i = 0; i < pltgot.size(); i++)
		printf("value: %lx expected shlib: %lx or pltstub_addr: %lx\n", pltgot[i].got_entry_va,pltgot[i].shl_entry_va, pltgot[i].plt_entry_va);
	
	/*
	 * Show fault address
 	 */
	printf("Fault location: %lx\n", ecfs.get_fault_location());
	
	/*
	 * Get argument vector (C style)
	 */
	char **arg;
	int ac = ecfs.get_argv(&arg);
	for (i = 0; i < ac; i++)
		printf("%s", arg[i]);
	

	/*
	 * Get a pointer into the .data section
	 */
	uint8_t *data_ptr;
	ssize_t dlen = ecfs.get_section_pointer(".data", data_ptr);
	for (i = 0; i < dlen; i++)
		printf("%02x", data_ptr[i]);

#endif
}	

