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

        /*
         * NOTE: 
         * Now that we've instantiated the ecfs object, we can access
         * various public members, namely the vectors that have already
         * been loaded: phdr, shdr, argv, auxv, fdinfo, symtab, dynsym, prstatus, shlib,
         */

	/*
	 * read the program headers and print each address
	 */
	printf("phdr count: %d\n", ecfs.m_phdr.size());
	for (i = 0; i < ecfs.m_phdr.size(); i++)
		printf("segment addresss %lx\n", ecfs.m_phdr[i].p_vaddr);

	/*
	 * read the section headers and print each address
	 */
	printf("shdr count: %d\n", ecfs.m_shdr.size());
	for (i = 0; i < ecfs.m_shdr.size(); i++)
		printf("section: %s: %lx\n", &ecfs.m_shstrtab[ecfs.m_shdr[i].sh_name], ecfs.m_shdr[i].sh_addr);

	/*
	 * Read fdinfo
	 */
	vector <fdinfo_64> fdinfo = ecfs.m_fdinfo;
	for (i = 0; i < fdinfo.size(); i++)
		printf("fd path: %s\n", fdinfo[i].path);

		
	/*
	 * Read local symbols (from .symtab)
	 */
	vector <ecfs_sym_t> symtab = ecfs.m_symtab;
	for (i = 0; i < symtab.size(); i++)
		printf("symbol name: %s value: %lx\n", symtab[i].name, symtab[i].symval);

	/*
	 * read dynamic symbols
	 */
	vector <ecfs_sym_t> dynsym = ecfs.m_dynsym;
	for (i = 0; i < dynsym.size(); i++)
		printf("symbol name: %s value: %lx\n", dynsym[i].name, dynsym[i].symval);

	/*
	 * Read prstatus
	 */
	vector <prstatus_64> prstatus = ecfs.m_prstatus;
	for (i = 0; i < prstatus.size(); i++)
		printf("pid: %d\n", prstatus[i].pr_pid);
	
	/*
	 * Read pltgot info
	 */
	vector <pltgotinfo_t> pltgot = ecfs.m_pltgot;
	for (i = 0; i < pltgot.size(); i++)
		printf("Reloc offset: %lx value: %lx expected shlib: %lx pltstub: %lx\n",
			pltgot[i].got_site, pltgot[i].got_entry_va, pltgot[i].shl_entry_va, pltgot[i].plt_entry_va);

	
	vector <string> args = ecfs.m_argv;
	for (i = 0; i < ecfs.m_argc; i++) {
		printf("%s", args[i].c_str());
	}
	
	vector <Elf64_auxv_t> auxv = ecfs.m_auxv;
	for (i = 0; i < auxv.size(); i++) {
		printf("auxv a_type: %lx a_val: %lx\n", auxv[i].a_type, auxv[i].a_un.a_val);
	}
	
	/* 
	 * Get thread count and exepath
	 */
	printf("There are %d threads in for %s\n",
	ecfs.get_thread_count(), ecfs.get_exe_path());
	
	
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
	 * Show fault address
 	 */
	printf("Fault location: %lx\n", ecfs.get_fault_location());
	

	/*
	 * Get a pointer into an arbitrary section, lets try the .data section
	 */
	uint8_t *data_ptr;
	ssize_t dlen = ecfs.get_section_pointer(".data", data_ptr);
	for (i = 0; i < dlen; i++)
		printf("%02x", data_ptr[i]);

}	

