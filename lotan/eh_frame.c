/*
 * ECFS (Extended core file snapshot) utility (C) 2014 Ryan O'Neill
 * http://www.bitlackeys.org/#research
 * elfmaster@zoho.com
 */


#include "ecfs.h"

#define UNDEF_VAL 2000
#define SAME_VAL 2001
#define CFA_VAL 2002


void print_fde_instrs(Dwarf_Debug, Dwarf_Fde, int, Dwarf_Error);
static int get_func_data(Dwarf_Debug dbg, Dwarf_Fde fde, int fdenum, struct fde_func_data *);

static struct fde_func_data * parse_frame_data(Dwarf_Debug dbg)
{
	Dwarf_Error error;
    	Dwarf_Signed cie_element_count = 0;
    	Dwarf_Signed fde_element_count = 0;
    	Dwarf_Signed fde_count;
	Dwarf_Cie *cie_data = 0;
    	Dwarf_Fde *fde_data = 0;
	int index;
    	int res = DW_DLV_ERROR;
	Dwarf_Signed fdenum = 0;
	struct fde_func_data func_data;
	struct fde_func_data *fdp;
	struct fde_func_data *fndata;

	res = dwarf_get_fde_list_eh(dbg, &cie_data, &cie_element_count, &fde_data, &fde_element_count, &error);
    	if(res == DW_DLV_NO_ENTRY) {
   		fprintf(stderr, "eh_frame parsing: No frame data present ");
        	return NULL;
    	}

    	if(res == DW_DLV_ERROR) {
        	fprintf(stderr, "eh_frame parsing: Error reading frame data ");
        	return NULL;
    	}
	
	
	fndata = malloc(sizeof(struct fde_func_data) * fde_element_count);
	if (fndata == NULL) {
		perror("malloc");
		exit(-1);
	} 
	
	for(fdenum = 0; fdenum < fde_element_count; ++fdenum) {
		Dwarf_Cie cie = 0;
        	res = dwarf_get_cie_of_fde(fde_data[fdenum], &cie, &error);
        	if(res != DW_DLV_OK) {
            		fprintf(stderr, "eh_frame parsing: Error accessing fdenum %" DW_PR_DSd
                	" to get its cie\n",fdenum);
            		return NULL;
        	}
        	get_func_data(dbg, fde_data[fdenum], fdenum, &func_data);
		fndata[fdenum].addr = func_data.addr;
		fndata[fdenum].size = func_data.size;
	}

	//dwarf_fde_cie_list_dealloc(dbg, cie_data, cie_element_count, fde_data, fde_element_count);
   
	return fndata;
}


int get_func_data(Dwarf_Debug dbg, Dwarf_Fde fde, int fdenum, struct fde_func_data *func_data)
{
	int res;
	Dwarf_Error error;
	Dwarf_Unsigned func_length = 0;
	Dwarf_Unsigned fde_byte_length = 0;
	Dwarf_Off cie_offset = 0;
	Dwarf_Off fde_offset = 0;
	Dwarf_Addr lowpc = 0;
	Dwarf_Signed cie_index = 0;
	Dwarf_Ptr fde_bytes;
	
	
	res = dwarf_get_fde_range(fde, &lowpc, &func_length, &fde_bytes, &fde_byte_length, 
				  &cie_offset, &cie_index, &fde_offset, &error);
	if (res != DW_DLV_OK) {
		fprintf(stderr, "Failed to get fde range\n");
		return -1;
	}
		
	/*
	 * XXX
	 * Workaround here; it should be func_data->addr = lowpc;
	 * we add 4 though to offset a weird misalignment issue
	 * in reconstructing the sections for eh_frame and eh_frame_hdr.
	 */
	func_data->addr = (lowpc + 4);
	func_data->size = func_length;

	return 0;
}


int get_all_functions(const char *filepath, struct fde_func_data **funcs)
{
	int fd;
	int i;
	int res = DW_DLV_ERROR;
	int regtabrulecount = 0;
	Dwarf_Debug dbg;
	Dwarf_Error error;
	Dwarf_Ptr errarg = 0;
	Dwarf_Handler errhand = 0;
        Dwarf_Signed cie_element_count = 0;
        Dwarf_Signed fde_element_count = 0;
        Dwarf_Signed fde_count;
        Dwarf_Cie *cie_data = 0;
        Dwarf_Fde *fde_data = 0;
	struct fde_func_data *fndata;

	if ((fd = open(filepath, O_RDONLY)) < 0) {
		perror("open");
		exit(-1);
	}

	if ((res = dwarf_init(fd, /*DW_DLC_REA*/ 0, errhand, errarg, &dbg, &error)) != DW_DLV_OK) {
		fprintf(stderr, "dwarf_init() failed\n");
		exit(-1);
	}

    	regtabrulecount = 1999;
    	dwarf_set_frame_undefined_value(dbg, UNDEF_VAL);
    	dwarf_set_frame_rule_initial_value(dbg, UNDEF_VAL);
    	dwarf_set_frame_same_value(dbg, SAME_VAL);
    	dwarf_set_frame_cfa_value(dbg, CFA_VAL);
    	dwarf_set_frame_rule_table_size(dbg, regtabrulecount);
	
	res = dwarf_get_fde_list_eh(dbg, &cie_data, &cie_element_count, &fde_data, &fde_element_count, &error);
        if(res == DW_DLV_NO_ENTRY) {
                fprintf(stderr, "eh_frame parsing err1: No frame data present\n");
                return -1;
        }
	
	if ((*funcs = parse_frame_data(dbg)) == NULL) {
		fprintf(stderr, "eh_frame parsing err2: parse_frame_data() failed\n");
		return -1;
	}
	fndata = *funcs;
	
	res = dwarf_finish(dbg, &error);
	if(res != DW_DLV_OK) 
        	fprintf(stderr, "eh_frame parsing err3: dwarf_finish failed!\n");

	close(fd);
    	
	return fde_element_count;
}


	
	
