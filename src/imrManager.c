#include "imrManager.h"
#include "bpfgen_configuration.h"
#include "bpf_insn.h"

/*
	JIT an IMR rule to BPF 
	@param bprog - program to add rule to 
	@param state - imr_state to conver to bpf 
	@param i - index of objects to convert 
	@return Number of rules added 
*/
static int imr_jit_rule(struct bpf_prog *bprog, struct imr_state *state, int i)
{
	unsigned int start, end, count, len_cur;

	end = state->num_objects;
	if (i >= end)
		return -EINVAL;

	len_cur = bprog->len_cur;

	/*EMIT(bprog, BPF_MOV64_REG(BPF_REG_1, BPF_REG_2));
	EMIT(bprog, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1,
			   sizeof(struct ethhdr) + sizeof(struct iphdr)));
	EMIT(bprog, BPF_JMP_REG(BPF_JGT, BPF_REG_1, BPF_REG_3, 0));
	EMIT(bprog, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -(int)sizeof(struct iphdr)));*/

	/*start = i;
	count = 0;

	for (i = start; start < end; i++) {
		int ret = imr_jit_object(bprog, state, state->objects[i]);

		if (ret < 0) {
			fprintf(stderr, "failed to JIT object type %d\n",  state->objects[i]->type);
			return ret;
		}

		count++;

		if (state->objects[i]->type == IMR_OBJ_TYPE_VERDICT)
			break;
	}

	//malformed - no verdict
	if (i == end) {
		fprintf(stderr, "rule had no verdict, start %d end %d\n", start, end);
		exit(1);
	}

	imr_fixup_jumps(state, len_cur);*/

	count = 1;

	return count;
}

/*
	Generate the prologue for BPF program
	@param bprog - bpf program that has image to load the prologue into 
	@return Return code for generating prologue 
*/
static int imr_jit_prologue(struct bpf_prog *bprog)
{
	int ret = 0;

	//Switch the type 
	switch(bprog->type) 
	{
		//XDP layer 
		case BPF_PROG_TYPE_XDP:
			ret = xdp_imr_jit_prologue(bprog);
			break;
		//HERE: sk_buff imr_reload_skb_data
		//bprog->type is not supported 
		default:
			ret = -1;
			break;
	}
	
	return ret;
}

/*
	JIT a verdict to BPF 
	@param bprog - bpf program to add verdict to 
	@return Return code of EMITing 
*/
static int imr_jit_verdict(struct bpf_prog *bprog)
{
	EMIT(bprog, BPF_MOV32_IMM(BPF_REG_0, bprog->verdict));
	EMIT(bprog, BPF_EXIT_INSN());
	return 0;
}

/*
	Read in the bpf_config_file
	@return a json object of the bpf configuration file
*/
json_t *read_bpf_file(void) {
	//Variable initialization 
	json_t *bpf_settings;
	json_error_t jerr;

	//Load bpf file into a json object 
	bpf_settings = json_load_file(bpf_config_file, 0, &jerr);
	if (!bpf_settings) 
	{
		perror("json_load_file");
		return NULL;
	}

	return bpf_settings;
}

/*
	Read in bpf settings i.e. rules for bpfs
	@param bpf_settings - The bpf_settings 
	@return The imr_state that represents a structure of the rules 
			so json doesn't have to be reparsed
*/
struct imr_state *imr_ruleset_read(json_t *bpf_settings)
{
	//Variable definition 
	struct imr_state *state; 

	//If bpf_settings is not array, then configuration file is malformed 
	if (!json_is_array(bpf_settings))
	{
		perror("error: root is not an array");
		return NULL;
	}

	//Allocate the imr state 
	state = imr_state_alloc();
	if (!state)
		return NULL;

	//HERE: read in bpf settings into IMR

	//Print out function
	imr_state_print(stdout, state);

	return state;
}

/*
	Translate an imr_state into a bpf program
	@param s - imr_state to translate to bpf 
	@return Return code from all the translation 
*/
int imr_do_bpf(struct imr_state *s)
{
	//Variable init 
    struct bpf_prog bprog;
    int ret, i = 0;

	//Allocate and initialize the bprof program, return if failure  
    ret = bpfprog_init(&bprog);
    if (ret < 0) {
    	return ret;
	}

	//Create bpf proglogue for bpf program 
	ret = imr_jit_prologue(&bprog);
	if (ret < 0)
		return ret;

	//Don't use first four registers 
	/*s->regcount = 4;

	//JIT each object in imr_state 
	do {
		//Jit the object based on index 
		int bpf_insn = imr_jit_rule(&bprog, s, i);

		//If jit failed, return accordingly
		if (bpf_insn < 0) {
			ret = bpf_insn; 
			break;
		}

		//Needs to have at least 1 for bpf_insn
		if (bpf_insn == 0) 
		{
			perror("rule jit yields 0 insn - can't have that");
			exit(EXIT_FAILURE);
		}

		i += bpf_insn;
	} while (i < s->num_objects);

	//Error generating program
	if (ret != 0) {
		fprintf(stderr, "Error generating bpf program\n");
		return ret;
	}*/

	//Add a bpf verdict and fail if verdict failed
	ret = imr_jit_verdict(&bprog);
	if (ret < 0)
		return ret;

	//HERE select interface 
	bprog.ifindex = 1;

	//Commit the bpf program into a fd to be loaded 
	ret = bpfprog_commit(&bprog);

	//Free memory
    bpfprog_destroy(&bprog);

    return ret;
}
