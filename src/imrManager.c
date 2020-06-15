#include "imrManager.h"
#include "bpfgen_configuration.h"

/*
	JIT an IMR rule to BPF 
	@param bprog - program to add rule to 
	@param state - imr_state to conver to bpf 
	@param i - index of objects to convert 
	@return Number of rules added 
*/
static int imr_jit_rule(struct bpf_prog *bprog, struct imr_state *state, int i)
{
	return 1;
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
	ret = bpfprog_prologue(&bprog);
	if (ret < 0)
		return ret;

	//Don't use first four registers 
	s->regcount = 4;

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
	}

	//Add a bpf verdict and fail if verdict failed
	ret = imr_jit_verdict(&bprog);
	if (ret < 0)
		return ret;

	//HERE select interface 
	bprog.ifindex = 5;

	//Commit the bpf program into a fd to be loaded 
	ret = bpfprog_commit(&bprog);

	//Free memory
    bpfprog_destroy(&bprog);

    return ret;
}