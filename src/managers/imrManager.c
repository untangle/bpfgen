#include "imrManager.h"
#include "../bpfgen_configuration.h"
#include "../bpf_insn.h"
#include "../test/bpfgen_bootstrap.h"

#include <linux/filter.h>

#include <linux/if_ether.h>
typedef __u16 __bitwise __sum16; /* hack */
#include <linux/ip.h>
#include <arpa/inet.h>
#include <linux/tcp.h>

/*
	JIT a verdict to BPF 
	@param bprog - bpf program to add verdict to 
	@return Return code of EMITing 
*/
static int imr_jit_verdict(struct bpf_prog *bprog, int verdict)
{
	EMIT(bprog, BPF_MOV32_IMM(BPF_REG_0, verdict));
	EMIT(bprog, BPF_EXIT_INSN());
	return 0;
}

/*
	JIT an IMR object of type verdict to BPF
	@param bprog - bpf program to add to
	@param o - imr_object to JIT
	@return Return code of JITing the object 
*/
static int imr_jit_obj_verdict(struct bpf_prog *bprog,
			                   const struct imr_object *o)
{
	//Get the verdict from the object 
	int imr_verdict = o->verdict.verdict;
	int verdict = -1;

	//Switch the hook type and get what the BPF verdict will be
	//based on the type 
	switch (bprog->type) {
	case BPF_PROG_TYPE_XDP: 
		verdict = xdp_imr_jit_obj_verdict(imr_verdict);
		break;
	default:
		fprintf(stderr, "Unsupported type for IMR_VERDICT");
		exit(EXIT_FAILURE);
	}

	//JIT the verdict 
	return imr_jit_verdict(bprog, verdict);
}

/*
	JIT an imr object of type immediate to BPF
	@param bprog - bpf_prog to add the jitted object to
	@param s - imr_state in order to determine registers needed 
	@param o - imr object to jit 
	@return Return of code of jitting object
*/
static int imr_jit_obj_immediate(struct bpf_prog *bprog,
								 struct imr_state *s,
				                 const struct imr_object *o)
{
	//Get a register to use 
	int bpf_reg = imr_register_get(s, o->len);

	//Switch on if 32 or 64 bit immediate, then JIT
	switch (o->len) {
	case sizeof(uint32_t):
		EMIT(bprog, BPF_MOV32_IMM(bpf_reg, o->imm.value32));
		return 0;
	case sizeof(uint64_t):
		EMIT(bprog, BPF_LD_IMM64(bpf_reg, o->imm.value64));
		return 0;
	default:
		break;
	}

	fprintf(stderr, "unhandled immediate size");
	return -EINVAL;
}

/*
	JIT and imr_object of type payload
	@param bprog - bpf_prog to add jitted object to 
	@param state - imr_state used to determine registers 
	@param o - imr object to jit
	@return Return code of jitting payload
*/
static int imr_jit_obj_payload(struct bpf_prog *bprog,
			       const struct imr_state *state,
			       const struct imr_object *o)
{
	int ret = 0;

	//Switch on payload type and jit accordingly
	switch(o->payload.base) {
		case IMR_DEST_PORT: //Destination port
			EMIT(bprog, BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_2, 
				sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, dest)));
			break;
		case IMR_SRC_PORT: //Source port
			EMIT(bprog, BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_2,
				sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, source)));
			break;
		default:
			fprintf(stderr, "Payload type not recognized\n");
			ret = -1;
			break;
	}
	return ret;
}

//ALU OPERATIONS
/*
	JIT and imr_object of type alu
	@param bprog - bpf_prog to add jitted object to 
	@param state - imr_state used to determine registers 
	@param o - imr object to jit
	@return Return code of jitting alu
*/
static int imr_jit_obj_alu(struct bpf_prog *bprog,
				  struct imr_state *state,
				  const struct imr_object *o)
{
	//Variable declaration
	const struct imr_object *right;
	enum imr_reg_num regl, regr;
	int ret, op, bpf_reg;

	//For jump reasons, will do the negative bpf opcode 
	switch (o->alu.op) {
	case IMR_ALU_OP_EQ:
		op = BPF_JNE;
		break;
	case IMR_ALU_OP_NE:
		op = BPF_JEQ;
		break;
	default:
		return -EINVAL;
	}

	//Jit the left side 
	ret = imr_jit_object(bprog, state, o->alu.left);
	if (ret < 0) 
		return ret;

	//Get the regsiter for the left side 
	regl = imr_register_get(state, o->len);
	if (regl < 0) 
		return -EINVAL;

	//Get the right object 
	right = o->alu.right;

	// avoid jitting and using a 2nd register if possible for immediate values
	//Create a branch for immediate values
	if (right->type == IMR_OBJ_TYPE_IMMEDIATE) {
		//Only support 32-bit sizes for now 
		switch (right->len) {
		case sizeof(uint32_t):
			EMIT(bprog, BPF_JMP_IMM(op, regl, right->imm.value32, 0));
			return 0;
		}
	}

	//Return -1 as operation is not supported 
	return -1;
}

/*
	JIT the beginning of an imr rule i.e. network/transport layer checks
	@param bprog - bpf_prog to add jitted items to 
	@param state - imr_state to use for determing layer for now 
*/
static int imr_jit_rule_begin(struct bpf_prog *bprog, struct imr_state *state) {
	int ret = 0;
	//Network Layer
	switch(state->network_layer){
		case NETWORK_IP4: //Ipv4
			//Ensure it's an ipv4 packet
			EMIT(bprog, BPF_MOV64_REG(BPF_REG_1, BPF_REG_2));
			EMIT(bprog, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 
				sizeof(struct ethhdr) + sizeof(struct iphdr)));
			EMIT(bprog, BPF_JMP_REG(BPF_JLE, BPF_REG_1, BPF_REG_3, 2));
			break;
		default:
			fprintf(stderr, "Unsupported network layer");
			ret = -1;
			break;
	}

	//Exit if not right network layer
	ret = imr_jit_verdict(bprog, bprog->verdict);
	if (ret != 0) {
		fprintf(stderr, "Failure to JIT network layer verdict");
		return ret;
	}

	//Transport layer 
	switch(state->transport_layer) {
		case TRANSPORT_TCP: //TCP
			//Ensure it's a tcp packet and pass if not
			EMIT(bprog, BPF_MOV64_REG(BPF_REG_1, BPF_REG_2));
			EMIT(bprog, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 
				sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)));
			EMIT(bprog, BPF_JMP_REG(BPF_JLE, BPF_REG_1, BPF_REG_3, 2));
			//Exit if not right transport layer
			ret = imr_jit_verdict(bprog, bprog->verdict);
			if (ret != 0) {
				fprintf(stderr, "Failure to JIT transport layer verdict");
				return ret;
			}
			EMIT(bprog, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_2, sizeof(struct ethhdr) + offsetof(struct iphdr, protocol)));
			EMIT(bprog, BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 255));
			EMIT(bprog, BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, IPPROTO_TCP, 2));
			ret = imr_jit_verdict(bprog, bprog->verdict);
			if (ret != 0) {
				fprintf(stderr, "Failure to JIT transport layer verdict");
				return ret;
			}
			break;
		default:
			fprintf(stderr, "Unsupported transport layer");
			ret = -1;
			break;
	}

	//Return return code of jitting verdict
	return ret;
}

/*
	JIT an IMR rule to BPF 
	@param bprog - program to add rule to 
	@param state - imr_state to conver to bpf 
	@param i - index of objects to convert 
	@return Number of rules added 
*/
static int imr_jit_rule(struct bpf_prog *bprog, struct imr_state *state, int i)
{
	//Variable initialization 
	unsigned int start, end, count, len_cur, ret;

	//Get number of objects 
	end = state->num_objects;

	//Incomplete IMR rule check 
	if (i >= end) {
		fprintf(stderr, "Incomplete IMR Rule");
		return -EINVAL;
	}

	//Current length of the bprog
	len_cur = bprog->len_cur;

	//Beginning of imr_rule
	ret = imr_jit_rule_begin(bprog, state);
	if (ret != 0) {
		fprintf(stderr, "Failed to JIT rule begin");
		return ret;

	}

	//Start at the objects that are part of the rule 
	start = i;
	count = 0;

	//Loop through objects and jit each object in the rule 
	for (i = start; start < end; i++) {
		//Jit object 
		ret = imr_jit_object(bprog, state, state->objects[i]);

		//Jitting failed
		if (ret < 0) {
			fprintf(stderr, "failed to JIT object type %d\n",  state->objects[i]->type);
			return ret;
		}

		//Increase object count 
		count++;

		//Once hit a verdict, rule is done 
		if (state->objects[i]->type == IMR_OBJ_TYPE_VERDICT)
			break;
	}

	//malformed - no verdict
	if (i == end) {
		fprintf(stderr, "rule had no verdict, start %d end %d\n", start, end);
		exit(EXIT_FAILURE);
	}

	//Return number of objects jitted 
	return count;
}

/*
	Generate the prologue for BPF program
	@param bprog - bpf program that has image to load the prologue into 
	@return Return code for generating prologue 
*/
static int imr_jit_prologue(struct bpf_prog *bprog, struct imr_state *state)
{
	int ret = 0;

	//Switch the hook
	switch(bprog->type) 
	{
		//XDP layer 
		case BPF_PROG_TYPE_XDP:
			ret = xdp_imr_jit_prologue(bprog, state);
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
	JIT an imr_object
	@param bprog - bpf_prog to add to 
	@param s - imr_state used for register determination 
	@param o - imr_object to jit 
*/
int imr_jit_object(struct bpf_prog *bprog,
			  struct imr_state *s,
			  const struct imr_object *o)
{
	//Switch on imr_object type and call the appropriate function
	switch (o->type) {
	case IMR_OBJ_TYPE_VERDICT:
		return imr_jit_obj_verdict(bprog, o);
	case IMR_OBJ_TYPE_PAYLOAD:
		return imr_jit_obj_payload(bprog, s, o);
	case IMR_OBJ_TYPE_IMMEDIATE:
		return imr_jit_obj_immediate(bprog, s, o);
	case IMR_OBJ_TYPE_ALU:
		return imr_jit_obj_alu(bprog, s, o);
	}

	return -EINVAL;
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
	@param run_bootstrap - if bootstrap tests are being run
	@param test_to_run - which bootstrap test to run 
	@return The imr_state that represents a structure of the rules 
			so json doesn't have to be reparsed
*/
struct imr_state *imr_ruleset_read(json_t *bpf_settings, int run_bootstrap, int test_to_run)
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

	//If running the bootstrap, fill_imr state with the test_to_run
	if (run_bootstrap) {
		int ret = fill_imr(state, test_to_run);
		if (ret != 0)
			return NULL;
	}

	//Print out function
	if (!run_bootstrap)
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
	ret = imr_jit_prologue(&bprog, s);
	if (ret < 0)
		return ret;

	if (s->num_objects > 0)
	{
		//Don't use first four registers 
		s->regcount = 2;

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
	}

	//Add a bpf verdict and fail if verdict failed
	ret = imr_jit_verdict(&bprog, bprog.verdict);
	if (ret < 0)
		return ret;

	//HERE select interface 
	bprog.ifindex = 2;

	//Commit the bpf program into a fd to be loaded 
	ret = bpfprog_commit(&bprog);

	//Free memory
    bpfprog_destroy(&bprog);

    return ret;
}