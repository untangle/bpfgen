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

static int imr_jit_obj_verdict(struct bpf_prog *bprog,
			                   const struct imr_object *o)
{
	int imr_verdict = o->verdict.verdict;
	int verdict = -1;

	switch (bprog->type) {
	case BPF_PROG_TYPE_XDP: 
		verdict = xdp_imr_jit_obj_verdict(imr_verdict);
		break;
	default:
		fprintf(stderr, "Unsupported type for IMR_VERDICT");
		exit(EXIT_FAILURE);
	}

	return imr_jit_verdict(bprog, verdict);
}

static int imr_jit_obj_immediate(struct bpf_prog *bprog,
								 struct imr_state *s,
				                 const struct imr_object *o)
{
	int bpf_reg = imr_register_get(s, o->len);

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

static int imr_jit_obj_payload(struct bpf_prog *bprog,
			       const struct imr_state *state,
			       const struct imr_object *o)
{
	int ret = 0;
	switch(o->payload.base) {
		case IMR_DEST_PORT:
			EMIT(bprog, BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_2, 
				sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, dest)));
			break;
		case IMR_SRC_PORT:
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

static void imr_fixup_jumps(struct bpf_prog *bprog, unsigned int poc_start)
{
	unsigned int pc, pc_end, i;

	if (poc_start >= bprog->len_cur)
	{
		fprintf(stderr, "old poc >= current one");
		exit(EXIT_FAILURE);
	}

	pc = 0;
	pc_end = bprog->len_cur - poc_start;

	for (i = poc_start; pc < pc_end; pc++, i++) {
		if (BPF_CLASS(bprog->img[i].code) == BPF_JMP) {
			if (bprog->img[i].code == (BPF_EXIT | BPF_JMP))
				continue;
			if (bprog->img[i].code == (BPF_CALL | BPF_JMP))
				continue;

			if (bprog->img[i].off)
				continue;
			bprog->img[i].off = pc_end - pc - 1;
		}
	}
}

//ALU OPERATIONS
/* map op to negated bpf opcode.
 * This is because if we want to check 'eq', we need
 * to jump to end of rule ('break') on inequality, i.e.
 * 'branch if NOT equal'.
 */
static int imr_jit_obj_alu(struct bpf_prog *bprog,
				  struct imr_state *state,
				  const struct imr_object *o)
{
	const struct imr_object *right;
	enum imr_reg_num regl, regr;
	int ret, op, bpf_reg;

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

	ret = imr_jit_object(bprog, state, o->alu.left);
	if (ret < 0) 
		return ret;

	regl = imr_register_get(state, o->len);
	if (regl < 0) 
		return -EINVAL;

	right = o->alu.right;

	/* avoid 2nd register if possible for immediate values*/
	if (right->type == IMR_OBJ_TYPE_IMMEDIATE) {
		switch (right->len) {
		case sizeof(uint32_t):
			EMIT(bprog, BPF_JMP_IMM(op, regl, right->imm.value32, 0));
			return 0;
		}
	}

	return 0;
}

static int imr_jit_rule_begin(struct bpf_prog *bprog, struct imr_state *state) {
	int ret = 0;
	//Network Layer
	switch(state->network_layer){
		case NETWORK_IP4:
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
		case TRANSPORT_TCP:
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
	unsigned int start, end, count, len_cur, ret;

	end = state->num_objects;
	if (i >= end) {
		fprintf(stderr, "Incomplete IMR Rule");
		return -EINVAL;
	}

	len_cur = bprog->len_cur;

	ret = imr_jit_rule_begin(bprog, state);
	if (ret != 0) {
		fprintf(stderr, "Failed to JIT rule begin");
		return ret;

	}

	start = i;
	count = 0;

	for (i = start; start < end; i++) {
		ret = imr_jit_object(bprog, state, state->objects[i]);

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
		exit(EXIT_FAILURE);
	}

	imr_fixup_jumps(bprog, len_cur);

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

int imr_jit_object(struct bpf_prog *bprog,
			  struct imr_state *s,
			  const struct imr_object *o)
{
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