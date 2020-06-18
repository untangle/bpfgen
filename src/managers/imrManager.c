#include "imrManager.h"
#include "../bpfgen_configuration.h"
#include "../bpf_insn.h"

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

	switch (bprog->type) {
		case BPF_PROG_TYPE_XDP:
			ret = xdp_imr_jit_obj_payload(bprog, state, o);
			break;
		default:
			fprintf(stderr, "Unsupported type for payload");
			exit(EXIT_FAILURE);
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
static int alu_jmp_get_negated_bpf_opcode(enum imr_alu_op op)
{
	switch (op) {
	case IMR_ALU_OP_EQ:
		return BPF_JNE;
	case IMR_ALU_OP_NE:
		return BPF_JEQ;
	case IMR_ALU_OP_LT:
		return BPF_JGE;
	case IMR_ALU_OP_LTE:
		return BPF_JGT;
	case IMR_ALU_OP_GT:
		return BPF_JLE;
	case IMR_ALU_OP_GTE:
		return BPF_JLT;
	case IMR_ALU_OP_LSHIFT:
	case IMR_ALU_OP_AND:
		break;
        }

	fprintf(stderr, "invalid imr alu op");
	return -EINVAL;
}

static int __imr_jit_obj_alu_jmp(struct bpf_prog *bprog,
	            struct imr_state *state,
			    const struct imr_object *o,
				int regl)
{
	const struct imr_object *right;
	enum imr_reg_num regr;
	int op, ret;

	right = o->alu.right;

	op = alu_jmp_get_negated_bpf_opcode(o->alu.op);

	/* avoid 2nd register if possible */
	if (right->type == IMR_OBJ_TYPE_IMMEDIATE) {
		switch (right->len) {
		case sizeof(uint32_t):
			EMIT(bprog, BPF_JMP_IMM(op, regl, right->imm.value32, 0));
			return 0;
		}
	}

	regr = imr_register_alloc(state, right->len);
	if (regr < 0)
		return -ENOSPC;

	ret = imr_jit_object(bprog, state, right);
	if (ret == 0) {
		EMIT(bprog, BPF_MOV32_IMM(BPF_REG_0, -2)); /* NFT_BREAK */
		EMIT(bprog, BPF_JMP_REG(op, regl, regr, 0));
	}

	imr_register_release(state, right->len);
	return ret;
}

static int imr_jit_obj_alu_jmp(struct bpf_prog *bprog,
	               struct imr_state *state,
			       const struct imr_object *o,
			       int regl)

{
	int ret;

	/* multiple tests on same source? */
	if (o->alu.left->type == IMR_OBJ_TYPE_ALU) {
		ret = imr_jit_obj_alu_jmp(bprog, state, o->alu.left, regl);
		if (ret < 0)
			return ret;
	} else {
		ret = imr_jit_object(bprog, state, o->alu.left);
		if (ret < 0)
			return ret;
	}

	ret = __imr_jit_obj_alu_jmp(bprog, state, o, regl);

	return ret;
}

static int imr_jit_memcmp_sub64(struct bpf_prog *bprog,
	              struct imr_state *state,
				  struct imr_object *sub,
				  int regl)
{
	int ret = imr_jit_object(bprog, state, sub->alu.left);
	int regr = imr_register_alloc(state, sizeof(uint64_t));

	if (ret < 0)
		return ret;

	ret = imr_jit_object(bprog, state, sub->alu.right);

	EMIT(bprog, BPF_ALU64_REG(BPF_SUB, regl, regr));

	imr_register_release(state, sizeof(uint64_t));
	return 0;
}

static int imr_jit_memcmp_sub32(struct bpf_prog *bprog,
	              struct imr_state *state,
				  struct imr_object *sub,
				  int regl)
{
	const struct imr_object *right = sub->alu.right;
	int regr, ret = imr_jit_object(bprog, state, sub->alu.left);

	if (right->type == IMR_OBJ_TYPE_IMMEDIATE && right->len) {
		EMIT(bprog, BPF_ALU32_IMM(BPF_SUB, regl, right->imm.value32));
		return 0;
	}

	regr = imr_register_alloc(state, sizeof(uint32_t));
	if (ret < 0)
		return ret;

	ret = imr_jit_object(bprog, state, right);
	if (ret < 0) {
		imr_register_release(state, sizeof(uint32_t));
		return ret;
	}

	EMIT(bprog, BPF_ALU32_REG(BPF_SUB, regl, regr));
	return 0;
}

static int imr_jit_alu_bigcmp(struct bpf_prog *bprog, struct imr_state *state, const struct imr_object *o)
{
	struct imr_object *copy = imr_object_copy(o);
	unsigned int start_insn = state->len_cur;
	int regl, ret;

	if (!copy)
		return -ENOMEM;

	regl = imr_register_alloc(state, sizeof(uint64_t));
	do {
		struct imr_object *tmp;

		tmp = imr_object_split64(copy);
		if (!tmp) {
			imr_register_release(state, sizeof(uint64_t));
			imr_object_free(copy);
			return -ENOMEM;
		}

		ret = imr_jit_memcmp_sub64(bprog, state, tmp, regl);
		imr_object_free(tmp);
		if (ret < 0) {
			imr_register_release(state, sizeof(uint64_t));
			imr_object_free(copy);
			return ret;
		}
		// XXX: 64bit 
		EMIT(bprog, BPF_JMP_IMM(BPF_JNE, regl, 0, 0));
	} while (copy->len >= sizeof(uint64_t));

	if (copy->len && copy->len != sizeof(uint64_t)) {
		ret = imr_jit_memcmp_sub32(bprog, state, copy, regl);

		if (ret < 0) {
			imr_object_free(copy);
			imr_register_release(state, sizeof(uint64_t));
			return ret;
		}
	}

	imr_object_free(copy);
	imr_fixup_jumps(bprog, start_insn);

	switch (o->alu.op) {
	case IMR_ALU_OP_AND:
	case IMR_ALU_OP_LSHIFT:
		fprintf(stderr, "not a jump");
		exit(EXIT_FAILURE);
	case IMR_ALU_OP_EQ:
	case IMR_ALU_OP_NE:
	case IMR_ALU_OP_LT:
	case IMR_ALU_OP_LTE:
	case IMR_ALU_OP_GT:
	case IMR_ALU_OP_GTE:
		EMIT(bprog, BPF_JMP_IMM(alu_jmp_get_negated_bpf_opcode(o->alu.op), regl, 0, 0));
		break;
        }

	imr_register_release(state, sizeof(uint64_t));
	return 0;
}

static int imr_jit_obj_alu(struct bpf_prog *bprog, struct imr_state *state, const struct imr_object *o)
{
	const struct imr_object *right;
	enum imr_reg_num regl;
	int ret, op;

	switch (o->alu.op) {
	case IMR_ALU_OP_AND:
		op = BPF_AND;
		break;
	case IMR_ALU_OP_LSHIFT:
		op = BPF_LSH;
		break;
	case IMR_ALU_OP_EQ:
	case IMR_ALU_OP_NE:
	case IMR_ALU_OP_LT:
	case IMR_ALU_OP_LTE:
	case IMR_ALU_OP_GT:
	case IMR_ALU_OP_GTE:
		if (o->len > sizeof(uint64_t))
			return imr_jit_alu_bigcmp(bprog, state, o);

		regl = imr_register_alloc(state, o->len);
		if (regl < 0)
			return -ENOSPC;

		ret = imr_jit_obj_alu_jmp(bprog, state, o, regl);
		imr_register_release(state, o->len);
		return ret;
	}

	ret = imr_jit_object(bprog, state, o->alu.left);
	if (ret)
		return ret;

	regl = imr_register_get(state, o->len);
	if (regl < 0)
		return -EINVAL;

	right = o->alu.right;

	// avoid 2nd register if possible 
	if (right->type == IMR_OBJ_TYPE_IMMEDIATE) {
		switch (right->len) {
		case sizeof(uint32_t):
			EMIT(bprog, BPF_ALU32_IMM(op, regl, right->imm.value32));
			return 0;
		}
	}

	fprintf(stderr, "alu bitops only handle 32bit immediate RHS");
	return -EINVAL;
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
	unsigned int start, end, count, len_cur;

	end = state->num_objects;
	if (i >= end) {
		fprintf(stderr, "Incomplete IMR Rule");
		return -EINVAL;
	}

	len_cur = bprog->len_cur;

	/*if (bprog->type == BPF_PROG_TYPE_XDP)
	{
		EMIT(bprog, BPF_MOV64_REG(BPF_REG_1, BPF_REG_2));
		EMIT(bprog, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1,
			   sizeof(struct ethhdr) + sizeof(struct iphdr)));
		EMIT(bprog, BPF_JMP_REG(BPF_JGT, BPF_REG_1, BPF_REG_3, 0));
		EMIT(bprog, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -(int)sizeof(struct iphdr)));
	}*/

	start = i;
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

	//imr_fixup_jumps(state, len_cur);

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
	//HERE: META and others
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

	if (s->num_objects > 0)
	{
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
	}

	//Add a bpf verdict and fail if verdict failed
	ret = imr_jit_verdict(&bprog, bprog.verdict);
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