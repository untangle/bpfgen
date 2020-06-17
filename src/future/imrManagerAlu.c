#include "imrManagerAlu.h"
#include "../bpf_insn.h"
#include "common.h"

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

	ret = imr_jit_object(state, right);
	if (ret == 0) {
		EMIT(bprog, BPF_MOV32_IMM(BPF_REG_0, -2)); /* NFT_BREAK */
		EMIT(bprog, BPF_JMP_REG(op, regl, regr, 0));
	}

	imr_register_release(state, right->len);
	return ret;
}

static int imr_jit_obj_alu_jmp(struct imr_state *state,
			       const struct imr_object *o,
			       int regl)

{
	int ret;

	/* multiple tests on same source? */
	if (o->alu.left->type == IMR_OBJ_TYPE_ALU) {
		ret = imr_jit_obj_alu_jmp(state, o->alu.left, regl);
		if (ret < 0)
			return ret;
	} else {
		ret = imr_jit_object(state, o->alu.left);
		if (ret < 0)
			return ret;
	}

	ret = __imr_jit_obj_alu_jmp(state, o, regl);

	return ret;
}

static int imr_jit_alu_bigcmp(struct imr_state *state, const struct imr_object *o)
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

		ret = __imr_jit_memcmp_sub64(state, tmp, regl);
		imr_object_free(tmp);
		if (ret < 0) {
			imr_register_release(state, sizeof(uint64_t));
			imr_object_free(copy);
			return ret;
		}
		/* XXX: 64bit */
		EMIT(state, BPF_JMP_IMM(BPF_JNE, regl, 0, 0));
	} while (copy->len >= sizeof(uint64_t));

	if (copy->len && copy->len != sizeof(uint64_t)) {
		ret = __imr_jit_memcmp_sub32(state, copy, regl);

		if (ret < 0) {
			imr_object_free(copy);
			imr_register_release(state, sizeof(uint64_t));
			return ret;
		}
	}

	imr_object_free(copy);
	imr_fixup_jumps(state, start_insn);

	switch (o->alu.op) {
	case IMR_ALU_OP_AND:
	case IMR_ALU_OP_LSHIFT:
		fprintf(stderr, "not a jump");
		EXIT(EXIT_FAILURE);
	case IMR_ALU_OP_EQ:
	case IMR_ALU_OP_NE:
	case IMR_ALU_OP_LT:
	case IMR_ALU_OP_LTE:
	case IMR_ALU_OP_GT:
	case IMR_ALU_OP_GTE:
		EMIT(state, BPF_JMP_IMM(alu_jmp_get_negated_bpf_opcode(o->alu.op), regl, 0, 0));
		break;
        }

	imr_register_release(state, sizeof(uint64_t));
	return 0;
}

int imr_jit_obj_alu(struct bpf_prog *bprog, struct imr_state *state, const struct imr_object *o)
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
			return imr_jit_alu_bigcmp(state, o);

		regl = imr_register_alloc(state, o->len);
		if (regl < 0)
			return -ENOSPC;

		ret = imr_jit_obj_alu_jmp(state, o, regl);
		imr_register_release(state, o->len);
		return ret;
	}

	ret = imr_jit_object(state, o->alu.left);
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
			EMIT(state, BPF_ALU32_IMM(op, regl, right->imm.value32));
			return 0;
		}
	}

	internal_error("alu bitops only handle 32bit immediate RHS");
	return -EINVAL;

    return 0;
}