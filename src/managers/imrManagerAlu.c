#include "imrManagerAlu.h"
#include "../bpf_insn.h"

int imr_jit_obj_alu(struct bpf_prog *bprog, struct imr_state *state, const struct imr_object *o)
{
	/*const struct imr_object *right;
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
	return -EINVAL;*/

    return 0;
}