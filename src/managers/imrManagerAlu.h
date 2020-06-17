#ifndef IMR_MANAGER_ALU_H
#define IMR_MANAGER_ALU_H
#include "../bpfload.h"
#include "../imr.h"

int imr_jit_obj_alu(struct bpf_prog *bprog, struct imr_state *state, const struct imr_object *o);

#endif