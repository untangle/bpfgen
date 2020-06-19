#ifndef IMR_MANAGER_XDP_H
#define IMR_MANAGER_XDP_H
#include "../bpfload.h"
#include "../imr.h"
#include "../common.h"

int xdp_load_fd(int ifindex, int fd, __u32 flags);
int xdp_imr_jit_prologue(struct bpf_prog *bprog, struct imr_state *state);
int xdp_imr_jit_obj_verdict(int imr_verdict);

#endif