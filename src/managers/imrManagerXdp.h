#ifndef IMR_MANAGER_XDP_H
#define IMR_MANAGER_XDP_H
#include "../bpfload.h"

int xdp_load_fd(int ifindex, int fd, __u32 flags);
int xdp_imr_jit_prologue(struct bpf_prog *bprog);

#endif