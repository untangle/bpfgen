#ifndef COMMON_H
#define COMMON_H
#include <stdint.h>
#include "../imr.h"

unsigned int imr_regs_needed(unsigned int len);
int imr_register_get(const struct imr_state *s, uint32_t len);
int bpf_reg_width(unsigned int len);

#endif 