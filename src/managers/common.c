#include "common.h"
#include "../bpfload.h"

unsigned int imr_regs_needed(unsigned int len)
{
	return div_round_up(len, sizeof(uint64_t));
}

int imr_register_get(const struct imr_state *s, uint32_t len)
{
	unsigned int regs_needed = imr_regs_needed(len);

	if (s->regcount < regs_needed) {
		fprintf(stderr, "not enough registers in use");
		exit(EXIT_FAILURE);
	}

	return s->regcount - regs_needed;
}

int bpf_reg_width(unsigned int len)
{
	switch (len) {
	case sizeof(uint8_t): return BPF_B;
	case sizeof(uint16_t): return BPF_H;
	case sizeof(uint32_t): return BPF_W;
	case sizeof(uint64_t): return BPF_DW;
	default:
		fprintf(stderr, "reg size not supported");
		exit(EXIT_FAILURE);
	}

	return -EINVAL;
}