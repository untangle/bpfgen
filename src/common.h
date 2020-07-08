#ifndef COMMON_H
#define COMMON_H
#include <stdio.h>

//EMIT function declared
#define div_round_up(n, d)      (((n) + (d) - 1) / (d))
#define ARRAY_SIZE_BPF(x) (sizeof(x) / sizeof(*(x)))
#define EMIT(ctx, x)							\
	do {								\
		struct bpf_insn __tmp[] = { x };			\
		if ((ctx)->len_cur + ARRAY_SIZE_BPF(__tmp) > BPF_MAXINSNS)	\
			return -ENOMEM;					\
		memcpy((ctx)->img + (ctx)->len_cur, &__tmp, sizeof(__tmp));		\
		(ctx)->len_cur += ARRAY_SIZE_BPF(__tmp);			\
	} while (0)

#endif