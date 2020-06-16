#ifndef BPFLOAD_H
#define BPFLOAD_H
#include <stdbool.h>
#include <stddef.h>

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

//bpf_prog that holds information on a bpf program being created and loaded 
struct bpf_prog {
	struct bpf_insn	   *img;      // Bpf program image 
	__u32			   len_cur;   // Length of bpf image 
	__u32			   verdict;   // Verdict of bpf prog i.e. pass/forward 
	int			       fd;        // File descriptor to bpf file to load 
	int			       ifindex;   // Interface to load the program to 
	bool			   offloaded; // If hardware offload occurred 
	enum bpf_prog_type type;
};

//Function declaration
int bpfprog_init(struct bpf_prog *bprog);
int bpfprog_prologue(struct bpf_prog *bprog);
int bpfprog_commit(struct bpf_prog *bprog);
void bpfprog_destroy(struct bpf_prog *bprog);

#endif