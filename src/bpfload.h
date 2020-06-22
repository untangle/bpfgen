#ifndef BPFLOAD_H
#define BPFLOAD_H
#include <stdbool.h>
#include <stddef.h>

#include <linux/bpf.h>

#include "common.h"

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
int bpfprog_commit(struct bpf_prog *bprog);
void bpfprog_destroy(struct bpf_prog *bprog);

#endif