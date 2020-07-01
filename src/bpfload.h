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
	__u32			   verdict;   // Final verdict of bpf program
	int			       fd;        // File descriptor to bpf file to load 
	int			       ifindex;   // Interface to load the program to 
	bool			   offloaded; // If hardware offload occurred 
	enum bpf_prog_type type;	  // Hook type i.e. XDP
	bool				debug;	  // If bpf_prog will include logging information

	//Register tracking
	uint8_t		            regcount;        //Register count 
};

//Function declaration
int bpfprog_init(struct bpf_prog *bprog);
int bpfprog_commit(struct bpf_prog *bprog);
void bpfprog_destroy(struct bpf_prog *bprog);

//Register operations
unsigned int bpf_regs_needed(unsigned int len);
int bpf_register_get(const struct bpf_prog *bprog, uint32_t len);
int bpf_reg_width(unsigned int len);
int bpf_register_alloc(struct bpf_prog *bprog, uint32_t len);
void bpf_register_release(struct bpf_prog *bprog, uint32_t len);

#endif