#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <linux/bpf.h>
typedef __u16 __bitwise __sum16; /* hack */
#include <linux/ip.h>

#include <arpa/inet.h>

#include "bpfload.h"
#include "bpf_insn.h"
#include "managers/imrManagerXdp.h"

extern FILE *logger;
char bpf_log_buf[BPFGEN_LOG_BUF_SIZE];
/*
	Placeholder for determining ifindex from name of interface 
	@param ifname - The name of the interface to convert to number
	@return Integer representing the ifindex
*/
unsigned int if_nametoindex(const char *ifname);

/*
	Convert a pointer to a __u64 type for working with the bpf syscall and objects 
	@param ptr - Pointer to convert a __u64
	@return The __u64(unsigned long) ptr 
*/
static inline __u64 bpf_ptr_to_u64(const void *ptr)
{
	return (__u64)(unsigned long)ptr;
}

/*
	Call the BPF syscall
	@param cmd - BPF command to run e.g. BPF_PROG_LOAD
	@param attr - bpf_attr object that holds information on the bpf program
	@param size - size of the attr object
	@return Return code from the bpf syscall
*/
static int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
#ifndef __NR_bpf
#define __NR_bpf 321 /* x86_64 */
#endif
        return syscall(__NR_bpf, cmd, attr, size);
}

/*
	Instantiate the bpf_attr that is passed to the BPF syscall
	@param prog - bpf_prog object that holds information on the BPF program from the IMR translation
	@return Return code from calling the bpf function that calls the BPF syscall
	@param TODO
*/
static int bpf_prog_load(const struct bpf_prog *prog)
{
	//Variable initialization 
	union bpf_attr attr = {};
	int ret;

	attr.prog_type  = prog->type;
	attr.insns      = (uint64_t)prog->img;
	attr.insn_cnt   = prog->len_cur;
	attr.license    = (uint64_t)("GPL");

	//Set up logging for BPF
	attr.log_buf   = (uint64_t) &bpf_log_buf;
	attr.log_size  = BPFGEN_LOG_BUF_SIZE;
	attr.log_level = 1;
	
	//Call the bpf function to call the bpf syscall 
	ret = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
	if (ret < 0) 
		fprintf(logger, "bpf errlog: %i - %i - %s - %s\n", ret, errno, strerror(errno), bpf_log_buf);

	return ret;
}

/*
	Function to load the BPF program file descriptor into the chosen layer
	@param bprog - bpf_prog structure which has the interface and fd variables 
	@return Return code of loading the fd type 
*/
static int bpf_load_fd(struct bpf_prog *bprog)
{
	//Variable init 
	int ret; 
	__u32 xdp_flags = 0; //Basic flags needed 
	
	//Switch the type 
	switch(bprog->type) 
	{
		//XDP layer 
		case BPF_PROG_TYPE_XDP:
			ret = xdp_load_fd(bprog->ifindex, bprog->fd, xdp_flags);
			break;
		//bprog->type is not supported 
		default:
			fprintf(logger, "bprog->type not yet supported\n");
			ret = -1;
			break;
	}

	return ret;
}

/*
	Load/generate the bpf file and load it into the proper layer 
	@param bprog - bpf_prog structure which holds the proper information for the bpf program 
	@return Return code for loading/generating the bpf file and loading it 
	@param TODO
*/
int bpfprog_commit(struct bpf_prog *bprog)
{
	//HERE: tc types and the nftables example type, likely earlier 
	//Variable init 
	int ret;

	//Load the bprog as is 
	ret = bpf_prog_load(bprog);

	//If offloaded, set to true 
	if (ret > 0)
		bprog->offloaded = true;

	//Bpf file loading returned a valid fd, so load the fd 
	if (ret > 0) {
		bprog->fd = ret;
		ret = bpf_load_fd(bprog);
	}

	return ret < 0 ? ret : 0;
}

/*
	Initialize the bpf_prog structure 
	@param bprog - The bpf_prog pointer to initialize i.e. the bprog image 
	@return Return code for success/failure of initialization
*/
int bpfprog_init(struct bpf_prog *bprog)
{
	//Load the bprog BPF image 
	memset(bprog, 0, sizeof(*bprog));
	bprog->img = calloc(BPF_MAXINSNS, sizeof(struct bpf_insn));
	if (!bprog->img)
		return -ENOMEM;

	//Default values 
	bprog->fd = -1;
	bprog->regcount = 2;
	bprog->debug = false;

	//Default is XDP
	bprog->type = BPF_PROG_TYPE_XDP;

	return 0;
}

/*
	Free the bpf_prog 
	@param bprog - pointer to bpf_prog to free 
*/
void bpfprog_destroy(struct bpf_prog *bprog)
{
	free(bprog->img);
	close(bprog->fd);
}

//REGISTER OPERATIONS
/*
	Registers needed 
	@param len - length of imr_register space needed 
	@return Number of registers needed 
*/
unsigned int bpf_regs_needed(unsigned int len)
{
	return div_round_up(len, sizeof(uint64_t));
}

/*
	Get the register number to use 
	@param bprog - bpf_prog for doing register operations 
	@param len - length of imr_register space needed 
	@return Register number to use 
*/
int bpf_register_get(const struct bpf_prog *bprog, uint32_t len)
{
	//Get registers needed 
	unsigned int regs_needed = bpf_regs_needed(len);

	//determine if not enough registers are in use 
	if (bprog->regcount < regs_needed) {
		fprintf(logger, "not enough registers in use\n");
		exit(EXIT_FAILURE);
	}

	//Return register number
	return bprog->regcount - regs_needed;
}

/*
	Determine length of bpf register to use 
	@param len - length of item to determine 
	@return Type of BPF size register needed
*/
int bpf_reg_width(unsigned int len)
{
	switch (len) {
	case sizeof(uint8_t): return BPF_B;
	case sizeof(uint16_t): return BPF_H;
	case sizeof(uint32_t): return BPF_W;
	case sizeof(uint64_t): return BPF_DW;
	default:
		fprintf(logger, "reg size not supported");
		exit(EXIT_FAILURE);
	}

	return -EINVAL;
}

/*
	allocate registers to keep accurate count 
	@param s - imr_state to use for register operations 
	@param len - length of imr_registers needed 
	@return register count 
*/
int bpf_register_alloc(struct bpf_prog *bprog, uint32_t len)
{
	//Determine registers needed
	unsigned int regs_needed = bpf_regs_needed(len);

	//Initialize reg to the current regcount
	uint8_t reg = bprog->regcount;

	//Determine if out of bpf registers 
	if (bprog->regcount + regs_needed >= IMR_REG_COUNT) {
		fprintf(logger, "out of BPF registers");
		return -1;
	}

	//Add to regcout the allocated registers 
	bprog->regcount += regs_needed;

	//Return new regcount
	return reg;
}

/*
	Release registers 
	@s - imr_state for register operations 
	@len - length of imr_registers to release 
*/
void bpf_register_release(struct bpf_prog *bprog, uint32_t len)
{
	//Registers needed 
	unsigned int regs_needed = bpf_regs_needed(len);

	//Releasing too many 
	if (bprog->regcount < regs_needed) {
		fprintf(logger, "regcount underflow");
		exit(EXIT_FAILURE);
	}

	//Decrease state's reg count
	bprog->regcount -= regs_needed;
}
