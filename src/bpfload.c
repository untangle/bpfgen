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
*/
static int bpf_prog_load(const struct bpf_prog *prog)
{
	//Variable initialization 
	union bpf_attr attr = {};
	char *log;
	int ret;

	attr.prog_type  = prog->type;
	attr.insns      = (uint64_t)prog->img;
	attr.insn_cnt   = prog->len_cur;
	attr.license    = (uint64_t)("GPL");

	//Set up logging for BPF 
	log = malloc(8192);
	attr.log_buf    = (uint64_t)log;
	attr.log_size   = 8192;
	attr.log_level  = 1;

	//Call the bpf function to call the bpf syscall 
	ret = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
	if (ret < 0)
		fprintf(/*log_file*/stderr, "bpf errlog: %i - %i - %s - %s\n", ret, errno, strerror(errno), log);

	//Free memory 
	free(log);

	return ret;
}

/*
	NOTE: function taken from linux BPF sample's directory 
	Load the BPF file descriptor into the XDP layer of the given interface 
	@param ifindex - interface to load onto 
	@param fd - file descriptor of where bpf program is 
	@param flags - any XDP flags to be passed
	@return Return code of loading into the XDP layer 
*/
static int bpf_set_link_xdp_fd(int ifindex, int fd, __u32 flags)
{
	struct sockaddr_nl sa;
	int sock, seq = 0, len, ret = -1;
	char buf[4096];
	struct nlattr *nla, *nla_xdp;
	struct {
		struct nlmsghdr  nh;
		struct ifinfomsg ifinfo;
		char             attrbuf[64];
	} req;
	struct nlmsghdr *nh;
	struct nlmsgerr *err;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		printf("open netlink socket: %s\n", strerror(errno));
		return -1;
	}

	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		printf("bind to netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_type = RTM_SETLINK;
	req.nh.nlmsg_pid = 0;
	req.nh.nlmsg_seq = ++seq;
	req.ifinfo.ifi_family = AF_UNSPEC;
	req.ifinfo.ifi_index = ifindex;

	/* started nested attribute for XDP */
	nla = (struct nlattr *)(((char *)&req)
				+ NLMSG_ALIGN(req.nh.nlmsg_len));
	nla->nla_type = NLA_F_NESTED | 43/*IFLA_XDP*/;
	nla->nla_len = NLA_HDRLEN;

	/* add XDP fd */
	nla_xdp = (struct nlattr *)((char *)nla + nla->nla_len);
	nla_xdp->nla_type = 1/*IFLA_XDP_FD*/;
	nla_xdp->nla_len = NLA_HDRLEN + sizeof(int);
	memcpy((char *)nla_xdp + NLA_HDRLEN, &fd, sizeof(fd));
	nla->nla_len += nla_xdp->nla_len;

	/* if user passed in any flags, add those too */
	if (flags) {
		nla_xdp = (struct nlattr *)((char *)nla + nla->nla_len);
		nla_xdp->nla_type = 3/*IFLA_XDP_FLAGS*/;
		nla_xdp->nla_len = NLA_HDRLEN + sizeof(flags);
		memcpy((char *)nla_xdp + NLA_HDRLEN, &flags, sizeof(flags));
		nla->nla_len += nla_xdp->nla_len;
	}

	req.nh.nlmsg_len += NLA_ALIGN(nla->nla_len);

	if (send(sock, &req, req.nh.nlmsg_len, 0) < 0) {
		printf("send to netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0) {
		printf("recv from netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len);
	     nh = NLMSG_NEXT(nh, len)) {
		if (nh->nlmsg_pid != getpid()) {
			printf("Wrong pid %d, expected %d\n",
			       nh->nlmsg_pid, getpid());
			goto cleanup;
		}
		if (nh->nlmsg_seq != seq) {
			printf("Wrong seq %d, expected %d\n",
			       nh->nlmsg_seq, seq);
			goto cleanup;
		}
		switch (nh->nlmsg_type) {
		case NLMSG_ERROR:
			err = (struct nlmsgerr *)NLMSG_DATA(nh);
			if (!err->error)
				continue;
			printf("nlmsg error %s\n", strerror(-err->error));
			goto cleanup;
		case NLMSG_DONE:
			break;
		}
	}

	ret = 0;

cleanup:
	close(sock);
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
			ret = bpf_set_link_xdp_fd(bprog->ifindex, bprog->fd, xdp_flags);
			break;
		//bprog->type is not supported 
		default:
			ret = -1;
			break;
	}

	return ret;
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

	//Default is XDP
	bprog->type = BPF_PROG_TYPE_XDP;
	bprog->verdict = XDP_PASS;

	return 0;
}

/*
	Generate the prologue for BPF program
	@param bprog - bpf program that has image to load the prologue into 
	@return Return code for generating prologue 
*/
int bpfprog_prologue(struct bpf_prog *bprog)
{
	//XDP prologue
	EMIT(bprog, BPF_MOV64_REG(BPF_REG_9, BPF_REG_1));              /* r9 = r1 */                          
	EMIT(bprog, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_9,		   /* r2 = r9 + xdp_md data length*/
			 offsetof(struct xdp_md, data)));               
	EMIT(bprog, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_9,		   /* r3 = r9 + xdp_md data_end length*/ 
			 offsetof(struct xdp_md, data_end)));           
	EMIT(bprog, BPF_MOV64_REG(BPF_REG_1, BPF_REG_2));              /* r1 = r2 */
	EMIT(bprog, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, ETH_HLEN));      // r1 += ETH_HLEN
	EMIT(bprog, BPF_JMP_REG(BPF_JLE, BPF_REG_1, BPF_REG_3, 2));    // if (r1 <= r3) goto pc + 2
	EMIT(bprog, BPF_MOV32_IMM(BPF_REG_0, bprog->verdict));         // r0 = verdict (default: pass)
 	EMIT(bprog, BPF_EXIT_INSN());                                  /* return r0 */   

	return 0;
}

/*
	Load/generate the bpf file and load it into the proper layer 
	@param bprog - bpf_prog structure which holds the proper information for the bpf program 
	@return Return code for loading/generating the bpf file and loading it 
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

	//Initial load did not work 
	if (ret < 0) 
	{
		//Try with the 0th interface 
		fprintf(stderr, "Desired ifindex loading not successful. Trying local\n");
		bprog->ifindex = 0;
		ret = bpf_prog_load(bprog);
	}

	//Bpf file loading returned a valid fd, so load the fd 
	if (ret > 0) {
		bprog->fd = ret;
		ret = bpf_load_fd(bprog);
	}

	return ret < 0 ? ret : 0;
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
