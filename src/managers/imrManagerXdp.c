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

#include "imrManagerXdp.h"
#include "../bpf_insn.h"

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

int xdp_load_fd(int ifindex, int fd, __u32 flags)
{
    return bpf_set_link_xdp_fd(ifindex, fd, flags);
}

int xdp_imr_jit_prologue(struct bpf_prog *bprog)
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

int xdp_imr_jit_obj_verdict(int imr_verdict)
{
	int verdict; 

	switch (imr_verdict) {
	case IMR_VERDICT_NEXT: /* no-op: continue with next rule */
		return 0;
	case IMR_VERDICT_NONE:
	case IMR_VERDICT_PASS:
		verdict = XDP_PASS;
		break;
	case IMR_VERDICT_DROP:
		verdict = XDP_DROP;
		break;
	default:
		fprintf(stderr, "unhandled verdict");
		exit(EXIT_FAILURE);
	}

	return verdict;
}

int xdp_imr_jit_obj_payload(struct bpf_prog *bprog, 
                            const struct imr_state *state, 
                            const struct imr_object *o) {
	int base = o->payload.base;
	int offset;
	int bpf_width, bpf_reg;

	offset = o->payload.offset;

	switch (base) {
	case IMR_PAYLOAD_BASE_LL:
	        EMIT(bprog, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1,
                    -(int)sizeof(struct ethhdr)));
		break;
	case IMR_PAYLOAD_BASE_NH:
		break;
	case IMR_PAYLOAD_BASE_TH:
		/* XXX: ip options */
		offset += sizeof(struct iphdr);
		break;
	}

	bpf_width = bpf_reg_width(o->len);
	bpf_reg = imr_register_get(state, o->len);

	//fprintf(stderr, "store payload in bpf reg %d\n", bpf_reg);
    EMIT(bprog, BPF_LDX_MEM(bpf_width, bpf_reg, BPF_REG_1, offset));

	switch (base) {
	case IMR_PAYLOAD_BASE_LL:
	        EMIT(bprog, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1,
					(int)sizeof(struct ethhdr)));
		break;
	case IMR_PAYLOAD_BASE_NH:
		break;
	case IMR_PAYLOAD_BASE_TH:
	        EMIT(bprog, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1,
					-(int)sizeof(struct iphdr)));
		break;
	}

	return 0;
}