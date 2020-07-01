#include "imrManager.h"
#include "../bpfgen_configuration.h"
#include "../bpf_insn.h"
#include "../test/bpfgen_bootstrap.h"

#include <linux/filter.h>

#include <linux/if_ether.h>
typedef __u16 __bitwise __sum16; /* hack */
#include <linux/ip.h>
#include <arpa/inet.h>
#include <linux/tcp.h>

/*
	JIT a verdict to BPF 
	@param bprog - bpf program to add verdict to 
	@return Return code of EMITing 
*/
static int imr_jit_verdict(struct bpf_prog *bprog, int verdict)
{
	EMIT(bprog, BPF_MOV32_IMM(BPF_REG_0, verdict));
	EMIT(bprog, BPF_EXIT_INSN());
	return 0;
}

static int imr_jit_end_verdict(struct bpf_prog *bprog, int verdict) 
{
	//Switch the hook type and get what the BPF verdict will be
	//based on the type 
	switch (bprog->type) {
	case BPF_PROG_TYPE_XDP: 
		verdict = xdp_imr_jit_obj_verdict(verdict);
		break;
	default:
		fprintf(stderr, "Unsupported type for IMR_VERDICT");
		exit(EXIT_FAILURE);
	}

	//JIT the verdict 
	return imr_jit_verdict(bprog, verdict);
}

/*
	JIT an IMR object of type verdict to BPF
	@param bprog - bpf program to add to
	@param o - imr_object to JIT
	@return Return code of JITing the object 
*/
static int imr_jit_obj_verdict(struct bpf_prog *bprog,
			                   const struct imr_object *o)
{
	//Get the verdict from the object 
	int imr_verdict = o->verdict.verdict;
	int verdict = -1;

	//Switch the hook type and get what the BPF verdict will be
	//based on the type 
	switch (bprog->type) {
	case BPF_PROG_TYPE_XDP: 
		verdict = xdp_imr_jit_obj_verdict(imr_verdict);
		break;
	default:
		fprintf(stderr, "Unsupported type for IMR_VERDICT");
		exit(EXIT_FAILURE);
	}

	//JIT the verdict 
	return imr_jit_verdict(bprog, verdict);
}

/*
	JIT an imr object of type immediate to BPF
	@param bprog - bpf_prog to add the jitted object to
	@param s - imr_state in order to determine registers needed 
	@param o - imr object to jit 
	@return Return of code of jitting object
*/
static int imr_jit_obj_immediate(struct bpf_prog *bprog,
				                 const struct imr_object *o)
{
	//Get a register to use 
	int bpf_reg = bpf_register_get(bprog, o->len);

	//Switch on if 32 or 64 bit immediate, then JIT
	switch (o->len) {
	case sizeof(uint32_t):
		EMIT(bprog, BPF_MOV32_IMM(bpf_reg, o->imm.value32));
		return 0;
	case sizeof(uint64_t):
		EMIT(bprog, BPF_LD_IMM64(bpf_reg, o->imm.value64));
		return 0;
	default:
		break;
	}

	fprintf(stderr, "unhandled immediate size");
	return -EINVAL;
}

/*
	Fixup jumps in bpf program 
	@param bprog - bpf_prog to fix jumps for 
	@param poc_start - start of where to check jump fixing
*/
static void imr_fixup_jumps(struct bpf_prog *bprog, unsigned int poc_start)
{
	//Variable declaration
	unsigned int pc, pc_end, i;

	//Check to make sure the old poc is not greater than current bpf prog length 
	if (poc_start >= bprog->len_cur)
	{
		fprintf(stderr, "old poc >= current one");
		exit(EXIT_FAILURE);
	}

	//Determine section to check 
	pc = 0;
	pc_end = bprog->len_cur - poc_start;

	//Loop through section fixing jumps
	for (i = poc_start; pc < pc_end; pc++, i++) {
		//If the current code piece is a jump
		if (BPF_CLASS(bprog->img[i].code) == BPF_JMP) {
			//Don't fix exit jumps, call jump, non jump count 
			if (bprog->img[i].code == (BPF_EXIT | BPF_JMP))
				continue;
			if (bprog->img[i].code == (BPF_CALL | BPF_JMP))
				continue;
			if (bprog->img[i].off)
				continue;

			//Fix the jump count to the right jump fix
			bprog->img[i].off = pc_end - pc - 1;
		}
	}
}

/*
	JIT and imr_object of type payload
	@param bprog - bpf_prog to add jitted object to 
	@param state - imr_state used to determine registers 
	@param o - imr object to jit
	@return Return code of jitting payload
*/
static int imr_jit_obj_payload(struct bpf_prog *bprog,
			       const struct imr_object *o)
{
	int ret = 0;

	//Switch on payload type and jit accordingly
	switch(o->payload.base) {
		case IMR_DEST_PORT: //Destination port
			EMIT(bprog, BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_2, 
				sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, dest)));
			break;
		case IMR_SRC_PORT: //Source port
			EMIT(bprog, BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_2,
				sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, source)));
			break;
		default:
			fprintf(stderr, "Payload type not recognized\n");
			ret = -1;
			break;
	}
	return ret;
}

//ALU OPERATIONS
/*
	JIT and imr_object of type alu
	@param bprog - bpf_prog to add jitted object to 
	@param state - imr_state used to determine registers 
	@param o - imr object to jit
	@return Return code of jitting alu
*/
static int imr_jit_obj_alu(struct bpf_prog *bprog,
				  const struct imr_object *o)
{
	//Variable declaration
	const struct imr_object *right;
	enum imr_reg_num regl, regr;
	int ret, op, bpf_reg;

	//For jump reasons, will do the negative bpf opcode 
	switch (o->alu.op) {
	case IMR_ALU_OP_EQ:
		op = BPF_JNE;
		break;
	case IMR_ALU_OP_NE:
		op = BPF_JEQ;
		break;
	default:
		return -EINVAL;
	}

	//Jit the left side 
	ret = imr_jit_object(bprog, o->alu.left);
	if (ret < 0) 
		return ret;

	//Get the regsiter for the left side 
	regl = bpf_register_get(bprog, o->len);
	if (regl < 0) 
		return -EINVAL;

	//Get the right object 
	right = o->alu.right;

	// avoid jitting and using a 2nd register if possible for immediate values
	//Create a branch for immediate values
	if (right->type == IMR_OBJ_TYPE_IMMEDIATE) {
		//Only support 32-bit sizes for now 
		switch (right->len) {
		case sizeof(uint32_t):
			EMIT(bprog, BPF_JMP_IMM(op, regl, right->imm.value32, 0));
			return 0;
		}
	}

	//Return -1 as operation is not supported 
	return -1;
}

/*
	JIT the beginning of an imr rule i.e. network/transport layer checks
	@param bprog - bpf_prog to add jitted items to 
	@param state - imr_state to use for determing layer for now 
*/
static int imr_jit_rule_begin(struct bpf_prog *bprog, struct imr_object *object) {
	int ret = 0;
	if (object->type != IMR_OBJ_TYPE_BEGIN) {
		fprintf(stderr, "Not right object type for rule beginning %s\n", type_to_str(object->type));
		return -1;
	}
	//Network Layer
	switch(object->beginning.network_layer){
		case NO_NETWORK:
			break;
		case NETWORK_IP4: //Ipv4
			//Ensure it's an ipv4 packet
			EMIT(bprog, BPF_MOV64_REG(BPF_REG_1, BPF_REG_2));
			EMIT(bprog, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 
				sizeof(struct ethhdr) + sizeof(struct iphdr)));
			EMIT(bprog, BPF_JMP_REG(BPF_JLE, BPF_REG_1, BPF_REG_3, 2));
			break;
		default:
			fprintf(stderr, "Unsupported network layer");
			ret = -1;
			break;
	}

	//Exit if not right network layer
	ret = imr_jit_verdict(bprog, bprog->verdict);
	if (ret != 0) {
		fprintf(stderr, "Failure to JIT network layer verdict");
		return ret;
	}

	//Transport layer 
	switch(object->beginning.transport_layer) {
		case NO_TRANSPORT:
			break;
		case TRANSPORT_TCP: //TCP
			//Ensure it's a tcp packet and pass if not
			EMIT(bprog, BPF_MOV64_REG(BPF_REG_1, BPF_REG_2));
			EMIT(bprog, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 
				sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)));
			EMIT(bprog, BPF_JMP_REG(BPF_JLE, BPF_REG_1, BPF_REG_3, 2));
			//Exit if not right transport layer
			ret = imr_jit_verdict(bprog, bprog->verdict);
			if (ret != 0) {
				fprintf(stderr, "Failure to JIT transport layer verdict");
				return ret;
			}
			EMIT(bprog, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_2, sizeof(struct ethhdr) + offsetof(struct iphdr, protocol)));
			EMIT(bprog, BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 255));
			EMIT(bprog, BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, IPPROTO_TCP, 2));
			ret = imr_jit_verdict(bprog, bprog->verdict);
			if (ret != 0) {
				fprintf(stderr, "Failure to JIT transport layer verdict");
				return ret;
			}
			break;
		default:
			fprintf(stderr, "Unsupported transport layer");
			ret = -1;
			break;
	}

	//Return return code of jitting beginning of rule
	return ret;
}

/*
	JIT an IMR rule to BPF 
	@param bprog - program to add rule to 
	@param state - imr_state to conver to bpf 
	@param i - index of objects to convert 
	@return Number of rules added 
*/
static int imr_jit_rule(struct bpf_prog *bprog, struct imr_state *state, int start)
{
	//Variable initialization 
	unsigned int i, end, len_cur;
	int count = 0;
	int ret;

	//Get number of objects 
	end = state->num_objects;

	//Incomplete IMR rule check 
	if (i >= end) {
		fprintf(stderr, "Incomplete IMR Rule");
		return -EINVAL;
	}

	//Current length of the bprog
	len_cur = bprog->len_cur;

	//Beginning of imr_rule - needs an imr_rule beginning
	ret = imr_jit_rule_begin(bprog, state->objects[start]);
	if (ret < 0) {
		fprintf(stderr, "Failed to JIT rule begin\n");
		return ret;
	}
	count++; //Increase count for rule beginning

	//Loop through objects and jit each object in the rule 
	for (i = start+1; i < end; i++) {
		//Jit object 
		ret = imr_jit_object(bprog, state->objects[i]);

		//Jitting failed
		if (ret < 0) {
			fprintf(stderr, "failed to JIT object type %d\n",  state->objects[i]->type);
			return ret;
		}

		//Increase object count 
		count++;

		//Once hit a verdict, rule is done 
		if (state->objects[i]->type == IMR_OBJ_TYPE_VERDICT)
			break;
	}

	//malformed - no verdict
	if (i == end) {
		fprintf(stderr, "rule had no verdict, start %d end %d\n", start, end);
		exit(EXIT_FAILURE);
	}

	//Fixup jumps
	imr_fixup_jumps(bprog, len_cur);

	//Return number of objects jitted 
	return count;
}

/*
	Generate the prologue for BPF program
	@param bprog - bpf program that has image to load the prologue into 
	@return Return code for generating prologue 
*/
static int imr_jit_prologue(struct bpf_prog *bprog, struct imr_state *state)
{
	int ret = 0;

	//Switch the hook
	switch(bprog->type) 
	{
		//XDP layer 
		case BPF_PROG_TYPE_XDP:
			state->link_layer = LINK_ETHERNET;
			ret = xdp_imr_jit_prologue(bprog, state);
			break;
		//HERE: sk_buff imr_reload_skb_data
		//bprog->type is not supported 
		default:
			ret = -1;
			break;
	}
	
	return ret;
}

static void print_imr_read_ruleset_error(int ret) {
	switch(ret) {
		case -1:
			fprintf(stderr, "JSON is malformed\n");
			break;
		case -2:
			fprintf(stderr, "Error creating a imr_object\n");
			break;
		case -3: 
			fprintf(stderr, "Error adding a valid imr_object to an imr_state\n");
			break;
		case -4:
			fprintf(stderr, "Unknown type of rule\n");
			break;
		default:
			fprintf(stderr, "Error");
			break;
	}
}

static int imr_read_ruleset_alu_eq_imm32(const json_t *rule, struct imr_state *state) {
	json_t *conditions, *network_layer_val, *transport_layer_val, \
	       *payload_val, *imm32_val, *verdict_val;
	json_int_t network_layer, transport_layer, payload, imm32, verdict;
	
	conditions = json_object_get(rule, "conditions");
	if (!json_is_object(conditions))
		return -1;

	network_layer_val = json_object_get(conditions, "network_layer");
	if (!json_is_integer(network_layer_val)) 
		return -1;
	network_layer = json_integer_value(network_layer_val);

	transport_layer_val = json_object_get(conditions, "transport_layer");
	if (!json_is_integer(transport_layer_val)) 
		return -1;
	transport_layer = json_integer_value(transport_layer_val);

	payload_val = json_object_get(conditions, "payload");
	if (!json_is_integer(payload_val)) 
		return -1;
	payload = json_integer_value(payload_val);	

	imm32_val = json_object_get(conditions, "immediate");
	if (!json_is_integer(imm32_val)) 
		return -1;
	imm32 = json_integer_value(imm32_val);

	verdict_val = json_object_get(rule, "action");
	if (!json_is_integer(verdict_val)) 
		return -1;
	verdict = json_integer_value(verdict_val);

	struct imr_object *begin = imr_object_alloc_beginning(network_layer, transport_layer);
	if (!begin)
		return -2;
	struct imr_object *payload_obj = imr_object_alloc_payload(payload);
	if (!payload_obj)
		return -2;
	struct imr_object *imm = imr_object_alloc_imm32(ntohs(imm32));
	if (!imm)
		return -2;
	struct imr_object *alu = imr_object_alloc_alu(IMR_ALU_OP_EQ, payload_obj, imm);
	if (!alu)
		return -2;
	struct imr_object *verdict_obj = imr_object_alloc_verdict(verdict);
	if (!verdict_obj)
		return -2;

	int ret; 
	ret = imr_state_add_obj(state, begin);
	if (ret < 0) 
		return -3;
	ret = imr_state_add_obj(state, alu);
	if (ret < 0) 
		return -3;
	ret = imr_state_add_obj(state, verdict_obj);
	if (ret < 0) 
		return -3;

	return 0;
}

static int imr_read_ruleset_rules (const json_t *chain, struct imr_state *state) {
	json_t *rules;
	int i;
	int ret = 0;

	rules = json_object_get(chain, "rules");
	if (!json_is_array(rules))
		return -1;

	for (i = 0; i < json_array_size(rules); i++) {
		if (ret < 0)
			break;
		json_t *rule, *rule_type_val;;
		json_int_t rule_type;

		rule = json_array_get(rules, i);
		if (!json_is_object(rule)) 
			return -1;

		rule_type_val = json_object_get(rule, "type");
		if (!json_is_integer(rule_type_val)) 
			return -1;

		rule_type = json_integer_value(rule_type_val);

		switch(rule_type) {
			case IMR_ALU_EQ_IMM32:
				ret = imr_read_ruleset_alu_eq_imm32(rule, state);
				break;
			case IMR_DROP_ALL:
				state->verdict = IMR_VERDICT_DROP;
				break;
			default:
				ret = -4;
				break;
		}
	}

	return 0;
}

/*
	JIT an imr_object
	@param bprog - bpf_prog to add to 
	@param s - imr_state used for register determination 
	@param o - imr_object to jit 
*/
int imr_jit_object(struct bpf_prog *bprog,
			  const struct imr_object *o)
{
	//Switch on imr_object type and call the appropriate function
	switch (o->type) {
	case IMR_OBJ_TYPE_VERDICT:
		return imr_jit_obj_verdict(bprog, o);
	case IMR_OBJ_TYPE_PAYLOAD:
		return imr_jit_obj_payload(bprog, o);
	case IMR_OBJ_TYPE_IMMEDIATE:
		return imr_jit_obj_immediate(bprog, o);
	case IMR_OBJ_TYPE_ALU:
		return imr_jit_obj_alu(bprog, o);
	}

	return -EINVAL;
}

/*
	Read in the bpf_config_file
	@return a json object of the bpf configuration file
*/
json_t *read_bpf_file(void) {
	//Variable initialization 
	json_t *bpf_settings;
	json_error_t jerr;

	//Load bpf file into a json object 
	bpf_settings = json_load_file(bpf_config_file, 0, &jerr);
	if (!bpf_settings) 
	{
		perror("json_load_file");
		return NULL;
	}

	return bpf_settings;
}

/*
	Read in bpf settings i.e. rules for bpfs
	@param bpf_settings - The bpf_settings
	@param run_bootstrap - if bootstrap tests are being run
	@param test_to_run - which bootstrap test to run 
	@param debug - bool for if debug information is printed
	@return The imr_state that represents a structure of the rules 
			so json doesn't have to be reparsed
*/
struct imr_state *imr_ruleset_read(json_t *bpf_settings, int run_bootstrap, int test_to_run, bool debug)
{
	//Variable definition 
	struct imr_state *state; 
	int i, j;

	//If bpf_settings is not array, then configuration file is malformed 
	if (!json_is_array(bpf_settings))
	{
		perror("error: root is not an array");
		return NULL;
	}

	//Allocate the imr state 
	state = imr_state_alloc();
	if (!state)
		return NULL;

	//If running the bootstrap, fill_imr state with the test_to_run
	if (run_bootstrap) {
		int ret = fill_imr(state, test_to_run);
		if (ret < 0) {
			imr_state_free(state);
			return NULL;
		}
	} else { //If not running bootstrap, fill the ruleset properly
		int ret = 0;
		for (i = 0; i < json_array_size(bpf_settings); i++) {
			if (ret < 0)
				break;
			json_t *chain, *rules;

			chain = json_array_get(bpf_settings, i);
			if (!json_is_object(chain)) {
				ret = -1;
				break;
			}

			ret = imr_read_ruleset_rules(chain, state);
		}

		if (ret < 0) {
			print_imr_read_ruleset_error(ret);
			imr_state_free(state);
			return NULL;
		}
	}

	//Print out function
	if (debug) {
		int ret = imr_state_print(stdout, state);
		if (ret < 0) {
			fprintf(stderr, "Print failed\n");
			imr_state_free(state);
			return NULL;
		}
	}

	return state;
}

/*
	Translate an imr_state into a bpf program
	@param s - imr_state to translate to bpf 
	@return Return code from all the translation 
*/
int imr_do_bpf(struct imr_state *s, bool debug)
{
	//Variable init 
    struct bpf_prog bprog;
    int ret, i = 0;

	//Allocate and initialize the bprof program, return if failure  
    ret = bpfprog_init(&bprog);
    if (ret < 0) {
    	return ret;
	}

	//Verdict from state
	bprog.verdict = s->verdict;

	//Debug for bprog
	bprog.debug = debug;

	//Create bpf proglogue for bpf program 
	ret = imr_jit_prologue(&bprog, s);
	if (ret < 0)
		return ret;

	if (s->num_objects > 0)
	{
		//JIT each object in imr_state 
		do {
			//Jit the object based on index 
			int bpf_insn = imr_jit_rule(&bprog, s, i);

			//If jit failed, return accordingly
			if (bpf_insn < 0) {
				fprintf(stderr, "rule jit failed\n");
				ret = bpf_insn; 
				break;
			}

			//Needs to have at least 1 for bpf_insn
			if (bpf_insn == 0) 
			{
				perror("rule jit yields 0 insn - can't have that");
				exit(EXIT_FAILURE);
			}

			i += bpf_insn;
		} while (i < s->num_objects);

		//Error generating program
		if (ret < 0) {
			fprintf(stderr, "Error generating bpf program\n");
			return ret;
		}
	}

	//Add a bpf verdict and fail if verdict failed
	ret = imr_jit_end_verdict(&bprog, bprog.verdict);
	if (ret < 0)
		return ret;

	//HERE select interface 
	bprog.ifindex = 2;

	//Commit the bpf program into a fd to be loaded 
	ret = bpfprog_commit(&bprog);

	//Free memory
    bpfprog_destroy(&bprog);

    return ret;
}
