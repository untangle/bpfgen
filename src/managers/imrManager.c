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

extern FILE *logger;
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

/*
	JIT the final verdict in a bpf prog
	@param bprog - bpf program to add to 
	@param verdict - final veerdict to add to
	@return Return code of jitting the verdict
	@param TODO
*/
static int imr_jit_end_verdict(struct bpf_prog *bprog, int verdict) 
{
	//Switch the hook type and get what the BPF verdict will be
	//based on the type 
	switch (bprog->type) {
	case BPF_PROG_TYPE_XDP: 
		verdict = xdp_imr_jit_obj_verdict(verdict);
		break;
	default:
		fprintf(logger, "Unsupported type for IMR_VERDICT");
		exit(EXIT_FAILURE);
	}

	//JIT the verdict 
	return imr_jit_verdict(bprog, verdict);
}

/*
	JIT an IMR object of type verdict to BPF
	@param bprog - bpf program to add to
	@param o - imr_object to JIT
	@param TODO
	@return Return code of JITing the object 
*/
static int imr_jit_obj_verdict(struct bpf_prog *bprog, const struct imr_object *o, int rule_id, int object_id)
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
		fprintf(logger, "rule %i object %i: Unsupported type for IMR_VERDICT\n", rule_id, object_id);
		exit(EXIT_FAILURE);
	}

	if (verdict < 0) {
		fprintf(logger, "rule %i, object %i: Failed to get bpf verdict from imr_type\n", rule_id, object_id);
		return -1;
	}

	//JIT the verdict 
	return imr_jit_verdict(bprog, verdict);
}

/*
	JIT an imr object of type immediate to BPF
	@param bprog - bpf_prog to add the jitted object to
	@param o - imr object to jit 
	@return Return of code of jitting object
*/
static int imr_jit_obj_immediate(struct bpf_prog *bprog, const struct imr_object *o, int rule_id, int object_id)
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

	fprintf(logger, "rule_id %i, object_id %i: unhandled immediate size\n", rule_id, object_id);
	return -EINVAL;
}

/*
	Fixup jumps in bpf program 
	@param bprog - bpf_prog to fix jumps for 
	@param poc_start - start of where to check jump fixing
	@param TODO
*/
static void imr_fixup_jumps(struct bpf_prog *bprog, unsigned int poc_start, int rule_id)
{
	//Variable declaration
	unsigned int pc, pc_end, i;

	//Check to make sure the old poc is not greater than current bpf prog length 
	if (poc_start >= bprog->len_cur)
	{
		fprintf(logger, "rule_id %i: old poc >= current one\n", rule_id);
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
	@param o - imr object to jit
	@return Return code of jitting payload
*/
static int imr_jit_obj_payload(struct bpf_prog *bprog, const struct imr_object *o, int rule_id, int object_id)
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
			fprintf(logger, "rule_id %i, object_id %i: Payload type not recognized\n", rule_id, object_id);
			ret = -1;
			break;
	}
	return ret;
}

//ALU OPERATIONS
/*
	JIT and imr_object of type alu
	@param bprog - bpf_prog to add jitted object to 
	@param o - imr object to jit
	@param TODO
	@return Return code of jitting alu
*/
static int imr_jit_obj_alu(struct bpf_prog *bprog, const struct imr_object *o, int rule_id, int object_id)
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
	ret = imr_jit_object(bprog, o->alu.left, rule_id, object_id);
	if (ret < 0) {
		fprintf(logger, "rule_id %i, object_id %i: Failed to JIT left side of an alu\n", rule_id, object_id);
		return ret;
	}

	//Get the regsiter for the left side 
	regl = bpf_register_get(bprog, o->len);
	if (regl < 0) {
		fprintf(logger, "rule_id %i, object_id %i: Failed to get register for left side of an alu object\n", rule_id, object_id);
		return -EINVAL;
	}

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
	fprintf(logger, "rule_id %i, object_id %i: Operation not supported for alu object\n", rule_id, object_id);
	return -1;
}

/*
	JIT the beginning of an imr rule i.e. network/transport layer checks
	@param bprog - bpf_prog to add jitted items to 
	@param object - imr_object to jit
	@param TODO
*/
static int imr_jit_rule_begin(struct bpf_prog *bprog, struct imr_object *object, int rule_id) {
	int ret = 0;
	if (object->type != IMR_OBJ_TYPE_BEGIN) {
		fprintf(logger, "rule_id %i: Not right object type for rule beginning %s\n", rule_id, type_to_str(object->type));
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
			fprintf(logger, "rule_id %i: Unsupported network layer\n", rule_id);
			ret = -1;
			break;
	}

	//Exit if not right network layer
	ret = imr_jit_verdict(bprog, bprog->verdict);
	if (ret != 0) {
		fprintf(logger, "rule_id %i: Failure to JIT network layer verdict", rule_id);
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
				fprintf(logger, "rule_id %i: Failure to JIT transport layer verdict 1", rule_id);
				return ret;
			}
			EMIT(bprog, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_2, sizeof(struct ethhdr) + offsetof(struct iphdr, protocol)));
			EMIT(bprog, BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 255));
			EMIT(bprog, BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, IPPROTO_TCP, 2));
			ret = imr_jit_verdict(bprog, bprog->verdict);
			if (ret != 0) {
				fprintf(logger, "rule_id %i: Failure to JIT transport layer verdict 2", rule_id);
				return ret;
			}
			break;
		default:
			fprintf(logger, "rule_id %i: Unsupported transport layer", rule_id);
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
	@param start - index of objects to convert 
	@param TODO
	@return Number of rules added 
*/
static int imr_jit_rule(struct bpf_prog *bprog, struct imr_state *state, int start)
{
	//Variable initialization 
	unsigned int i, end, len_cur;
	int count = 0;
	int ret;
	int rule_start = start;

	//Get number of objects 
	end = state->num_objects;

	//Incomplete IMR rule check 
	if (i >= end) {
		fprintf(logger, "rule %i: Incomplete IMR Rule\n", rule_start);
		return -EINVAL;
	}

	//Current length of the bprog
	len_cur = bprog->len_cur;

	//Beginning of imr_rule - needs an imr_rule beginning
	ret = imr_jit_rule_begin(bprog, state->objects[start], rule_start);
	if (ret < 0) {
		fprintf(logger, "rule %i: Failed to JIT rule begin\n", rule_start);
		return ret;
	}
	count++; //Increase count for rule beginning

	//Loop through objects and jit each object in the rule 
	for (i = start+1; i < end; i++) {
		//Jit object 
		ret = imr_jit_object(bprog, state->objects[i], rule_start, i);

		//Jitting failed
		if (ret < 0) {
			fprintf(logger, "rule_id %i, object_id %i: failed to JIT object type %d\n", rule_start, i, state->objects[i]->type);
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
		fprintf(logger, "rule_id %i: no verdict, start %d end %d\n", rule_start, start, end);
		exit(EXIT_FAILURE);
	}

	//Fixup jumps
	imr_fixup_jumps(bprog, len_cur, rule_start);

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

//TODO: docs
static const char *condition_failure_to_str(enum imr_read_ruleset_conditions_failure f) {
	
	switch(f) {
		case CONDITION_NO_FAILURE: return "No failure";
		case NETWORK_LAYER_NOT_INTEGER: return "Network layer was not an integer";
		case TRANSPORT_LAYER_NOT_INTEGER: return "Transport layer was not an integer";
		case PAYLOAD_NOT_INTEGER: return "Payload was not an integer";
		case IMMEDIATE_NOT_INTEGER: return "Immediate was not an integer";
		case ACTION_NOT_INTEGER: return "Action was not an integer";
		case CONDITION_IMR_FAILURE: return "IMR failure on condition";
	}

	return "unknown";
}

//Todo : docs 
static const char *rule_failure_to_str(enum imr_read_ruleset_rule_failure f) {

	switch(f) {
		case RULE_NO_FAILURE: return "No failure";
		case RULE_NOT_OBJECT: return "Rule not a json object";
		case RULE_TYPE_NOT_INTEGER: return "Rule type was not an integer";
		case RULE_IMR_FAILURE: return "IMR failure on rule";
		case CONDITION_NOT_OBJECT: return "Condition variable not an object";
	}

	return "unknown";
}

//TODO: docs
static const char *chain_failure_to_str(enum imr_read_ruleset_chain_failure f) {

	switch(f){
		case CHAIN_NO_FAILURE: return "No failure";
		case CHAIN_NOT_OBJECT: return "Chain not a json object";
		case CHAIN_IMR_FAILURE: return "IMR failure on chain";
	}

	return "unknown";
}

/*
	Print error message based on return code of ruleset read
	@param ret - return code to determine error message with
	@param TODO
*/
static void print_imr_read_ruleset_error(int ret, struct imr_read_ruleset_tracker *tracker) {
	switch(ret) {
		case -1:
			fprintf(logger, "Chain Id %i: ", tracker->chain_id);
			if (tracker->rule_id > -1) {
				fprintf(logger, "Rule Id %i: ", tracker->rule_id);
				if (tracker->condition_id > -1) {
					fprintf(logger, "Condition Id %i: ", tracker->condition_id);
					fprintf(logger, "JSON is malformed: ");
					fprintf(logger, "%s", condition_failure_to_str(tracker->condition_failure));
				}
				else {
					fprintf(logger, "JSON is malformed: ");
					fprintf(logger, "%s", rule_failure_to_str(tracker->rule_failure));
				}
			}
			else {
				fprintf(logger, "JSON is malformed: ");
				fprintf(logger, "%s", chain_failure_to_str(tracker->chain_failure));
			}
			fprintf(logger, "\n");
			break;
		case -2:
			//Will have rule and chain
			fprintf(logger, "Chain Id %i: Rule Id %i: ", tracker->chain_id, tracker->rule_id);
			fprintf(logger, "Error creating a imr_object: ");
			fprintf(logger, "Type: %s\n", type_to_str(tracker->imr_failure));
			break;
		case -3: 
			//Will have rule and chain
			fprintf(logger, "Chain Id %i: Rule Id %i: ", tracker->chain_id, tracker->rule_id);
			fprintf(logger, "Error adding a valid imr_object to an imr_state: ");
			fprintf(logger, "Type: %s\n", type_to_str(tracker->imr_failure));
			break;
		case -4:
			fprintf(logger, "Unknown type of rule\n");
			break;
		default:
			fprintf(logger, "Error reading imr ruleset");
			break;
	}
}

/*
	Generate an imr_rule from a alu with a payload eq imm32
	@param rule - the JSON format of rule 
	@param state - imr_state to add to 
	@param TODO
	@return Return code of adding rule to state
*/
static int imr_read_ruleset_alu_eq_imm32(const json_t *rule, 
                                         struct imr_state *state,
										 struct imr_read_ruleset_tracker *tracker) {
	//Variable initialization
	json_t *conditions, *network_layer_val, *transport_layer_val, \
	       *payload_val, *imm32_val, *verdict_val;
	json_int_t network_layer, transport_layer, payload, imm32, verdict;
	
	//Get the conditions
	conditions = json_object_get(rule, "conditions");
	if (!json_is_object(conditions)) {
		tracker->rule_failure = CONDITION_NOT_OBJECT;
		return -1;
	}

	//Get the network_layer type. The integer will match the enum
	tracker->condition_id = 0;
	network_layer_val = json_object_get(conditions, "network_layer");
	if (!json_is_integer(network_layer_val)) {
		tracker->condition_failure = NETWORK_LAYER_NOT_INTEGER;
		return -1;
	}
	network_layer = json_integer_value(network_layer_val);

	//Get the transport_layer type. The integer will match the enum
	tracker->condition_id = 1;
	transport_layer_val = json_object_get(conditions, "transport_layer");
	if (!json_is_integer(transport_layer_val)) {
		tracker->condition_failure = TRANSPORT_LAYER_NOT_INTEGER;
		return -1;
	}
	transport_layer = json_integer_value(transport_layer_val);

	//Get the payload type. The integer will match the enum
	tracker->condition_id = 2;
	payload_val = json_object_get(conditions, "payload");
	if (!json_is_integer(payload_val)) {
		tracker->condition_failure = PAYLOAD_NOT_INTEGER;
		return -1;
	}
	payload = json_integer_value(payload_val);	

	//Get the immediate value 
	tracker->condition_id = 3;
	imm32_val = json_object_get(conditions, "immediate");
	if (!json_is_integer(imm32_val)) {
		tracker->condition_failure = IMMEDIATE_NOT_INTEGER;
		return -1;
	}
	imm32 = json_integer_value(imm32_val);

	//Get the verdict val. The integer will match the enum
	tracker->condition_id = 4;
	verdict_val = json_object_get(rule, "action");
	if (!json_is_integer(verdict_val)) {
		tracker->condition_failure = ACTION_NOT_INTEGER;
		return -1;
	}
	verdict = json_integer_value(verdict_val);

	//Create imr_objects 
	tracker->chain_failure = CHAIN_IMR_FAILURE; //To limit amount of code, set to failure 
	tracker->rule_failure = RULE_IMR_FAILURE; //To limit amount of code, set to failure 
	tracker->condition_failure = CONDITION_IMR_FAILURE; //To limit amount of code, set to failure
	struct imr_object *begin = imr_object_alloc_beginning(network_layer, transport_layer);
	if (!begin) {
		tracker->imr_failure = IMR_OBJ_TYPE_BEGIN;
		return -2;
	}
	struct imr_object *payload_obj = imr_object_alloc_payload(payload);
	if (!payload_obj) {
		tracker->imr_failure = IMR_OBJ_TYPE_PAYLOAD;
		return -2;
	}
	struct imr_object *imm = imr_object_alloc_imm32(ntohs(imm32));
	if (!imm) {
		tracker->imr_failure = IMR_OBJ_TYPE_IMMEDIATE;
		return -2;
	}
	struct imr_object *alu = imr_object_alloc_alu(IMR_ALU_OP_EQ, payload_obj, imm);
	if (!alu) {
		tracker->imr_failure = IMR_OBJ_TYPE_ALU;
		return -2;
	}
	struct imr_object *verdict_obj = imr_object_alloc_verdict(verdict);
	if (!verdict_obj) {
		tracker->imr_failure = IMR_OBJ_TYPE_VERDICT;
		return -2;
	}

	//Add imr_objects begin, alu, and verdict in that order to imr_state
	int ret; 
	ret = imr_state_add_obj(state, begin);
	if (ret < 0) {
		tracker->imr_failure = IMR_OBJ_TYPE_BEGIN;
		return -3;
	}
	ret = imr_state_add_obj(state, alu);
	if (ret < 0) {
		tracker->imr_failure = IMR_OBJ_TYPE_ALU;
		return -3;
	}
	ret = imr_state_add_obj(state, verdict_obj);
	if (ret < 0) {
		tracker->imr_failure = IMR_OBJ_TYPE_VERDICT;
		return -3;
	}

	tracker->chain_failure = CHAIN_NO_FAILURE; //Set back to none if all passed
	tracker->rule_failure = RULE_NO_FAILURE; //Set back to none if all passed
	tracker->condition_failure = CONDITION_NO_FAILURE; //Set back to none if all passed
	
	return 0;
}

/*
	Read in the rules from the ruleset 
	@param chain - chain to read rules from
	@param state - imr_state struct to add to 
	@param TODO
	@return Return code of adding rule to state
*/
static int imr_read_ruleset_rules (const json_t *chain, 
                                   struct imr_state *state,
								   struct imr_read_ruleset_tracker *tracker) {
	//Variable initialization
	json_t *rules;
	int i;
	int ret = 0;

	//Get rules 
	rules = json_object_get(chain, "rules");
	if (!json_is_array(rules))
		return -1;

	//Loop through rules 
	for (i = 0; i < json_array_size(rules); i++) {
		//If return code is bad, return 
		if (ret < 0)
			break;

		json_t *rule, *rule_type_val;;
		json_int_t rule_type;
		tracker->rule_id = i;

		//Get rule information 
		rule = json_array_get(rules, i);
		if (!json_is_object(rule)) {
			tracker->rule_failure = RULE_NOT_OBJECT;
			return -1;
		}

		//Get type of rule. Integer will be from enum  
		rule_type_val = json_object_get(rule, "type");
		if (!json_is_integer(rule_type_val)) {
			tracker->rule_failure = RULE_TYPE_NOT_INTEGER;
			return -1;
		}
		rule_type = json_integer_value(rule_type_val);

		//Switch on type 
		switch(rule_type) {
			case IMR_ALU_EQ_IMM32: //Handle the alu eq imm32 case 
				ret = imr_read_ruleset_alu_eq_imm32(rule, state, tracker);
				break;
			case IMR_DROP_ALL: //Set final verdict to drop
				state->verdict = IMR_VERDICT_DROP;
				break;
			default: //Unknown type
				ret = -4;
				break;
		}

		//If return code is bad, return 
		if (ret < 0)
			break;
	}

	return ret;
}

/*
	JIT an imr_object
	@param bprog - bpf_prog to add to 
	@param o - imr_object to jit 
	@param TODO
*/
int imr_jit_object(struct bpf_prog *bprog, const struct imr_object *o, int rule_id, int object_id)
{
	//Switch on imr_object type and call the appropriate function
	switch (o->type) {
	case IMR_OBJ_TYPE_VERDICT:
		return imr_jit_obj_verdict(bprog, o, rule_id, object_id);
	case IMR_OBJ_TYPE_PAYLOAD:
		return imr_jit_obj_payload(bprog, o, rule_id, object_id);
	case IMR_OBJ_TYPE_IMMEDIATE:
		return imr_jit_obj_immediate(bprog, o, rule_id, object_id);
	case IMR_OBJ_TYPE_ALU:
		return imr_jit_obj_alu(bprog, o, rule_id, object_id);
	}

	return -EINVAL;
}

/*
	Read in the bpf_config_file
	@param TODO
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
		fprintf(logger, "jannsson failed to load file: ");
		fprintf(logger, "%s\n", jerr.text);
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
	@param TODO
	@return The imr_state that represents a structure of the rules 
			so json doesn't have to be reparsed
*/
struct imr_state *imr_ruleset_read(json_t *bpf_settings, 
                                   int run_bootstrap, 
								   int test_to_run, 
								   bool debug)
{
	//Variable definition 
	struct imr_state *state; 
	struct imr_read_ruleset_tracker *tracker;
	int i, j;

	//Allocate tracker
	tracker = calloc(1, sizeof(struct imr_read_ruleset_tracker));
	if (!tracker) {
		fprintf(logger, "error: could not create ruleset_tracker\n");
		return NULL;
	}

	//If bpf_settings is not array, then configuration file is malformed 
	if (!json_is_array(bpf_settings))
	{
		fprintf(logger, "error: root of bpf_settings is not an array\n");
		return NULL;
	}

	//Allocate the imr state 
	state = imr_state_alloc();
	if (!state) {
		fprintf(logger, "error: Could not create a new imr state\n");
		return NULL;
	}

	//If running the bootstrap, fill_imr state with the test_to_run
	if (run_bootstrap) {
		int ret = fill_imr(state, test_to_run);
		if (ret < 0) {
			fprintf(logger, "error: Bootstrap failed to fill at test %i", test_to_run);
			imr_state_free(state);
			return NULL;
		}
	} else { //If not running bootstrap, fill the ruleset properly
		int ret = 0;
		//Loop through bpf_settings
		for (i = 0; i < json_array_size(bpf_settings); i++) {
			//If return code is bad, break
			if (ret < 0)
				break;

			json_t *chain, *rules;
			tracker->chain_id = i;
			tracker->rule_id = -1;
			tracker->condition_id = -1;
			tracker->chain_failure = CHAIN_NO_FAILURE;
			tracker->rule_failure = RULE_NO_FAILURE;
			tracker->condition_failure = CONDITION_NO_FAILURE;
			tracker->imr_failure = IMR_OBJ_TYPE_NONE;

			//Get the chain the loop is currently on
			chain = json_array_get(bpf_settings, i);
			if (!json_is_object(chain)) {
				tracker->chain_failure = CHAIN_NOT_OBJECT;
				ret = -1;
				break;
			}

			//Call function to read in rules
			ret = imr_read_ruleset_rules(chain, state, tracker);

			//If return code is bad, break
			if (ret < 0)
				break;
		}

		//Print out errors 
		if (ret < 0) {
			print_imr_read_ruleset_error(ret, tracker);
			imr_state_free(state);
			return NULL;
		}
	}

	//Print out function only if debug is passed
	if (debug) {
		int ret = imr_state_print(logger, state);
		if (ret < 0) {
			fprintf(logger, "error: Print failed\n");
			imr_state_free(state);
			return NULL;
		}
	}

	return state;
}

/*
	Translate an imr_state into a bpf program
	@param s - imr_state to translate to bpf 
	@param debug - bool to determine if printing information
	@param TODO
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
		fprintf(logger, "error: Failed to create bpf program\n");
    	return ret;
	}

	//Verdict from state
	bprog.verdict = s->verdict;

	//Debug for bprog
	bprog.debug = debug;

	//Create bpf proglogue for bpf program 
	ret = imr_jit_prologue(&bprog, s);
	if (ret < 0) {
		fprintf(logger, "error: Failed to create prologue for bpf program\n");
		return ret;
	}

	if (s->num_objects > 0)
	{
		//JIT each object in imr_state 
		do {
			//Jit the object based on index 
			int bpf_insn = imr_jit_rule(&bprog, s, i);

			//If jit failed, return accordingly
			if (bpf_insn < 0) {
				fprintf(logger, "rule_id %i: rule jit failed\n", i);
				ret = bpf_insn; 
				break;
			}

			//Needs to have at least 1 for bpf_insn
			if (bpf_insn == 0) 
			{
				fprintf(logger, "rule_id %i: rule jit yields 0 insn - can't have that\n", i);
				ret = -1;
				break;
			}

			i += bpf_insn;
		} while (i < s->num_objects);

		//Error generating program
		if (ret < 0) {
			fprintf(logger, "Error generating bpf program\n");
			return ret;
		}
	}

	//Add a bpf verdict and fail if verdict failed
	ret = imr_jit_end_verdict(&bprog, bprog.verdict);
	if (ret < 0) {
		fprintf(logger, "Error generating bpf program verdict\n");
		return ret;
	}

	//HERE select interface 
	bprog.ifindex = 2;

	//Commit the bpf program into a fd to be loaded 
	ret = bpfprog_commit(&bprog);

	//Free memory
    bpfprog_destroy(&bprog);

    return ret;
}
