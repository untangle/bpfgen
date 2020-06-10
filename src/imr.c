#include "imr.h"
#include "bpfgen_configuration.h"

/*
	Convert imr_obj_type to string for printing purposes 
	@param t - imr_obj_type to convert 
	@return String representation of imr_obj_type parameter, t 
*/
static const char *type_to_str(enum imr_obj_type t)
{
	switch (t) {
	case IMR_OBJ_TYPE_VERDICT: return "verdict";
	case IMR_OBJ_TYPE_IMMEDIATE: return "imm";
	case IMR_OBJ_TYPE_PAYLOAD: return "payload";
	case IMR_OBJ_TYPE_ALU: return "alu";
	case IMR_OBJ_TYPE_META: return "meta";
	}

	return "unknown";
}

/*
	Convert imr_alu_op to string for printing purposes 
	@param op - imr_alu_op to convert 
	@return String representation of imr_alu_op parameter, op
*/
static const char * alu_op_to_str(enum imr_alu_op op)
{
	switch (op) {
	case IMR_ALU_OP_EQ: return "eq";
	case IMR_ALU_OP_NE: return "ne";
	case IMR_ALU_OP_LT: return "<";
	case IMR_ALU_OP_LTE: return "<=";
	case IMR_ALU_OP_GT: return ">";
	case IMR_ALU_OP_GTE: return ">=";
	case IMR_ALU_OP_AND: return "&";
	case IMR_ALU_OP_LSHIFT: return "<<";
	}

	return "?";
}

/*
	Convert imr_meta_key to string for printing purposes 
	@param k - imr_meta_key to convert
	@return String representation of imr_meta_key parameter, k
*/
static const char *meta_to_str(enum imr_meta_key k)
{
	switch (k) {
	case IMR_META_NFMARK:
		return "nfmark";
	case IMR_META_NFPROTO:
		return "nfproto";
	case IMR_META_L4PROTO:
		return "l4proto";
	}

	return "unknown";
}

/*
	Convert imr_verdict to string for printing purposes 
	@param v - imr_verdict to convert 
	@return String representation of imr_verdict parameter, v
*/
static const char *verdict_to_str(enum imr_verdict v)
{
	switch (v) {
	case IMR_VERDICT_NONE: return "none";
	case IMR_VERDICT_NEXT: return "next";
	case IMR_VERDICT_PASS: return "pass";
	case IMR_VERDICT_DROP: return "drop";
	}

	return "invalid";
}

/*
	Convert imr_object_imm to string and print out result  
	@param fp - file/place to print information to
	@param o - imr_object with imm attribute to print 
	@return Return code from fprints
*/
static int imr_object_print_imm(FILE *fp, const struct imr_object *o)
{
	//Initialize printing 
	int ret = fprintf(fp, "TYPE_IMMEDIATE (");
	if (ret < 0)
		return ret;

	//Based on object length print out right attribute value
	switch (o->len) {
	case sizeof(uint64_t):
		return fprintf(fp, "0x%16llx)\n", (unsigned long long)o->imm.value64);
	case sizeof(uint32_t):
		return fprintf(fp, "0x%08x)\n", (unsigned int)o->imm.value32);
	default:
		return fprintf(fp, "0x%llx (?)\n", (unsigned long long)o->imm.value64);
	}
}

/*
	Print out an imr_object 
	@param fp - file/place to print information out to 
	@param o - imr_object to print 
	@return Cumulative return code of all the prints to determine if a failure occured
*/
static int imr_object_print(FILE *fp, const struct imr_object *o)
{
	//Variable init
	int ret = 0;
	int total = 0; //Track how many objects are printed 

	//Print out type 
	ret = fprintf(fp, "%s", type_to_str(o->type));
	if (ret < 0)
		return ret;
	total += ret;

	//Call right function based on object type 
	switch (o->type) {
	case IMR_OBJ_TYPE_VERDICT:
		//Verdict 
		ret = fprintf(fp, "(%s)", verdict_to_str(o->verdict.verdict));

		//Don't add to total if print failed, otherwise add to total
		if (ret < 0)
			break;
		total += ret; 
		break;
	case IMR_OBJ_TYPE_PAYLOAD:
		//Payload 
		ret = fprintf(fp, "(base %d, off %d, len %d)",
				o->payload.base, o->payload.offset, o->len);

		//Don't add to total if print failed, otherwise add to total
		if (ret < 0)
			break;
		total += ret;
		break;
	case IMR_OBJ_TYPE_IMMEDIATE:
		//Immediate 
		ret = imr_object_print_imm(fp, o);

		//Don't add to total if print failed, otherwise add to total
		if (ret < 0)
			break;
		total += ret;
		break;
	case IMR_OBJ_TYPE_ALU:
		//ALU
		//Start of print 
		ret = fprintf(fp, "(");

		//Don't add to total if print failed, otherwise add to total
		if (ret < 0)
			break;
		total += ret;

		//Print left alu object 
		ret = imr_object_print(fp, o->alu.left);
		//Don't add to total if print failed, otherwise add to total
		if (ret < 0)
			break;
		total += ret;

		//Print ALU op 
		ret = fprintf(fp , " %s ", alu_op_to_str(o->alu.op));
		//Don't add to total if print failed, otherwise add to total
		if (ret < 0)
			break;
		total += ret;

		//Print ALU right object 
		ret = imr_object_print(fp, o->alu.right);
		//Don't add to total if print failed, otherwise add to total
		if (ret < 0)
			break;
		total += ret;

		//Print ALU ending 
		ret = fprintf(fp, ") ");
		//Don't add to total if print failed, otherwise add to total
		if (ret < 0)
			break;
		total += ret;
		break;
	case IMR_OBJ_TYPE_META:
		//Meta 
		ret = fprintf(fp , " %s ", meta_to_str(o->meta.key));

		//Don't add to total if print failed, otherwise add to total
		if (ret < 0)
			break;
		total += ret;
		break;
	default:
		//Failure for missing print support
		perror("Missing print support");
		exit(EXIT_FAILURE);
		break;
	}

	return total;
}

/*
	JIT an IMR rule to BPF 
	@param bprog - program to add rule to 
	@param state - imr_state to conver to bpf 
	@param i - index of objects to convert 
	@return Number of rules added 
*/
static int imr_jit_rule(struct bpf_prog *bprog, struct imr_state *state, int i)
{
	return 1;
}

/*
	JIT a verdict to BPF 
	@param bprog - bpf program to add verdict to 
	@return Return code of EMITing 
*/
static int imr_jit_verdict(struct bpf_prog *bprog)
{
	EMIT(bprog, BPF_MOV32_IMM(BPF_REG_0, bprog->verdict));
	EMIT(bprog, BPF_EXIT_INSN());
	return 0;
}

/*
	Allocate an imr_state struct 
	@return The allocated imr_state 
*/
struct imr_state *imr_state_alloc(void)
{
    return calloc(1, sizeof(struct imr_state));
}

/*
	Print out an imr_state 
	@param fp - file/place to print out to 
	@param s - imr_state to print 
*/
void imr_state_print(FILE *fp, struct imr_state *s)
{
	//Variable init 
	int i;

	//Initial print 
    fprintf(fp, "Printing IMR\n");

	//Print out each object in state 
	for (i = 0; i < s->num_objects; i++) {
		imr_object_print(fp, s->objects[i]);
		putc('\n', fp);
	}
}

/*
	Free an imr_state 
	@param s - imr_state to free 
*/
void imr_state_free(struct imr_state *s)
{
	//Variable init 
	int i;

	//Free all imr_object in struct 
	for (i = 0; i < s->num_objects; i++)
		imr_object_free(s->objects[i]);

	//Free object structure and finally the imr_state 
	free(s->objects);
	free(s);
}

/*
	Free the imr_object 
	@param o - imr_object to free 
*/
void imr_object_free(struct imr_object *o)
{
	//If it doesn't exist, then nothing to free 
	if (!o)
		return;

	//Avoid double free 
	if (o->refcnt == 0) {
		perror("double-free, refcnt already zero");
		o->refcnt--;
	}

	//Free based on the type 
	switch (o->type) {
	case IMR_OBJ_TYPE_VERDICT:
	case IMR_OBJ_TYPE_IMMEDIATE:
	case IMR_OBJ_TYPE_PAYLOAD:
	case IMR_OBJ_TYPE_META:
		break;
	case IMR_OBJ_TYPE_ALU:
		//Free each ALU object 
		imr_object_free(o->alu.left);
		imr_object_free(o->alu.right);
		break;
	}

	//Keep track of reference count for object 
	//Don't free until refcnt is 0
	o->refcnt--;
	if (o->refcnt > 0)
		return;

	//Free final object 
	free(o);
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
	@return The imr_state that represents a structure of the rules 
			so json doesn't have to be reparsed
*/
struct imr_state *imr_ruleset_read(json_t *bpf_settings)
{
	//Variable definition 
	struct imr_state *state; 

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

	//HERE: read in bpf settings into IMR

	//Print out function
	imr_state_print(stdout, state);

	return state;
}

/*
	Translate an imr_state into a bpf program
	@param s - imr_state to translate to bpf 
	@return Return code from all the translation 
*/
int imr_do_bpf(struct imr_state *s)
{
	//Variable init 
    struct bpf_prog bprog;
    int ret, i = 0;

	//Allocate and initialize the bprof program, return if failure  
    ret = bpfprog_init(&bprog);
    if (ret < 0) {
    	return ret;
	}

	//Create bpf proglogue for bpf program 
	ret = bpfprog_prologue(&bprog);
	if (ret < 0)
		return ret;

	//Don't use first four registers 
	s->regcount = 4;

	//JIT each object in imr_state 
	do {
		//Jit the object based on index 
		int bpf_insn = imr_jit_rule(&bprog, s, i);

		//If jit failed, return accordingly
		if (bpf_insn < 0) {
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
	if (ret != 0) {
		fprintf(stderr, "Error generating bpf program\n");
		return ret;
	}

	//Add a bpf verdict and fail if verdict failed
	ret = imr_jit_verdict(&bprog);
	if (ret < 0)
		return ret;

	//HERE select interface 
	bprog.ifindex = 5;

	//Commit the bpf program into a fd to be loaded 
	ret = bpfprog_commit(&bprog);

	//Free memory
    bpfprog_destroy(&bprog);

    return ret;
}
