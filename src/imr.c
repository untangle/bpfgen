#include "imr.h"

/*
	Convert imr_obj_type to string for printing purposes 
	@param t - imr_obj_type to convert 
	@return String representation of imr_obj_type parameter, t 
*/
static const char *type_to_str(enum imr_obj_type t)
{
	switch (t) {
	case IMR_OBJ_TYPE_VERDICT: return "VERDICT: ";
	case IMR_OBJ_TYPE_IMMEDIATE: return "IMM: ";
	case IMR_OBJ_TYPE_PAYLOAD: return "PAYLOAD: ";
	case IMR_OBJ_TYPE_ALU: return "ALU: ";
	case IMR_OBJ_TYPE_META: return "META: ";
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
	Convert imr_payload_base to string for printing purposes 
	@param p - imr_payload_base to convert 
	@return String representation of imr_payload_base, p
*/
static const char *payload_base_to_str(enum imr_payload_base p)
{
	switch(p) {
		case IMR_DEST_PORT: return "destination port";
		case IMR_SRC_PORT:  return "source port";
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
static int imr_object_print(FILE *fp, int depth, const struct imr_object *o)
{
	//Variable init
	int ret = 0;
	int total = 0; //Track how many objects are printed 
	int i;

	//Print out type 
	for (i = 0; i < depth; i++) {
		ret = fprintf(fp, "\t");
		if (ret < 0)
			return ret;
	}

	ret = fprintf(fp, "%s", type_to_str(o->type));
	if (ret < 0)
		return ret;

	//Call right function based on object type 
	switch (o->type) {
	case IMR_OBJ_TYPE_VERDICT:
		//Verdict 
		ret = fprintf(fp, "%s", verdict_to_str(o->verdict.verdict));

		//Don't add to total if print failed, otherwise add to total
		if (ret < 0)
			break;
		total += ret; 
		break;
	case IMR_OBJ_TYPE_PAYLOAD:
		//Payload 
		ret = fprintf(fp, "%s",
				payload_base_to_str(o->payload.base));

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
		++depth;
		//Start of print 
		ret = fprintf(fp, "\n");

		//Don't add to total if print failed, otherwise add to total
		if (ret < 0)
			break;
		total += ret;

		//Print left alu object 
		ret = imr_object_print(fp, depth, o->alu.left);
		//Don't add to total if print failed, otherwise add to total
		if (ret < 0)
			break;
		total += ret;

		//Print ALU op 
		for (i = 0; i < depth; i++)
			fprintf(fp, "\n\t");
		ret = fprintf(fp , "op: %s \n", alu_op_to_str(o->alu.op));
		//Don't add to total if print failed, otherwise add to total
		if (ret < 0)
			break;
		total += ret;

		//Print ALU right object 
		ret = imr_object_print(fp, depth, o->alu.right);
		//Don't add to total if print failed, otherwise add to total
		if (ret < 0)
			break;
		total += ret;

		//Print ALU ending 
		--depth;
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
		imr_object_print(fp, 0, s->objects[i]);
		putc('\n', fp);
	}
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
	Add an imr_object to an imr_state
	@param s - imr_state to add to
	@param o - imr_object to add 
	@return Return code of adding object 
*/
int imr_state_add_obj(struct imr_state *s, struct imr_object *o)
{
	//Variable declaration
	struct imr_object **new;
	uint32_t slot = s->num_objects;
	
	//Don't add too many objects
	if (s->num_objects >= (INT_MAX / sizeof(*o)))
		return -1;
	
	//Add number of objects
	s->num_objects++;
	//allocate object 
	new = realloc(s->objects, sizeof(o) * s->num_objects);
	if (!new) {
		imr_object_free(o);
		return -1;
	}

	//add in object
	new[slot] = o;
	if (new != s->objects)
		s->objects = new;

	return 0;
}

/*
	allocate an object 
	@param t - imr_obj_type of object 
	@return imr_object to return
*/
struct imr_object *imr_object_alloc(enum imr_obj_type t)
{
	struct imr_object *o = calloc(1, sizeof(*o));

	if (!o)
		return NULL;

	o->refcnt = 1;
	o->type = t;
	return o;
}

/*
	allocate an imr_object of type immediate 32
	@param value - uint32_t immediate value to set 
	@return imr_object of type immediate 32
*/
struct imr_object *imr_object_alloc_imm32(uint32_t value)
{
	//Allocate object
	struct imr_object *o = imr_object_alloc(IMR_OBJ_TYPE_IMMEDIATE);

	//Return null if object failed to allocate
	if (!o)
		return NULL;

	//Set value
	if (o) {
		o->imm.value32 = value;
		o->len = sizeof(value);
	}
	return o;
}

/*
	allocate an imr_object of type immediate 64
	@param value - uint32_t immediate value to set 
	@return imr_object of type immediate 64
*/
struct imr_object *imr_object_alloc_imm64(uint64_t value)
{
	//Allocate object
	struct imr_object *o = imr_object_alloc(IMR_OBJ_TYPE_IMMEDIATE);

	//Return null if object failed to allocate
	if (!o)
		return NULL;

	//Set value
	if (o) {
		o->imm.value64 = value;
		o->len = sizeof(value);
	}
	return o;
}

/*
	allocate an imr_object of type verdict
	@param vv- imr_verdict to set 
	@return imr_object of type verdict
*/
struct imr_object *imr_object_alloc_verdict(enum imr_verdict v)
{
	//Allocate object 
	struct imr_object *o = imr_object_alloc(IMR_OBJ_TYPE_VERDICT);

	//Return null if object failed to allocate 
	if (!o)
		return NULL;

	//Set value
	o->verdict.verdict = v;
	o->len = sizeof(v);

	//Return object
	return o;
}

/*
	allocate an imr_object of type payload
	@param b - imr_payload_base to set
	@return imr_object of type payload
*/
struct imr_object *imr_object_alloc_payload(enum imr_payload_base b)
{
	//Allocate object
	struct imr_object *o = imr_object_alloc(IMR_OBJ_TYPE_PAYLOAD);

	//Return null if object failed to allocate 
	if (!o)
		return NULL;

	//Set value
	o->payload.base = b;
	o->len = sizeof(b);

	return o;
}

/*
	allocate an imr_object of type alu
	@param op - imr_alu_op to set 
	@param l - left side imr_object to set alu to 
	@param r - right side imr_object to set alu to 
	@return imr_object of type alu
*/
struct imr_object *imr_object_alloc_alu(enum imr_alu_op op, struct imr_object *l, struct imr_object *r)
{
	//Allocate object
	struct imr_object *o = imr_object_alloc(IMR_OBJ_TYPE_ALU);

	//Return null if object failed to allocate 
	if (!o)
		return NULL;

	//Set values
	o->alu.op = op;
	o->alu.left = l;
	o->alu.right = r;

	//Don't set ALU with 0 length ojects 
	if (l->len == 0 || r->len == 0) {
		fprintf(stderr, "alu op with 0 op length\n");
		exit(EXIT_FAILURE);
	}

	//Set lengths properly
	o->len = l->len;
	if (r->len > o->len)
		o->len = r->len;

	//Return objects
	return o;
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

//REGISTER OPERATIONS
/*
	Registers needed 
	@param len - length of imr_register space needed 
	@return Number of registers needed 
*/
unsigned int imr_regs_needed(unsigned int len)
{
	return div_round_up(len, sizeof(uint64_t));
}

/*
	Get the register number to use 
	@param s - imr_state for doing register operations 
	@param len - length of imr_register space needed 
	@return Register number to use 
*/
int imr_register_get(const struct imr_state *s, uint32_t len)
{
	//Get registers needed 
	unsigned int regs_needed = imr_regs_needed(len);

	//determine if not enough registers are in use 
	if (s->regcount < regs_needed) {
		fprintf(stderr, "not enough registers in use");
		exit(EXIT_FAILURE);
	}

	//Return register number
	return s->regcount - regs_needed;
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
		fprintf(stderr, "reg size not supported");
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
int imr_register_alloc(struct imr_state *s, uint32_t len)
{
	//Determine registers needed
	unsigned int regs_needed = imr_regs_needed(len);

	//Initialize reg to the current regcount
	uint8_t reg = s->regcount;

	//Determine if out of bpf registers 
	if (s->regcount + regs_needed >= IMR_REG_COUNT) {
		fprintf(stderr, "out of BPF registers");
		return -1;
	}

	//Add to regcout the allocated registers 
	s->regcount += regs_needed;

	//Return new regcount
	return reg;
}

/*
	Release registers 
	@s - imr_state for register operations 
	@len - length of imr_registers to release 
*/
void imr_register_release(struct imr_state *s, uint32_t len)
{
	//Registers needed 
	unsigned int regs_needed = imr_regs_needed(len);

	//Releasing too many 
	if (s->regcount < regs_needed) {
		fprintf(stderr, "regcount underflow");
		exit(EXIT_FAILURE);
	}

	//Decrease state's reg count
	s->regcount -= regs_needed;
}