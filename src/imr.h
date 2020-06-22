#ifndef IMR_H
#define IMR_H
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/if_ether.h>

#include "common.h"

/* Type of imr_object */
enum imr_obj_type {
	IMR_OBJ_TYPE_VERDICT = 0,
	IMR_OBJ_TYPE_IMMEDIATE,
	IMR_OBJ_TYPE_PAYLOAD,
	IMR_OBJ_TYPE_ALU,
	IMR_OBJ_TYPE_META,
};

/* imr registers to allow for ease in switching to bpf registers */
enum imr_reg_num {
	IMR_REG_0 = 0,
	IMR_REG_1,
	IMR_REG_2,
	IMR_REG_3,
	IMR_REG_4,
	IMR_REG_5,
	IMR_REG_6,
	IMR_REG_7,
	IMR_REG_8,
	IMR_REG_9,
	IMR_REG_10,
	IMR_REG_COUNT,
};

/* imr_alu operations enum */
enum imr_alu_op {
	IMR_ALU_OP_EQ = 0,
	IMR_ALU_OP_NE,
	IMR_ALU_OP_LT,
	IMR_ALU_OP_LTE,
	IMR_ALU_OP_GT,
	IMR_ALU_OP_GTE,
	IMR_ALU_OP_AND,
	IMR_ALU_OP_LSHIFT,
};

/* imr verdicts */
enum imr_verdict {
	IMR_VERDICT_NONE = 0,	/* partially translated rule, no verdict */
	IMR_VERDICT_NEXT,		/* move to next rule */
	IMR_VERDICT_PASS,		/* end processing, accept packet */
	IMR_VERDICT_DROP,		/* end processing, drop packet */
};

/* payload base types */
enum imr_payload_base {
	IMR_DEST_PORT = 0,
	IMR_SRC_PORT,
};

enum link_type {
	LINK_ETHERNET = 0,
};

enum network_type {
	NETWORK_IP4 = 0,
};

enum transport_type {
	TRANSPORT_TCP = 0,
};

/* imr meta keys */
enum imr_meta_key {
	IMR_META_L4PROTO = 0,
	IMR_META_NFPROTO,
	IMR_META_NFMARK,
};

/* imr_object */
struct imr_object {
	enum imr_obj_type type:8; //Type 
	uint8_t len;              //Length of object 
	uint8_t refcnt;           //Count to references 

	//Union of all information the object can old 
	union {
		//For immediate types 
		struct {
			union {
				uint64_t value_large[8];
				uint64_t value64;
				uint32_t value32;
			};
		} imm; 
		//For payload types 
		struct {
			enum imr_payload_base base:8;
		} payload;
		//For verdict types 
		struct {
			enum imr_verdict verdict;
		} verdict;
		//For meta types 
		struct {
			enum imr_meta_key key:8;
		} meta;
		//For ALU types 
		struct {
			struct imr_object *left;
			struct imr_object *right;
			enum imr_alu_op op:8;
		} alu;
	};
};

/* imr_state struct */
struct imr_state {
	uint32_t                len_cur;         //Length of imr_state currently
	uint16_t	            num_objects;     //Number of objects 
	uint8_t		            regcount;        //Register count 
	enum link_type          link_layer;      //only ethernet for now 
	enum network_type       network_layer;  //only IP for now 
	enum transport_type     transport_layer; //only tcp for now 

	struct imr_object *registers[IMR_REG_COUNT];

	struct imr_object **objects;
};

//Function declaration
struct imr_state *imr_state_alloc(void);
void imr_state_print(FILE *fp, struct imr_state *s);
void imr_state_free(struct imr_state *s);
void imr_object_free(struct imr_object *o);

struct imr_object *imr_object_alloc(enum imr_obj_type t); 
struct imr_object *imr_object_alloc_alu(enum imr_alu_op op, struct imr_object *l, struct imr_object *r);
struct imr_object *imr_object_alloc_payload(enum imr_payload_base b);
struct imr_object *imr_object_alloc_verdict(enum imr_verdict v);
struct imr_object *imr_object_alloc_imm64(uint64_t value);
struct imr_object *imr_object_alloc_imm32(uint32_t value);
int imr_state_add_obj(struct imr_state *s, struct imr_object *o);

//Register operations 
unsigned int imr_regs_needed(unsigned int len);
int imr_register_get(const struct imr_state *s, uint32_t len);
int bpf_reg_width(unsigned int len);
int imr_register_alloc(struct imr_state *s, uint32_t len);
void imr_register_release(struct imr_state *s, uint32_t len);
#endif
