#ifndef IMR_MANAGER_H
#define IMR_MANAGER_H
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <jansson.h>

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/if_ether.h>

#include <arpa/inet.h>

#include "../bpfload.h"
#include "../imr.h"
#include "../common.h"
#include "imrManagerXdp.h"

enum imr_read_ruleset_chain_failure {
	CHAIN_NO_FAILURE,
	CHAIN_NOT_OBJECT,
	CHAIN_IMR_FAILURE,
};

enum imr_read_ruleset_rule_failure {
	RULE_NO_FAILURE = 0,
	RULE_NOT_OBJECT,
	RULE_TYPE_NOT_INTEGER,
	RULE_IMR_FAILURE,
	CONDITION_NOT_OBJECT,
};

enum imr_read_ruleset_conditions_failure {
	CONDITION_NO_FAILURE = 0,
	NETWORK_LAYER_NOT_INTEGER,
	TRANSPORT_LAYER_NOT_INTEGER,
	PAYLOAD_NOT_INTEGER,
	IMMEDIATE_NOT_INTEGER,
	ACTION_NOT_INTEGER,
	CONDITION_IMR_FAILURE,
};

struct imr_read_ruleset_tracker {
	int chain_id;
	int rule_id;
	int condition_id;
	enum imr_read_ruleset_chain_failure chain_failure;
	enum imr_read_ruleset_rule_failure rule_failure;
	enum imr_read_ruleset_conditions_failure condition_failure;
	enum imr_obj_type imr_failure;
};

//Function definitions
int imr_jit_object(struct bpf_prog *bprog,
			  const struct imr_object *o,
			  int rule_id,
			  int object_id);
json_t *read_bpf_file(void);
struct imr_state *imr_ruleset_read(json_t *bpf_settings, 
                                   int run_bootstrap, 
								   int test_to_run, 
								   bool debug);
int imr_do_bpf(struct imr_state *s, bool debug);

#endif