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

#include "../bpfload.h"
#include "../imr.h"
#include "../common.h"
#include "imrManagerXdp.h"

int imr_jit_object(struct bpf_prog *bprog,
			  struct imr_state *s,
			  const struct imr_object *o);
json_t *read_bpf_file(void);
struct imr_state *imr_ruleset_read(json_t *bpf_settings);
int imr_do_bpf(struct imr_state *s);

#endif