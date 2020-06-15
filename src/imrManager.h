#ifndef IMR_MANAGER_H
#define IMR_MANAGER_H
#include <jansson.h>

#include "bpfload.h"
#include "imr.h"

json_t *read_bpf_file(void);
struct imr_state *imr_ruleset_read(json_t *bpf_settings);
int imr_do_bpf(struct imr_state *s);

#endif