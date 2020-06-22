#ifndef BPFGEN_BOOTSTRAP_H
#define BPFGEN_BOOTSTRAP_H
#include "../imr.h"

#include <arpa/inet.h>

//Function definition
int fill_imr(struct imr_state *state, int test_to_run);

#endif