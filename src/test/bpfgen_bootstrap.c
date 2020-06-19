#include "bpfgen_bootstrap.h"

static int test_1_dst_port(struct imr_state *state) 
{
    int ret = 0;

    struct imr_object *imm = imr_object_alloc_imm32(ntohs(80));
    if (!imm)
    {
        fprintf(stderr, "bootstrap 1 failed to create immediate");
        exit(EXIT_FAILURE);
    }
    struct imr_object *payload = imr_object_alloc_payload (IMR_DEST_PORT);
    if (!payload)
    {
        fprintf(stderr, "bootstrap 1 failed to create payload");
        exit(EXIT_FAILURE);
    }
    struct imr_object *alu = imr_object_alloc_alu(IMR_ALU_OP_EQ, payload, imm);
    if (!alu)
    {
        fprintf(stderr, "bootstrap 1 failed to create alu");
        exit(EXIT_FAILURE);
    }
    struct imr_object *verdict = imr_object_alloc_verdict(IMR_VERDICT_DROP);
    if (!verdict)
    {
        fprintf(stderr, "bootstrap 1 failed to create verdict");
        exit(EXIT_FAILURE);
    }

    ret = imr_state_add_obj(state, alu);
    ret = imr_state_add_obj(state, verdict);

    return ret;
}

static int test_2_src_port(struct imr_state *state) 
{
    int ret = 0;

    struct imr_object *imm = imr_object_alloc_imm32(ntohs(80));
    if (!imm)
    {
        fprintf(stderr, "bootstrap 2 failed to create immediate");
        exit(EXIT_FAILURE);
    }
    struct imr_object *payload = imr_object_alloc_payload (IMR_SRC_PORT);
    if (!payload)
    {
        fprintf(stderr, "bootstrap 2 failed to create payload");
        exit(EXIT_FAILURE);
    }
    struct imr_object *alu = imr_object_alloc_alu(IMR_ALU_OP_EQ, payload, imm);
    if (!alu)
    {
        fprintf(stderr, "bootstrap 2 failed to create alu");
        exit(EXIT_FAILURE);
    }
    struct imr_object *verdict = imr_object_alloc_verdict(IMR_VERDICT_DROP);
    if (!verdict)
    {
        fprintf(stderr, "bootstrap 2 failed to create verdict");
        exit(EXIT_FAILURE);
    }

    ret = imr_state_add_obj(state, alu);
    ret = imr_state_add_obj(state, verdict);

    return ret;
}

int fill_imr(struct imr_state *state, int test_to_run)
{
    int ret = 0;

    switch(test_to_run) {
        case 1:
            ret = test_1_dst_port(state);
            break;
        case 2:
            ret = test_2_src_port(state);
            break;
        default:
            fprintf(stderr, "Not a valid test number\n");
            ret = -1;
            break;
    }

    return ret;


}