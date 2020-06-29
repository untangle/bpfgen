#include "bpfgen_bootstrap.h"

/*
    Test 1: testing destination port in ip/tcp 
    @param state - imr_state to fill
    @return Return code of adding to the imr_state
*/
static int test_1_dst_port(struct imr_state *state) 
{
    int ret = 0;

    //Port 80
    struct imr_object *imm = imr_object_alloc_imm32(ntohs(80));
    if (!imm)
    {
        fprintf(stderr, "bootstrap 1 failed to create immediate");
        exit(EXIT_FAILURE);
    }
    //Payload is dest port 
    struct imr_object *payload = imr_object_alloc_payload (IMR_DEST_PORT);
    if (!payload)
    {
        fprintf(stderr, "bootstrap 1 failed to create payload");
        exit(EXIT_FAILURE);
    }
    //Alu - equality 
    struct imr_object *alu = imr_object_alloc_alu(IMR_ALU_OP_EQ, payload, imm);
    if (!alu)
    {
        fprintf(stderr, "bootstrap 1 failed to create alu");
        exit(EXIT_FAILURE);
    }
    //Drop port
    struct imr_object *verdict = imr_object_alloc_verdict(IMR_VERDICT_DROP);
    if (!verdict)
    {
        fprintf(stderr, "bootstrap 1 failed to create verdict");
        exit(EXIT_FAILURE);
    }

    //Add alu and verdict
    ret = imr_state_add_obj(state, alu);
    ret = imr_state_add_obj(state, verdict);

    return ret;
}

/*
    Test 2: source port 
    @param state - imr_state to add to
    @return Return code of adding to imr_state
*/
static int test_2_src_port(struct imr_state *state) 
{
    int ret = 0;

    //Immediate to port 80
    struct imr_object *imm = imr_object_alloc_imm32(ntohs(80));
    if (!imm)
    {
        fprintf(stderr, "bootstrap 2 failed to create immediate");
        exit(EXIT_FAILURE);
    }
    //Payload - source port
    struct imr_object *payload = imr_object_alloc_payload (IMR_SRC_PORT);
    if (!payload)
    {
        fprintf(stderr, "bootstrap 2 failed to create payload");
        exit(EXIT_FAILURE);
    }
    //ALU - port is 80
    struct imr_object *alu = imr_object_alloc_alu(IMR_ALU_OP_EQ, payload, imm);
    if (!alu)
    {
        fprintf(stderr, "bootstrap 2 failed to create alu");
        exit(EXIT_FAILURE);
    }
    //Drop XDP verdict
    struct imr_object *verdict = imr_object_alloc_verdict(IMR_VERDICT_DROP);
    if (!verdict)
    {
        fprintf(stderr, "bootstrap 2 failed to create verdict");
        exit(EXIT_FAILURE);
    }

    //Add alu and verdict to imr_state
    ret = imr_state_add_obj(state, alu);
    ret = imr_state_add_obj(state, verdict);

    return ret;
}

/*
    Based on test_to_run, fill the imr_state
    @param state - imr_state to fill
    @param test_to_run - test to run
    @return Return code of filling imr_state
*/
int fill_imr(struct imr_state *state, int test_to_run)
{
    int ret = 0;

    //Switch on test to run
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