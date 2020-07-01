#include "bpfgen_bootstrap.h"

static void failure_to_create(struct imr_object *o, enum imr_obj_type t) {
    if (!o) {
        fprintf(stderr, "bootstrap failed to create object of type %s\n", type_to_str(t));
        exit(EXIT_FAILURE);
    }
}

static void failure_to_add(int ret, enum imr_obj_type t) 
{
    if (ret < 0) {
        fprintf(stderr, "bootstrap failed to add object to an imr_state of type %s\n", type_to_str(t));
        exit(EXIT_FAILURE);
    }
}

/*
    Test 1: testing destination port in ip/tcp 
    @param state - imr_state to fill
    @return Return code of adding to the imr_state
*/
static int test_1_dst_port(struct imr_state *state) 
{
    int ret = 0;

    //Beginning object type 
    struct imr_object *begin = imr_object_alloc_beginning(NETWORK_IP4, TRANSPORT_TCP);
    failure_to_create(begin, IMR_OBJ_TYPE_BEGIN);
    //Port 80
    struct imr_object *imm = imr_object_alloc_imm32(ntohs(80));
    failure_to_create(imm, IMR_OBJ_TYPE_IMMEDIATE);
    //Payload is dest port 
    struct imr_object *payload = imr_object_alloc_payload (IMR_DEST_PORT);
    failure_to_create(payload, IMR_OBJ_TYPE_PAYLOAD);
    //Alu - equality 
    struct imr_object *alu = imr_object_alloc_alu(IMR_ALU_OP_EQ, payload, imm);
    failure_to_create(alu, IMR_OBJ_TYPE_ALU);
    //Drop port
    struct imr_object *verdict = imr_object_alloc_verdict(IMR_VERDICT_DROP);
    failure_to_create(verdict, IMR_OBJ_TYPE_VERDICT);

    //Add object types
    ret = imr_state_add_obj(state, begin);
    failure_to_add(ret, IMR_OBJ_TYPE_BEGIN);

    ret = imr_state_add_obj(state, alu);
    failure_to_add(ret, IMR_OBJ_TYPE_ALU);

    ret = imr_state_add_obj(state, verdict);
    failure_to_add(ret, IMR_OBJ_TYPE_VERDICT);

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

    //Beginning object type 
    struct imr_object *begin = imr_object_alloc_beginning(NETWORK_IP4, TRANSPORT_TCP);
    failure_to_create(begin, IMR_OBJ_TYPE_BEGIN);
    //Port 80
    struct imr_object *imm = imr_object_alloc_imm32(ntohs(80));
    failure_to_create(imm, IMR_OBJ_TYPE_IMMEDIATE);
    //Payload is dest port 
    struct imr_object *payload = imr_object_alloc_payload (IMR_SRC_PORT);
    failure_to_create(payload, IMR_OBJ_TYPE_PAYLOAD);
    //Alu - equality 
    struct imr_object *alu = imr_object_alloc_alu(IMR_ALU_OP_EQ, payload, imm);
    failure_to_create(alu, IMR_OBJ_TYPE_ALU);
    //Drop port
    struct imr_object *verdict = imr_object_alloc_verdict(IMR_VERDICT_DROP);
    failure_to_create(verdict, IMR_OBJ_TYPE_VERDICT);

    //Add object types
    ret = imr_state_add_obj(state, begin);
    failure_to_add(ret, IMR_OBJ_TYPE_BEGIN);

    ret = imr_state_add_obj(state, alu);
    failure_to_add(ret, IMR_OBJ_TYPE_ALU);

    ret = imr_state_add_obj(state, verdict);
    failure_to_add(ret, IMR_OBJ_TYPE_VERDICT);

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