#include "bpfgen_bootstrap.h"

int fill_imr(struct imr_state *state)
{
    int ret = 0;

    struct imr_object *imm = imr_object_alloc_imm64(22);
    if (!imm)
    {
        fprintf(stderr, "bootstrap failed to create immediate");
        exit(EXIT_FAILURE);
    }
    /*struct imr_object *payload = imr_object_alloc_payload ();
    struct imr_object *alu = imr_object_alloc_alu();

    int ret = imr_state_add_obj(state, alu);


    struct imr_object *verdict = imr_object_alloc_verdict();*/


}