#include <arch/ppc64le/codegen/codegen_types.h>

const char *retrec::ppc64le::operation_names[] = {
#define OPERATION_NAME(op, ...) "Operation::" #op,
    PPC64LE_ENUMERATE_OPERATIONS(OPERATION_NAME)
#undef OPERATION_NAME
};

