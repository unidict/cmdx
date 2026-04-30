//
//  cmdx_data.c
//  libcmdx
//

#include "cmdx_types.h"
#include <stdlib.h>

void cmdx_data_free_shallow(cmdx_data *data) {
    if (data) {
        free(data);
    }
}

void cmdx_data_free_deep(cmdx_data *data) {
    if (data) {
        free(data->data);
        free(data);
    }
}
