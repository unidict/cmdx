//
//  cmdx_v3_block_info.c
//  libud
//
//  Created by kejinlu on 2025/12/15.
//

#include "cmdx_unit_info.h"
#include "cmdx_endian.h"

cmdx_unit_info cmdx_unit_info_read(FILE *fp) {
    cmdx_unit_info header = {0};
    if (!fp) {
        return header;
    }

    if (fread(&header.unit_type, 1, 1, fp) != 1) {
        return header;
    }

    if (fread(header.reserved1, 1, sizeof(header.reserved1), fp) !=
        sizeof(header.reserved1)) {
        return header;
    }
    if (!fread_uint64_be(fp, &header.reserved2)) {
        return header;
    }
    if (!fread_uint32_be(fp, &header.block_count)) {
        return header;
    }
    if (!fread_uint64_be(fp, &header.data_section_length)) {
        return header;
    }

    header.valid = true;
    return header;
}
