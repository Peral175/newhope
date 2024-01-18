#ifndef NEWHOPE_MASKED_FIPS202_H
#define NEWHOPE_MASKED_FIPS202_H

#include <string.h>
#include "fips202.h"
#include "params.h"

#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

typedef struct {
    uint64_t s_masked[25 * (MASKING_ORDER + 1)];
} keccak_state_masked;

void shake256_masked(uint8_t* out_masked, size_t outlen, const uint8_t* in_masked, size_t inlen);

#endif //NEWHOPE_MASKED_FIPS202_H
