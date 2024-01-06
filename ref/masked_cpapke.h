#ifndef NEWHOPE_MASKED_CPAPKE_H
#define NEWHOPE_MASKED_CPAPKE_H

#include "poly.h"

void masked_cpapke_keypair(unsigned char *pk,
                    unsigned char *sk);

void masked_cpapke_enc(unsigned char *c,
                const unsigned char *m,
                const unsigned char *pk,
                const unsigned char *coins);

void masked_cpapke_dec(unsigned char *m,
                const unsigned char *c,
                const unsigned char *sk);

// To be removed later, this is for testing
void masked_sample(masked_poly *r, const unsigned char *seed, unsigned char nonce);

#endif //NEWHOPE_MASKED_CPAPKE_H
