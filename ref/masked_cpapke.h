#ifndef NEWHOPE_MASKED_CPAPKE_H
#define NEWHOPE_MASKED_CPAPKE_H

#include "poly.h"

void decode_c(poly *b, poly *v, const unsigned char *r);

void masked_poly_sub(masked_poly *r, const masked_poly *a, const poly *b);

void masked_cpapke_keypair(unsigned char *pk,
                    unsigned char *sk);

void masked_cpapke_enc(unsigned char *c,
                const unsigned char *m,
                const unsigned char *pk,
                const unsigned char *coins);

void masked_cpapke_dec(unsigned char *m,
                const unsigned char *c,
                const unsigned char *sk);

void masked_cpapke_enc2(masked_poly *vprime,
                        masked_poly *uhat,
                        const unsigned char *m,
                        const unsigned char *pk,
                        const unsigned char *coin);

void masked_cpapke_dec2(unsigned char *m,
                        const masked_poly *vprime,
                        const masked_poly *uhat,
                        const unsigned char *sk);


#endif //NEWHOPE_MASKED_CPAPKE_H
