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
void NTT_masked_poly(masked_poly *a);
void reverse_NTT_masked_poly(masked_poly *a);
void masked_poly_mul(masked_poly *r, const masked_poly *a, const poly *b);
void masked_poly_add(masked_poly *r, const masked_poly *a, const masked_poly *b);
void recombine(poly *r, const masked_poly *a);
void masked_poly_tobytes(unsigned char *r, const masked_poly *p);
void masked_poly_frombytes(masked_poly *r, const unsigned char *a);
void masked_poly_frommsg(masked_poly *r, const unsigned char *msg);
void test_from_message(const uint8_t m[(NEWHOPE_N/8)*(MASKING_ORDER+1)], masked_poly* y);

#endif //NEWHOPE_MASKED_CPAPKE_H
