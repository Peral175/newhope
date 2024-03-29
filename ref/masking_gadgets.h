#ifndef NEWHOPE_MASKING_GADGETS_H
#define NEWHOPE_MASKING_GADGETS_H
#include "poly.h"

typedef struct Masked {uint16_t shares[MASKING_ORDER+1];} Masked;

// Only used in the LEQ and SecAdd function, didn't have the time to make this work with the Masked we already had
// or make sure everything would work with this one instead.
typedef struct CompMasked {uint32_t shares[MASKING_ORDER+1];} CompMasked;

void masked_binomial_dist(Masked* a, Masked* x, Masked* y, int k);

void arith_refresh(Masked* x, int q);
void boolean_refresh(Masked* x);

void opti_B2A(Masked* y, Masked* x, int k);
void opti_A2B(Masked *s, Masked *z);
void A2B(Masked* y, Masked* x);

void SecLeq_masked_res(Masked* res, CompMasked* x, int phi, int k);
int SecLeq_unmasked_res(Masked* x, int phi, int k);

void SecAdd(CompMasked* z, CompMasked* x, CompMasked* y, int k);
void SecMult(Masked* z, Masked* a, Masked* b);
int polyZeroTestExpo(int K,  int L, masked_poly* X);


#endif //NEWHOPE_MASKING_GADGETS_H
