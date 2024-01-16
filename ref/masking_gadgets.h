#ifndef NEWHOPE_MASKING_GADGETS_H
#define NEWHOPE_MASKING_GADGETS_H

#define MASKING_ORDER 3
typedef struct Masked {uint16_t shares[MASKING_ORDER+1];} Masked;

// Only used in the LEQ function, didn't have the time to make this work with the Masked we already had.
typedef struct CompMasked {uint32_t shares[MASKING_ORDER+1];} CompMasked;

void masked_binomial_dist(Masked* a, Masked* x, Masked* y, int k);
void arith_refresh(Masked* x);
void opti_B2A(Masked* y, Masked* x, int k);
void A2B(Masked* y, Masked* x);


#endif //NEWHOPE_MASKING_GADGETS_H
