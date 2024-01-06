#include <stdio.h>
#include "poly.h"
#include "randombytes.h"
#include "fips202.h"
#include "masking_gadgets.h"
#include "masked_cpapke.h"

static void gen_a(poly *a, const unsigned char *seed)
{
    poly_uniform(a,seed);
}

int main(int argc, char *argv[]){
    unsigned char z[2*NEWHOPE_SYMBYTES];
    unsigned char *publicseed = z;
    unsigned char *noiseseed = z+NEWHOPE_SYMBYTES;
    masked_poly shat, ahat_shat, ehat, bhat;
    poly complete_before, complete_before_mul, complete_before_mul_add, ahat, ehat_complete;

    masked_sample(&shat, noiseseed, 0);
    masked_sample(&ehat, noiseseed, 1);

    for(int i = 0; i<NEWHOPE_N; i++){
        uint16_t coeff_i = 0;
        uint16_t coeff_i_ehat = 0;
        for(int j = 0; j <= MASKING_ORDER; j++){
            coeff_i = (coeff_i + shat.poly_shares[j].coeffs[i]) % NEWHOPE_Q;
            coeff_i_ehat = (coeff_i_ehat + ehat.poly_shares[j].coeffs[i]) % NEWHOPE_Q;
        }
        complete_before.coeffs[i] = coeff_i;
        ehat_complete.coeffs[i] = coeff_i_ehat;
    }

    for(int i = 0; i <= MASKING_ORDER; i++){
        poly_ntt(&(shat.poly_shares[i]));
        poly_ntt(&(ehat.poly_shares[i]));
    }
    poly_ntt(&complete_before);
    poly_ntt(&ehat_complete);

    gen_a(&ahat, publicseed);

    poly_mul_pointwise(&complete_before_mul, &complete_before, &ahat);
    for(int i = 0; i <= MASKING_ORDER; i++){
        poly_mul_pointwise(&ahat_shat.poly_shares[i], &shat.poly_shares[i], &ahat);
    }

    for(int i = 0; i <= MASKING_ORDER; i++){
        poly_add(&bhat.poly_shares[i], &ehat.poly_shares[i], &ahat_shat.poly_shares[i]);
    }

    poly_add(&complete_before_mul_add, &ehat_complete, &complete_before_mul);


    /*poly_invntt(&complete_before_mul);
    for(int i = 0; i <= MASKING_ORDER; i++){
        poly_invntt(&ahat_shat.poly_shares[i]);
    }*/


    poly complete_after;
    for(int i = 0; i<NEWHOPE_N; i++){
        uint16_t coeff_i = 0;
        for(int j = 0; j <= MASKING_ORDER; j++){
            coeff_i = (coeff_i + bhat.poly_shares[j].coeffs[i]) % NEWHOPE_Q;
        }
        complete_after.coeffs[i] = coeff_i;
    }

    for(int i = 0; i<NEWHOPE_N; i++){
        printf("Coeff: %d, complete_before: %d, complete_after: %d \n", i, complete_before_mul_add.coeffs[i], complete_after.coeffs[i]);
    }
}
