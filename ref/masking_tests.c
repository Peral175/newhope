#include <stdio.h>
#include "poly.h"
#include "randombytes.h"
#include "fips202.h"
#include "masking_gadgets.h"
#include "masked_cpapke.h"
#include <stdlib.h>

static void gen_a(poly *a, const unsigned char *seed)
{
    poly_uniform(a,seed);
}

int main(int argc, char *argv[]){
    unsigned char pk[NEWHOPE_CPAPKE_PUBLICKEYBYTES];
    unsigned char sk[NEWHOPE_CPAPKE_SECRETKEYBYTES * (MASKING_ORDER+1)];
    unsigned char c[NEWHOPE_CPAPKE_CIPHERTEXTBYTES];
    unsigned char m[NEWHOPE_SYMBYTES * (MASKING_ORDER+1)];
    unsigned char m_combined[NEWHOPE_SYMBYTES];
    unsigned char m_dec[NEWHOPE_SYMBYTES];
    unsigned char coin[NEWHOPE_SYMBYTES];
    masked_poly test_m;
    poly p_test_m;

    randombytes(m,NEWHOPE_SYMBYTES * (MASKING_ORDER+1));

    for(int i = 0; i < 32; i++){
        for(int j = 0; j <= MASKING_ORDER; j++){
            m_combined[i] ^= m[i + (j*NEWHOPE_SYMBYTES)];
        }
    }


    poly test_m2;

    //poly_frommsg(&test_m2, m_combined);

    //masked_poly_frommsg(&test_m, m);

    //recombine(&p_test_m, &test_m);

    //poly_tomsg(m_dec, &p_test_m);

    //poly_tomsg(m_dec, &test_m2);
    /*Masked temp1;
    for(int k=0; k <= MASKING_ORDER; k ++) {
        temp1.shares[k] = (-((m[0 + k * (NEWHOPE_SYMBYTES)] >> 0) & 1)) & (NEWHOPE_Q / 2);
    }

    uint16_t tval = 0;
    for(int j = 0; j <= MASKING_ORDER; j++){
        tval ^= temp1.shares[j];
    }

    unsigned int mask;
    mask = -((m_combined[0] >> 0)&1) & (NEWHOPE_Q / 2);

    printf("Before: %d, After dec: %d \n", tval, mask);*/


    //recombine(&p_test_m, &test_m);
    //poly_frommsg(&test_m2, m_combined);

    //poly_tomsg(m_dec, &p_test_m);
    //printf("What is this %d \n", -(1 & 1) & (NEWHOPE_Q/2));

    randombytes(coin,NEWHOPE_SYMBYTES * (MASKING_ORDER+1));

    for(int i = 0; i<32; i++){
        printf("Message index %d, Combined: %d \n", i, m_combined[i]);
    }

    masked_cpapke_keypair(pk, sk);

    masked_cpapke_enc(c, m, pk, coin);

    masked_cpapke_dec(m_dec, c, sk);

    for(int i = 0; i<32; i++){
        printf("Message index %d, Before: %d, After dec: %d \n", i, m_combined[i], m_dec[i]);
    }
}
