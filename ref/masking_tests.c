#include <stdio.h>
#include "poly.h"
#include "randombytes.h"
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
    unsigned char c_masked[NEWHOPE_CPAPKE_CIPHERTEXTBYTES * (MASKING_ORDER+1)];
    unsigned char m[NEWHOPE_SYMBYTES * (MASKING_ORDER+1)];
    unsigned char m_combined[NEWHOPE_SYMBYTES];
    unsigned char m_dec[NEWHOPE_SYMBYTES * (MASKING_ORDER+1)];
    unsigned char m_dec_combined[NEWHOPE_SYMBYTES];
    unsigned char coin[NEWHOPE_SYMBYTES];

    /*
    // Test the first version of the cpapke enc and dec functions (The ones to be used in the CPA KEM)
    randombytes(m,NEWHOPE_SYMBYTES * (MASKING_ORDER+1));
    randombytes(coin,NEWHOPE_SYMBYTES);

    for(int i = 0; i < 32; i++){
        for(int j = 0; j <= MASKING_ORDER; j++){
            m_combined[i] ^= m[i + (j*NEWHOPE_SYMBYTES)];
        }
    }

    for(int i = 0; i<32; i++){
        printf("Message index %d, Combined: %d \n", i, m_combined[i]);
    }

    masked_cpapke_keypair(pk, sk);

    masked_cpapke_enc(c, m, pk, coin);

    masked_cpapke_dec(m_dec, c, sk);

    for(int i = 0; i < 32; i++){
        for(int j = 0; j <= MASKING_ORDER; j++){
            m_dec_combined[i] ^= m_dec[i + (j*NEWHOPE_SYMBYTES)];
        }
    }

    for(int i = 0; i<32; i++){
        printf("Message index %d, Before: %d, After dec: %d \n", i, m_combined[i], m_dec_combined[i]);
    }*/

    // Test the second version of the cpapke enc and dec functions (The ones to be used in the CCA KEM)
    randombytes(m,NEWHOPE_SYMBYTES * (MASKING_ORDER+1));
    randombytes(coin,NEWHOPE_SYMBYTES);

    for(int i = 0; i < 32; i++){
        for(int j = 0; j <= MASKING_ORDER; j++){
            m_combined[i] ^= m[i + (j*NEWHOPE_SYMBYTES)];
        }
    }

    for(int i = 0; i<32; i++){
        printf("Message index %d, Combined: %d \n", i, m_combined[i]);
    }

    masked_cpapke_keypair(pk, sk);

    masked_cpapke_enc2(c_masked, m, pk, coin);

    masked_cpapke_dec2(m_dec, c_masked, sk);

    for(int i = 0; i < 32; i++){
        for(int j = 0; j <= MASKING_ORDER; j++){
            m_dec_combined[i] ^= m_dec[i + (j*NEWHOPE_SYMBYTES)];
        }
    }

    for(int i = 0; i<32; i++){
        printf("Message index %d, Before: %d, After dec: %d \n", i, m_combined[i], m_dec_combined[i]);
    }
}
