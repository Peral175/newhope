#include <stdio.h>
#include "poly.h"
#include "randombytes.h"
#include "masking_gadgets.h"
#include "masked_cpapke.h"
#include <stdlib.h>
#include "masked_fips202.h"
#include "masked_cpakem.h"
#include "masked_ccakem.h"
#include "cpucycles.h"

#define ITER 100

static void gen_a(poly *a, const unsigned char *seed)
{
    poly_uniform(a,seed);
}

int main(int argc, char *argv[]){
    unsigned char pk[NEWHOPE_CPAPKE_PUBLICKEYBYTES];
    unsigned char sk[NEWHOPE_CPAPKE_SECRETKEYBYTES * (MASKING_ORDER+1)];
    unsigned char c[NEWHOPE_CPAPKE_CIPHERTEXTBYTES];
    unsigned char ct[NEWHOPE_CPAPKE_CIPHERTEXTBYTES + NEWHOPE_SYMBYTES];
    unsigned char m[NEWHOPE_SYMBYTES * (MASKING_ORDER+1)];
    unsigned char m_combined[NEWHOPE_SYMBYTES];
    unsigned char m_dec[NEWHOPE_SYMBYTES * (MASKING_ORDER+1)];
    unsigned char m_dec_combined[NEWHOPE_SYMBYTES];
    unsigned char coin[NEWHOPE_SYMBYTES * (MASKING_ORDER+1)];
    unsigned char skh[NEWHOPE_CPAPKE_SECRETKEYBYTES * (MASKING_ORDER+1) + NEWHOPE_CCAKEM_PUBLICKEYBYTES + 2*NEWHOPE_SYMBYTES*(MASKING_ORDER+1)];


    // Test the first version of the cpapke enc and dec functions (The ones to be used in the CPA KEM)
    /*randombytes(m,NEWHOPE_SYMBYTES * (MASKING_ORDER+1));
    randombytes(coin,NEWHOPE_SYMBYTES * (MASKING_ORDER+1));

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

    // Test the CPAKEM
    /*randombytes(coin,NEWHOPE_SYMBYTES * (MASKING_ORDER+1));

    masked_keypair(pk, sk);

    // Here the m is an output
    masked_encaps(c, m, pk);

    // Here the m_dec should be the same as m, though we got m from the encaps instead of generating it ourselves
    masked_decaps(m_dec, c, sk);

    for(int i = 0; i < 32; i++){
        for(int j = 0; j <= MASKING_ORDER; j++){
            m_combined[i] ^= m[i + (j*NEWHOPE_SYMBYTES)];
        }
    }

    // This part is not needed when we are not using the masked decode
    for(int i = 0; i < 32; i++){
        for(int j = 0; j <= MASKING_ORDER; j++){
            m_dec_combined[i] ^= m_dec[i + (j*NEWHOPE_SYMBYTES)];
        }
    }

    for(int i = 0; i<32; i++){
        printf("Message index %d, Encaps m: %d, Decaps m %d \n", i, m_combined[i], m_dec[i]);
    }*/

    // Test the CCAKEM
    masked_CCA_keypair(pk, skh);

    // Here the m is an output
    masked_CCA_encaps(ct, m, pk);

    // Here the m_dec should be the same as m, though we got m from the encaps instead of generating it ourselves
    masked_CCA_decaps(m_dec, ct, skh);

    uint64_t start, stop;
    start = cpucycles();

    for (int i = 0; i <= ITER; i++) {
        masked_CCA_decaps(m_dec, ct, skh);
    }

    stop = cpucycles();

    printf("Cpucycles for Masking order %d: %lu\n", MASKING_ORDER, (stop - start) / ITER);

    for(int i = 0; i < 32; i++){
        for(int j = 0; j <= MASKING_ORDER; j++){
            m_combined[i] ^= m[i + (j*NEWHOPE_SYMBYTES)];
        }
    }

    for(int i = 0; i < 32; i++){
        for(int j = 0; j <= MASKING_ORDER; j++){
            m_dec_combined[i] ^= m_dec[i + (j*NEWHOPE_SYMBYTES)];
        }
    }

    for(int i = 0; i<32; i++){
        printf("Message index %d, Encaps m: %d, Decaps m %d \n", i, m_combined[i], m_dec_combined[i]);
    }
    // Testing how the masked hash function works.
    /*unsigned char t1[1 * (MASKING_ORDER+1)];
    unsigned char t2[1 * (MASKING_ORDER+1)];
    unsigned char t3[1 * (MASKING_ORDER+1)];
    Masked m1;
    int m2 = 0;
    int m3 = 0;
    randombytes(m,NEWHOPE_SYMBYTES * (MASKING_ORDER+1));

    for(int i = 0; i <= MASKING_ORDER; i++){
        m1.shares[i] = t1[i];
    }

    shake256_masked(t2, 1, t1, 1);

    boolean_refresh(&m1);

    for(int i = 0; i <= MASKING_ORDER; i++){
        t1[i] = m1.shares[i];
    }

    shake256_masked(t3, 1, t1, 1);

    for(int i = 0; i <= MASKING_ORDER; i++){
        //m2 = (m2 + t2[i]) % NEWHOPE_Q;
        //m3 = (m3 + t3[i]) % NEWHOPE_Q;
        m2 ^= t2[i];
        m3 ^= t3[i];
    }

    printf("Before refresh: %d, After refresh %d\n", m2, m3);*/
}
