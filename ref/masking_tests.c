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
            m_combined[i] ^= m[i + (j*MASKING_ORDER)];
        }
    }

    test_from_message(m, &test_m);

    recombine(&p_test_m, &test_m);

    poly_tomsg(m_dec, &p_test_m);


    /*randombytes(coin,NEWHOPE_SYMBYTES * (MASKING_ORDER+1));

    for(int i = 0; i < 32; i++){
        for(int j = 0; j <= MASKING_ORDER; j++){
            m_combined[i] = m_combined[i] + m[i + (j*MASKING_ORDER)] % NEWHOPE_Q;
        }
    }

    for(int i = 0; i<32; i++){
        printf("Message index %d, Combined: %d \n", i, m_combined[i]);
    }

    masked_cpapke_keypair(pk, sk);

    masked_cpapke_enc(c, m, pk, coin);

    masked_cpapke_dec(m_dec, c, sk);*/

    for(int i = 0; i<32; i++){
        printf("Message index %d, Before: %d, After dec: %d \n", i, m_combined[i], m_dec[i]);
    }
}
