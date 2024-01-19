#include "masked_ccakem.h"
#include "masked_cpapke.h"
#include "randombytes.h"
#include "masked_fips202.h"

// Masked keypair generation for the CCAKEM
int masked_CCA_keypair(unsigned char *pk, unsigned char *skh)
{
    // temp value needed to test
    //int temp = (MASKING_ORDER+1) * (NEWHOPE_CPAPKE_SECRETKEYBYTES + 2*NEWHOPE_SYMBYTES) + NEWHOPE_CPAPKE_PUBLICKEYBYTES;
    unsigned char sk[NEWHOPE_CPAPKE_SECRETKEYBYTES * (MASKING_ORDER+1)];
    unsigned char s[NEWHOPE_SYMBYTES * (MASKING_ORDER+1)];
    unsigned char t[NEWHOPE_SYMBYTES * (MASKING_ORDER+1)];
    unsigned char pk_mask[NEWHOPE_CCAKEM_PUBLICKEYBYTES * (MASKING_ORDER+1)] = {0};

    // Start by putting the secret key at the beginning of skh (in masked form)
    masked_cpapke_keypair(pk, skh);

    // Increment the pointer of skh behind the secret key
    skh += NEWHOPE_CPAPKE_SECRETKEYBYTES * (MASKING_ORDER+1);

    for(int i = 0; i < NEWHOPE_CCAKEM_PUBLICKEYBYTES; i++){
        // Append the public key to skh
        skh[i] = pk[i];
        // Set the first share of pk_mask to the public key, all the other shares are kept at zero
        pk_mask[i] = pk[i];
    }

    // Increment the pointer of skh behind the public key
    skh += NEWHOPE_CCAKEM_PUBLICKEYBYTES;

    // Append the hash of the public key to skh
    shake256_masked(skh, NEWHOPE_SYMBYTES, pk_mask, NEWHOPE_CCAKEM_PUBLICKEYBYTES);

    // Increment the pointer of skh behind the hash
    skh += NEWHOPE_SYMBYTES * (MASKING_ORDER+1);

    // Lastly append the randomly generated s
    randombytes(skh, NEWHOPE_SYMBYTES * (MASKING_ORDER+1));

    return 0;
}


// TODO: Implement Masked encapsulation for the CCAKEM
int masked_CCA_encaps(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{
    unsigned char buf[2*NEWHOPE_SYMBYTES*(MASKING_ORDER+1)];

    for(int i = 0; i <= MASKING_ORDER; i++){
        randombytes(buf+1 + i*(NEWHOPE_SYMBYTES) + 1*i,NEWHOPE_SYMBYTES);
        buf[i*(NEWHOPE_SYMBYTES+1)] = 0;
    }
    buf[0] = 0x02;

    shake256_masked(buf,2*NEWHOPE_SYMBYTES,buf,NEWHOPE_SYMBYTES + 1);

    masked_cpapke_enc(ct, buf, pk, buf+NEWHOPE_SYMBYTES*(MASKING_ORDER+1));

    shake256_masked(ss, NEWHOPE_SYMBYTES, buf, NEWHOPE_SYMBYTES);

    return 0;
}


// TODO: Implement Masked decapsulation for the CCAKEM
int masked_CCA_decaps(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{
    masked_cpapke_dec(ss, ct, sk);

    shake256_masked(ss, NEWHOPE_SYMBYTES, ss, NEWHOPE_SYMBYTES);

    return 0;
}
