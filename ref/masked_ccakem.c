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


// TODO: Needs testing
int masked_CCA_encaps(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{
    unsigned char coin[(NEWHOPE_SYMBYTES+1)*(MASKING_ORDER+1)];
    unsigned char coin_prime[NEWHOPE_SYMBYTES*(MASKING_ORDER+1)];
    unsigned char m[NEWHOPE_SYMBYTES*(MASKING_ORDER+1)];
    unsigned char pk_masked[NEWHOPE_SYMBYTES*(MASKING_ORDER+1)];
    unsigned char pk_hash[NEWHOPE_SYMBYTES*(MASKING_ORDER+1)];
    unsigned char hash_buf[3*NEWHOPE_SYMBYTES*(MASKING_ORDER+1)];
    unsigned char input_buf[(2*NEWHOPE_SYMBYTES + 1)*(MASKING_ORDER+1)];
    unsigned char last_hash_input[2*NEWHOPE_SYMBYTES*(MASKING_ORDER+1)];

    for(int i = 0; i <= MASKING_ORDER; i++){
        randombytes(coin+1 + i*(NEWHOPE_SYMBYTES) + 1*i,NEWHOPE_SYMBYTES);
        coin[i*(NEWHOPE_SYMBYTES+1)] = 0;
    }
    coin[0] = 0x04;

    for(int i = 0; i < NEWHOPE_SYMBYTES; i++){
        pk_masked[i] = pk[i];
    }

    for(int i = 1; i <= MASKING_ORDER; i++) {
        for (int j = 0; j < NEWHOPE_SYMBYTES; j++) {
            pk_masked[j + i*NEWHOPE_SYMBYTES] = 0;
        }
    }

    shake256_masked(pk_hash,NEWHOPE_SYMBYTES,pk_masked,NEWHOPE_SYMBYTES);

    for(int i = 0; i <= MASKING_ORDER; i++){
        for (int j = 0; j < NEWHOPE_SYMBYTES; j++) {
            input_buf[j + i*2*NEWHOPE_SYMBYTES + 1*i + 1] = m[j + i*NEWHOPE_SYMBYTES];
            input_buf[j + i*2*NEWHOPE_SYMBYTES + 1*i + 1 + NEWHOPE_SYMBYTES] = pk_hash[j + i*NEWHOPE_SYMBYTES];
        }
        input_buf[i*(NEWHOPE_SYMBYTES*2+1)] = 0;
    }
    input_buf[0] = 0x08;

    shake256_masked(hash_buf,3*NEWHOPE_SYMBYTES,input_buf,2*NEWHOPE_SYMBYTES + 1);

    for (int j = 0; j < NEWHOPE_SYMBYTES; j++) {
        ct[j + NEWHOPE_SYMBYTES + NEWHOPE_CPAPKE_CIPHERTEXTBYTES] = 0;
        for(int i = 0; i <= MASKING_ORDER; i++){
            last_hash_input[j + i*2*NEWHOPE_SYMBYTES] = hash_buf[j + 3*i*NEWHOPE_SYMBYTES];
            last_hash_input[j + i*2*NEWHOPE_SYMBYTES + NEWHOPE_SYMBYTES] = 0;
            coin_prime[j + i*NEWHOPE_SYMBYTES] = hash_buf[j + 3*i*NEWHOPE_SYMBYTES + NEWHOPE_SYMBYTES];
            ct[j + NEWHOPE_SYMBYTES + NEWHOPE_CPAPKE_CIPHERTEXTBYTES] ^= hash_buf[j + 3*i*NEWHOPE_SYMBYTES + 2*NEWHOPE_SYMBYTES];
        }
    }

    masked_cpapke_enc(ct, m, pk, coin_prime);

    // Here the regular shake 256 is used since the term c||d(The input here) is not.
    shake256(last_hash_input+NEWHOPE_SYMBYTES, 32,  ct, NEWHOPE_CCAKEM_CIPHERTEXTBYTES);

    shake256_masked(ss, NEWHOPE_SYMBYTES, last_hash_input, 2*NEWHOPE_SYMBYTES);

    return 0;
}


// TODO: Implement Masked decapsulation for the CCAKEM
int masked_CCA_decaps(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{
    masked_cpapke_dec(ss, ct, sk);

    shake256_masked(ss, NEWHOPE_SYMBYTES, ss, NEWHOPE_SYMBYTES);

    return 0;
}
