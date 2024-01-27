#include "masked_ccakem.h"
#include "masked_cpapke.h"
#include "randombytes.h"
#include "masked_fips202.h"
#include "masking_gadgets.h"


void fill_final_array(unsigned char* final, unsigned char* input){
    for (int j = 0; j < NEWHOPE_SYMBYTES; j++) {
        for(int i = 0; i <= MASKING_ORDER; i++){
            final[j + i*2*NEWHOPE_SYMBYTES] = input[j + i*NEWHOPE_SYMBYTES];
            // Set the second part of the final buffer to 0, since the content will be unmasked, so we only
            // have to overwrite the first part later.
            final[j + i*2*NEWHOPE_SYMBYTES + NEWHOPE_SYMBYTES] = 0;
        }
    }
}

// Masked keypair generation for the CCAKEM
int masked_CCA_keypair(unsigned char *pk, unsigned char *skh){

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
    unsigned char pk_masked[NEWHOPE_CCAKEM_PUBLICKEYBYTES*(MASKING_ORDER+1)];
    unsigned char pk_hash[NEWHOPE_SYMBYTES*(MASKING_ORDER+1)];
    unsigned char hash_buf[3*NEWHOPE_SYMBYTES*(MASKING_ORDER+1)];
    unsigned char input_buf[(2*NEWHOPE_SYMBYTES + 1)*(MASKING_ORDER+1)];
    unsigned char last_hash_input[2*NEWHOPE_SYMBYTES*(MASKING_ORDER+1)];

    for(int i = 0; i <= MASKING_ORDER; i++){
        randombytes(coin+1 + i*(NEWHOPE_SYMBYTES) + 1*i,NEWHOPE_SYMBYTES);
        coin[i*(NEWHOPE_SYMBYTES+1)] = 0;
    }
    coin[0] = 0x04;

    for(int i = 0; i < NEWHOPE_CCAKEM_PUBLICKEYBYTES; i++){
        pk_masked[i] = pk[i];
    }

    for(int i = 1; i <= MASKING_ORDER; i++) {
        for (int j = 0; j < NEWHOPE_CCAKEM_PUBLICKEYBYTES; j++) {
            pk_masked[j + i*NEWHOPE_SYMBYTES] = 0;
        }
    }

    shake256_masked(pk_hash,NEWHOPE_SYMBYTES,pk_masked,NEWHOPE_CCAKEM_PUBLICKEYBYTES);

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
        ct[j + NEWHOPE_CPAPKE_CIPHERTEXTBYTES] = 0;
        for(int i = 0; i <= MASKING_ORDER; i++){
            last_hash_input[j + i*2*NEWHOPE_SYMBYTES] = hash_buf[j + 3*i*NEWHOPE_SYMBYTES];
            // Set the second part of the last_hash_input buffer to 0, since the content will be unmasked, so we only
            // have to overwrite the first part later.
            last_hash_input[j + i*2*NEWHOPE_SYMBYTES + NEWHOPE_SYMBYTES] = 0;
            coin_prime[j + i*NEWHOPE_SYMBYTES] = hash_buf[j + 3*i*NEWHOPE_SYMBYTES + NEWHOPE_SYMBYTES];
            ct[j + NEWHOPE_CPAPKE_CIPHERTEXTBYTES] ^= hash_buf[j + 3*i*NEWHOPE_SYMBYTES + 2*NEWHOPE_SYMBYTES];
        }
    }

    masked_cpapke_enc(ct, m, pk, coin_prime);

    // Here the regular shake 256 is used since the term c||d(The input here) is not masked.
    shake256(last_hash_input+NEWHOPE_SYMBYTES, 32,  ct, NEWHOPE_CCAKEM_CIPHERTEXTBYTES);

    shake256_masked(ss, NEWHOPE_SYMBYTES, last_hash_input, 2*NEWHOPE_SYMBYTES);

    return 0;
}


// TODO: Implement Masked decapsulation for the CCAKEM
int masked_CCA_decaps(unsigned char *ss, const unsigned char *ct, const unsigned char *skh)
{
    poly uhat, vprime;
    masked_poly m_uhat, m_vprime, uhat_diff;
    unsigned char c[NEWHOPE_CPAPKE_CIPHERTEXTBYTES];

    unsigned char coin_prime_prime[NEWHOPE_SYMBYTES*(MASKING_ORDER+1)];
    unsigned char sk[NEWHOPE_CPAPKE_SECRETKEYBYTES * (MASKING_ORDER+1)];
    unsigned char pk[NEWHOPE_CCAKEM_PUBLICKEYBYTES];
    unsigned char h[NEWHOPE_SYMBYTES*(MASKING_ORDER+1)];
    unsigned char s[NEWHOPE_SYMBYTES*(MASKING_ORDER+1)];
    unsigned char k_prime[NEWHOPE_SYMBYTES*(MASKING_ORDER+1)];
    unsigned char m_prime[NEWHOPE_SYMBYTES*(MASKING_ORDER+1)];
    unsigned char input_buf[(2*NEWHOPE_SYMBYTES + 1)*(MASKING_ORDER+1)];
    unsigned char hash_buf[3*NEWHOPE_SYMBYTES*(MASKING_ORDER+1)];
    unsigned char last_hash_input[2*NEWHOPE_SYMBYTES*(MASKING_ORDER+1)];
    int start;

    // Get the regular secret key out of skh, secret key is in masked form
    for(int j = 0; j <= MASKING_ORDER; j++){
        for(int i = 0; i < NEWHOPE_CPAPKE_SECRETKEYBYTES; i++){
            sk[i + j*(NEWHOPE_CPAPKE_SECRETKEYBYTES)] = skh[i + j*(NEWHOPE_CPAPKE_SECRETKEYBYTES)];
        }
    }

    start = (MASKING_ORDER+1)*(NEWHOPE_CPAPKE_SECRETKEYBYTES);

    // Get the public key out of skh, public key is not in masked form
    for(int i = 0; i < NEWHOPE_CCAKEM_PUBLICKEYBYTES; i++){
        pk[i] = skh[i + start];
    }

    start += NEWHOPE_CCAKEM_PUBLICKEYBYTES;

    // Get h out of skh, h is in masked form
    for(int j = 0; j <= MASKING_ORDER; j++){
        for(int i = 0; i < NEWHOPE_SYMBYTES; i++){
            h[i + j*(NEWHOPE_SYMBYTES)] = skh[i + j*(NEWHOPE_SYMBYTES) + start];
        }
    }

    start += (MASKING_ORDER+1) * NEWHOPE_SYMBYTES;

    // Get s out of skh, s is in masked form
    for(int j = 0; j <= MASKING_ORDER; j++){
        for(int i = 0; i < NEWHOPE_SYMBYTES; i++){
            s[i + j*(NEWHOPE_SYMBYTES)] = skh[i + j*(NEWHOPE_SYMBYTES) + start];
        }
    }

    // Set up the input buffer
    for(int i = 0; i <= MASKING_ORDER; i++){
        for (int j = 0; j < NEWHOPE_SYMBYTES; j++) {
            input_buf[j + i*2*NEWHOPE_SYMBYTES + 1*i + 1] = m_prime[j + i*NEWHOPE_SYMBYTES];
            input_buf[j + i*2*NEWHOPE_SYMBYTES + 1*i + 1 + NEWHOPE_SYMBYTES] = h[j + i*NEWHOPE_SYMBYTES];
        }
        input_buf[i*(NEWHOPE_SYMBYTES*2+1)] = 0;
    }
    input_buf[0] = 0x08;

    shake256_masked(hash_buf,3*NEWHOPE_SYMBYTES,input_buf,2*NEWHOPE_SYMBYTES + 1);

    // Take k_prime and coin_prime_prime out of hash_buf
    for (int j = 0; j < NEWHOPE_SYMBYTES; j++) {
        for(int i = 0; i <= MASKING_ORDER; i++){
            k_prime[j + i*NEWHOPE_SYMBYTES] = hash_buf[j + 3*i*NEWHOPE_SYMBYTES];
            coin_prime_prime[j + i*NEWHOPE_SYMBYTES] = hash_buf[j + 3*i*NEWHOPE_SYMBYTES + NEWHOPE_SYMBYTES];
        }
    }

    // decrypt the given c
    masked_cpapke_dec(m_prime, ct, sk);

    // re-encrypt the m_prime we got, this encryption does not encode the ciphertext and directly returns the masked
    // polynomials
    masked_cpapke_enc2(&m_vprime, &m_uhat, m_prime, pk, coin_prime_prime);

    // decode the given c back into its polynomials to compare against the re-encrypted message
    decode_c(&uhat, &vprime, c);

    // Substract the uhat that was given from the one we calculated, then see if it is equal to zero, checking only
    // uhat should be sufficient for verification.
    masked_poly_sub(&uhat_diff, &m_uhat, &uhat);

    // Currently this only works for NEWHOPE_N = 1024
    if(polyZeroTestExpo(8, NEWHOPE_N, &uhat_diff)){
        fill_final_array(last_hash_input, k_prime);
    } else {
        fill_final_array(last_hash_input, s);
    }

    // Here the regular shake 256 is used since the term c||d(The input here) is not masked.
    shake256(last_hash_input+NEWHOPE_SYMBYTES, 32,  ct, NEWHOPE_CCAKEM_CIPHERTEXTBYTES);

    shake256_masked(ss, NEWHOPE_SYMBYTES, last_hash_input, 2*NEWHOPE_SYMBYTES);

    return 0;
}
