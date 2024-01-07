#include "masked_cpapke.h"
#include "poly.h"
#include "randombytes.h"
#include "fips202.h"
#include "masking_gadgets.h"

// Copied from cpapke.c
static void encode_pk(unsigned char *r, const poly *pk, const unsigned char *seed)
{
    int i;
    poly_tobytes(r, pk);
    for(i=0;i<NEWHOPE_SYMBYTES;i++)
        r[NEWHOPE_POLYBYTES+i] = seed[i];
}

// Copied from cpapke.c
static void decode_pk(poly *pk, unsigned char *seed, const unsigned char *r)
{
    int i;
    poly_frombytes(pk, r);
    for(i=0;i<NEWHOPE_SYMBYTES;i++)
        seed[i] = r[NEWHOPE_POLYBYTES+i];
}

// Copied from cpapke.c
static void encode_c(unsigned char *r, const poly *b, const poly *v)
{
    poly_tobytes(r,b);
    poly_compress(r+NEWHOPE_POLYBYTES,v);
}

// Copied from cpapke.c
static void decode_c(poly *b, poly *v, const unsigned char *r)
{
    poly_frombytes(b, r);
    poly_decompress(v, r+NEWHOPE_POLYBYTES);
}

// Copied from cpapke.c
static void gen_a(poly *a, const unsigned char *seed)
{
    poly_uniform(a,seed);
}

//TODO: Make these functions static

// Applying the NTT to every share of a polynomial
void NTT_masked_poly(masked_poly *a){
    for(int i = 0; i <= MASKING_ORDER; i++){
        poly_ntt(&(a->poly_shares[i]));
    }
}

// Applying the reverse NTT to every share of a polynomial
void reverse_NTT_masked_poly(masked_poly *a){
    for(int i = 0; i <= MASKING_ORDER; i++){
        poly_invntt(&(a->poly_shares[i]));
    }
}

// Multiply a masked poly with a non-masked polynomial, both in the NTT domain
void masked_poly_mul(masked_poly *r, const masked_poly *a, const poly *b){
    for(int i = 0; i <= MASKING_ORDER; i++){
        poly_mul_pointwise(&r->poly_shares[i], &a->poly_shares[i], b);
    }
}

// Addition of two masked polynomials
void masked_poly_add(masked_poly *r, const masked_poly *a, const masked_poly *b){
    for(int i = 0; i <= MASKING_ORDER; i++){
        poly_add(&r->poly_shares[i], &a->poly_shares[i], &b->poly_shares[i]);
    }
}

// Substraction of an unmasked polynomial from a masked one
void masked_poly_sub(masked_poly *r, const masked_poly *a, const poly *b){
    poly_sub(&r->poly_shares[0], &a->poly_shares[0], b);
    for(int i = 1; i <= MASKING_ORDER; i++){
        r->poly_shares[i] = a->poly_shares[i];
    }
}

// Recombine the shares of a (arithmetically) masked polynomial into the polynomial
void recombine(poly *r, const masked_poly *a){
    for(int i = 0; i<NEWHOPE_N; i++){
        uint16_t coeff_i = 0;
        for(int j = 0; j <= MASKING_ORDER; j++){
            coeff_i = (coeff_i + a->poly_shares[j].coeffs[i]) % NEWHOPE_Q;
        }
        r->coeffs[i] = coeff_i;
    }
}

// Transform masked polynomial into byte array
void masked_poly_tobytes(unsigned char *r, const masked_poly *p){
    for(int i = 0; i <= MASKING_ORDER; i++){
        poly_tobytes(r+(NEWHOPE_CPAPKE_PUBLICKEYBYTES*i), &(p->poly_shares[i]));
    }
}

// Transform byte array into masked polynomial
void masked_poly_frombytes(masked_poly *r, const unsigned char *a){
    for(int i = 0; i <= MASKING_ORDER; i++){
        poly_frombytes(&(r->poly_shares[i]), a+(NEWHOPE_CPAPKE_PUBLICKEYBYTES*i));
    }
}

// Get a polynomial from a (MASKING_ORDER+1)*32 Byte masked message.
// Assuming every 32 bytes represent 1 share of the message and that it is in boolean masked form.
void masked_poly_frommsg(masked_poly *r, const unsigned char *msg){
    Masked temp1;
    Masked temp2;
    for(int i=0;i<32;i++) // XXX: MACRO for 32
    {
        for(int j=0;j<8;j++)
        {
            for(int k=0; k <= MASKING_ORDER; k ++){
                temp1.shares[k] = (-((msg[i+k*(NEWHOPE_SYMBYTES)] >> j)&1)) & (NEWHOPE_Q/2);
            }
            opti_B2A(&temp2, &temp1, 16);

            for(int k=0; k <= MASKING_ORDER; k ++) {
                r->poly_shares[k].coeffs[8 * i + j + 0] = temp2.shares[k];
                r->poly_shares[k].coeffs[8 * i + j + 256] = temp2.shares[k];
#if (NEWHOPE_N == 1024)
                r->poly_shares[k].coeffs[8 * i + j + 512] = temp2.shares[k];
                r->poly_shares[k].coeffs[8 * i + j + 768] = temp2.shares[k];
#endif
            }
        }
    }
}


void masked_sample(masked_poly *r, const unsigned char *seed, unsigned char nonce){
#if NEWHOPE_K != 8
#error "poly_sample in poly.c only supports k=8"
#endif
    unsigned char buf[128*(MASKING_ORDER+1)];
    Masked a, b;
    int i,j;

    unsigned char extseed[NEWHOPE_SYMBYTES+2];

    for(i=0;i<NEWHOPE_SYMBYTES;i++)
        extseed[i] = seed[i];
    extseed[NEWHOPE_SYMBYTES] = nonce;

    for(i=0;i<NEWHOPE_N/64;i++) /* Generate noise in blocks of 64 coefficients */
    {
        extseed[NEWHOPE_SYMBYTES+1] = i;
        shake256(buf,128*(MASKING_ORDER+1),extseed,NEWHOPE_SYMBYTES+2);
        for(j=0;j<64;j++)
        {
            for(int z = 0; z <= MASKING_ORDER; z++){
                a.shares[z] = buf[2*(MASKING_ORDER+1)*j+z];
                b.shares[z] = buf[2*(MASKING_ORDER+1)*j+MASKING_ORDER+1+z];
            }
            Masked samp;
            masked_binomial_dist(&samp, &a, &b, 16);
            for(int z = 0; z <= MASKING_ORDER; z++) {
                r->poly_shares[z].coeffs[64 * i + j] = samp.shares[z];
            }
        }
    }
}

void masked_cpapke_keypair(unsigned char *pk, unsigned char *sk){
    masked_poly ehat, ahat_shat, bhat, shat;
    poly ahat;
    unsigned char z[2*NEWHOPE_SYMBYTES];
    unsigned char *publicseed = z;
    unsigned char *noiseseed = z+NEWHOPE_SYMBYTES;

    z[0] = 0x01;
    randombytes(z+1, NEWHOPE_SYMBYTES);
    shake256(z, 2*NEWHOPE_SYMBYTES, z, NEWHOPE_SYMBYTES + 1);

    gen_a(&ahat, publicseed);

    masked_sample(&shat, noiseseed, 0);
    NTT_masked_poly(&shat);

    masked_sample(&ehat, noiseseed, 1);
    NTT_masked_poly(&ehat);

    masked_poly_mul(&ahat_shat, &shat, &ahat);
    masked_poly_add(&bhat, &ehat, &ahat_shat);

    masked_poly_tobytes(sk, &shat);

    // Since bhat is the public key we can recombine it at this point, since we don't care to keep it secret
    poly bhat_recomb;
    recombine(&bhat_recomb, &bhat);
    encode_pk(pk, &bhat_recomb, publicseed);
}


void masked_cpapke_enc(unsigned char *c, const unsigned char *m, const unsigned char *pk, const unsigned char *coin){
    poly ahat, bhat, uhat_recomb, vprime_recomb;
    masked_poly sprime, eprime, vprime, eprimeprime, v, uhat;
    unsigned char publicseed[NEWHOPE_SYMBYTES];

    masked_poly_frommsg(&v, m);

    decode_pk(&bhat, publicseed, pk);
    gen_a(&ahat, publicseed);

    masked_sample(&sprime, coin, 0);
    masked_sample(&eprime, coin, 1);
    masked_sample(&eprimeprime, coin, 2);

    NTT_masked_poly(&sprime);
    NTT_masked_poly(&eprime);

    masked_poly_mul(&uhat, &sprime, &ahat);
    masked_poly_add(&uhat, &uhat, &eprime);

    masked_poly_mul(&vprime, &sprime, &bhat);
    reverse_NTT_masked_poly(&vprime);

    masked_poly_add(&vprime, &vprime, &eprimeprime);
    masked_poly_add(&vprime, &vprime, &v); // add message

    // At this point the ciphertext is finished and, at least for the CPA, we don't care to keep the ciphertext in shared form.
    recombine(&uhat_recomb, &uhat);
    recombine(&vprime_recomb, &vprime);

    encode_c(c, &uhat_recomb, &vprime_recomb);
}

void masked_cpapke_dec(unsigned char *m, const unsigned char *c, const unsigned char *sk){
    poly vprime, uhat, tmp_recomb;
    masked_poly shat, tmp;

    // Secret key should still be masked here
    masked_poly_frombytes(&shat, sk);

    decode_c(&uhat, &vprime, c);
    masked_poly_mul(&tmp, &shat, &uhat);
    reverse_NTT_masked_poly(&tmp);

    masked_poly_sub(&tmp, &tmp, &vprime);

    //TODO: Recombine should be done after tomsg, figure out how to perform tomsg on a masked poly.
    recombine(&tmp_recomb, &tmp);
    poly_tomsg(m, &tmp_recomb);
}