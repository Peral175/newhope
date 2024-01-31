#include "masked_cpapke.h"
#include "poly.h"
#include "randombytes.h"
#include "masked_fips202.h"
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
void decode_c(poly *b, poly *v, const unsigned char *r)
{
    poly_frombytes(b, r);
    poly_decompress(v, r+NEWHOPE_POLYBYTES);
}

// Copied from cpapke.c
static void gen_a(poly *a, const unsigned char *seed)
{
    poly_uniform(a,seed);
}

// Applying the NTT to every share of a polynomial
static void NTT_masked_poly(masked_poly *a){
    for(int i = 0; i <= MASKING_ORDER; i++){
        poly_ntt(&(a->poly_shares[i]));
    }
}

// Applying the reverse NTT to every share of a polynomial
static void reverse_NTT_masked_poly(masked_poly *a){
    for(int i = 0; i <= MASKING_ORDER; i++){
        poly_invntt(&(a->poly_shares[i]));
    }
}

// Multiply a masked poly with a non-masked polynomial, both in the NTT domain
static void masked_poly_mul(masked_poly *r, const masked_poly *a, const poly *b){
    for(int i = 0; i <= MASKING_ORDER; i++){
        poly_mul_pointwise(&r->poly_shares[i], &a->poly_shares[i], b);
    }
}

// Addition of two masked polynomials
static void masked_poly_add(masked_poly *r, const masked_poly *a, const masked_poly *b){
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

// Substraction of a masked polynomial from an unmasked one
void masked_poly_sub3(masked_poly *r, const poly *b, const masked_poly *a){
    poly_sub(&r->poly_shares[0], b, &a->poly_shares[0]);
    for(int i = 1; i <= MASKING_ORDER; i++){
        for(int j = 0; j < NEWHOPE_N; j++){
            r->poly_shares[i].coeffs[j] = (-a->poly_shares[i].coeffs[j]) % NEWHOPE_Q;
        }
    }
}

// Recombine the shares of a (arithmetically) masked polynomial into the polynomial
static void recombine(poly *r, const masked_poly *a){
    for(int i = 0; i<NEWHOPE_N; i++){
        uint16_t coeff_i = 0;
        for(int j = 0; j <= MASKING_ORDER; j++){
            coeff_i = (coeff_i + a->poly_shares[j].coeffs[i]) % NEWHOPE_Q;
        }
        r->coeffs[i] = coeff_i;
    }
}

// Transform masked polynomial into byte array
static void masked_poly_tobytes(unsigned char *r, const masked_poly *p){
    for(int i = 0; i <= MASKING_ORDER; i++){
        poly_tobytes(r+(NEWHOPE_CPAPKE_SECRETKEYBYTES*i), &(p->poly_shares[i]));
    }
}

// Transform byte array into masked polynomial
static void masked_poly_frombytes(masked_poly *r, const unsigned char *a){
    for(int i = 0; i <= MASKING_ORDER; i++){
        poly_frombytes(&(r->poly_shares[i]), a+(NEWHOPE_CPAPKE_SECRETKEYBYTES*i));
    }
}

// Get a polynomial from a (MASKING_ORDER+1)*32 Byte masked message.
// Assuming every 32 bytes represent 1 share of the message and that it is in boolean masked form.
static void masked_poly_frommsg(masked_poly *r, const unsigned char *msg){
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


// Helper function to get the difference between two masked values.
// Done by checking which value is smaller first and then substracting it from the larger one
static void helper_abs(Masked *x, Masked *bX, int phi){
    if(SecLeq_unmasked_res(bX, phi, 16) == 1){
        x->shares[0] = ((phi + NEWHOPE_Q) - (x->shares[0] % NEWHOPE_Q)) % NEWHOPE_Q;
        for(int i = 1; i <= MASKING_ORDER; i++){
            x->shares[i] = ((0 + NEWHOPE_Q) - (x->shares[i] % NEWHOPE_Q)) % NEWHOPE_Q;
        }
        //arith_refresh(x, NEWHOPE_Q);
    } else {
        x->shares[0] = ((x->shares[0] + NEWHOPE_Q) - phi) % NEWHOPE_Q;
    }
}

// Masked version of the poly_tomsg function, currently only works for NEWHOPE_N = 1024
static void masked_poly_tomsg(unsigned char *msg, const masked_poly *x) {
    Masked t, t1, t2, t3, t4, Bt1, Bt2, Bt3, Bt4, final_res;
    CompMasked c1, c2, c3, c4, sum1, sum2, sum3;

    for(int i = 0; i < 32 * (MASKING_ORDER+1); i++) {
        msg[i] = 0;
    }

    for(int i = 0; i < 256; i++){

        for(int j = 0; j <= MASKING_ORDER; j++){
            t.shares[j] = 0;
            t1.shares[j] = x->poly_shares[j].coeffs[i + 0] % NEWHOPE_Q;
            t2.shares[j] = x->poly_shares[j].coeffs[i + 256] % NEWHOPE_Q;
            t3.shares[j] = x->poly_shares[j].coeffs[i + 512] % NEWHOPE_Q;
            t4.shares[j] = x->poly_shares[j].coeffs[i + 768] % NEWHOPE_Q;
        }

        A2B(&Bt1, &t1);
        A2B(&Bt2, &t2);
        A2B(&Bt3, &t3);
        A2B(&Bt4, &t4);

        int phi = (NEWHOPE_Q-1)/2;
        helper_abs(&t1, &Bt1, phi);
        helper_abs(&t2, &Bt2, phi);
        helper_abs(&t3, &Bt3, phi);
        helper_abs(&t4, &Bt4, phi);

        A2B(&Bt1, &t1);
        A2B(&Bt2, &t2);
        A2B(&Bt3, &t3);
        A2B(&Bt4, &t4);

        // Swap the new boolean shares over to CompMasked structs (Need more bits)
        for(int j = 0; j <= MASKING_ORDER; j++){
            c1.shares[j] = Bt1.shares[j];
            c2.shares[j] = Bt2.shares[j];
            c3.shares[j] = Bt3.shares[j];
            c4.shares[j] = Bt4.shares[j];
        }

        // Need 17 bits because we would overflow with 16 bits with a masking order of 5 or higher.
        SecAdd(&sum1, &c1, &c2, 17);
        SecAdd(&sum2, &sum1, &c3, 17);
        SecAdd(&sum3, &sum2, &c4, 17);

        SecLeq_masked_res(&final_res, &sum3, NEWHOPE_Q, 17);

        int byte_pos = i >> 3;
        int bit_pos = i - byte_pos * 8;
        for(int j = 0; j <= MASKING_ORDER; j++){
            msg[byte_pos + (j*NEWHOPE_SYMBYTES)] ^= final_res.shares[j] << bit_pos;
        }
    }
}


static void masked_sample(masked_poly *r, const unsigned char *seed, unsigned char nonce){
#if NEWHOPE_K != 8
#error "poly_sample in poly.c only supports k=8"
#endif
    unsigned char buf[128*(MASKING_ORDER+1)];
    Masked a, b;
    int i,j;

    unsigned char extseed[(NEWHOPE_SYMBYTES+2)*(MASKING_ORDER+1)] = {0};

    for(int z = 0; z <= MASKING_ORDER+1; z++){
        for(i=0;i<NEWHOPE_SYMBYTES;i++)
            extseed[i + z*(NEWHOPE_SYMBYTES+2)] = seed[i + z*NEWHOPE_SYMBYTES];
    }
    extseed[NEWHOPE_SYMBYTES] = nonce;

    for(i=0;i<NEWHOPE_N/64;i++) /* Generate noise in blocks of 64 coefficients */
    {
        extseed[NEWHOPE_SYMBYTES+1] = i;

        shake256_masked(buf,128,extseed, NEWHOPE_SYMBYTES+2);
        for(j=0;j<64;j++)
        {
            for(int z = 0; z <= MASKING_ORDER; z++){
                a.shares[z] = buf[2*j + z*128];
                b.shares[z] = buf[2*j + 1 + z*128];
            }
            Masked samp;
            masked_binomial_dist(&samp, &a, &b, 14);
            for(int z = 0; z <= MASKING_ORDER; z++) {
                r->poly_shares[z].coeffs[64 * i + j] = samp.shares[z];
            }
        }
    }
}


void masked_cpapke_keypair(unsigned char *pk, unsigned char *sk){
    masked_poly ehat, ahat_shat, bhat, shat;
    poly ahat;
    unsigned char z[NEWHOPE_SYMBYTES + (MASKING_ORDER + 1) * NEWHOPE_SYMBYTES];
    unsigned char *publicseed = z;
    unsigned char *noiseseed = z+NEWHOPE_SYMBYTES;

    z[0] = 0x01;
    randombytes(z+1, NEWHOPE_SYMBYTES);
    shake256(z, NEWHOPE_SYMBYTES + (MASKING_ORDER + 1) * NEWHOPE_SYMBYTES, z, NEWHOPE_SYMBYTES + 1);

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
    poly vprime, uhat, tmp_comb;
    masked_poly shat, tmp;

    // Secret key should still be masked here
    masked_poly_frombytes(&shat, sk);

    decode_c(&uhat, &vprime, c);
    masked_poly_mul(&tmp, &shat, &uhat);
    reverse_NTT_masked_poly(&tmp);

    // It seems like it doesn't matter which one you substract from which, the decoding will get you the correct message back in both cases
    masked_poly_sub(&tmp, &tmp, &vprime);
    //masked_poly_sub3(&tmp, &vprime, &tmp);

    // masked_poly_tomsg is much too inefficient, for now we will unmask before calling the regular tomsg, this is of
    // course not secure, however the overhead is too great to be practical as of now
    //masked_poly_tomsg(m, &tmp);

    recombine(&tmp_comb, &tmp);
    poly_tomsg(m, &tmp_comb);
}

// Encode the ciphertext while it is still in masked form
static void masked_encode_c(unsigned char *r, const masked_poly *b, const masked_poly *v){
    for(int i = 0; i <= MASKING_ORDER; i++){
        encode_c(r + (NEWHOPE_CPAPKE_CIPHERTEXTBYTES*i), &b->poly_shares[i], &v->poly_shares[i]);
    }
}

// Decode a masked ciphertext
static void masked_decode_c(masked_poly *b, masked_poly *v, const unsigned char *r) {
    for(int i = 0; i <= MASKING_ORDER; i++){
        decode_c(&b->poly_shares[i], &v->poly_shares[i], r + (NEWHOPE_CPAPKE_CIPHERTEXTBYTES*i));
    }
}

// Substraction of a masked polynomial from another masked polynomial
static void masked_poly_sub2(masked_poly *r, const masked_poly *a, const masked_poly *b){
    for(int i = 0; i <= MASKING_ORDER; i++){
        poly_sub(&r->poly_shares[i], &a->poly_shares[i], &b->poly_shares[i]);
    }
}

// Multiply a masked poly with a non-masked polynomial, both in the NTT domain
static void masked_poly_mul2(masked_poly *r, const masked_poly *a, const masked_poly *b){
    Masked temp1;
    Masked temp2;
    Masked res;
    for(int i = 0; i < NEWHOPE_N; i++){
        for(int j = 0; j <= MASKING_ORDER; j++){
            temp1.shares[j] = a->poly_shares[j].coeffs[i];
            temp2.shares[j] = b->poly_shares[j].coeffs[i];
        }
        SecMult(&res, &temp1, &temp2);

        for(int j = 0; j <= MASKING_ORDER; j++){
            r->poly_shares[j].coeffs[i] = res.shares[j];
        }
    }
}

// Version of the masked encryption that keeps the ciphertext masked but doesn't encode it at the end, and instead
// returns the two masked polynomials that make up the ciphertext as they are,used in the CCA decapsulation
void masked_cpapke_enc2(masked_poly *vprime, masked_poly *uhat, const unsigned char *m, const unsigned char *pk, const unsigned char *coin){
    poly ahat, bhat;
    masked_poly sprime, eprime, eprimeprime, v;
    unsigned char publicseed[NEWHOPE_SYMBYTES];

    masked_poly_frommsg(&v, m);

    decode_pk(&bhat, publicseed, pk);
    gen_a(&ahat, publicseed);

    masked_sample(&sprime, coin, 0);
    masked_sample(&eprime, coin, 1);
    masked_sample(&eprimeprime, coin, 2);

    NTT_masked_poly(&sprime);
    NTT_masked_poly(&eprime);

    masked_poly_mul(uhat, &sprime, &ahat);
    masked_poly_add(uhat, uhat, &eprime);

    masked_poly_mul(vprime, &sprime, &bhat);
    reverse_NTT_masked_poly(vprime);

    masked_poly_add(vprime, vprime, &eprimeprime);
    masked_poly_add(vprime, vprime, &v); // add message

    //masked_encode_c(c, &uhat, &vprime);
}


// Version of the masked decryption that takes the ciphertext still masked but not encoded, only used for testing
void masked_cpapke_dec2(unsigned char *m, const masked_poly *vprime, const masked_poly *uhat, const unsigned char *sk){
    masked_poly shat, tmp;

    masked_poly_frombytes(&shat, sk);

    //masked_decode_c(&uhat, &vprime, c);

    masked_poly_mul2(&tmp, &shat, uhat);
    reverse_NTT_masked_poly(&tmp);

    masked_poly_sub2(&tmp, &tmp, vprime);

    masked_poly_tomsg(m, &tmp);
}