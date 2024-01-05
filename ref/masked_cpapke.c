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

// To be relegated to masking_gadgets.c later
void masked_sample(poly *r, const unsigned char *seed, unsigned char nonce){
#if NEWHOPE_K != 8
#error "poly_sample in poly.c only supports k=8"
#endif
    unsigned char buf[128], a, b;
    int i,j;

    unsigned char extseed[NEWHOPE_SYMBYTES+2];

    for(i=0;i<NEWHOPE_SYMBYTES;i++)
        extseed[i] = seed[i];
    extseed[NEWHOPE_SYMBYTES] = nonce;

    for(i=0;i<NEWHOPE_N/64;i++) /* Generate noise in blocks of 64 coefficients */
    {
        extseed[NEWHOPE_SYMBYTES+1] = i;
        shake256(buf,128,extseed,NEWHOPE_SYMBYTES+2);
        for(j=0;j<64;j++)
        {
            a = buf[2*j];
            b = buf[2*j+1];
            r->coeffs[64*i+j] = hw(a) + NEWHOPE_Q - hw(b);
        }
    }
}

void masked_cpapke_keypair(unsigned char *pk, unsigned char *sk){
    poly ahat, ehat, ahat_shat, bhat, shat;
    unsigned char z[2*NEWHOPE_SYMBYTES];
    unsigned char *publicseed = z;
    unsigned char *noiseseed = z+NEWHOPE_SYMBYTES;

    z[0] = 0x01;
    randombytes(z+1, NEWHOPE_SYMBYTES);
    shake256(z, 2*NEWHOPE_SYMBYTES, z, NEWHOPE_SYMBYTES + 1);

    gen_a(&ahat, publicseed);

    masked_sample(&shat, noiseseed, 0);
    poly_ntt(&shat);

    masked_sample(&ehat, noiseseed, 1);
    poly_ntt(&ehat);

    poly_mul_pointwise(&ahat_shat, &shat, &ahat);
    poly_add(&bhat, &ehat, &ahat_shat);

    poly_tobytes(sk, &shat);
    encode_pk(pk, &bhat, publicseed);
}

void masked_cpapke_enc(unsigned char *c, const unsigned char *m, const unsigned char *pk, const unsigned char *coins){

}

void masked_cpapke_dec(unsigned char *m, const unsigned char *c, const unsigned char *sk){

}