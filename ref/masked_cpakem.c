
#include "masked_cpakem.h"
#include "masked_cpapke.h"
#include "randombytes.h"
#include "masked_fips202.h"

// Masked keypair generation for the CPAKEM
int masked_keypair(unsigned char *pk, unsigned char *sk)
{
    masked_cpapke_keypair(pk, sk);

    return 0;
}


// Masked encapsulation for the CPAKEM
int masked_encaps(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
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


// Masked decapsulation for the CPAKEM
int masked_decaps(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{
    masked_cpapke_dec(ss, ct, sk);

    // The masked hash function is not necessary if we are not using the masked decode
    //shake256_masked(ss, NEWHOPE_SYMBYTES, ss, NEWHOPE_SYMBYTES);

    shake256(ss, NEWHOPE_SYMBYTES, ss, NEWHOPE_SYMBYTES);

    return 0;
}
