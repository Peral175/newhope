
#include "masked_cpakem.h"
#include "masked_cpapke.h"
#include "randombytes.h"
#include "fips202.h"

// Masked keypair generation for the CPAKEM
int masked_keypair(unsigned char *pk, unsigned char *sk)
{
    masked_cpapke_keypair(pk, sk);

    return 0;
}


// Masked encapsulation for the CPAKEM
int masked_encaps(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{
    unsigned char buf[NEWHOPE_SYMBYTES + NEWHOPE_SYMBYTES*(MASKING_ORDER+1)];

    buf[0] = 0x02;
    randombytes(buf+1,NEWHOPE_SYMBYTES);

    shake256(buf,NEWHOPE_SYMBYTES + NEWHOPE_SYMBYTES*(MASKING_ORDER+1),buf,NEWHOPE_SYMBYTES + 1);

    masked_cpapke_enc(ct, buf, pk, buf+NEWHOPE_SYMBYTES*(MASKING_ORDER+1));

    //TODO: Need to use the masked shake here since we want to keep the message in buf masked and it has to match the ss from dec which will have different shares.
    shake256(ss, NEWHOPE_SYMBYTES, buf, NEWHOPE_SYMBYTES);

    return 0;
}


// Masked decapsulation for the CPAKEM
int masked_decaps(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{
    masked_cpapke_dec(ss, ct, sk);

    //TODO: Need to use the masked shake here since we want to keep the message in buf masked.
    shake256(ss, NEWHOPE_SYMBYTES, ss, NEWHOPE_SYMBYTES);

    return 0;
}
