#ifndef NEWHOPE_MASKED_CPAKEM_H
#define NEWHOPE_MASKED_CPAKEM_H

int masked_keypair(unsigned char *pk, unsigned char *sk);
int masked_encaps(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int masked_decaps(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif //NEWHOPE_MASKED_CPAKEM_H
