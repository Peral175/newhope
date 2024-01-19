#ifndef NEWHOPE_MASKED_CCAKEM_H
#define NEWHOPE_MASKED_CCAKEM_H


int masked_CCA_keypair(unsigned char *pk, unsigned char *sk);
int masked_CCA_encaps(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int masked_CCA_decaps(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif //NEWHOPE_MASKED_CCAKEM_H
