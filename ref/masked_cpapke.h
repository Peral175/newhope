#ifndef NEWHOPE_MASKED_CPAPKE_H
#define NEWHOPE_MASKED_CPAPKE_H

void masked_cpapke_keypair(unsigned char *pk,
                    unsigned char *sk);

void masked_cpapke_enc(unsigned char *c,
                const unsigned char *m,
                const unsigned char *pk,
                const unsigned char *coins);

void masked_cpapke_dec(unsigned char *m,
                const unsigned char *c,
                const unsigned char *sk);

#endif //NEWHOPE_MASKED_CPAPKE_H
