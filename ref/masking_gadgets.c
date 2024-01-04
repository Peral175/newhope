#include <stdio.h> // Take out later probably
#include <stdint.h>
#include <stdlib.h>
#include <math.h>  // Take out later probably
#include <time.h>  // Take out later probably
#include "params.h"
#include "fips202.h"
#include "poly.h"

#define NEWHOPE_Q 12289
#define MASKING_ORDER 3

// Need one more share than the order we want to have.
typedef struct Masked {uint16_t shares[MASKING_ORDER+1];} Masked;


uint16_t random16(){
    //srand(time(NULL));  // Set at start of the new_hope functions later, don't keep it here
    uint16_t x = rand();
    return x;
}


// Only for testing
void basic_gen_shares(Masked *x, Masked *y){
    for(int i = 0; i <= MASKING_ORDER; i++) {
        x->shares[i] = random16();
        y->shares[i] = random16();
    }
}

// Exchange the c modulos with the modulo function implemented in new hope later
// From paper "High-order Table-based Conversion Algorithms and Masking Lattice-based Encryptio
void arith_refresh(Masked* x){
    for(int j = 0; j < MASKING_ORDER; j++){
        uint16_t r = random16() % NEWHOPE_Q;
        x->shares[j] = (x->shares[j] + r) % NEWHOPE_Q;
        x->shares[MASKING_ORDER] = (x->shares[MASKING_ORDER] + NEWHOPE_Q - r) % NEWHOPE_Q;
    }
}


// Used in opti_B2A, this function is not used for anything other than k = 1
// From paper "High-order Table-based Conversion Algorithms and Masking Lattice-based Encryptio
void B2A(Masked* y, Masked* x, int k){
    Masked T[1 << k];
    Masked T_p[1 << k];
    for(int u = 0;  u < (1 << k); u++) {
        // Exchange the c modulo with the modulo function later
        T[u].shares[0] = u % NEWHOPE_Q;
        for (int i = 1; i <= MASKING_ORDER; i++){
            T[u].shares[i] = 0;
        }
    }

    for(int i = 0; i < MASKING_ORDER; i++){
        for(int u = 0;  u < (1 << k); u++) {
            for(int j = 0; j <= MASKING_ORDER; j++){
                T_p[u].shares[j] = T[u^(x->shares[i])].shares[j];
            }
        }

        for(int u = 0;  u < (1 << k); u++) {
            arith_refresh(&T_p[u]);
            for(int j = 0; j <= MASKING_ORDER; j++){
                T[u].shares[j] = T_p[u].shares[j];
            }
        }
    }
    for(int i = 0; i <= MASKING_ORDER; i++){
        y->shares[i] = T[x->shares[MASKING_ORDER]].shares[i];
    }
    arith_refresh(y);
}

// From paper "High-order Table-based Conversion Algorithms and Masking Lattice-based Encryption"
void opti_B2A(Masked* y, Masked* x, int k){
    for(int i = 0; i <= MASKING_ORDER; i++){
        y->shares[i] = 0;
    }

    for(int j = 0; j < k; j++){
        Masked z;
        for(int i = 0; i <= MASKING_ORDER; i++){
            z.shares[i] = ((x->shares[i]) >> j) & 1;
        }
        Masked t;
        B2A(&t, &z, 1);
        for(int i = 0; i <= MASKING_ORDER; i++){
            y->shares[i] = (y->shares[i] + (t.shares[i] << j)) % NEWHOPE_Q;
        }
    }
}

// From paper "High-order Table-based Conversion Algorithms and Masking Lattice-based Encryption"
// Almost identical to opti_B2A, except for the last line, where the shift by j is missing.
void masked_Hamming_Weight(Masked* a, Masked* x, int k){
    for(int i = 0; i <= MASKING_ORDER; i++){
        a->shares[i] = 0;
    }

    for(int j = 0; j < k; j++){
        Masked z;
        for(int i = 0; i <= MASKING_ORDER; i++){
            z.shares[i] = ((x->shares[i]) >> j) & 1;
        }
        Masked t;
        B2A(&t, &z, 1);
        for(int i = 0; i <= MASKING_ORDER; i++){
            a->shares[i] = (a->shares[i] + t.shares[i]) % NEWHOPE_Q;
        }
    }
}

void SecSampleBasic(Masked* a, Masked* x, Masked* y, int k){
    Masked Hx;
    Masked Hy;

    // Calculate the hamming weight of the masked values
    masked_Hamming_Weight(&Hx, x, 16);
    masked_Hamming_Weight(&Hy, y, 16);

    // Calculate the substraction mod q for every share
    for(int i = 0; i <= MASKING_ORDER; i++){
        a->shares[i] = (Hx.shares[i] + NEWHOPE_Q - Hy.shares[i]);
    }

    // Refresh shares
    arith_refresh(a);
}

int main(int argc, char *argv[]){
    //if (argc != 2){
    //	return -1;
    //}
    srand(time(NULL));
    Masked x;
    Masked y;
    basic_gen_shares(&x, &y);

    uint16_t X = 0;
    uint16_t Y = 0;
    for(int i = 0; i <= MASKING_ORDER; i++){
        printf("X Share %d: %d \n", i, x.shares[i]);
        X ^= x.shares[i];
        printf("Y Share %d: %d \n", i, y.shares[i]);
        Y ^= y.shares[i];
    }

    unsigned char i, rx = 0, ry = 0;
    for(i=0;i<16;i++) {
        rx += (X >> i) & 1;
        ry += (Y >> i) & 1;
    }

    printf("X: %d \n", X % NEWHOPE_Q);
    printf("Y: %d \n", Y % NEWHOPE_Q);

    uint16_t reg_sample = (rx + NEWHOPE_Q - ry) % NEWHOPE_Q;

    Masked masked_sample;
    SecSampleBasic(&masked_sample, &x, &y, 16);

    uint16_t masked_sam = 0;
    for(int i = 0; i <= MASKING_ORDER; i++){
        masked_sam = (masked_sam + masked_sample.shares[i]) % NEWHOPE_Q;
    }

    printf("Reg Sample %d\n", reg_sample);
    printf("Masked Sample %d\n", masked_sam);
}
