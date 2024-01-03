#include <stdio.h> // Take out later probably
#include <stdint.h>
#include <stdlib.h>
#include <math.h>  // Take out later probably
#include <time.h>  // Take out later probably

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
void arith_refresh(Masked* x){
    for(int j = 0; j < MASKING_ORDER; j++){
        uint16_t r = random16() % NEWHOPE_Q;
        x->shares[j] = (x->shares[j] + r) % NEWHOPE_Q;
        x->shares[MASKING_ORDER] = (x->shares[MASKING_ORDER] + NEWHOPE_Q - r) % NEWHOPE_Q;
    }
}


// Used in b2a, this function is not used for anything other than k = 1
void b2a_reg(Masked* y, Masked* x, int k){
    // Tables with 2^k rows and MASKING_ORDER+1 number of elements in each.
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

void b2a(Masked* y, Masked* x, int k){
    for(int i = 0; i <= MASKING_ORDER; i++){
        y->shares[i] = 0;
    }

    for(int j = 0; j < k; j++){
        Masked z;
        for(int i = 0; i <= MASKING_ORDER; i++){
            z.shares[i] = ((x->shares[i]) >> j) & 1;
        }
        Masked t;
        b2a_reg(&t, &z, 1);
        for(int i = 0; i <= MASKING_ORDER; i++){
            y->shares[i] = (y->shares[i] + (t.shares[i] << j)) % NEWHOPE_Q;
        }
    }
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
    for(int i = 0; i <= MASKING_ORDER; i++){
        printf("X Share %d: %d \n", i, x.shares[i]);
        X ^= x.shares[i];
    }

    b2a(&y, &x, 16);

    uint16_t Y = 0;
    for(int i = 0; i <= MASKING_ORDER; i++){
        printf("Y Share %d: %d \n", i, y.shares[i]);
        Y = (Y + y.shares[i]) % NEWHOPE_Q;
    }
    printf("X: %d \n", X  % NEWHOPE_Q);
    printf("Y: %d \n\n", Y);
}
