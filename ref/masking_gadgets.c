#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>  // Take out later probably
#include "masking_gadgets.h"
#include "poly.h"

#define NEWHOPE_Q 12289


typedef struct {
    uint16_t coeffs[8];
} short_poly __attribute__ ((aligned (8)));


typedef struct {
    short_poly poly_shares[MASKING_ORDER+1];
} masked_short_poly;


// Need one more share than the order we want to have.
//typedef struct Masked {uint16_t shares[MASKING_ORDER+1];} Masked;


uint16_t random16(){
    //srand(time(NULL));  // Set at start of the new_hope functions later, don't keep it here
    uint16_t x = rand();
    return x;
}


uint16_t random16mod(){
    //srand(time(NULL));  // Set at start of the new_hope functions later, don't keep it here
    uint16_t x = rand() % NEWHOPE_Q;
    return x;
}


void basic_gen_shares_mod(Masked *x){
    for(int i = 0; i <= MASKING_ORDER; i++) {
        x->shares[i] = random16mod();
    }
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


/*
 * This function implements the algorithm 9 Refresh
 * from: "High-order Table-based Conversion Algorithms and Masking
Lattice-based Encryption"
 * Input:
 *      Masked* x: Mask to be refreshed
 **/
void boolean_refresh(Masked* x){
    for(int j = 0; j < MASKING_ORDER; j++){
        uint16_t r = random16();
        x->shares[j] = (x->shares[j] ^ r);
        x->shares[MASKING_ORDER] = x->shares[MASKING_ORDER] ^ r;
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


/*
 * This function implements the algorithm 8 ArithmeticToBoolean
 * from: "High-order Table-based Conversion Algorithms and Masking
Lattice-based Encryption"
 * Input:
 *      Masked* x: a pointer to a type Masked which contains shares
 *      Masked* y: a pointer to a type Masked which contains shares
 *      y will be transformed into a boolean masked form via the arithmetic values of x.
 **/
void A2B(Masked* y, Masked* x){
    Masked T[NEWHOPE_Q];
    Masked T_p[NEWHOPE_Q];
    for(int u = 0;  u < NEWHOPE_Q; u++) {
        T[u].shares[0] = u;
        for (int i = 1; i <= MASKING_ORDER; i++){
            T[u].shares[i] = 0;
        }
    }
    for(int i = 0; i < MASKING_ORDER; i++){
        for(int u = 0;  u < NEWHOPE_Q; u++) {
            for(int j = 0; j <= MASKING_ORDER; j++){
                T_p[u].shares[j] = T[(u + x->shares[i])%NEWHOPE_Q].shares[j];
            }
        }
        for(int u = 0;  u < NEWHOPE_Q; u++) {
            boolean_refresh(&T_p[u]);
            for(int j = 0; j <= MASKING_ORDER; j++){
                T[u].shares[j] = T_p[u].shares[j];
            }
        }
    }
    for(int i = 0; i <= MASKING_ORDER; i++){
        y->shares[i] = T[x->shares[MASKING_ORDER]].shares[i];
    }
    boolean_refresh(y);
}


/*
 * This function implements the algorithm 11 SecAnd
 * From: "High-order Polynomial Comparison and Masking Lattice-based Encryption"
 * Input:
 *      Masked* a: first operand
 *      Masked* b: second operand
 *      Masked* z: output of operation
 **/
void secAnd(Masked* z, Masked* a, Masked* b, int k){
    for (int i=0; i<=MASKING_ORDER;i++){
        z->shares[i] = a->shares[i] & b->shares[i];
    }
    for (int i=0; i<=MASKING_ORDER;i++){
        for (int j=i+1; j<=MASKING_ORDER;j++){
            uint16_t r,r_p;
            r = random16() >> (16 - k);
            r_p = (r ^ (a->shares[i] & b->shares[j])) ^ (a->shares[j] & b->shares[i]);
            z->shares[i] ^= r;
            z->shares[j] ^= r_p;
        }
    }
}


/*
 * This function implements the algorithm 17 SecMult
 * From: "High-order Polynomial Comparison and Masking Lattice-based Encryption"
 * Input:
 *      Masked* a: first operand
 *      Masked* b: second operand
 *      Masked* z: output of operation
 **/
void secMult(Masked* z, Masked* a, Masked* b){
    for (int i=0; i<=MASKING_ORDER;i++){
        z->shares[i] = (a->shares[i] * b->shares[i]) % NEWHOPE_Q;
    }
    for (int i=0; i<=MASKING_ORDER;i++){
        for (int j=i+1; j<=MASKING_ORDER;j++){
            uint16_t r,r_p;
            r = random16() % NEWHOPE_Q;
            r_p = ((r + (a->shares[i] * b->shares[j]) % NEWHOPE_Q) + (a->shares[j] * b->shares[i]) % NEWHOPE_Q) % NEWHOPE_Q;
            z->shares[i] = (NEWHOPE_Q + z->shares[i] - r) % NEWHOPE_Q;
            z->shares[j] = (z->shares[j]+ r_p) % NEWHOPE_Q;
        }
    }
}


/*
 * This function implements the algorithm 12 RefreshMasks
 * From: "High-order Polynomial Comparison and Masking Lattice-based Encryption"
 * Input:
 *      Masked* a: Mask to be refreshed
 *      Masked* c: output of operation
 **/
void refreshMasks(Masked* c, Masked* a){
    for (int i=0;i<=MASKING_ORDER;i++){
        c->shares[i] = a->shares[i];
    }
    for (int i=0;i<=MASKING_ORDER;i++){
        for (int j=i+1; j<=MASKING_ORDER;j++){
            uint16_t r = random16mod();
            c->shares[i] = (c->shares[i] + r) % NEWHOPE_Q;
            c->shares[j] = (NEWHOPE_Q + c->shares[j] - r) % NEWHOPE_Q;
        }
    }
}  //algo 12


/*
 * This function implements the algorithm 18 SecExpo
 * From: "High-order Polynomial Comparison and Masking Lattice-based Encryption"
 * Input:
 *      Masked* A: first operand
 *      Masked* e: exponent
 *      Masked* z: output of operation
 **/
void secExpo(Masked* B, Masked* A, int e){
    B->shares[0] = 1;
    for (int j=1;j<=MASKING_ORDER;j++){
        B->shares[j] = 0;
    }
    for (int i=ceil(log2( e));i>=0;--i){
        Masked C;
        refreshMasks(&C, B);
        Masked tmp2;
        secMult(&tmp2, B, &C);
        for(int j = 0; j <= MASKING_ORDER; j++){
            B->shares[j] = tmp2.shares[j] % NEWHOPE_Q;
        }
        if ((e & (int) pow(2,i)) == (int) pow(2,i)) {
            Masked tmp3;
            secMult(&tmp3, A, B);
            for(int j = 0; j <= MASKING_ORDER; j++){
                B->shares[j] = tmp3.shares[j] % NEWHOPE_Q;
            }
        }
    }
}


//todo: test
void polyZeroTestRed(int K, int size, masked_poly X[size], masked_short_poly Y[K]){
    for (int k=0; k<K;k++){
        for (int i=0; i<=MASKING_ORDER;i++){
            Y->poly_shares[i].coeffs[k] = 0;
        }
        for (int j=0;j<size;j++){
            uint16_t a = random16mod();
            for (int i=0;i<=MASKING_ORDER;i++){
                uint64_t r = (a * X->poly_shares[i].coeffs[j])%NEWHOPE_Q;
                Y->poly_shares[i].coeffs[k] = (Y->poly_shares[i].coeffs[k] + r)%NEWHOPE_Q;
            }
        }
    }
}  //algo 23


void zeroTestExpoShares(Masked* B, Masked* A){
    Masked tmp;
    secExpo(&tmp,A,NEWHOPE_Q-1);
    B->shares[0] = NEWHOPE_Q + 1 - tmp.shares[0] % NEWHOPE_Q;
    for (int j=1;j<=MASKING_ORDER;j++){
        B->shares[j] = NEWHOPE_Q - tmp.shares[j] % NEWHOPE_Q;
    }
} //algo 19


int polyZeroTestExpo(int K,  int L, masked_poly X[L], masked_short_poly Y[K]){
    polyZeroTestRed(K,L,X,Y);
    Masked B,C,G;
    for (int m=0;m<=MASKING_ORDER;m++){
        G.shares[m] = Y->poly_shares[m].coeffs[0];
    }
    zeroTestExpoShares(&B,&G);
    for (int j=1;j<K;j++){
        Masked tmp,H;
        for (int m=0;m<=MASKING_ORDER;m++){
            H.shares[m] = Y->poly_shares[m].coeffs[j];
        }
        zeroTestExpoShares(&C,&H);
        secMult(&tmp,&B,&C);
        B = tmp;
    }
    refreshMasks(&C,&B);
    int b=0;
    for (int m=0;m<=MASKING_ORDER;m++){
        b = (b + C.shares[m]) %NEWHOPE_Q;
    }
    if (b == 1){
        return 1;
    } else {
        return 0;
    }
} //algo 25


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


void masked_binomial_dist(Masked* a, Masked* x, Masked* y, int k){
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


// Take boolean shares x, y, z, each 1 bit size, and calculate x+y+z;
// Taken from paper "Bitslicing Arithmetic/Boolean Masking Conversions for Fun and Profit with Application to Lattice-Based KEMs"
void fullAdder(Masked* w, Masked* x, Masked* y, Masked* z){
    Masked a;
    Masked temp;
    Masked temp2;

    for(int i = 0; i <= MASKING_ORDER; i++){
        a.shares[i] = x->shares[i] ^ y->shares[i];
        w->shares[i] = z->shares[i] ^ a.shares[i];
        temp2.shares[i] = z->shares[i] ^ x->shares[i];
    }

    secAnd(&temp, &a, &temp2, 1);

    for(int i = 0; i <= MASKING_ORDER; i++){
        w->shares[i] ^= (x->shares[i] ^ temp.shares[i]) << 1;
    }
}


// Take boolean shares x, y, with x and y between 0 and 2^16. Output boolean shared z = x+y mod 2^16
// Taken from paper "Bitslicing Arithmetic/Boolean Masking Conversions for Fun and Profit with Application to Lattice-Based KEMs"
void SecAdd(CompMasked* z, CompMasked* x, CompMasked* y, int k){
    Masked c;
    Masked t;
    Masked temp;
    Masked temp2;

    for(int i = 0; i <= MASKING_ORDER; i++){
        c.shares[i] = 0;
        z->shares[i] = 0;
    }

    for(int i = 0; i <= k-2; i++){
        for(int j = 0; j <= MASKING_ORDER; j++){
            temp.shares[j] = (x->shares[j] >> i) & 1;
            temp2.shares[j] = (y->shares[j] >> i) & 1;
        }

        fullAdder(&t, &temp, &temp2, &c);

        for(int j = 0; j <= MASKING_ORDER; j++) {
            z->shares[j] ^= (t.shares[j] & 1) << i;
            c.shares[j] &= 0;
            c.shares[j] ^= (t.shares[j] >> 1) & 1;
        }
    }

    for(int i = 0; i <= MASKING_ORDER; i++){
        temp.shares[i] = (x->shares[i] >> (k-1)) & 1;
        temp2.shares[i] = (y->shares[i] >> (k-1)) & 1;
    }

    for(int i = 0; i <= MASKING_ORDER; i++){
        z->shares[i] ^= (temp.shares[i] ^ temp2.shares[i] ^ c.shares[i]) << (k-1);
    }
}


// Take boolean shared value x and check if it is smaller or equal to phi
// Taken from paper "Protecting Dilithium against Leakage Revisited Sensitivity Analysis and Improved Implementations"
void SecLeq_masked_res(Masked* res, CompMasked* x, int phi, int k){
    int t;
    CompMasked temp;
    CompMasked temp2;
    CompMasked tx;

    for(int i = 0; i <= MASKING_ORDER; i++){
        res->shares[i] = 0;
        temp2.shares[i] = 0;
        tx.shares[i] = x->shares[i];
    }
    t = pow(2, k+1);

    temp2.shares[0] = t - phi - 1;

    SecAdd(&temp, &tx, &temp2, k+1);

    for(int i = 0; i <= MASKING_ORDER; i++){
        res->shares[i] ^= (temp.shares[i] >> k) & 1;
    }
}


// Take boolean shared value x and check if it is smaller or equal to phi, same as masked, just put the return bit together before returning.
int SecLeq_unmasked_res(Masked* x, int phi, int k){
    Masked res;
    CompMasked cx;

    for(int i = 0; i <= MASKING_ORDER; i++){
        cx.shares[i] = x->shares[i];
    }

    int ret_val = 0;
    SecLeq_masked_res(&res, &cx, phi, k);

    for(int i = 0; i <= MASKING_ORDER; i++){
        ret_val ^= res.shares[i];
    }

    return ret_val;
}


/*int main(int argc, char *argv[]) {
//    if (argc != 2){
//    	return -1;
//    }
    srand(time(NULL));
    /*
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
    masked_binomial_dist(&masked_sample, &x, &y, 16);

    uint16_t masked_sam = 0;

    for(int i = 0; i <= MASKING_ORDER; i++){
        masked_sam = (masked_sam + masked_sample.shares[i]) % NEWHOPE_Q;
    }

    printf("Reg Sample %d\n", reg_sample);
    printf("Masked Sample %d\n", masked_sam);
    */

    /*// Alex
    Masked x2,y2;
    basic_gen_shares_mod(&x2);
    uint16_t X2 = 0;
    for(int i = 0; i <= MASKING_ORDER; i++){
        printf("X2 Share %d: %d \n", i, x2.shares[i]);
        X2 = (X2 + x2.shares[i]) % NEWHOPE_Q;
    }

    A2B(&y2,&x2);

    uint16_t Y2 = 0;
    for(int i = 0; i <= MASKING_ORDER; i++){
        printf("Y2 Share %d: %d \n", i, y2.shares[i]);
        Y2 ^= y2.shares[i];
    }
    printf("X2: %d \n", X2             ); // bin
    printf("Y2: %d \n", Y2  % NEWHOPE_Q); // arith*/

    /*
    Masked a,b,c,d,e,f;
    basic_gen_shares_mod(&a);
    basic_gen_shares_mod(&b);
    basic_gen_shares_mod(&d);
    basic_gen_shares_mod(&e);
    uint16_t A = 0;
    uint16_t B = 0;
    uint16_t C = 0;
    secAnd(&c,&a,&b);
    for(int i = 0; i <= MASKING_ORDER; i++){
        printf("a Share %d: %d \n", i, a.shares[i]);
        A ^= a.shares[i];
    }
    for(int i = 0; i <= MASKING_ORDER; i++){
        printf("b Share %d: %d \n", i, b.shares[i]);
        B ^= b.shares[i];
    }
    for(int i = 0; i <= MASKING_ORDER; i++){
        printf("c Share %d: %d \n", i, c.shares[i]);
        C ^= c.shares[i];
    }
    printf("A: %d \n", A % NEWHOPE_Q);
    printf("B: %d \n", B % NEWHOPE_Q);
    printf("C: %d \n", C % NEWHOPE_Q);
    printf("A & B: %d \n", (A & B) % NEWHOPE_Q);

    uint16_t D = 0;
    uint16_t E = 0;
    uint16_t F = 0;
    secMult(&f,&d,&e);
    for(int i = 0; i <= MASKING_ORDER; i++){
        printf("d Share %d: %d \n", i, d.shares[i]);
        D += d.shares[i];
    }
    for(int i = 0; i <= MASKING_ORDER; i++){
        printf("e Share %d: %d \n", i, e.shares[i]);
        E += e.shares[i];
    }
    for(int i = 0; i <= MASKING_ORDER; i++){
        printf("f Share %d: %d \n", i, f.shares[i]);
        F += f.shares[i];
    }
    printf("D: %d \n", D % NEWHOPE_Q);
    printf("E: %d \n", E % NEWHOPE_Q);
    printf("F: %d \n", F % NEWHOPE_Q);
    printf("D * E mod Q: %d \n", (D * E) % NEWHOPE_Q);
    Masked x1,y1;
    uint16_t X1=0;
    uint16_t Y1=0;
    basic_gen_shares_mod(&x1);
    int eee = 2;
    for(int i = 0; i <= MASKING_ORDER; i++){
        printf("x Share %d: %d \n", i, x1.shares[i]);
        X1 += x1.shares[i];
    }
    printf("X: %d \n", X1 % NEWHOPE_Q);
    secExpo(&y1,&x1,eee);
    for(int i = 0; i <= MASKING_ORDER; i++){
        printf("y Share %d: %d \n", i, y1.shares[i]);
        Y1 += y1.shares[i];
    }
    printf("Y should be : %d \n", (int) pow(X1,eee) % NEWHOPE_Q);
    printf("Y: %d \n", Y1 % NEWHOPE_Q);


//    // Algorithm 23 test!
//    Masked v,w,x;
//    basic_gen_shares_mod(&v);
//    basic_gen_shares_mod(&w);
//    Masked arr1[] = {v, w};
//    Masked arr2[] = {x};
//    int size,k;
//    k = 1;
//    size = sizeof(arr1) / sizeof(arr1[0]);
//    polyZeroTestRed(k, size, arr1, arr2);

//    // Algorithm 19 test!
//    Masked a,b;
//    uint16_t A;
//    a.shares[0]=0;
//    a.shares[1]=0;
//    a.shares[2]=0;
//    a.shares[3]=0;
//    for(int i = 0; i <= MASKING_ORDER; i++){
//        printf("x Share %d: %d \n", i, a.shares[i]);
//        A += a.shares[i];
//    }
//    zeroTestExpoShares(&b,&a);
//    uint16_t B;
//    for(int i = 0; i <= MASKING_ORDER; i++){
//        printf("y Share %d: %d \n", i, b.shares[i]);
//        B += b.shares[i];
//    }
//    printf("A: %d \n", A % NEWHOPE_Q);
//    printf("B: %d \n", B % NEWHOPE_Q);

    // Algorithm 25 test!
    masked_poly X;
    for (int i=0;i<1024;i++) {
        for (int j = 0; j <= MASKING_ORDER; j++) {
            X.poly_shares[j].coeffs[i] = 0;
        }
    }

    masked_short_poly Y;
    int k = 8;
    int l = 1024;
    int bool = polyZeroTestExpo(k,l, &X, &Y);
    printf("bool: %d \n", bool);
}*/