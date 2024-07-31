#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <stdlib.h>
#include <time.h>

int64_t cpucycles(void)
{
    unsigned int hi, lo;

        __asm__ __volatile__ ("rdtsc\n\t" : "=a" (lo), "=d"(hi));

        return ((int64_t)lo) | (((int64_t)hi) << 32);
}

#define DEBUG_IMP 0
#define DEBUG_PERF 0

//BENCH ROUND
#define BENCH_ROUND 100000

// round of block cipher
#define NUM_ROUND 80

// basic operation
#define ROR(x,r) ((x>>r) | (x<<(8-r)))
#define ROL(x,r) ((x<<r) | (x>>(8-r)))

// constant :: cryptogr in ASCII
#define CONSTANT0 0x63
#define CONSTANT1 0x72
#define CONSTANT2 0x79
#define CONSTANT3 0x70
#define CONSTANT4 0x74
#define CONSTANT5 0x6F
#define CONSTANT6 0x67
#define CONSTANT7 0x72

// constant :: shift offset
#define OFFSET1 1
#define OFFSET3 3
#define OFFSET5 5
#define OFFSET7 7

// constant :: nonce value
#define NONCE1 0x12
#define NONCE2 0x34
#define NONCE3 0x56
#define NONCE4 0x78
#define NONCE5 0x9A
#define NONCE6 0xBC
#define NONCE7 0xDE

//
void key_scheduling(uint8_t* MK, uint8_t* RK){
    uint32_t i=0;
        
    //initialization
    for(i=0;i<8;i++){
        RK[i] = MK[i];
    }
        
    for(i=1;i<NUM_ROUND;i++){
        RK[i*8 + 0]= ROL( RK[(i-1)*8 + 0], (i+OFFSET1)%8) + ROL (CONSTANT0, (i+OFFSET3)%8);
        RK[i*8 + 1]= ROL( RK[(i-1)*8 + 1], (i+OFFSET5)%8) + ROL (CONSTANT1, (i+OFFSET7)%8);
        RK[i*8 + 2]= ROL( RK[(i-1)*8 + 2], (i+OFFSET1)%8) + ROL (CONSTANT2, (i+OFFSET3)%8);
        RK[i*8 + 3]= ROL( RK[(i-1)*8 + 3], (i+OFFSET5)%8) + ROL (CONSTANT3, (i+OFFSET7)%8);
        
        RK[i*8 + 4]= ROL( RK[(i-1)*8 + 4], (i+OFFSET1)%8) + ROL (CONSTANT4, (i+OFFSET3)%8);
        RK[i*8 + 5]= ROL( RK[(i-1)*8 + 5], (i+OFFSET5)%8) + ROL (CONSTANT5, (i+OFFSET7)%8);
        RK[i*8 + 6]= ROL( RK[(i-1)*8 + 6], (i+OFFSET1)%8) + ROL (CONSTANT6, (i+OFFSET3)%8);
        RK[i*8 + 7]= ROL( RK[(i-1)*8 + 7], (i+OFFSET5)%8) + ROL (CONSTANT7, (i+OFFSET7)%8);
    }
}

//
void ROUND_FUNC(uint8_t *intermediate, uint8_t *RK, uint8_t index, uint8_t loop_indx, uint8_t offset){
    intermediate[index] = RK[loop_indx*8 + index] ^ intermediate[index];
    intermediate[index] = RK[loop_indx*8 + index] ^ intermediate[index-1] + intermediate[index];
    intermediate[index] = ROL(intermediate[index], offset);
}
    

//
void block_encryption(uint8_t* PT, uint8_t* RK, uint8_t* CT){
    uint32_t i=0;
    uint32_t j=0;
    uint8_t intermediate[8]={0,};
    uint8_t tmp=0;
    
    for(i=0;i<8;i++){
        intermediate[i] = PT[i];
    }
    
    for(i=0;i<NUM_ROUND;i++){
        for(j=7;j>0;j--){
            ROUND_FUNC(intermediate,RK,j,i,j);
        }
        
        tmp = intermediate[0];
        for(j=1;j<8;j++){
            intermediate[j-1] = intermediate[j];
        }
        intermediate[7] = tmp;
    }
    
    for(i=0;i<8;i++){
        CT[i] = intermediate[i];
    }
    
}

//
void CTR_mode(uint8_t* PT, uint8_t* MK, uint8_t* CT, uint8_t num_enc){
    uint32_t i=0;
    uint32_t j=0;
    uint8_t intermediate[8] ={0,};
    uint8_t intermediate2[8] ={0,};
    uint8_t ctr = 0;
    
    uint8_t RK[8* NUM_ROUND]={0,};
    
    //key schedule
    key_scheduling(MK, RK);
    
    //nonce setting
    intermediate[1] = NONCE1;
    intermediate[2] = NONCE2;
    intermediate[3] = NONCE3;
    intermediate[4] = NONCE4;
    intermediate[5] = NONCE5;
    intermediate[6] = NONCE6;
    intermediate[7] = NONCE7;
    
    
    for(i=0;i<num_enc;i++){
        //ctr setting
        intermediate[0] = ctr++;
        block_encryption(intermediate,RK,intermediate2);
        for(j=0;j<8;j++){
            CT[i*8+j] = PT[i*8+j] ^ intermediate2[j];
        }
    }
}

//
void POLY_MUL_RED(uint8_t* IN1, uint8_t* IN2, uint8_t* OUT){
    uint64_t* in1_64_p = (uint64_t*) IN1;
    uint64_t* in2_64_p = (uint64_t*) IN2;
    uint64_t* out_64_p = (uint64_t*) OUT;
    
    uint64_t in1_64 = in1_64_p[0];
    uint64_t in2_64 = in2_64_p[0];
    uint64_t one = 1;
    
    uint64_t result[2] = {0,};
    
    int32_t i=0;
    
    for(i=0;i<64;i++){
        if( (( one<<i ) & in1_64) > 0  ){
            result[0] ^= in2_64<<i;
            if(i!=0){
                result[1] ^= in2_64>>(64-i);
            }
        }
    }
    
    // reduction
    result[0] ^= result[1];
    result[0] ^= result[1]<<9;
    result[0] ^= result[1]>>55;
    result[0] ^= (result[1]>>55)<<9;
    
    out_64_p[0] = result[0];
}

//
void AUTH_mode(uint8_t* CT, uint8_t* AUTH, uint8_t num_auth){
    uint8_t AUTH_nonce[8] = {0,};
    uint8_t AUTH_inter[8] = {0,};
    uint32_t i, j;
    
    //nonce setting
    AUTH_nonce[0] = num_auth;
    AUTH_nonce[1] = num_auth ^ NONCE1;
    AUTH_nonce[2] = num_auth & NONCE2;
    AUTH_nonce[3] = num_auth | NONCE3;
    AUTH_nonce[4] = num_auth ^ NONCE4;
    AUTH_nonce[5] = num_auth & NONCE5;
    AUTH_nonce[6] = num_auth | NONCE6;
    AUTH_nonce[7] = num_auth ^ NONCE7;
    
    POLY_MUL_RED(AUTH_nonce, AUTH_nonce, AUTH_inter);
    
    for(i=0;i<num_auth;i++){
        for(j=0;j<8;j++){
            AUTH_inter[j] ^= CT[i*8 + j];
        }
        POLY_MUL_RED(AUTH_nonce, AUTH_inter, AUTH_inter);
        POLY_MUL_RED(AUTH_inter, AUTH_inter, AUTH_inter);
    }
    
    for(i=0;i<8;i++){
        AUTH[i] = AUTH_inter[i];
    }
}

#if DEBUG_PERF
int64_t ta, tb, tc;
#endif

void ENC_AUTH(uint8_t* PT, uint8_t* MK, uint8_t* CT, uint8_t* AUTH, uint8_t length_in_byte){
#if DEBUG_PERF
    ta = cpucycles();
#endif
    uint8_t num_enc_auth = length_in_byte / 8;
    
    CTR_mode(PT, MK, CT, num_enc_auth);
#if DEBUG_PERF
    tb = cpucycles();
#endif
    AUTH_mode(CT,AUTH,num_enc_auth);
#if DEBUG_PERF
    tc = cpucycles();
#endif
}

// EDIT START

static inline uint8_t rol8(uint8_t x, uint8_t r) {
  return (x << r) | (x >> (8 - r));
}

static inline uint64_t rol64(uint64_t x, uint8_t r) {
  switch (r) {
    case 0: return x;
    case 1: return ((x << 1) & 0xFEFEFEFEFEFEFEFE) | ((x >> 7) & 0x0101010101010101);
    case 2: return ((x << 2) & 0xFCFCFCFCFCFCFCFC) | ((x >> 6) & 0x0303030303030303);
    case 3: return ((x << 3) & 0xF8F8F8F8F8F8F8F8) | ((x >> 5) & 0x0707070707070707);
    case 4: return ((x << 4) & 0xF0F0F0F0F0F0F0F0) | ((x >> 4) & 0x0F0F0F0F0F0F0F0F);
    case 5: return ((x << 5) & 0xE0E0E0E0E0E0E0E0) | ((x >> 3) & 0x1F1F1F1F1F1F1F1F);
    case 6: return ((x << 6) & 0xC0C0C0C0C0C0C0C0) | ((x >> 2) & 0x3F3F3F3F3F3F3F3F);
    case 7: return ((x << 7) & 0x8080808080808080) | ((x >> 1) & 0x7F7F7F7F7F7F7F7F);
  }
}

static inline uint64_t pack64(uint8_t x0, uint8_t x1, uint8_t x2, uint8_t x3, uint8_t x4, uint8_t x5, uint8_t x6, uint8_t x7) {
  return x0 | ((uint64_t)x1 << 8) | ((uint64_t)x2 << 16) | ((uint64_t)x3 << 24) | ((uint64_t)x4 << 32) | ((uint64_t)x5 << 40) | ((uint64_t)x6 << 48) | ((uint64_t)x7 << 56);
}

// compiled to paddb
static inline uint64_t bytewise_add(uint64_t a, uint64_t b) {
  uint64_t c;
  for (int i = 0; i < 8; ++i) {
    ((uint8_t*)&c)[i] = ((uint8_t*)&a)[i] + ((uint8_t*)&b)[i];
  }
  return c;
}

// compiled to pshuflw and pxor
static inline uint64_t bytewise_xor(uint8_t a, uint64_t b) {
  uint64_t c;
  for (int i = 0; i < 8; ++i) {
    ((uint8_t*)&c)[i] = a ^ ((uint8_t*)&b)[i];
  }
  return c;
}

static inline uint64_t dup8(uint8_t a) {
  return a * 0x0101010101010101;
}

static inline uint64_t clsq_32b(uint64_t a) {
  uint64_t c = 0;
  uint64_t DB[4] = {0, a, a << 1, a ^ (a << 1)};
  for (int i = 0; i < 32; i+= 2) {
    c ^= DB[(a >> i) & 3] << i;
  }
  return c;
}

static inline void POLY_MUL_RED_IMP_SQ(uint8_t *INOUT) {
  uint64_t p1 = *(uint64_t *)INOUT;
  uint32_t p1l = p1;
  uint32_t p1h = p1 >> 32;
  uint64_t z0 = clsq_32b(p1l);
  uint64_t z2 = clsq_32b(p1h);
  uint64_t z1 = clsq_32b(p1l ^ p1h) ^ z0 ^ z2;
  uint64_t result0 = z0 ^ (z1 << 32);
  uint64_t result1 = (z1 >> 32) ^ z2;
  result0 ^= result1;
  result0 ^= result1 << 9;
  result0 ^= result1 >> 55;
  result0 ^= (result1 >> 55) << 9;
  *(uint64_t*)INOUT = result0;
}

#define DB_SIZE 256
#define DB_SIZE_LOG 8

static inline void POLY_MUL_RED_IMP_DB3(uint8_t *INOUT, uint64_t (*db1), uint64_t (*db2), uint64_t (*db3)) {
  uint64_t p = *(uint64_t *)INOUT;
  uint64_t p1 = p & 0xFFFFFFFF;
  uint64_t p2 = p >> 32;
  uint64_t p3 = p1 ^ p2;
  uint64_t z0 = 0, z1 = 0, z2 = 0;
  for (int i = 0; i < 32; i+= DB_SIZE_LOG) {
    z0 ^= db1[(p1 >> i) & (DB_SIZE - 1)] << i;
    z2 ^= db2[(p2 >> i) & (DB_SIZE - 1)] << i;
    z1 ^= db3[(p3 >> i) & (DB_SIZE - 1)] << i;
  }
  z1 ^= z0 ^ z2;
  uint64_t result0 = z0 ^ (z1 << 32);
  uint64_t result1 = (z1 >> 32) ^ z2;
  result0 ^= result1;
  result0 ^= result1 << 9;
  result0 ^= result1 >> 55;
  result0 ^= (result1 >> 55) << 9;
  *(uint64_t*)INOUT = result0;
}

int64_t st, keygen, ctr, auth;

void ENC_AUTH_IMP(uint8_t* PT, uint8_t* MK, uint8_t* CT, uint8_t* AUTH, uint8_t length_in_byte){
  #if DEBUG_PERF
  st = cpucycles();
  #endif

  uint8_t num_enc_auth = length_in_byte / 8;
  uint8_t RK[NUM_ROUND][8];
  *(uint64_t*)RK = *(uint64_t*)MK;
  RK[1][0] = rol8(RK[0][0], (1 + OFFSET1) % 8) + rol8(CONSTANT0, (1 + OFFSET3) % 8); RK[1][1] = rol8(RK[0][1], (1 + OFFSET5) % 8) + rol8(CONSTANT1, (1 + OFFSET7) % 8); RK[1][2] = rol8(RK[0][2], (1 + OFFSET1) % 8) + rol8(CONSTANT2, (1 + OFFSET3) % 8); RK[1][3] = rol8(RK[0][3], (1 + OFFSET5) % 8) + rol8(CONSTANT3, (1 + OFFSET7) % 8); RK[1][4] = rol8(RK[0][4], (1 + OFFSET1) % 8) + rol8(CONSTANT4, (1 + OFFSET3) % 8); RK[1][5] = rol8(RK[0][5], (1 + OFFSET5) % 8) + rol8(CONSTANT5, (1 + OFFSET7) % 8); RK[1][6] = rol8(RK[0][6], (1 + OFFSET1) % 8) + rol8(CONSTANT6, (1 + OFFSET3) % 8); RK[1][7] = rol8(RK[0][7], (1 + OFFSET5) % 8) + rol8(CONSTANT7, (1 + OFFSET7) % 8); RK[2][0] = rol8(RK[1][0], (2 + OFFSET1) % 8) + rol8(CONSTANT0, (2 + OFFSET3) % 8); RK[2][1] = rol8(RK[1][1], (2 + OFFSET5) % 8) + rol8(CONSTANT1, (2 + OFFSET7) % 8); RK[2][2] = rol8(RK[1][2], (2 + OFFSET1) % 8) + rol8(CONSTANT2, (2 + OFFSET3) % 8); RK[2][3] = rol8(RK[1][3], (2 + OFFSET5) % 8) + rol8(CONSTANT3, (2 + OFFSET7) % 8); RK[2][4] = rol8(RK[1][4], (2 + OFFSET1) % 8) + rol8(CONSTANT4, (2 + OFFSET3) % 8); RK[2][5] = rol8(RK[1][5], (2 + OFFSET5) % 8) + rol8(CONSTANT5, (2 + OFFSET7) % 8); RK[2][6] = rol8(RK[1][6], (2 + OFFSET1) % 8) + rol8(CONSTANT6, (2 + OFFSET3) % 8); RK[2][7] = rol8(RK[1][7], (2 + OFFSET5) % 8) + rol8(CONSTANT7, (2 + OFFSET7) % 8); RK[3][0] = rol8(RK[2][0], (3 + OFFSET1) % 8) + rol8(CONSTANT0, (3 + OFFSET3) % 8); RK[3][1] = rol8(RK[2][1], (3 + OFFSET5) % 8) + rol8(CONSTANT1, (3 + OFFSET7) % 8); RK[3][2] = rol8(RK[2][2], (3 + OFFSET1) % 8) + rol8(CONSTANT2, (3 + OFFSET3) % 8); RK[3][3] = rol8(RK[2][3], (3 + OFFSET5) % 8) + rol8(CONSTANT3, (3 + OFFSET7) % 8); RK[3][4] = rol8(RK[2][4], (3 + OFFSET1) % 8) + rol8(CONSTANT4, (3 + OFFSET3) % 8); RK[3][5] = rol8(RK[2][5], (3 + OFFSET5) % 8) + rol8(CONSTANT5, (3 + OFFSET7) % 8); RK[3][6] = rol8(RK[2][6], (3 + OFFSET1) % 8) + rol8(CONSTANT6, (3 + OFFSET3) % 8); RK[3][7] = rol8(RK[2][7], (3 + OFFSET5) % 8) + rol8(CONSTANT7, (3 + OFFSET7) % 8); RK[4][0] = rol8(RK[3][0], (4 + OFFSET1) % 8) + rol8(CONSTANT0, (4 + OFFSET3) % 8); RK[4][1] = rol8(RK[3][1], (4 + OFFSET5) % 8) + rol8(CONSTANT1, (4 + OFFSET7) % 8); RK[4][2] = rol8(RK[3][2], (4 + OFFSET1) % 8) + rol8(CONSTANT2, (4 + OFFSET3) % 8); RK[4][3] = rol8(RK[3][3], (4 + OFFSET5) % 8) + rol8(CONSTANT3, (4 + OFFSET7) % 8); RK[4][4] = rol8(RK[3][4], (4 + OFFSET1) % 8) + rol8(CONSTANT4, (4 + OFFSET3) % 8); RK[4][5] = rol8(RK[3][5], (4 + OFFSET5) % 8) + rol8(CONSTANT5, (4 + OFFSET7) % 8); RK[4][6] = rol8(RK[3][6], (4 + OFFSET1) % 8) + rol8(CONSTANT6, (4 + OFFSET3) % 8); RK[4][7] = rol8(RK[3][7], (4 + OFFSET5) % 8) + rol8(CONSTANT7, (4 + OFFSET7) % 8); RK[5][0] = rol8(RK[4][0], (5 + OFFSET1) % 8) + rol8(CONSTANT0, (5 + OFFSET3) % 8); RK[5][1] = rol8(RK[4][1], (5 + OFFSET5) % 8) + rol8(CONSTANT1, (5 + OFFSET7) % 8); RK[5][2] = rol8(RK[4][2], (5 + OFFSET1) % 8) + rol8(CONSTANT2, (5 + OFFSET3) % 8); RK[5][3] = rol8(RK[4][3], (5 + OFFSET5) % 8) + rol8(CONSTANT3, (5 + OFFSET7) % 8); RK[5][4] = rol8(RK[4][4], (5 + OFFSET1) % 8) + rol8(CONSTANT4, (5 + OFFSET3) % 8); RK[5][5] = rol8(RK[4][5], (5 + OFFSET5) % 8) + rol8(CONSTANT5, (5 + OFFSET7) % 8); RK[5][6] = rol8(RK[4][6], (5 + OFFSET1) % 8) + rol8(CONSTANT6, (5 + OFFSET3) % 8); RK[5][7] = rol8(RK[4][7], (5 + OFFSET5) % 8) + rol8(CONSTANT7, (5 + OFFSET7) % 8); RK[6][0] = rol8(RK[5][0], (6 + OFFSET1) % 8) + rol8(CONSTANT0, (6 + OFFSET3) % 8); RK[6][1] = rol8(RK[5][1], (6 + OFFSET5) % 8) + rol8(CONSTANT1, (6 + OFFSET7) % 8); RK[6][2] = rol8(RK[5][2], (6 + OFFSET1) % 8) + rol8(CONSTANT2, (6 + OFFSET3) % 8); RK[6][3] = rol8(RK[5][3], (6 + OFFSET5) % 8) + rol8(CONSTANT3, (6 + OFFSET7) % 8); RK[6][4] = rol8(RK[5][4], (6 + OFFSET1) % 8) + rol8(CONSTANT4, (6 + OFFSET3) % 8); RK[6][5] = rol8(RK[5][5], (6 + OFFSET5) % 8) + rol8(CONSTANT5, (6 + OFFSET7) % 8); RK[6][6] = rol8(RK[5][6], (6 + OFFSET1) % 8) + rol8(CONSTANT6, (6 + OFFSET3) % 8); RK[6][7] = rol8(RK[5][7], (6 + OFFSET5) % 8) + rol8(CONSTANT7, (6 + OFFSET7) % 8); RK[7][0] = rol8(RK[6][0], (7 + OFFSET1) % 8) + rol8(CONSTANT0, (7 + OFFSET3) % 8); RK[7][1] = rol8(RK[6][1], (7 + OFFSET5) % 8) + rol8(CONSTANT1, (7 + OFFSET7) % 8); RK[7][2] = rol8(RK[6][2], (7 + OFFSET1) % 8) + rol8(CONSTANT2, (7 + OFFSET3) % 8); RK[7][3] = rol8(RK[6][3], (7 + OFFSET5) % 8) + rol8(CONSTANT3, (7 + OFFSET7) % 8); RK[7][4] = rol8(RK[6][4], (7 + OFFSET1) % 8) + rol8(CONSTANT4, (7 + OFFSET3) % 8); RK[7][5] = rol8(RK[6][5], (7 + OFFSET5) % 8) + rol8(CONSTANT5, (7 + OFFSET7) % 8); RK[7][6] = rol8(RK[6][6], (7 + OFFSET1) % 8) + rol8(CONSTANT6, (7 + OFFSET3) % 8); RK[7][7] = rol8(RK[6][7], (7 + OFFSET5) % 8) + rol8(CONSTANT7, (7 + OFFSET7) % 8); RK[8][0] = rol8(RK[7][0], (8 + OFFSET1) % 8) + rol8(CONSTANT0, (8 + OFFSET3) % 8); RK[8][1] = rol8(RK[7][1], (8 + OFFSET5) % 8) + rol8(CONSTANT1, (8 + OFFSET7) % 8); RK[8][2] = rol8(RK[7][2], (8 + OFFSET1) % 8) + rol8(CONSTANT2, (8 + OFFSET3) % 8); RK[8][3] = rol8(RK[7][3], (8 + OFFSET5) % 8) + rol8(CONSTANT3, (8 + OFFSET7) % 8); RK[8][4] = rol8(RK[7][4], (8 + OFFSET1) % 8) + rol8(CONSTANT4, (8 + OFFSET3) % 8); RK[8][5] = rol8(RK[7][5], (8 + OFFSET5) % 8) + rol8(CONSTANT5, (8 + OFFSET7) % 8); RK[8][6] = rol8(RK[7][6], (8 + OFFSET1) % 8) + rol8(CONSTANT6, (8 + OFFSET3) % 8); RK[8][7] = rol8(RK[7][7], (8 + OFFSET5) % 8) + rol8(CONSTANT7, (8 + OFFSET7) % 8); RK[9][0] = rol8(RK[8][0], (9 + OFFSET1) % 8) + rol8(CONSTANT0, (9 + OFFSET3) % 8); RK[9][1] = rol8(RK[8][1], (9 + OFFSET5) % 8) + rol8(CONSTANT1, (9 + OFFSET7) % 8); RK[9][2] = rol8(RK[8][2], (9 + OFFSET1) % 8) + rol8(CONSTANT2, (9 + OFFSET3) % 8); RK[9][3] = rol8(RK[8][3], (9 + OFFSET5) % 8) + rol8(CONSTANT3, (9 + OFFSET7) % 8); RK[9][4] = rol8(RK[8][4], (9 + OFFSET1) % 8) + rol8(CONSTANT4, (9 + OFFSET3) % 8); RK[9][5] = rol8(RK[8][5], (9 + OFFSET5) % 8) + rol8(CONSTANT5, (9 + OFFSET7) % 8); RK[9][6] = rol8(RK[8][6], (9 + OFFSET1) % 8) + rol8(CONSTANT6, (9 + OFFSET3) % 8); RK[9][7] = rol8(RK[8][7], (9 + OFFSET5) % 8) + rol8(CONSTANT7, (9 + OFFSET7) % 8); RK[10][0] = rol8(RK[9][0], (10 + OFFSET1) % 8) + rol8(CONSTANT0, (10 + OFFSET3) % 8); RK[10][1] = rol8(RK[9][1], (10 + OFFSET5) % 8) + rol8(CONSTANT1, (10 + OFFSET7) % 8); RK[10][2] = rol8(RK[9][2], (10 + OFFSET1) % 8) + rol8(CONSTANT2, (10 + OFFSET3) % 8); RK[10][3] = rol8(RK[9][3], (10 + OFFSET5) % 8) + rol8(CONSTANT3, (10 + OFFSET7) % 8); RK[10][4] = rol8(RK[9][4], (10 + OFFSET1) % 8) + rol8(CONSTANT4, (10 + OFFSET3) % 8); RK[10][5] = rol8(RK[9][5], (10 + OFFSET5) % 8) + rol8(CONSTANT5, (10 + OFFSET7) % 8); RK[10][6] = rol8(RK[9][6], (10 + OFFSET1) % 8) + rol8(CONSTANT6, (10 + OFFSET3) % 8); RK[10][7] = rol8(RK[9][7], (10 + OFFSET5) % 8) + rol8(CONSTANT7, (10 + OFFSET7) % 8); RK[11][0] = rol8(RK[10][0], (11 + OFFSET1) % 8) + rol8(CONSTANT0, (11 + OFFSET3) % 8); RK[11][1] = rol8(RK[10][1], (11 + OFFSET5) % 8) + rol8(CONSTANT1, (11 + OFFSET7) % 8); RK[11][2] = rol8(RK[10][2], (11 + OFFSET1) % 8) + rol8(CONSTANT2, (11 + OFFSET3) % 8); RK[11][3] = rol8(RK[10][3], (11 + OFFSET5) % 8) + rol8(CONSTANT3, (11 + OFFSET7) % 8); RK[11][4] = rol8(RK[10][4], (11 + OFFSET1) % 8) + rol8(CONSTANT4, (11 + OFFSET3) % 8); RK[11][5] = rol8(RK[10][5], (11 + OFFSET5) % 8) + rol8(CONSTANT5, (11 + OFFSET7) % 8); RK[11][6] = rol8(RK[10][6], (11 + OFFSET1) % 8) + rol8(CONSTANT6, (11 + OFFSET3) % 8); RK[11][7] = rol8(RK[10][7], (11 + OFFSET5) % 8) + rol8(CONSTANT7, (11 + OFFSET7) % 8); RK[12][0] = rol8(RK[11][0], (12 + OFFSET1) % 8) + rol8(CONSTANT0, (12 + OFFSET3) % 8); RK[12][1] = rol8(RK[11][1], (12 + OFFSET5) % 8) + rol8(CONSTANT1, (12 + OFFSET7) % 8); RK[12][2] = rol8(RK[11][2], (12 + OFFSET1) % 8) + rol8(CONSTANT2, (12 + OFFSET3) % 8); RK[12][3] = rol8(RK[11][3], (12 + OFFSET5) % 8) + rol8(CONSTANT3, (12 + OFFSET7) % 8); RK[12][4] = rol8(RK[11][4], (12 + OFFSET1) % 8) + rol8(CONSTANT4, (12 + OFFSET3) % 8); RK[12][5] = rol8(RK[11][5], (12 + OFFSET5) % 8) + rol8(CONSTANT5, (12 + OFFSET7) % 8); RK[12][6] = rol8(RK[11][6], (12 + OFFSET1) % 8) + rol8(CONSTANT6, (12 + OFFSET3) % 8); RK[12][7] = rol8(RK[11][7], (12 + OFFSET5) % 8) + rol8(CONSTANT7, (12 + OFFSET7) % 8); RK[13][0] = rol8(RK[12][0], (13 + OFFSET1) % 8) + rol8(CONSTANT0, (13 + OFFSET3) % 8); RK[13][1] = rol8(RK[12][1], (13 + OFFSET5) % 8) + rol8(CONSTANT1, (13 + OFFSET7) % 8); RK[13][2] = rol8(RK[12][2], (13 + OFFSET1) % 8) + rol8(CONSTANT2, (13 + OFFSET3) % 8); RK[13][3] = rol8(RK[12][3], (13 + OFFSET5) % 8) + rol8(CONSTANT3, (13 + OFFSET7) % 8); RK[13][4] = rol8(RK[12][4], (13 + OFFSET1) % 8) + rol8(CONSTANT4, (13 + OFFSET3) % 8); RK[13][5] = rol8(RK[12][5], (13 + OFFSET5) % 8) + rol8(CONSTANT5, (13 + OFFSET7) % 8); RK[13][6] = rol8(RK[12][6], (13 + OFFSET1) % 8) + rol8(CONSTANT6, (13 + OFFSET3) % 8); RK[13][7] = rol8(RK[12][7], (13 + OFFSET5) % 8) + rol8(CONSTANT7, (13 + OFFSET7) % 8); RK[14][0] = rol8(RK[13][0], (14 + OFFSET1) % 8) + rol8(CONSTANT0, (14 + OFFSET3) % 8); RK[14][1] = rol8(RK[13][1], (14 + OFFSET5) % 8) + rol8(CONSTANT1, (14 + OFFSET7) % 8); RK[14][2] = rol8(RK[13][2], (14 + OFFSET1) % 8) + rol8(CONSTANT2, (14 + OFFSET3) % 8); RK[14][3] = rol8(RK[13][3], (14 + OFFSET5) % 8) + rol8(CONSTANT3, (14 + OFFSET7) % 8); RK[14][4] = rol8(RK[13][4], (14 + OFFSET1) % 8) + rol8(CONSTANT4, (14 + OFFSET3) % 8); RK[14][5] = rol8(RK[13][5], (14 + OFFSET5) % 8) + rol8(CONSTANT5, (14 + OFFSET7) % 8); RK[14][6] = rol8(RK[13][6], (14 + OFFSET1) % 8) + rol8(CONSTANT6, (14 + OFFSET3) % 8); RK[14][7] = rol8(RK[13][7], (14 + OFFSET5) % 8) + rol8(CONSTANT7, (14 + OFFSET7) % 8); RK[15][0] = rol8(RK[14][0], (15 + OFFSET1) % 8) + rol8(CONSTANT0, (15 + OFFSET3) % 8); RK[15][1] = rol8(RK[14][1], (15 + OFFSET5) % 8) + rol8(CONSTANT1, (15 + OFFSET7) % 8); RK[15][2] = rol8(RK[14][2], (15 + OFFSET1) % 8) + rol8(CONSTANT2, (15 + OFFSET3) % 8); RK[15][3] = rol8(RK[14][3], (15 + OFFSET5) % 8) + rol8(CONSTANT3, (15 + OFFSET7) % 8); RK[15][4] = rol8(RK[14][4], (15 + OFFSET1) % 8) + rol8(CONSTANT4, (15 + OFFSET3) % 8); RK[15][5] = rol8(RK[14][5], (15 + OFFSET5) % 8) + rol8(CONSTANT5, (15 + OFFSET7) % 8); RK[15][6] = rol8(RK[14][6], (15 + OFFSET1) % 8) + rol8(CONSTANT6, (15 + OFFSET3) % 8); RK[15][7] = rol8(RK[14][7], (15 + OFFSET5) % 8) + rol8(CONSTANT7, (15 + OFFSET7) % 8); RK[16][0] = rol8(RK[15][0], (16 + OFFSET1) % 8) + rol8(CONSTANT0, (16 + OFFSET3) % 8); RK[16][1] = rol8(RK[15][1], (16 + OFFSET5) % 8) + rol8(CONSTANT1, (16 + OFFSET7) % 8); RK[16][2] = rol8(RK[15][2], (16 + OFFSET1) % 8) + rol8(CONSTANT2, (16 + OFFSET3) % 8); RK[16][3] = rol8(RK[15][3], (16 + OFFSET5) % 8) + rol8(CONSTANT3, (16 + OFFSET7) % 8); RK[16][4] = rol8(RK[15][4], (16 + OFFSET1) % 8) + rol8(CONSTANT4, (16 + OFFSET3) % 8); RK[16][5] = rol8(RK[15][5], (16 + OFFSET5) % 8) + rol8(CONSTANT5, (16 + OFFSET7) % 8); RK[16][6] = rol8(RK[15][6], (16 + OFFSET1) % 8) + rol8(CONSTANT6, (16 + OFFSET3) % 8); RK[16][7] = rol8(RK[15][7], (16 + OFFSET5) % 8) + rol8(CONSTANT7, (16 + OFFSET7) % 8); RK[17][0] = rol8(RK[16][0], (17 + OFFSET1) % 8) + rol8(CONSTANT0, (17 + OFFSET3) % 8); RK[17][1] = rol8(RK[16][1], (17 + OFFSET5) % 8) + rol8(CONSTANT1, (17 + OFFSET7) % 8); RK[17][2] = rol8(RK[16][2], (17 + OFFSET1) % 8) + rol8(CONSTANT2, (17 + OFFSET3) % 8); RK[17][3] = rol8(RK[16][3], (17 + OFFSET5) % 8) + rol8(CONSTANT3, (17 + OFFSET7) % 8); RK[17][4] = rol8(RK[16][4], (17 + OFFSET1) % 8) + rol8(CONSTANT4, (17 + OFFSET3) % 8); RK[17][5] = rol8(RK[16][5], (17 + OFFSET5) % 8) + rol8(CONSTANT5, (17 + OFFSET7) % 8); RK[17][6] = rol8(RK[16][6], (17 + OFFSET1) % 8) + rol8(CONSTANT6, (17 + OFFSET3) % 8); RK[17][7] = rol8(RK[16][7], (17 + OFFSET5) % 8) + rol8(CONSTANT7, (17 + OFFSET7) % 8); RK[18][0] = rol8(RK[17][0], (18 + OFFSET1) % 8) + rol8(CONSTANT0, (18 + OFFSET3) % 8); RK[18][1] = rol8(RK[17][1], (18 + OFFSET5) % 8) + rol8(CONSTANT1, (18 + OFFSET7) % 8); RK[18][2] = rol8(RK[17][2], (18 + OFFSET1) % 8) + rol8(CONSTANT2, (18 + OFFSET3) % 8); RK[18][3] = rol8(RK[17][3], (18 + OFFSET5) % 8) + rol8(CONSTANT3, (18 + OFFSET7) % 8); RK[18][4] = rol8(RK[17][4], (18 + OFFSET1) % 8) + rol8(CONSTANT4, (18 + OFFSET3) % 8); RK[18][5] = rol8(RK[17][5], (18 + OFFSET5) % 8) + rol8(CONSTANT5, (18 + OFFSET7) % 8); RK[18][6] = rol8(RK[17][6], (18 + OFFSET1) % 8) + rol8(CONSTANT6, (18 + OFFSET3) % 8); RK[18][7] = rol8(RK[17][7], (18 + OFFSET5) % 8) + rol8(CONSTANT7, (18 + OFFSET7) % 8); RK[19][0] = rol8(RK[18][0], (19 + OFFSET1) % 8) + rol8(CONSTANT0, (19 + OFFSET3) % 8); RK[19][1] = rol8(RK[18][1], (19 + OFFSET5) % 8) + rol8(CONSTANT1, (19 + OFFSET7) % 8); RK[19][2] = rol8(RK[18][2], (19 + OFFSET1) % 8) + rol8(CONSTANT2, (19 + OFFSET3) % 8); RK[19][3] = rol8(RK[18][3], (19 + OFFSET5) % 8) + rol8(CONSTANT3, (19 + OFFSET7) % 8); RK[19][4] = rol8(RK[18][4], (19 + OFFSET1) % 8) + rol8(CONSTANT4, (19 + OFFSET3) % 8); RK[19][5] = rol8(RK[18][5], (19 + OFFSET5) % 8) + rol8(CONSTANT5, (19 + OFFSET7) % 8); RK[19][6] = rol8(RK[18][6], (19 + OFFSET1) % 8) + rol8(CONSTANT6, (19 + OFFSET3) % 8); RK[19][7] = rol8(RK[18][7], (19 + OFFSET5) % 8) + rol8(CONSTANT7, (19 + OFFSET7) % 8); RK[20][0] = rol8(RK[19][0], (20 + OFFSET1) % 8) + rol8(CONSTANT0, (20 + OFFSET3) % 8); RK[20][1] = rol8(RK[19][1], (20 + OFFSET5) % 8) + rol8(CONSTANT1, (20 + OFFSET7) % 8); RK[20][2] = rol8(RK[19][2], (20 + OFFSET1) % 8) + rol8(CONSTANT2, (20 + OFFSET3) % 8); RK[20][3] = rol8(RK[19][3], (20 + OFFSET5) % 8) + rol8(CONSTANT3, (20 + OFFSET7) % 8); RK[20][4] = rol8(RK[19][4], (20 + OFFSET1) % 8) + rol8(CONSTANT4, (20 + OFFSET3) % 8); RK[20][5] = rol8(RK[19][5], (20 + OFFSET5) % 8) + rol8(CONSTANT5, (20 + OFFSET7) % 8); RK[20][6] = rol8(RK[19][6], (20 + OFFSET1) % 8) + rol8(CONSTANT6, (20 + OFFSET3) % 8); RK[20][7] = rol8(RK[19][7], (20 + OFFSET5) % 8) + rol8(CONSTANT7, (20 + OFFSET7) % 8); RK[21][0] = rol8(RK[20][0], (21 + OFFSET1) % 8) + rol8(CONSTANT0, (21 + OFFSET3) % 8); RK[21][1] = rol8(RK[20][1], (21 + OFFSET5) % 8) + rol8(CONSTANT1, (21 + OFFSET7) % 8); RK[21][2] = rol8(RK[20][2], (21 + OFFSET1) % 8) + rol8(CONSTANT2, (21 + OFFSET3) % 8); RK[21][3] = rol8(RK[20][3], (21 + OFFSET5) % 8) + rol8(CONSTANT3, (21 + OFFSET7) % 8); RK[21][4] = rol8(RK[20][4], (21 + OFFSET1) % 8) + rol8(CONSTANT4, (21 + OFFSET3) % 8); RK[21][5] = rol8(RK[20][5], (21 + OFFSET5) % 8) + rol8(CONSTANT5, (21 + OFFSET7) % 8); RK[21][6] = rol8(RK[20][6], (21 + OFFSET1) % 8) + rol8(CONSTANT6, (21 + OFFSET3) % 8); RK[21][7] = rol8(RK[20][7], (21 + OFFSET5) % 8) + rol8(CONSTANT7, (21 + OFFSET7) % 8); RK[22][0] = rol8(RK[21][0], (22 + OFFSET1) % 8) + rol8(CONSTANT0, (22 + OFFSET3) % 8); RK[22][1] = rol8(RK[21][1], (22 + OFFSET5) % 8) + rol8(CONSTANT1, (22 + OFFSET7) % 8); RK[22][2] = rol8(RK[21][2], (22 + OFFSET1) % 8) + rol8(CONSTANT2, (22 + OFFSET3) % 8); RK[22][3] = rol8(RK[21][3], (22 + OFFSET5) % 8) + rol8(CONSTANT3, (22 + OFFSET7) % 8); RK[22][4] = rol8(RK[21][4], (22 + OFFSET1) % 8) + rol8(CONSTANT4, (22 + OFFSET3) % 8); RK[22][5] = rol8(RK[21][5], (22 + OFFSET5) % 8) + rol8(CONSTANT5, (22 + OFFSET7) % 8); RK[22][6] = rol8(RK[21][6], (22 + OFFSET1) % 8) + rol8(CONSTANT6, (22 + OFFSET3) % 8); RK[22][7] = rol8(RK[21][7], (22 + OFFSET5) % 8) + rol8(CONSTANT7, (22 + OFFSET7) % 8); RK[23][0] = rol8(RK[22][0], (23 + OFFSET1) % 8) + rol8(CONSTANT0, (23 + OFFSET3) % 8); RK[23][1] = rol8(RK[22][1], (23 + OFFSET5) % 8) + rol8(CONSTANT1, (23 + OFFSET7) % 8); RK[23][2] = rol8(RK[22][2], (23 + OFFSET1) % 8) + rol8(CONSTANT2, (23 + OFFSET3) % 8); RK[23][3] = rol8(RK[22][3], (23 + OFFSET5) % 8) + rol8(CONSTANT3, (23 + OFFSET7) % 8); RK[23][4] = rol8(RK[22][4], (23 + OFFSET1) % 8) + rol8(CONSTANT4, (23 + OFFSET3) % 8); RK[23][5] = rol8(RK[22][5], (23 + OFFSET5) % 8) + rol8(CONSTANT5, (23 + OFFSET7) % 8); RK[23][6] = rol8(RK[22][6], (23 + OFFSET1) % 8) + rol8(CONSTANT6, (23 + OFFSET3) % 8); RK[23][7] = rol8(RK[22][7], (23 + OFFSET5) % 8) + rol8(CONSTANT7, (23 + OFFSET7) % 8); RK[24][0] = rol8(RK[23][0], (24 + OFFSET1) % 8) + rol8(CONSTANT0, (24 + OFFSET3) % 8); RK[24][1] = rol8(RK[23][1], (24 + OFFSET5) % 8) + rol8(CONSTANT1, (24 + OFFSET7) % 8); RK[24][2] = rol8(RK[23][2], (24 + OFFSET1) % 8) + rol8(CONSTANT2, (24 + OFFSET3) % 8); RK[24][3] = rol8(RK[23][3], (24 + OFFSET5) % 8) + rol8(CONSTANT3, (24 + OFFSET7) % 8); RK[24][4] = rol8(RK[23][4], (24 + OFFSET1) % 8) + rol8(CONSTANT4, (24 + OFFSET3) % 8); RK[24][5] = rol8(RK[23][5], (24 + OFFSET5) % 8) + rol8(CONSTANT5, (24 + OFFSET7) % 8); RK[24][6] = rol8(RK[23][6], (24 + OFFSET1) % 8) + rol8(CONSTANT6, (24 + OFFSET3) % 8); RK[24][7] = rol8(RK[23][7], (24 + OFFSET5) % 8) + rol8(CONSTANT7, (24 + OFFSET7) % 8); RK[25][0] = rol8(RK[24][0], (25 + OFFSET1) % 8) + rol8(CONSTANT0, (25 + OFFSET3) % 8); RK[25][1] = rol8(RK[24][1], (25 + OFFSET5) % 8) + rol8(CONSTANT1, (25 + OFFSET7) % 8); RK[25][2] = rol8(RK[24][2], (25 + OFFSET1) % 8) + rol8(CONSTANT2, (25 + OFFSET3) % 8); RK[25][3] = rol8(RK[24][3], (25 + OFFSET5) % 8) + rol8(CONSTANT3, (25 + OFFSET7) % 8); RK[25][4] = rol8(RK[24][4], (25 + OFFSET1) % 8) + rol8(CONSTANT4, (25 + OFFSET3) % 8); RK[25][5] = rol8(RK[24][5], (25 + OFFSET5) % 8) + rol8(CONSTANT5, (25 + OFFSET7) % 8); RK[25][6] = rol8(RK[24][6], (25 + OFFSET1) % 8) + rol8(CONSTANT6, (25 + OFFSET3) % 8); RK[25][7] = rol8(RK[24][7], (25 + OFFSET5) % 8) + rol8(CONSTANT7, (25 + OFFSET7) % 8); RK[26][0] = rol8(RK[25][0], (26 + OFFSET1) % 8) + rol8(CONSTANT0, (26 + OFFSET3) % 8); RK[26][1] = rol8(RK[25][1], (26 + OFFSET5) % 8) + rol8(CONSTANT1, (26 + OFFSET7) % 8); RK[26][2] = rol8(RK[25][2], (26 + OFFSET1) % 8) + rol8(CONSTANT2, (26 + OFFSET3) % 8); RK[26][3] = rol8(RK[25][3], (26 + OFFSET5) % 8) + rol8(CONSTANT3, (26 + OFFSET7) % 8); RK[26][4] = rol8(RK[25][4], (26 + OFFSET1) % 8) + rol8(CONSTANT4, (26 + OFFSET3) % 8); RK[26][5] = rol8(RK[25][5], (26 + OFFSET5) % 8) + rol8(CONSTANT5, (26 + OFFSET7) % 8); RK[26][6] = rol8(RK[25][6], (26 + OFFSET1) % 8) + rol8(CONSTANT6, (26 + OFFSET3) % 8); RK[26][7] = rol8(RK[25][7], (26 + OFFSET5) % 8) + rol8(CONSTANT7, (26 + OFFSET7) % 8); RK[27][0] = rol8(RK[26][0], (27 + OFFSET1) % 8) + rol8(CONSTANT0, (27 + OFFSET3) % 8); RK[27][1] = rol8(RK[26][1], (27 + OFFSET5) % 8) + rol8(CONSTANT1, (27 + OFFSET7) % 8); RK[27][2] = rol8(RK[26][2], (27 + OFFSET1) % 8) + rol8(CONSTANT2, (27 + OFFSET3) % 8); RK[27][3] = rol8(RK[26][3], (27 + OFFSET5) % 8) + rol8(CONSTANT3, (27 + OFFSET7) % 8); RK[27][4] = rol8(RK[26][4], (27 + OFFSET1) % 8) + rol8(CONSTANT4, (27 + OFFSET3) % 8); RK[27][5] = rol8(RK[26][5], (27 + OFFSET5) % 8) + rol8(CONSTANT5, (27 + OFFSET7) % 8); RK[27][6] = rol8(RK[26][6], (27 + OFFSET1) % 8) + rol8(CONSTANT6, (27 + OFFSET3) % 8); RK[27][7] = rol8(RK[26][7], (27 + OFFSET5) % 8) + rol8(CONSTANT7, (27 + OFFSET7) % 8); RK[28][0] = rol8(RK[27][0], (28 + OFFSET1) % 8) + rol8(CONSTANT0, (28 + OFFSET3) % 8); RK[28][1] = rol8(RK[27][1], (28 + OFFSET5) % 8) + rol8(CONSTANT1, (28 + OFFSET7) % 8); RK[28][2] = rol8(RK[27][2], (28 + OFFSET1) % 8) + rol8(CONSTANT2, (28 + OFFSET3) % 8); RK[28][3] = rol8(RK[27][3], (28 + OFFSET5) % 8) + rol8(CONSTANT3, (28 + OFFSET7) % 8); RK[28][4] = rol8(RK[27][4], (28 + OFFSET1) % 8) + rol8(CONSTANT4, (28 + OFFSET3) % 8); RK[28][5] = rol8(RK[27][5], (28 + OFFSET5) % 8) + rol8(CONSTANT5, (28 + OFFSET7) % 8); RK[28][6] = rol8(RK[27][6], (28 + OFFSET1) % 8) + rol8(CONSTANT6, (28 + OFFSET3) % 8); RK[28][7] = rol8(RK[27][7], (28 + OFFSET5) % 8) + rol8(CONSTANT7, (28 + OFFSET7) % 8); RK[29][0] = rol8(RK[28][0], (29 + OFFSET1) % 8) + rol8(CONSTANT0, (29 + OFFSET3) % 8); RK[29][1] = rol8(RK[28][1], (29 + OFFSET5) % 8) + rol8(CONSTANT1, (29 + OFFSET7) % 8); RK[29][2] = rol8(RK[28][2], (29 + OFFSET1) % 8) + rol8(CONSTANT2, (29 + OFFSET3) % 8); RK[29][3] = rol8(RK[28][3], (29 + OFFSET5) % 8) + rol8(CONSTANT3, (29 + OFFSET7) % 8); RK[29][4] = rol8(RK[28][4], (29 + OFFSET1) % 8) + rol8(CONSTANT4, (29 + OFFSET3) % 8); RK[29][5] = rol8(RK[28][5], (29 + OFFSET5) % 8) + rol8(CONSTANT5, (29 + OFFSET7) % 8); RK[29][6] = rol8(RK[28][6], (29 + OFFSET1) % 8) + rol8(CONSTANT6, (29 + OFFSET3) % 8); RK[29][7] = rol8(RK[28][7], (29 + OFFSET5) % 8) + rol8(CONSTANT7, (29 + OFFSET7) % 8); RK[30][0] = rol8(RK[29][0], (30 + OFFSET1) % 8) + rol8(CONSTANT0, (30 + OFFSET3) % 8); RK[30][1] = rol8(RK[29][1], (30 + OFFSET5) % 8) + rol8(CONSTANT1, (30 + OFFSET7) % 8); RK[30][2] = rol8(RK[29][2], (30 + OFFSET1) % 8) + rol8(CONSTANT2, (30 + OFFSET3) % 8); RK[30][3] = rol8(RK[29][3], (30 + OFFSET5) % 8) + rol8(CONSTANT3, (30 + OFFSET7) % 8); RK[30][4] = rol8(RK[29][4], (30 + OFFSET1) % 8) + rol8(CONSTANT4, (30 + OFFSET3) % 8); RK[30][5] = rol8(RK[29][5], (30 + OFFSET5) % 8) + rol8(CONSTANT5, (30 + OFFSET7) % 8); RK[30][6] = rol8(RK[29][6], (30 + OFFSET1) % 8) + rol8(CONSTANT6, (30 + OFFSET3) % 8); RK[30][7] = rol8(RK[29][7], (30 + OFFSET5) % 8) + rol8(CONSTANT7, (30 + OFFSET7) % 8); RK[31][0] = rol8(RK[30][0], (31 + OFFSET1) % 8) + rol8(CONSTANT0, (31 + OFFSET3) % 8); RK[31][1] = rol8(RK[30][1], (31 + OFFSET5) % 8) + rol8(CONSTANT1, (31 + OFFSET7) % 8); RK[31][2] = rol8(RK[30][2], (31 + OFFSET1) % 8) + rol8(CONSTANT2, (31 + OFFSET3) % 8); RK[31][3] = rol8(RK[30][3], (31 + OFFSET5) % 8) + rol8(CONSTANT3, (31 + OFFSET7) % 8); RK[31][4] = rol8(RK[30][4], (31 + OFFSET1) % 8) + rol8(CONSTANT4, (31 + OFFSET3) % 8); RK[31][5] = rol8(RK[30][5], (31 + OFFSET5) % 8) + rol8(CONSTANT5, (31 + OFFSET7) % 8); RK[31][6] = rol8(RK[30][6], (31 + OFFSET1) % 8) + rol8(CONSTANT6, (31 + OFFSET3) % 8); RK[31][7] = rol8(RK[30][7], (31 + OFFSET5) % 8) + rol8(CONSTANT7, (31 + OFFSET7) % 8); RK[32][0] = rol8(RK[31][0], (32 + OFFSET1) % 8) + rol8(CONSTANT0, (32 + OFFSET3) % 8); RK[32][1] = rol8(RK[31][1], (32 + OFFSET5) % 8) + rol8(CONSTANT1, (32 + OFFSET7) % 8); RK[32][2] = rol8(RK[31][2], (32 + OFFSET1) % 8) + rol8(CONSTANT2, (32 + OFFSET3) % 8); RK[32][3] = rol8(RK[31][3], (32 + OFFSET5) % 8) + rol8(CONSTANT3, (32 + OFFSET7) % 8); RK[32][4] = rol8(RK[31][4], (32 + OFFSET1) % 8) + rol8(CONSTANT4, (32 + OFFSET3) % 8); RK[32][5] = rol8(RK[31][5], (32 + OFFSET5) % 8) + rol8(CONSTANT5, (32 + OFFSET7) % 8); RK[32][6] = rol8(RK[31][6], (32 + OFFSET1) % 8) + rol8(CONSTANT6, (32 + OFFSET3) % 8); RK[32][7] = rol8(RK[31][7], (32 + OFFSET5) % 8) + rol8(CONSTANT7, (32 + OFFSET7) % 8); RK[33][0] = rol8(RK[32][0], (33 + OFFSET1) % 8) + rol8(CONSTANT0, (33 + OFFSET3) % 8); RK[33][1] = rol8(RK[32][1], (33 + OFFSET5) % 8) + rol8(CONSTANT1, (33 + OFFSET7) % 8); RK[33][2] = rol8(RK[32][2], (33 + OFFSET1) % 8) + rol8(CONSTANT2, (33 + OFFSET3) % 8); RK[33][3] = rol8(RK[32][3], (33 + OFFSET5) % 8) + rol8(CONSTANT3, (33 + OFFSET7) % 8); RK[33][4] = rol8(RK[32][4], (33 + OFFSET1) % 8) + rol8(CONSTANT4, (33 + OFFSET3) % 8); RK[33][5] = rol8(RK[32][5], (33 + OFFSET5) % 8) + rol8(CONSTANT5, (33 + OFFSET7) % 8); RK[33][6] = rol8(RK[32][6], (33 + OFFSET1) % 8) + rol8(CONSTANT6, (33 + OFFSET3) % 8); RK[33][7] = rol8(RK[32][7], (33 + OFFSET5) % 8) + rol8(CONSTANT7, (33 + OFFSET7) % 8); RK[34][0] = rol8(RK[33][0], (34 + OFFSET1) % 8) + rol8(CONSTANT0, (34 + OFFSET3) % 8); RK[34][1] = rol8(RK[33][1], (34 + OFFSET5) % 8) + rol8(CONSTANT1, (34 + OFFSET7) % 8); RK[34][2] = rol8(RK[33][2], (34 + OFFSET1) % 8) + rol8(CONSTANT2, (34 + OFFSET3) % 8); RK[34][3] = rol8(RK[33][3], (34 + OFFSET5) % 8) + rol8(CONSTANT3, (34 + OFFSET7) % 8); RK[34][4] = rol8(RK[33][4], (34 + OFFSET1) % 8) + rol8(CONSTANT4, (34 + OFFSET3) % 8); RK[34][5] = rol8(RK[33][5], (34 + OFFSET5) % 8) + rol8(CONSTANT5, (34 + OFFSET7) % 8); RK[34][6] = rol8(RK[33][6], (34 + OFFSET1) % 8) + rol8(CONSTANT6, (34 + OFFSET3) % 8); RK[34][7] = rol8(RK[33][7], (34 + OFFSET5) % 8) + rol8(CONSTANT7, (34 + OFFSET7) % 8); RK[35][0] = rol8(RK[34][0], (35 + OFFSET1) % 8) + rol8(CONSTANT0, (35 + OFFSET3) % 8); RK[35][1] = rol8(RK[34][1], (35 + OFFSET5) % 8) + rol8(CONSTANT1, (35 + OFFSET7) % 8); RK[35][2] = rol8(RK[34][2], (35 + OFFSET1) % 8) + rol8(CONSTANT2, (35 + OFFSET3) % 8); RK[35][3] = rol8(RK[34][3], (35 + OFFSET5) % 8) + rol8(CONSTANT3, (35 + OFFSET7) % 8); RK[35][4] = rol8(RK[34][4], (35 + OFFSET1) % 8) + rol8(CONSTANT4, (35 + OFFSET3) % 8); RK[35][5] = rol8(RK[34][5], (35 + OFFSET5) % 8) + rol8(CONSTANT5, (35 + OFFSET7) % 8); RK[35][6] = rol8(RK[34][6], (35 + OFFSET1) % 8) + rol8(CONSTANT6, (35 + OFFSET3) % 8); RK[35][7] = rol8(RK[34][7], (35 + OFFSET5) % 8) + rol8(CONSTANT7, (35 + OFFSET7) % 8); RK[36][0] = rol8(RK[35][0], (36 + OFFSET1) % 8) + rol8(CONSTANT0, (36 + OFFSET3) % 8); RK[36][1] = rol8(RK[35][1], (36 + OFFSET5) % 8) + rol8(CONSTANT1, (36 + OFFSET7) % 8); RK[36][2] = rol8(RK[35][2], (36 + OFFSET1) % 8) + rol8(CONSTANT2, (36 + OFFSET3) % 8); RK[36][3] = rol8(RK[35][3], (36 + OFFSET5) % 8) + rol8(CONSTANT3, (36 + OFFSET7) % 8); RK[36][4] = rol8(RK[35][4], (36 + OFFSET1) % 8) + rol8(CONSTANT4, (36 + OFFSET3) % 8); RK[36][5] = rol8(RK[35][5], (36 + OFFSET5) % 8) + rol8(CONSTANT5, (36 + OFFSET7) % 8); RK[36][6] = rol8(RK[35][6], (36 + OFFSET1) % 8) + rol8(CONSTANT6, (36 + OFFSET3) % 8); RK[36][7] = rol8(RK[35][7], (36 + OFFSET5) % 8) + rol8(CONSTANT7, (36 + OFFSET7) % 8); RK[37][0] = rol8(RK[36][0], (37 + OFFSET1) % 8) + rol8(CONSTANT0, (37 + OFFSET3) % 8); RK[37][1] = rol8(RK[36][1], (37 + OFFSET5) % 8) + rol8(CONSTANT1, (37 + OFFSET7) % 8); RK[37][2] = rol8(RK[36][2], (37 + OFFSET1) % 8) + rol8(CONSTANT2, (37 + OFFSET3) % 8); RK[37][3] = rol8(RK[36][3], (37 + OFFSET5) % 8) + rol8(CONSTANT3, (37 + OFFSET7) % 8); RK[37][4] = rol8(RK[36][4], (37 + OFFSET1) % 8) + rol8(CONSTANT4, (37 + OFFSET3) % 8); RK[37][5] = rol8(RK[36][5], (37 + OFFSET5) % 8) + rol8(CONSTANT5, (37 + OFFSET7) % 8); RK[37][6] = rol8(RK[36][6], (37 + OFFSET1) % 8) + rol8(CONSTANT6, (37 + OFFSET3) % 8); RK[37][7] = rol8(RK[36][7], (37 + OFFSET5) % 8) + rol8(CONSTANT7, (37 + OFFSET7) % 8); RK[38][0] = rol8(RK[37][0], (38 + OFFSET1) % 8) + rol8(CONSTANT0, (38 + OFFSET3) % 8); RK[38][1] = rol8(RK[37][1], (38 + OFFSET5) % 8) + rol8(CONSTANT1, (38 + OFFSET7) % 8); RK[38][2] = rol8(RK[37][2], (38 + OFFSET1) % 8) + rol8(CONSTANT2, (38 + OFFSET3) % 8); RK[38][3] = rol8(RK[37][3], (38 + OFFSET5) % 8) + rol8(CONSTANT3, (38 + OFFSET7) % 8); RK[38][4] = rol8(RK[37][4], (38 + OFFSET1) % 8) + rol8(CONSTANT4, (38 + OFFSET3) % 8); RK[38][5] = rol8(RK[37][5], (38 + OFFSET5) % 8) + rol8(CONSTANT5, (38 + OFFSET7) % 8); RK[38][6] = rol8(RK[37][6], (38 + OFFSET1) % 8) + rol8(CONSTANT6, (38 + OFFSET3) % 8); RK[38][7] = rol8(RK[37][7], (38 + OFFSET5) % 8) + rol8(CONSTANT7, (38 + OFFSET7) % 8); RK[39][0] = rol8(RK[38][0], (39 + OFFSET1) % 8) + rol8(CONSTANT0, (39 + OFFSET3) % 8); RK[39][1] = rol8(RK[38][1], (39 + OFFSET5) % 8) + rol8(CONSTANT1, (39 + OFFSET7) % 8); RK[39][2] = rol8(RK[38][2], (39 + OFFSET1) % 8) + rol8(CONSTANT2, (39 + OFFSET3) % 8); RK[39][3] = rol8(RK[38][3], (39 + OFFSET5) % 8) + rol8(CONSTANT3, (39 + OFFSET7) % 8); RK[39][4] = rol8(RK[38][4], (39 + OFFSET1) % 8) + rol8(CONSTANT4, (39 + OFFSET3) % 8); RK[39][5] = rol8(RK[38][5], (39 + OFFSET5) % 8) + rol8(CONSTANT5, (39 + OFFSET7) % 8); RK[39][6] = rol8(RK[38][6], (39 + OFFSET1) % 8) + rol8(CONSTANT6, (39 + OFFSET3) % 8); RK[39][7] = rol8(RK[38][7], (39 + OFFSET5) % 8) + rol8(CONSTANT7, (39 + OFFSET7) % 8); RK[40][0] = rol8(RK[39][0], (40 + OFFSET1) % 8) + rol8(CONSTANT0, (40 + OFFSET3) % 8); RK[40][1] = rol8(RK[39][1], (40 + OFFSET5) % 8) + rol8(CONSTANT1, (40 + OFFSET7) % 8); RK[40][2] = rol8(RK[39][2], (40 + OFFSET1) % 8) + rol8(CONSTANT2, (40 + OFFSET3) % 8); RK[40][3] = rol8(RK[39][3], (40 + OFFSET5) % 8) + rol8(CONSTANT3, (40 + OFFSET7) % 8); RK[40][4] = rol8(RK[39][4], (40 + OFFSET1) % 8) + rol8(CONSTANT4, (40 + OFFSET3) % 8); RK[40][5] = rol8(RK[39][5], (40 + OFFSET5) % 8) + rol8(CONSTANT5, (40 + OFFSET7) % 8); RK[40][6] = rol8(RK[39][6], (40 + OFFSET1) % 8) + rol8(CONSTANT6, (40 + OFFSET3) % 8); RK[40][7] = rol8(RK[39][7], (40 + OFFSET5) % 8) + rol8(CONSTANT7, (40 + OFFSET7) % 8); RK[41][0] = rol8(RK[40][0], (41 + OFFSET1) % 8) + rol8(CONSTANT0, (41 + OFFSET3) % 8); RK[41][1] = rol8(RK[40][1], (41 + OFFSET5) % 8) + rol8(CONSTANT1, (41 + OFFSET7) % 8); RK[41][2] = rol8(RK[40][2], (41 + OFFSET1) % 8) + rol8(CONSTANT2, (41 + OFFSET3) % 8); RK[41][3] = rol8(RK[40][3], (41 + OFFSET5) % 8) + rol8(CONSTANT3, (41 + OFFSET7) % 8); RK[41][4] = rol8(RK[40][4], (41 + OFFSET1) % 8) + rol8(CONSTANT4, (41 + OFFSET3) % 8); RK[41][5] = rol8(RK[40][5], (41 + OFFSET5) % 8) + rol8(CONSTANT5, (41 + OFFSET7) % 8); RK[41][6] = rol8(RK[40][6], (41 + OFFSET1) % 8) + rol8(CONSTANT6, (41 + OFFSET3) % 8); RK[41][7] = rol8(RK[40][7], (41 + OFFSET5) % 8) + rol8(CONSTANT7, (41 + OFFSET7) % 8); RK[42][0] = rol8(RK[41][0], (42 + OFFSET1) % 8) + rol8(CONSTANT0, (42 + OFFSET3) % 8); RK[42][1] = rol8(RK[41][1], (42 + OFFSET5) % 8) + rol8(CONSTANT1, (42 + OFFSET7) % 8); RK[42][2] = rol8(RK[41][2], (42 + OFFSET1) % 8) + rol8(CONSTANT2, (42 + OFFSET3) % 8); RK[42][3] = rol8(RK[41][3], (42 + OFFSET5) % 8) + rol8(CONSTANT3, (42 + OFFSET7) % 8); RK[42][4] = rol8(RK[41][4], (42 + OFFSET1) % 8) + rol8(CONSTANT4, (42 + OFFSET3) % 8); RK[42][5] = rol8(RK[41][5], (42 + OFFSET5) % 8) + rol8(CONSTANT5, (42 + OFFSET7) % 8); RK[42][6] = rol8(RK[41][6], (42 + OFFSET1) % 8) + rol8(CONSTANT6, (42 + OFFSET3) % 8); RK[42][7] = rol8(RK[41][7], (42 + OFFSET5) % 8) + rol8(CONSTANT7, (42 + OFFSET7) % 8); RK[43][0] = rol8(RK[42][0], (43 + OFFSET1) % 8) + rol8(CONSTANT0, (43 + OFFSET3) % 8); RK[43][1] = rol8(RK[42][1], (43 + OFFSET5) % 8) + rol8(CONSTANT1, (43 + OFFSET7) % 8); RK[43][2] = rol8(RK[42][2], (43 + OFFSET1) % 8) + rol8(CONSTANT2, (43 + OFFSET3) % 8); RK[43][3] = rol8(RK[42][3], (43 + OFFSET5) % 8) + rol8(CONSTANT3, (43 + OFFSET7) % 8); RK[43][4] = rol8(RK[42][4], (43 + OFFSET1) % 8) + rol8(CONSTANT4, (43 + OFFSET3) % 8); RK[43][5] = rol8(RK[42][5], (43 + OFFSET5) % 8) + rol8(CONSTANT5, (43 + OFFSET7) % 8); RK[43][6] = rol8(RK[42][6], (43 + OFFSET1) % 8) + rol8(CONSTANT6, (43 + OFFSET3) % 8); RK[43][7] = rol8(RK[42][7], (43 + OFFSET5) % 8) + rol8(CONSTANT7, (43 + OFFSET7) % 8); RK[44][0] = rol8(RK[43][0], (44 + OFFSET1) % 8) + rol8(CONSTANT0, (44 + OFFSET3) % 8); RK[44][1] = rol8(RK[43][1], (44 + OFFSET5) % 8) + rol8(CONSTANT1, (44 + OFFSET7) % 8); RK[44][2] = rol8(RK[43][2], (44 + OFFSET1) % 8) + rol8(CONSTANT2, (44 + OFFSET3) % 8); RK[44][3] = rol8(RK[43][3], (44 + OFFSET5) % 8) + rol8(CONSTANT3, (44 + OFFSET7) % 8); RK[44][4] = rol8(RK[43][4], (44 + OFFSET1) % 8) + rol8(CONSTANT4, (44 + OFFSET3) % 8); RK[44][5] = rol8(RK[43][5], (44 + OFFSET5) % 8) + rol8(CONSTANT5, (44 + OFFSET7) % 8); RK[44][6] = rol8(RK[43][6], (44 + OFFSET1) % 8) + rol8(CONSTANT6, (44 + OFFSET3) % 8); RK[44][7] = rol8(RK[43][7], (44 + OFFSET5) % 8) + rol8(CONSTANT7, (44 + OFFSET7) % 8); RK[45][0] = rol8(RK[44][0], (45 + OFFSET1) % 8) + rol8(CONSTANT0, (45 + OFFSET3) % 8); RK[45][1] = rol8(RK[44][1], (45 + OFFSET5) % 8) + rol8(CONSTANT1, (45 + OFFSET7) % 8); RK[45][2] = rol8(RK[44][2], (45 + OFFSET1) % 8) + rol8(CONSTANT2, (45 + OFFSET3) % 8); RK[45][3] = rol8(RK[44][3], (45 + OFFSET5) % 8) + rol8(CONSTANT3, (45 + OFFSET7) % 8); RK[45][4] = rol8(RK[44][4], (45 + OFFSET1) % 8) + rol8(CONSTANT4, (45 + OFFSET3) % 8); RK[45][5] = rol8(RK[44][5], (45 + OFFSET5) % 8) + rol8(CONSTANT5, (45 + OFFSET7) % 8); RK[45][6] = rol8(RK[44][6], (45 + OFFSET1) % 8) + rol8(CONSTANT6, (45 + OFFSET3) % 8); RK[45][7] = rol8(RK[44][7], (45 + OFFSET5) % 8) + rol8(CONSTANT7, (45 + OFFSET7) % 8); RK[46][0] = rol8(RK[45][0], (46 + OFFSET1) % 8) + rol8(CONSTANT0, (46 + OFFSET3) % 8); RK[46][1] = rol8(RK[45][1], (46 + OFFSET5) % 8) + rol8(CONSTANT1, (46 + OFFSET7) % 8); RK[46][2] = rol8(RK[45][2], (46 + OFFSET1) % 8) + rol8(CONSTANT2, (46 + OFFSET3) % 8); RK[46][3] = rol8(RK[45][3], (46 + OFFSET5) % 8) + rol8(CONSTANT3, (46 + OFFSET7) % 8); RK[46][4] = rol8(RK[45][4], (46 + OFFSET1) % 8) + rol8(CONSTANT4, (46 + OFFSET3) % 8); RK[46][5] = rol8(RK[45][5], (46 + OFFSET5) % 8) + rol8(CONSTANT5, (46 + OFFSET7) % 8); RK[46][6] = rol8(RK[45][6], (46 + OFFSET1) % 8) + rol8(CONSTANT6, (46 + OFFSET3) % 8); RK[46][7] = rol8(RK[45][7], (46 + OFFSET5) % 8) + rol8(CONSTANT7, (46 + OFFSET7) % 8); RK[47][0] = rol8(RK[46][0], (47 + OFFSET1) % 8) + rol8(CONSTANT0, (47 + OFFSET3) % 8); RK[47][1] = rol8(RK[46][1], (47 + OFFSET5) % 8) + rol8(CONSTANT1, (47 + OFFSET7) % 8); RK[47][2] = rol8(RK[46][2], (47 + OFFSET1) % 8) + rol8(CONSTANT2, (47 + OFFSET3) % 8); RK[47][3] = rol8(RK[46][3], (47 + OFFSET5) % 8) + rol8(CONSTANT3, (47 + OFFSET7) % 8); RK[47][4] = rol8(RK[46][4], (47 + OFFSET1) % 8) + rol8(CONSTANT4, (47 + OFFSET3) % 8); RK[47][5] = rol8(RK[46][5], (47 + OFFSET5) % 8) + rol8(CONSTANT5, (47 + OFFSET7) % 8); RK[47][6] = rol8(RK[46][6], (47 + OFFSET1) % 8) + rol8(CONSTANT6, (47 + OFFSET3) % 8); RK[47][7] = rol8(RK[46][7], (47 + OFFSET5) % 8) + rol8(CONSTANT7, (47 + OFFSET7) % 8); RK[48][0] = rol8(RK[47][0], (48 + OFFSET1) % 8) + rol8(CONSTANT0, (48 + OFFSET3) % 8); RK[48][1] = rol8(RK[47][1], (48 + OFFSET5) % 8) + rol8(CONSTANT1, (48 + OFFSET7) % 8); RK[48][2] = rol8(RK[47][2], (48 + OFFSET1) % 8) + rol8(CONSTANT2, (48 + OFFSET3) % 8); RK[48][3] = rol8(RK[47][3], (48 + OFFSET5) % 8) + rol8(CONSTANT3, (48 + OFFSET7) % 8); RK[48][4] = rol8(RK[47][4], (48 + OFFSET1) % 8) + rol8(CONSTANT4, (48 + OFFSET3) % 8); RK[48][5] = rol8(RK[47][5], (48 + OFFSET5) % 8) + rol8(CONSTANT5, (48 + OFFSET7) % 8); RK[48][6] = rol8(RK[47][6], (48 + OFFSET1) % 8) + rol8(CONSTANT6, (48 + OFFSET3) % 8); RK[48][7] = rol8(RK[47][7], (48 + OFFSET5) % 8) + rol8(CONSTANT7, (48 + OFFSET7) % 8); RK[49][0] = rol8(RK[48][0], (49 + OFFSET1) % 8) + rol8(CONSTANT0, (49 + OFFSET3) % 8); RK[49][1] = rol8(RK[48][1], (49 + OFFSET5) % 8) + rol8(CONSTANT1, (49 + OFFSET7) % 8); RK[49][2] = rol8(RK[48][2], (49 + OFFSET1) % 8) + rol8(CONSTANT2, (49 + OFFSET3) % 8); RK[49][3] = rol8(RK[48][3], (49 + OFFSET5) % 8) + rol8(CONSTANT3, (49 + OFFSET7) % 8); RK[49][4] = rol8(RK[48][4], (49 + OFFSET1) % 8) + rol8(CONSTANT4, (49 + OFFSET3) % 8); RK[49][5] = rol8(RK[48][5], (49 + OFFSET5) % 8) + rol8(CONSTANT5, (49 + OFFSET7) % 8); RK[49][6] = rol8(RK[48][6], (49 + OFFSET1) % 8) + rol8(CONSTANT6, (49 + OFFSET3) % 8); RK[49][7] = rol8(RK[48][7], (49 + OFFSET5) % 8) + rol8(CONSTANT7, (49 + OFFSET7) % 8); RK[50][0] = rol8(RK[49][0], (50 + OFFSET1) % 8) + rol8(CONSTANT0, (50 + OFFSET3) % 8); RK[50][1] = rol8(RK[49][1], (50 + OFFSET5) % 8) + rol8(CONSTANT1, (50 + OFFSET7) % 8); RK[50][2] = rol8(RK[49][2], (50 + OFFSET1) % 8) + rol8(CONSTANT2, (50 + OFFSET3) % 8); RK[50][3] = rol8(RK[49][3], (50 + OFFSET5) % 8) + rol8(CONSTANT3, (50 + OFFSET7) % 8); RK[50][4] = rol8(RK[49][4], (50 + OFFSET1) % 8) + rol8(CONSTANT4, (50 + OFFSET3) % 8); RK[50][5] = rol8(RK[49][5], (50 + OFFSET5) % 8) + rol8(CONSTANT5, (50 + OFFSET7) % 8); RK[50][6] = rol8(RK[49][6], (50 + OFFSET1) % 8) + rol8(CONSTANT6, (50 + OFFSET3) % 8); RK[50][7] = rol8(RK[49][7], (50 + OFFSET5) % 8) + rol8(CONSTANT7, (50 + OFFSET7) % 8); RK[51][0] = rol8(RK[50][0], (51 + OFFSET1) % 8) + rol8(CONSTANT0, (51 + OFFSET3) % 8); RK[51][1] = rol8(RK[50][1], (51 + OFFSET5) % 8) + rol8(CONSTANT1, (51 + OFFSET7) % 8); RK[51][2] = rol8(RK[50][2], (51 + OFFSET1) % 8) + rol8(CONSTANT2, (51 + OFFSET3) % 8); RK[51][3] = rol8(RK[50][3], (51 + OFFSET5) % 8) + rol8(CONSTANT3, (51 + OFFSET7) % 8); RK[51][4] = rol8(RK[50][4], (51 + OFFSET1) % 8) + rol8(CONSTANT4, (51 + OFFSET3) % 8); RK[51][5] = rol8(RK[50][5], (51 + OFFSET5) % 8) + rol8(CONSTANT5, (51 + OFFSET7) % 8); RK[51][6] = rol8(RK[50][6], (51 + OFFSET1) % 8) + rol8(CONSTANT6, (51 + OFFSET3) % 8); RK[51][7] = rol8(RK[50][7], (51 + OFFSET5) % 8) + rol8(CONSTANT7, (51 + OFFSET7) % 8); RK[52][0] = rol8(RK[51][0], (52 + OFFSET1) % 8) + rol8(CONSTANT0, (52 + OFFSET3) % 8); RK[52][1] = rol8(RK[51][1], (52 + OFFSET5) % 8) + rol8(CONSTANT1, (52 + OFFSET7) % 8); RK[52][2] = rol8(RK[51][2], (52 + OFFSET1) % 8) + rol8(CONSTANT2, (52 + OFFSET3) % 8); RK[52][3] = rol8(RK[51][3], (52 + OFFSET5) % 8) + rol8(CONSTANT3, (52 + OFFSET7) % 8); RK[52][4] = rol8(RK[51][4], (52 + OFFSET1) % 8) + rol8(CONSTANT4, (52 + OFFSET3) % 8); RK[52][5] = rol8(RK[51][5], (52 + OFFSET5) % 8) + rol8(CONSTANT5, (52 + OFFSET7) % 8); RK[52][6] = rol8(RK[51][6], (52 + OFFSET1) % 8) + rol8(CONSTANT6, (52 + OFFSET3) % 8); RK[52][7] = rol8(RK[51][7], (52 + OFFSET5) % 8) + rol8(CONSTANT7, (52 + OFFSET7) % 8); RK[53][0] = rol8(RK[52][0], (53 + OFFSET1) % 8) + rol8(CONSTANT0, (53 + OFFSET3) % 8); RK[53][1] = rol8(RK[52][1], (53 + OFFSET5) % 8) + rol8(CONSTANT1, (53 + OFFSET7) % 8); RK[53][2] = rol8(RK[52][2], (53 + OFFSET1) % 8) + rol8(CONSTANT2, (53 + OFFSET3) % 8); RK[53][3] = rol8(RK[52][3], (53 + OFFSET5) % 8) + rol8(CONSTANT3, (53 + OFFSET7) % 8); RK[53][4] = rol8(RK[52][4], (53 + OFFSET1) % 8) + rol8(CONSTANT4, (53 + OFFSET3) % 8); RK[53][5] = rol8(RK[52][5], (53 + OFFSET5) % 8) + rol8(CONSTANT5, (53 + OFFSET7) % 8); RK[53][6] = rol8(RK[52][6], (53 + OFFSET1) % 8) + rol8(CONSTANT6, (53 + OFFSET3) % 8); RK[53][7] = rol8(RK[52][7], (53 + OFFSET5) % 8) + rol8(CONSTANT7, (53 + OFFSET7) % 8); RK[54][0] = rol8(RK[53][0], (54 + OFFSET1) % 8) + rol8(CONSTANT0, (54 + OFFSET3) % 8); RK[54][1] = rol8(RK[53][1], (54 + OFFSET5) % 8) + rol8(CONSTANT1, (54 + OFFSET7) % 8); RK[54][2] = rol8(RK[53][2], (54 + OFFSET1) % 8) + rol8(CONSTANT2, (54 + OFFSET3) % 8); RK[54][3] = rol8(RK[53][3], (54 + OFFSET5) % 8) + rol8(CONSTANT3, (54 + OFFSET7) % 8); RK[54][4] = rol8(RK[53][4], (54 + OFFSET1) % 8) + rol8(CONSTANT4, (54 + OFFSET3) % 8); RK[54][5] = rol8(RK[53][5], (54 + OFFSET5) % 8) + rol8(CONSTANT5, (54 + OFFSET7) % 8); RK[54][6] = rol8(RK[53][6], (54 + OFFSET1) % 8) + rol8(CONSTANT6, (54 + OFFSET3) % 8); RK[54][7] = rol8(RK[53][7], (54 + OFFSET5) % 8) + rol8(CONSTANT7, (54 + OFFSET7) % 8); RK[55][0] = rol8(RK[54][0], (55 + OFFSET1) % 8) + rol8(CONSTANT0, (55 + OFFSET3) % 8); RK[55][1] = rol8(RK[54][1], (55 + OFFSET5) % 8) + rol8(CONSTANT1, (55 + OFFSET7) % 8); RK[55][2] = rol8(RK[54][2], (55 + OFFSET1) % 8) + rol8(CONSTANT2, (55 + OFFSET3) % 8); RK[55][3] = rol8(RK[54][3], (55 + OFFSET5) % 8) + rol8(CONSTANT3, (55 + OFFSET7) % 8); RK[55][4] = rol8(RK[54][4], (55 + OFFSET1) % 8) + rol8(CONSTANT4, (55 + OFFSET3) % 8); RK[55][5] = rol8(RK[54][5], (55 + OFFSET5) % 8) + rol8(CONSTANT5, (55 + OFFSET7) % 8); RK[55][6] = rol8(RK[54][6], (55 + OFFSET1) % 8) + rol8(CONSTANT6, (55 + OFFSET3) % 8); RK[55][7] = rol8(RK[54][7], (55 + OFFSET5) % 8) + rol8(CONSTANT7, (55 + OFFSET7) % 8); RK[56][0] = rol8(RK[55][0], (56 + OFFSET1) % 8) + rol8(CONSTANT0, (56 + OFFSET3) % 8); RK[56][1] = rol8(RK[55][1], (56 + OFFSET5) % 8) + rol8(CONSTANT1, (56 + OFFSET7) % 8); RK[56][2] = rol8(RK[55][2], (56 + OFFSET1) % 8) + rol8(CONSTANT2, (56 + OFFSET3) % 8); RK[56][3] = rol8(RK[55][3], (56 + OFFSET5) % 8) + rol8(CONSTANT3, (56 + OFFSET7) % 8); RK[56][4] = rol8(RK[55][4], (56 + OFFSET1) % 8) + rol8(CONSTANT4, (56 + OFFSET3) % 8); RK[56][5] = rol8(RK[55][5], (56 + OFFSET5) % 8) + rol8(CONSTANT5, (56 + OFFSET7) % 8); RK[56][6] = rol8(RK[55][6], (56 + OFFSET1) % 8) + rol8(CONSTANT6, (56 + OFFSET3) % 8); RK[56][7] = rol8(RK[55][7], (56 + OFFSET5) % 8) + rol8(CONSTANT7, (56 + OFFSET7) % 8); RK[57][0] = rol8(RK[56][0], (57 + OFFSET1) % 8) + rol8(CONSTANT0, (57 + OFFSET3) % 8); RK[57][1] = rol8(RK[56][1], (57 + OFFSET5) % 8) + rol8(CONSTANT1, (57 + OFFSET7) % 8); RK[57][2] = rol8(RK[56][2], (57 + OFFSET1) % 8) + rol8(CONSTANT2, (57 + OFFSET3) % 8); RK[57][3] = rol8(RK[56][3], (57 + OFFSET5) % 8) + rol8(CONSTANT3, (57 + OFFSET7) % 8); RK[57][4] = rol8(RK[56][4], (57 + OFFSET1) % 8) + rol8(CONSTANT4, (57 + OFFSET3) % 8); RK[57][5] = rol8(RK[56][5], (57 + OFFSET5) % 8) + rol8(CONSTANT5, (57 + OFFSET7) % 8); RK[57][6] = rol8(RK[56][6], (57 + OFFSET1) % 8) + rol8(CONSTANT6, (57 + OFFSET3) % 8); RK[57][7] = rol8(RK[56][7], (57 + OFFSET5) % 8) + rol8(CONSTANT7, (57 + OFFSET7) % 8); RK[58][0] = rol8(RK[57][0], (58 + OFFSET1) % 8) + rol8(CONSTANT0, (58 + OFFSET3) % 8); RK[58][1] = rol8(RK[57][1], (58 + OFFSET5) % 8) + rol8(CONSTANT1, (58 + OFFSET7) % 8); RK[58][2] = rol8(RK[57][2], (58 + OFFSET1) % 8) + rol8(CONSTANT2, (58 + OFFSET3) % 8); RK[58][3] = rol8(RK[57][3], (58 + OFFSET5) % 8) + rol8(CONSTANT3, (58 + OFFSET7) % 8); RK[58][4] = rol8(RK[57][4], (58 + OFFSET1) % 8) + rol8(CONSTANT4, (58 + OFFSET3) % 8); RK[58][5] = rol8(RK[57][5], (58 + OFFSET5) % 8) + rol8(CONSTANT5, (58 + OFFSET7) % 8); RK[58][6] = rol8(RK[57][6], (58 + OFFSET1) % 8) + rol8(CONSTANT6, (58 + OFFSET3) % 8); RK[58][7] = rol8(RK[57][7], (58 + OFFSET5) % 8) + rol8(CONSTANT7, (58 + OFFSET7) % 8); RK[59][0] = rol8(RK[58][0], (59 + OFFSET1) % 8) + rol8(CONSTANT0, (59 + OFFSET3) % 8); RK[59][1] = rol8(RK[58][1], (59 + OFFSET5) % 8) + rol8(CONSTANT1, (59 + OFFSET7) % 8); RK[59][2] = rol8(RK[58][2], (59 + OFFSET1) % 8) + rol8(CONSTANT2, (59 + OFFSET3) % 8); RK[59][3] = rol8(RK[58][3], (59 + OFFSET5) % 8) + rol8(CONSTANT3, (59 + OFFSET7) % 8); RK[59][4] = rol8(RK[58][4], (59 + OFFSET1) % 8) + rol8(CONSTANT4, (59 + OFFSET3) % 8); RK[59][5] = rol8(RK[58][5], (59 + OFFSET5) % 8) + rol8(CONSTANT5, (59 + OFFSET7) % 8); RK[59][6] = rol8(RK[58][6], (59 + OFFSET1) % 8) + rol8(CONSTANT6, (59 + OFFSET3) % 8); RK[59][7] = rol8(RK[58][7], (59 + OFFSET5) % 8) + rol8(CONSTANT7, (59 + OFFSET7) % 8); RK[60][0] = rol8(RK[59][0], (60 + OFFSET1) % 8) + rol8(CONSTANT0, (60 + OFFSET3) % 8); RK[60][1] = rol8(RK[59][1], (60 + OFFSET5) % 8) + rol8(CONSTANT1, (60 + OFFSET7) % 8); RK[60][2] = rol8(RK[59][2], (60 + OFFSET1) % 8) + rol8(CONSTANT2, (60 + OFFSET3) % 8); RK[60][3] = rol8(RK[59][3], (60 + OFFSET5) % 8) + rol8(CONSTANT3, (60 + OFFSET7) % 8); RK[60][4] = rol8(RK[59][4], (60 + OFFSET1) % 8) + rol8(CONSTANT4, (60 + OFFSET3) % 8); RK[60][5] = rol8(RK[59][5], (60 + OFFSET5) % 8) + rol8(CONSTANT5, (60 + OFFSET7) % 8); RK[60][6] = rol8(RK[59][6], (60 + OFFSET1) % 8) + rol8(CONSTANT6, (60 + OFFSET3) % 8); RK[60][7] = rol8(RK[59][7], (60 + OFFSET5) % 8) + rol8(CONSTANT7, (60 + OFFSET7) % 8); RK[61][0] = rol8(RK[60][0], (61 + OFFSET1) % 8) + rol8(CONSTANT0, (61 + OFFSET3) % 8); RK[61][1] = rol8(RK[60][1], (61 + OFFSET5) % 8) + rol8(CONSTANT1, (61 + OFFSET7) % 8); RK[61][2] = rol8(RK[60][2], (61 + OFFSET1) % 8) + rol8(CONSTANT2, (61 + OFFSET3) % 8); RK[61][3] = rol8(RK[60][3], (61 + OFFSET5) % 8) + rol8(CONSTANT3, (61 + OFFSET7) % 8); RK[61][4] = rol8(RK[60][4], (61 + OFFSET1) % 8) + rol8(CONSTANT4, (61 + OFFSET3) % 8); RK[61][5] = rol8(RK[60][5], (61 + OFFSET5) % 8) + rol8(CONSTANT5, (61 + OFFSET7) % 8); RK[61][6] = rol8(RK[60][6], (61 + OFFSET1) % 8) + rol8(CONSTANT6, (61 + OFFSET3) % 8); RK[61][7] = rol8(RK[60][7], (61 + OFFSET5) % 8) + rol8(CONSTANT7, (61 + OFFSET7) % 8); RK[62][0] = rol8(RK[61][0], (62 + OFFSET1) % 8) + rol8(CONSTANT0, (62 + OFFSET3) % 8); RK[62][1] = rol8(RK[61][1], (62 + OFFSET5) % 8) + rol8(CONSTANT1, (62 + OFFSET7) % 8); RK[62][2] = rol8(RK[61][2], (62 + OFFSET1) % 8) + rol8(CONSTANT2, (62 + OFFSET3) % 8); RK[62][3] = rol8(RK[61][3], (62 + OFFSET5) % 8) + rol8(CONSTANT3, (62 + OFFSET7) % 8); RK[62][4] = rol8(RK[61][4], (62 + OFFSET1) % 8) + rol8(CONSTANT4, (62 + OFFSET3) % 8); RK[62][5] = rol8(RK[61][5], (62 + OFFSET5) % 8) + rol8(CONSTANT5, (62 + OFFSET7) % 8); RK[62][6] = rol8(RK[61][6], (62 + OFFSET1) % 8) + rol8(CONSTANT6, (62 + OFFSET3) % 8); RK[62][7] = rol8(RK[61][7], (62 + OFFSET5) % 8) + rol8(CONSTANT7, (62 + OFFSET7) % 8); RK[63][0] = rol8(RK[62][0], (63 + OFFSET1) % 8) + rol8(CONSTANT0, (63 + OFFSET3) % 8); RK[63][1] = rol8(RK[62][1], (63 + OFFSET5) % 8) + rol8(CONSTANT1, (63 + OFFSET7) % 8); RK[63][2] = rol8(RK[62][2], (63 + OFFSET1) % 8) + rol8(CONSTANT2, (63 + OFFSET3) % 8); RK[63][3] = rol8(RK[62][3], (63 + OFFSET5) % 8) + rol8(CONSTANT3, (63 + OFFSET7) % 8); RK[63][4] = rol8(RK[62][4], (63 + OFFSET1) % 8) + rol8(CONSTANT4, (63 + OFFSET3) % 8); RK[63][5] = rol8(RK[62][5], (63 + OFFSET5) % 8) + rol8(CONSTANT5, (63 + OFFSET7) % 8); RK[63][6] = rol8(RK[62][6], (63 + OFFSET1) % 8) + rol8(CONSTANT6, (63 + OFFSET3) % 8); RK[63][7] = rol8(RK[62][7], (63 + OFFSET5) % 8) + rol8(CONSTANT7, (63 + OFFSET7) % 8); RK[64][0] = rol8(RK[63][0], (64 + OFFSET1) % 8) + rol8(CONSTANT0, (64 + OFFSET3) % 8); RK[64][1] = rol8(RK[63][1], (64 + OFFSET5) % 8) + rol8(CONSTANT1, (64 + OFFSET7) % 8); RK[64][2] = rol8(RK[63][2], (64 + OFFSET1) % 8) + rol8(CONSTANT2, (64 + OFFSET3) % 8); RK[64][3] = rol8(RK[63][3], (64 + OFFSET5) % 8) + rol8(CONSTANT3, (64 + OFFSET7) % 8); RK[64][4] = rol8(RK[63][4], (64 + OFFSET1) % 8) + rol8(CONSTANT4, (64 + OFFSET3) % 8); RK[64][5] = rol8(RK[63][5], (64 + OFFSET5) % 8) + rol8(CONSTANT5, (64 + OFFSET7) % 8); RK[64][6] = rol8(RK[63][6], (64 + OFFSET1) % 8) + rol8(CONSTANT6, (64 + OFFSET3) % 8); RK[64][7] = rol8(RK[63][7], (64 + OFFSET5) % 8) + rol8(CONSTANT7, (64 + OFFSET7) % 8); RK[65][0] = rol8(RK[64][0], (65 + OFFSET1) % 8) + rol8(CONSTANT0, (65 + OFFSET3) % 8); RK[65][1] = rol8(RK[64][1], (65 + OFFSET5) % 8) + rol8(CONSTANT1, (65 + OFFSET7) % 8); RK[65][2] = rol8(RK[64][2], (65 + OFFSET1) % 8) + rol8(CONSTANT2, (65 + OFFSET3) % 8); RK[65][3] = rol8(RK[64][3], (65 + OFFSET5) % 8) + rol8(CONSTANT3, (65 + OFFSET7) % 8); RK[65][4] = rol8(RK[64][4], (65 + OFFSET1) % 8) + rol8(CONSTANT4, (65 + OFFSET3) % 8); RK[65][5] = rol8(RK[64][5], (65 + OFFSET5) % 8) + rol8(CONSTANT5, (65 + OFFSET7) % 8); RK[65][6] = rol8(RK[64][6], (65 + OFFSET1) % 8) + rol8(CONSTANT6, (65 + OFFSET3) % 8); RK[65][7] = rol8(RK[64][7], (65 + OFFSET5) % 8) + rol8(CONSTANT7, (65 + OFFSET7) % 8); RK[66][0] = rol8(RK[65][0], (66 + OFFSET1) % 8) + rol8(CONSTANT0, (66 + OFFSET3) % 8); RK[66][1] = rol8(RK[65][1], (66 + OFFSET5) % 8) + rol8(CONSTANT1, (66 + OFFSET7) % 8); RK[66][2] = rol8(RK[65][2], (66 + OFFSET1) % 8) + rol8(CONSTANT2, (66 + OFFSET3) % 8); RK[66][3] = rol8(RK[65][3], (66 + OFFSET5) % 8) + rol8(CONSTANT3, (66 + OFFSET7) % 8); RK[66][4] = rol8(RK[65][4], (66 + OFFSET1) % 8) + rol8(CONSTANT4, (66 + OFFSET3) % 8); RK[66][5] = rol8(RK[65][5], (66 + OFFSET5) % 8) + rol8(CONSTANT5, (66 + OFFSET7) % 8); RK[66][6] = rol8(RK[65][6], (66 + OFFSET1) % 8) + rol8(CONSTANT6, (66 + OFFSET3) % 8); RK[66][7] = rol8(RK[65][7], (66 + OFFSET5) % 8) + rol8(CONSTANT7, (66 + OFFSET7) % 8); RK[67][0] = rol8(RK[66][0], (67 + OFFSET1) % 8) + rol8(CONSTANT0, (67 + OFFSET3) % 8); RK[67][1] = rol8(RK[66][1], (67 + OFFSET5) % 8) + rol8(CONSTANT1, (67 + OFFSET7) % 8); RK[67][2] = rol8(RK[66][2], (67 + OFFSET1) % 8) + rol8(CONSTANT2, (67 + OFFSET3) % 8); RK[67][3] = rol8(RK[66][3], (67 + OFFSET5) % 8) + rol8(CONSTANT3, (67 + OFFSET7) % 8); RK[67][4] = rol8(RK[66][4], (67 + OFFSET1) % 8) + rol8(CONSTANT4, (67 + OFFSET3) % 8); RK[67][5] = rol8(RK[66][5], (67 + OFFSET5) % 8) + rol8(CONSTANT5, (67 + OFFSET7) % 8); RK[67][6] = rol8(RK[66][6], (67 + OFFSET1) % 8) + rol8(CONSTANT6, (67 + OFFSET3) % 8); RK[67][7] = rol8(RK[66][7], (67 + OFFSET5) % 8) + rol8(CONSTANT7, (67 + OFFSET7) % 8); RK[68][0] = rol8(RK[67][0], (68 + OFFSET1) % 8) + rol8(CONSTANT0, (68 + OFFSET3) % 8); RK[68][1] = rol8(RK[67][1], (68 + OFFSET5) % 8) + rol8(CONSTANT1, (68 + OFFSET7) % 8); RK[68][2] = rol8(RK[67][2], (68 + OFFSET1) % 8) + rol8(CONSTANT2, (68 + OFFSET3) % 8); RK[68][3] = rol8(RK[67][3], (68 + OFFSET5) % 8) + rol8(CONSTANT3, (68 + OFFSET7) % 8); RK[68][4] = rol8(RK[67][4], (68 + OFFSET1) % 8) + rol8(CONSTANT4, (68 + OFFSET3) % 8); RK[68][5] = rol8(RK[67][5], (68 + OFFSET5) % 8) + rol8(CONSTANT5, (68 + OFFSET7) % 8); RK[68][6] = rol8(RK[67][6], (68 + OFFSET1) % 8) + rol8(CONSTANT6, (68 + OFFSET3) % 8); RK[68][7] = rol8(RK[67][7], (68 + OFFSET5) % 8) + rol8(CONSTANT7, (68 + OFFSET7) % 8); RK[69][0] = rol8(RK[68][0], (69 + OFFSET1) % 8) + rol8(CONSTANT0, (69 + OFFSET3) % 8); RK[69][1] = rol8(RK[68][1], (69 + OFFSET5) % 8) + rol8(CONSTANT1, (69 + OFFSET7) % 8); RK[69][2] = rol8(RK[68][2], (69 + OFFSET1) % 8) + rol8(CONSTANT2, (69 + OFFSET3) % 8); RK[69][3] = rol8(RK[68][3], (69 + OFFSET5) % 8) + rol8(CONSTANT3, (69 + OFFSET7) % 8); RK[69][4] = rol8(RK[68][4], (69 + OFFSET1) % 8) + rol8(CONSTANT4, (69 + OFFSET3) % 8); RK[69][5] = rol8(RK[68][5], (69 + OFFSET5) % 8) + rol8(CONSTANT5, (69 + OFFSET7) % 8); RK[69][6] = rol8(RK[68][6], (69 + OFFSET1) % 8) + rol8(CONSTANT6, (69 + OFFSET3) % 8); RK[69][7] = rol8(RK[68][7], (69 + OFFSET5) % 8) + rol8(CONSTANT7, (69 + OFFSET7) % 8); RK[70][0] = rol8(RK[69][0], (70 + OFFSET1) % 8) + rol8(CONSTANT0, (70 + OFFSET3) % 8); RK[70][1] = rol8(RK[69][1], (70 + OFFSET5) % 8) + rol8(CONSTANT1, (70 + OFFSET7) % 8); RK[70][2] = rol8(RK[69][2], (70 + OFFSET1) % 8) + rol8(CONSTANT2, (70 + OFFSET3) % 8); RK[70][3] = rol8(RK[69][3], (70 + OFFSET5) % 8) + rol8(CONSTANT3, (70 + OFFSET7) % 8); RK[70][4] = rol8(RK[69][4], (70 + OFFSET1) % 8) + rol8(CONSTANT4, (70 + OFFSET3) % 8); RK[70][5] = rol8(RK[69][5], (70 + OFFSET5) % 8) + rol8(CONSTANT5, (70 + OFFSET7) % 8); RK[70][6] = rol8(RK[69][6], (70 + OFFSET1) % 8) + rol8(CONSTANT6, (70 + OFFSET3) % 8); RK[70][7] = rol8(RK[69][7], (70 + OFFSET5) % 8) + rol8(CONSTANT7, (70 + OFFSET7) % 8); RK[71][0] = rol8(RK[70][0], (71 + OFFSET1) % 8) + rol8(CONSTANT0, (71 + OFFSET3) % 8); RK[71][1] = rol8(RK[70][1], (71 + OFFSET5) % 8) + rol8(CONSTANT1, (71 + OFFSET7) % 8); RK[71][2] = rol8(RK[70][2], (71 + OFFSET1) % 8) + rol8(CONSTANT2, (71 + OFFSET3) % 8); RK[71][3] = rol8(RK[70][3], (71 + OFFSET5) % 8) + rol8(CONSTANT3, (71 + OFFSET7) % 8); RK[71][4] = rol8(RK[70][4], (71 + OFFSET1) % 8) + rol8(CONSTANT4, (71 + OFFSET3) % 8); RK[71][5] = rol8(RK[70][5], (71 + OFFSET5) % 8) + rol8(CONSTANT5, (71 + OFFSET7) % 8); RK[71][6] = rol8(RK[70][6], (71 + OFFSET1) % 8) + rol8(CONSTANT6, (71 + OFFSET3) % 8); RK[71][7] = rol8(RK[70][7], (71 + OFFSET5) % 8) + rol8(CONSTANT7, (71 + OFFSET7) % 8); RK[72][0] = rol8(RK[71][0], (72 + OFFSET1) % 8) + rol8(CONSTANT0, (72 + OFFSET3) % 8); RK[72][1] = rol8(RK[71][1], (72 + OFFSET5) % 8) + rol8(CONSTANT1, (72 + OFFSET7) % 8); RK[72][2] = rol8(RK[71][2], (72 + OFFSET1) % 8) + rol8(CONSTANT2, (72 + OFFSET3) % 8); RK[72][3] = rol8(RK[71][3], (72 + OFFSET5) % 8) + rol8(CONSTANT3, (72 + OFFSET7) % 8); RK[72][4] = rol8(RK[71][4], (72 + OFFSET1) % 8) + rol8(CONSTANT4, (72 + OFFSET3) % 8); RK[72][5] = rol8(RK[71][5], (72 + OFFSET5) % 8) + rol8(CONSTANT5, (72 + OFFSET7) % 8); RK[72][6] = rol8(RK[71][6], (72 + OFFSET1) % 8) + rol8(CONSTANT6, (72 + OFFSET3) % 8); RK[72][7] = rol8(RK[71][7], (72 + OFFSET5) % 8) + rol8(CONSTANT7, (72 + OFFSET7) % 8); RK[73][0] = rol8(RK[72][0], (73 + OFFSET1) % 8) + rol8(CONSTANT0, (73 + OFFSET3) % 8); RK[73][1] = rol8(RK[72][1], (73 + OFFSET5) % 8) + rol8(CONSTANT1, (73 + OFFSET7) % 8); RK[73][2] = rol8(RK[72][2], (73 + OFFSET1) % 8) + rol8(CONSTANT2, (73 + OFFSET3) % 8); RK[73][3] = rol8(RK[72][3], (73 + OFFSET5) % 8) + rol8(CONSTANT3, (73 + OFFSET7) % 8); RK[73][4] = rol8(RK[72][4], (73 + OFFSET1) % 8) + rol8(CONSTANT4, (73 + OFFSET3) % 8); RK[73][5] = rol8(RK[72][5], (73 + OFFSET5) % 8) + rol8(CONSTANT5, (73 + OFFSET7) % 8); RK[73][6] = rol8(RK[72][6], (73 + OFFSET1) % 8) + rol8(CONSTANT6, (73 + OFFSET3) % 8); RK[73][7] = rol8(RK[72][7], (73 + OFFSET5) % 8) + rol8(CONSTANT7, (73 + OFFSET7) % 8); RK[74][0] = rol8(RK[73][0], (74 + OFFSET1) % 8) + rol8(CONSTANT0, (74 + OFFSET3) % 8); RK[74][1] = rol8(RK[73][1], (74 + OFFSET5) % 8) + rol8(CONSTANT1, (74 + OFFSET7) % 8); RK[74][2] = rol8(RK[73][2], (74 + OFFSET1) % 8) + rol8(CONSTANT2, (74 + OFFSET3) % 8); RK[74][3] = rol8(RK[73][3], (74 + OFFSET5) % 8) + rol8(CONSTANT3, (74 + OFFSET7) % 8); RK[74][4] = rol8(RK[73][4], (74 + OFFSET1) % 8) + rol8(CONSTANT4, (74 + OFFSET3) % 8); RK[74][5] = rol8(RK[73][5], (74 + OFFSET5) % 8) + rol8(CONSTANT5, (74 + OFFSET7) % 8); RK[74][6] = rol8(RK[73][6], (74 + OFFSET1) % 8) + rol8(CONSTANT6, (74 + OFFSET3) % 8); RK[74][7] = rol8(RK[73][7], (74 + OFFSET5) % 8) + rol8(CONSTANT7, (74 + OFFSET7) % 8); RK[75][0] = rol8(RK[74][0], (75 + OFFSET1) % 8) + rol8(CONSTANT0, (75 + OFFSET3) % 8); RK[75][1] = rol8(RK[74][1], (75 + OFFSET5) % 8) + rol8(CONSTANT1, (75 + OFFSET7) % 8); RK[75][2] = rol8(RK[74][2], (75 + OFFSET1) % 8) + rol8(CONSTANT2, (75 + OFFSET3) % 8); RK[75][3] = rol8(RK[74][3], (75 + OFFSET5) % 8) + rol8(CONSTANT3, (75 + OFFSET7) % 8); RK[75][4] = rol8(RK[74][4], (75 + OFFSET1) % 8) + rol8(CONSTANT4, (75 + OFFSET3) % 8); RK[75][5] = rol8(RK[74][5], (75 + OFFSET5) % 8) + rol8(CONSTANT5, (75 + OFFSET7) % 8); RK[75][6] = rol8(RK[74][6], (75 + OFFSET1) % 8) + rol8(CONSTANT6, (75 + OFFSET3) % 8); RK[75][7] = rol8(RK[74][7], (75 + OFFSET5) % 8) + rol8(CONSTANT7, (75 + OFFSET7) % 8); RK[76][0] = rol8(RK[75][0], (76 + OFFSET1) % 8) + rol8(CONSTANT0, (76 + OFFSET3) % 8); RK[76][1] = rol8(RK[75][1], (76 + OFFSET5) % 8) + rol8(CONSTANT1, (76 + OFFSET7) % 8); RK[76][2] = rol8(RK[75][2], (76 + OFFSET1) % 8) + rol8(CONSTANT2, (76 + OFFSET3) % 8); RK[76][3] = rol8(RK[75][3], (76 + OFFSET5) % 8) + rol8(CONSTANT3, (76 + OFFSET7) % 8); RK[76][4] = rol8(RK[75][4], (76 + OFFSET1) % 8) + rol8(CONSTANT4, (76 + OFFSET3) % 8); RK[76][5] = rol8(RK[75][5], (76 + OFFSET5) % 8) + rol8(CONSTANT5, (76 + OFFSET7) % 8); RK[76][6] = rol8(RK[75][6], (76 + OFFSET1) % 8) + rol8(CONSTANT6, (76 + OFFSET3) % 8); RK[76][7] = rol8(RK[75][7], (76 + OFFSET5) % 8) + rol8(CONSTANT7, (76 + OFFSET7) % 8); RK[77][0] = rol8(RK[76][0], (77 + OFFSET1) % 8) + rol8(CONSTANT0, (77 + OFFSET3) % 8); RK[77][1] = rol8(RK[76][1], (77 + OFFSET5) % 8) + rol8(CONSTANT1, (77 + OFFSET7) % 8); RK[77][2] = rol8(RK[76][2], (77 + OFFSET1) % 8) + rol8(CONSTANT2, (77 + OFFSET3) % 8); RK[77][3] = rol8(RK[76][3], (77 + OFFSET5) % 8) + rol8(CONSTANT3, (77 + OFFSET7) % 8); RK[77][4] = rol8(RK[76][4], (77 + OFFSET1) % 8) + rol8(CONSTANT4, (77 + OFFSET3) % 8); RK[77][5] = rol8(RK[76][5], (77 + OFFSET5) % 8) + rol8(CONSTANT5, (77 + OFFSET7) % 8); RK[77][6] = rol8(RK[76][6], (77 + OFFSET1) % 8) + rol8(CONSTANT6, (77 + OFFSET3) % 8); RK[77][7] = rol8(RK[76][7], (77 + OFFSET5) % 8) + rol8(CONSTANT7, (77 + OFFSET7) % 8); RK[78][0] = rol8(RK[77][0], (78 + OFFSET1) % 8) + rol8(CONSTANT0, (78 + OFFSET3) % 8); RK[78][1] = rol8(RK[77][1], (78 + OFFSET5) % 8) + rol8(CONSTANT1, (78 + OFFSET7) % 8); RK[78][2] = rol8(RK[77][2], (78 + OFFSET1) % 8) + rol8(CONSTANT2, (78 + OFFSET3) % 8); RK[78][3] = rol8(RK[77][3], (78 + OFFSET5) % 8) + rol8(CONSTANT3, (78 + OFFSET7) % 8); RK[78][4] = rol8(RK[77][4], (78 + OFFSET1) % 8) + rol8(CONSTANT4, (78 + OFFSET3) % 8); RK[78][5] = rol8(RK[77][5], (78 + OFFSET5) % 8) + rol8(CONSTANT5, (78 + OFFSET7) % 8); RK[78][6] = rol8(RK[77][6], (78 + OFFSET1) % 8) + rol8(CONSTANT6, (78 + OFFSET3) % 8); RK[78][7] = rol8(RK[77][7], (78 + OFFSET5) % 8) + rol8(CONSTANT7, (78 + OFFSET7) % 8); RK[79][0] = rol8(RK[78][0], (79 + OFFSET1) % 8) + rol8(CONSTANT0, (79 + OFFSET3) % 8); RK[79][1] = rol8(RK[78][1], (79 + OFFSET5) % 8) + rol8(CONSTANT1, (79 + OFFSET7) % 8); RK[79][2] = rol8(RK[78][2], (79 + OFFSET1) % 8) + rol8(CONSTANT2, (79 + OFFSET3) % 8); RK[79][3] = rol8(RK[78][3], (79 + OFFSET5) % 8) + rol8(CONSTANT3, (79 + OFFSET7) % 8); RK[79][4] = rol8(RK[78][4], (79 + OFFSET1) % 8) + rol8(CONSTANT4, (79 + OFFSET3) % 8); RK[79][5] = rol8(RK[78][5], (79 + OFFSET5) % 8) + rol8(CONSTANT5, (79 + OFFSET7) % 8); RK[79][6] = rol8(RK[78][6], (79 + OFFSET1) % 8) + rol8(CONSTANT6, (79 + OFFSET3) % 8); RK[79][7] = rol8(RK[78][7], (79 + OFFSET5) % 8) + rol8(CONSTANT7, (79 + OFFSET7) % 8); 

  #if DEBUG_PERF
  keygen = cpucycles();
  #endif

  for (int i = 0; i < num_enc_auth / 8; i++) {
    uint64_t tmp[8];
    tmp[0] = pack64(i * 8 + 0, i * 8 + 1, i * 8 + 2, i * 8 + 3, i * 8 + 4, i * 8 + 5, i * 8 + 6, i * 8 + 7);
    tmp[1] = dup8(NONCE1);
    tmp[2] = dup8(NONCE2);
    tmp[3] = dup8(NONCE3);
    tmp[4] = dup8(NONCE4);
    tmp[5] = dup8(NONCE5);
    tmp[6] = dup8(NONCE6);
    tmp[7] = dup8(NONCE7);

    for (int r = 0; r < NUM_ROUND; r++) {
      uint64_t tmp0 = tmp[0];
      tmp[0] = rol64(dup8(RK[r][1]) ^ bytewise_add(tmp[0], dup8(RK[r][1]) ^ tmp[1]), 1);
      tmp[1] = rol64(dup8(RK[r][2]) ^ bytewise_add(tmp[1], dup8(RK[r][2]) ^ tmp[2]), 2);
      tmp[2] = rol64(dup8(RK[r][3]) ^ bytewise_add(tmp[2], dup8(RK[r][3]) ^ tmp[3]), 3);
      tmp[3] = rol64(dup8(RK[r][4]) ^ bytewise_add(tmp[3], dup8(RK[r][4]) ^ tmp[4]), 4);
      tmp[4] = rol64(dup8(RK[r][5]) ^ bytewise_add(tmp[4], dup8(RK[r][5]) ^ tmp[5]), 5);
      tmp[5] = rol64(dup8(RK[r][6]) ^ bytewise_add(tmp[5], dup8(RK[r][6]) ^ tmp[6]), 6);
      tmp[6] = rol64(dup8(RK[r][7]) ^ bytewise_add(tmp[6], dup8(RK[r][7]) ^ tmp[7]), 7);
      tmp[7] = tmp0;
    }

    for (int j = 0; j < 8; j++) {
      for (int k = 0; k < 8; ++k) {
        CT[i * 64 + j * 8 + k] = PT[i * 64 + j * 8 + k] ^ ((uint8_t*)&tmp[k])[j];
      }
    }
  }

  #if DEBUG_PERF
  ctr = cpucycles();
  #endif

  uint64_t H = pack64(num_enc_auth, num_enc_auth ^ NONCE1, num_enc_auth & NONCE2, num_enc_auth | NONCE3, num_enc_auth ^ NONCE4, num_enc_auth & NONCE5, num_enc_auth | NONCE6, num_enc_auth ^ NONCE7);
  uint64_t CMUL_DB1[DB_SIZE];
  uint64_t CMUL_DB2[DB_SIZE];
  uint64_t CMUL_DB3[DB_SIZE];
  uint64_t H1 = H & 0xFFFFFFFF;
  uint64_t H2 = H >> 32;
  uint64_t H3 = H1 ^ H2;
  CMUL_DB1[0] = 0;
  CMUL_DB2[0] = 0;
  CMUL_DB3[0] = 0;
  for (int i = 1, j = 0; i < DB_SIZE; i *= 2, ++j) {
    CMUL_DB1[i] = H1 << j;
    CMUL_DB2[i] = H2 << j;
    CMUL_DB3[i] = H3 << j;
    for (int k = i + 1; k < 2 * i; ++k) {
      CMUL_DB1[k] = CMUL_DB1[k - i] ^ CMUL_DB1[i];
      CMUL_DB2[k] = CMUL_DB2[k - i] ^ CMUL_DB2[i];
      CMUL_DB3[k] = CMUL_DB3[k - i] ^ CMUL_DB3[i];
    }
  }

  *(uint64_t*)AUTH = H;
  POLY_MUL_RED_IMP_DB3(AUTH, CMUL_DB1, CMUL_DB2, CMUL_DB3);
  for (int i = 0; i < num_enc_auth; i++) {
    *(uint64_t*)AUTH ^= *(uint64_t*)&CT[i * 8];
    POLY_MUL_RED_IMP_DB3(AUTH, CMUL_DB1, CMUL_DB2, CMUL_DB3);
    POLY_MUL_RED_IMP_SQ(AUTH);
  }

  #if DEBUG_PERF
  auth = cpucycles();
  #endif
}

// EDIT END

//PT range (1-255 bytes)
#define LENGTH0 64
#define LENGTH1 128
#define LENGTH2 192


int main(int argc, const char * argv[]) {
    uint8_t PT0[LENGTH0]={
        0x42,0xFB,0x9F,0xE0,0x59,0x81,0x5A,0x81,0x66,0xA1,0x0E,0x5C,0x4E,0xB4,0xDA,0xEC,
        0x2F,0xF5,0x60,0x7E,0x8A,0xED,0x3B,0xCA,0x2B,0xD5,0x82,0x69,0x1D,0xC3,0x84,0x13,
        0x0E,0xA6,0x6A,0x10,0xB3,0x3C,0xB4,0x4E,0x9A,0x80,0x4F,0x61,0x06,0x82,0x17,0xF4,
        0xCA,0x76,0xBA,0x84,0xE2,0xDC,0xC9,0x66,0x4F,0xA5,0x07,0x8C,0x8E,0x36,0xD1,0x97};
    uint8_t PT1[LENGTH1]={
        0x4E,0xE2,0xB3,0x54,0x05,0x90,0xB0,0xFD,0x87,0x9B,0x30,0xAB,0x19,0xC4,0x66,0x8F,
        0x2F,0x22,0x30,0xA8,0x5E,0x23,0x5B,0x0B,0xB1,0xEB,0xD6,0xAD,0x10,0x0F,0x33,0x25,
        0x90,0x66,0xC5,0x82,0xE7,0x1B,0x47,0xCA,0xBE,0x61,0xA3,0x91,0xDB,0xC2,0x19,0x97,
        0x04,0x6A,0x73,0x02,0x08,0x70,0x28,0x44,0x38,0x69,0xB5,0xCE,0x55,0x95,0xCB,0x90,
        0xD3,0x8A,0xE2,0x60,0x89,0x2A,0x15,0xCA,0x36,0x9B,0x73,0xEC,0xEF,0xD0,0x43,0x0B,
        0xA7,0xFC,0xDA,0x4B,0xAB,0xE7,0xB3,0xC9,0xB7,0xF5,0xD8,0x86,0xA2,0xC5,0x41,0x5D,
        0x18,0xC3,0x0C,0x30,0xDB,0xC2,0xFE,0x68,0x42,0x3D,0x33,0xFA,0x6D,0xA0,0xD3,0x6F,
        0x03,0x1F,0x87,0x75,0x3C,0x1E,0x81,0x58,0x88,0xAA,0xF4,0x90,0x56,0xA1,0x93,0x64};
    uint8_t PT2[LENGTH2]={
        0xA7,0xF1,0xD9,0x2A,0x82,0xC8,0xD8,0xFE,0x43,0x4D,0x98,0x55,0x8C,0xE2,0xB3,0x47,
        0x17,0x11,0x98,0x54,0x2F,0x11,0x2D,0x05,0x58,0xF5,0x6B,0xD6,0x88,0x07,0x99,0x92,
        0x48,0x33,0x62,0x41,0xF3,0x0D,0x23,0xE5,0x5F,0x30,0xD1,0xC8,0xED,0x61,0x0C,0x4B,
        0x02,0x35,0x39,0x81,0x84,0xB8,0x14,0xA2,0x9C,0xB4,0x5A,0x67,0x2A,0xCA,0xE5,0x48,
        0xE9,0xC5,0xF1,0xB0,0xC4,0x15,0x8A,0xE5,0x9B,0x4D,0x39,0xF6,0xF7,0xE8,0xA1,0x05,
        0xD3,0xFE,0xED,0xA5,0xD5,0xF3,0xD9,0xE4,0x5B,0xFA,0x6C,0xC3,0x51,0xE2,0x20,0xAE,
        0x0C,0xE1,0x06,0x98,0x6D,0x61,0xFF,0x34,0xA1,0x1E,0x19,0xFD,0x36,0x50,0xE9,0xB7,
        0x81,0x8F,0xC3,0x3A,0x1E,0x0F,0xC0,0x2C,0x44,0x55,0x7A,0xC8,0xAB,0x50,0xC9,0xB2,
        0xDE,0xB2,0xF6,0xB5,0xE2,0x4C,0x4F,0xDD,0x9F,0x88,0x67,0xBD,0xCE,0x1F,0xF2,0x61,
        0x00,0x8E,0x78,0x97,0x97,0x0E,0x34,0x62,0x07,0xD7,0x5E,0x47,0xA1,0x58,0x29,0x8E,
        0x5B,0xA2,0xF5,0x62,0x46,0x86,0x9C,0xC4,0x2E,0x36,0x2A,0x02,0x73,0x12,0x64,0xE6,
        0x06,0x87,0xEF,0x53,0x09,0xD1,0x08,0x53,0x4F,0x51,0xF8,0x65,0x8F,0xB4,0xF0,0x80};
    
    uint8_t CT_TMP[LENGTH2]={0,};
    
    uint8_t CT0[LENGTH0]={
        0xEC,0x83,0x3A,0xB7,0xFB,0xB0,0xD3,0x65,0xB6,0xE7,0x2F,0x50,0x57,0x84,0xE2,0x43,
        0x47,0x47,0xCE,0xB2,0x39,0x39,0xB9,0x7D,0x83,0x0B,0x32,0x32,0xCF,0x06,0x00,0x25,
        0xBC,0x48,0xD6,0xD2,0x21,0xB2,0x55,0xEB,0x4A,0x45,0xA0,0x68,0xD0,0x46,0x18,0x38,
        0x10,0xFF,0xE5,0x03,0x7E,0xF7,0xB7,0x25,0xAB,0xC0,0x26,0x07,0x28,0x1F,0x6D,0x85};
    uint8_t CT1[LENGTH1]={
        0x49,0x78,0x8B,0x7C,0x18,0x56,0x0F,0x1A,0xB1,0xA7,0x8F,0x94,0x88,0xE0,0x8F,0x46,
        0x0E,0x7F,0x53,0x7B,0xE6,0x40,0x02,0x84,0x32,0xAF,0xEE,0xD0,0x29,0x73,0x0D,0x1D,
        0xBF,0xCE,0x60,0x29,0xDE,0xB1,0xA0,0xC2,0xCA,0x77,0x34,0xED,0x70,0x38,0x5E,0x78,
        0x89,0xB6,0x8C,0x80,0xBC,0xBE,0x37,0xC0,0xCB,0x32,0xB0,0x2C,0xEC,0xA6,0x06,0xA4,
        0x50,0x87,0xFD,0x41,0xD1,0xA4,0x32,0x19,0x59,0xBA,0xDB,0xE4,0x82,0xCE,0xF5,0x69,
        0xAE,0xD4,0x67,0xBD,0xEA,0x11,0x8F,0xDF,0x53,0x34,0x12,0x6F,0x73,0x0C,0x10,0x3F,
        0x29,0xEE,0x80,0x82,0xCF,0xBC,0x0C,0x14,0x97,0x6D,0x7C,0xDE,0x41,0x24,0x1A,0x30,
        0x8B,0xAB,0x21,0x97,0x34,0xD5,0x5E,0x08,0x25,0xA7,0x56,0xFD,0x61,0xE0,0xB9,0xA6};
    uint8_t CT2[LENGTH2]={
        0xC6,0x1E,0x1A,0xC8,0x88,0x1A,0x29,0x9A,0xB1,0xE0,0xFF,0xA7,0x55,0xC7,0xD2,0xEF,
        0x55,0x21,0x85,0x92,0xE1,0xF1,0xC1,0x3F,0x7C,0xEC,0x87,0x40,0x38,0xF2,0xB0,0x1F,
        0xB8,0xCD,0x5B,0x61,0x78,0x08,0xCC,0x13,0x46,0x56,0x0A,0xDA,0xCD,0x7B,0x2E,0x97,
        0xC3,0xA3,0x14,0x18,0x44,0x26,0xB9,0xAC,0xAC,0xE0,0x5B,0x0D,0xA0,0x55,0xD0,0xB1,
        0x0F,0xD4,0x49,0xA1,0xCB,0xC1,0x37,0x69,0x63,0x27,0xF1,0x92,0x40,0x79,0x24,0xCE,
        0xA9,0x90,0x68,0xC8,0xBE,0xBC,0x65,0x43,0x13,0x10,0x00,0x5E,0x21,0xA3,0x85,0x1D,
        0xB6,0xAB,0xC3,0x4D,0xD3,0xED,0x81,0x48,0x9F,0xEA,0x9F,0xE2,0xF1,0x31,0x9C,0xC6,
        0xCF,0xD8,0x1D,0xCC,0x08,0x4C,0x7C,0x92,0xA6,0xDD,0x39,0xF6,0xFB,0x2E,0xCB,0x34,
        0x00,0x71,0xB8,0x9C,0x72,0xFC,0x96,0x6E,0x70,0x72,0xFD,0x60,0x8C,0x12,0x9F,0x2E,
        0xAB,0x2E,0x16,0x86,0xCD,0x98,0x1F,0xDD,0xE6,0xA4,0x82,0x9D,0x47,0xA3,0x70,0xBF,
        0x53,0xC8,0xCD,0x69,0xCD,0x47,0x3C,0xFC,0x2E,0xBE,0x16,0x7F,0x8C,0x52,0x42,0x55,
        0x0B,0x5B,0x1D,0x37,0xAA,0xD5,0x75,0xC5,0xBB,0xE6,0x42,0x95,0x59,0x88,0xF5,0x17};
    
    uint8_t AUTH_TMP[8]={0,};
    
    uint8_t AUTH0[8]={0x8B,0x76,0x4F,0x3B,0x4D,0xC4,0x17,0x73};
    uint8_t AUTH1[8]={0xC4,0x47,0xEC,0xB3,0x2D,0xF0,0xA7,0x5F};
    uint8_t AUTH2[8]={0x51,0x85,0x2C,0x12,0x91,0xA9,0xB0,0xF2};
    
    uint8_t MK0[8]={0xF5,0xD3,0x8D,0x7F,0x87,0x58,0x88,0xFC};
    uint8_t MK1[8]={0x47,0x33,0xC9,0xFC,0x8E,0x35,0x88,0x11};
    uint8_t MK2[8]={0xD8,0x99,0x28,0xC3,0xDA,0x29,0x6B,0xB0};
    
    uint32_t i=0;
    
    long long int cycles, cycles1, cycles2;
    
    printf("--- TEST VECTOR ---\n");
    
    ENC_AUTH(PT0, MK0, CT_TMP, AUTH_TMP, LENGTH0);
    
    for(i=0;i<LENGTH0;i++){
        if(CT_TMP[i] != CT0[i]){
            printf("wrong result.\n");
            return 0;
        }
        CT_TMP[i] = 0;
    }
    for(i=0;i<8;i++){
        if(AUTH_TMP[i] != AUTH0[i]){
            printf("wrong result.\n");
            return 0;
        }
        AUTH_TMP[i] = 0;
    }
    
    ENC_AUTH(PT1, MK1, CT_TMP, AUTH_TMP, LENGTH1);
    
    for(i=0;i<LENGTH1;i++){
        if(CT_TMP[i] != CT1[i]){
            printf("wrong result.\n");
            return 0;
        }
        CT_TMP[i] = 0;
    }
    for(i=0;i<8;i++){
        if(AUTH_TMP[i] != AUTH1[i]){
            printf("wrong result.\n");
            return 0;
        }
        AUTH_TMP[i] = 0;
    }
    
    ENC_AUTH(PT2, MK2, CT_TMP, AUTH_TMP, LENGTH2);
   
    for(i=0;i<LENGTH2;i++){
        if(CT_TMP[i] != CT2[i]){
            printf("wrong result.\n");
            return 0;
        }
        CT_TMP[i] = 0;
    }
    for(i=0;i<8;i++){
        if(AUTH_TMP[i] != AUTH2[i]){
            printf("wrong result.\n");
            return 0;
        }
        AUTH_TMP[i] = 0;
    }    
    printf("test pass. \n");

    if (DEBUG_IMP) {
    printf("--- TEST VECTOR for imp ---\n");
    
    ENC_AUTH_IMP(PT0, MK0, CT_TMP, AUTH_TMP, LENGTH0);
    
    for(i=0;i<LENGTH0;i++){
        if(CT_TMP[i] != CT0[i]){
            printf("wrong result.\n");
            return 0;
        }
        CT_TMP[i] = 0;
    }
    for(i=0;i<8;i++){
        if(AUTH_TMP[i] != AUTH0[i]){
            printf("wrong result.\n");
            return 0;
        }
        AUTH_TMP[i] = 0;
    }
    
    ENC_AUTH_IMP(PT1, MK1, CT_TMP, AUTH_TMP, LENGTH1);
    
    for(i=0;i<LENGTH1;i++){
        if(CT_TMP[i] != CT1[i]){
            printf("wrong result.\n");
            return 0;
        }
        CT_TMP[i] = 0;
    }
    for(i=0;i<8;i++){
        if(AUTH_TMP[i] != AUTH1[i]){
            printf("wrong result.\n");
            return 0;
        }
        AUTH_TMP[i] = 0;
    }
    
    ENC_AUTH_IMP(PT2, MK2, CT_TMP, AUTH_TMP, LENGTH2);
   
    for(i=0;i<LENGTH2;i++){
        if(CT_TMP[i] != CT2[i]){
            printf("wrong result.\n");
            return 0;
        }
        CT_TMP[i] = 0;
    }
    for(i=0;i<8;i++){
        if(AUTH_TMP[i] != AUTH2[i]){
            printf("wrong result.\n");
            return 0;
        }
        AUTH_TMP[i] = 0;
    }    
    printf("test pass. \n");
    }
        
    printf("--- BENCHMARK ---\n");
for (int iter = 0; iter < 3; ++iter) {
    cycles=0;
    cycles1 = cpucycles();
    for(i=0;i<BENCH_ROUND;i++){
        ENC_AUTH(PT2, MK2, CT_TMP, AUTH_TMP, LENGTH2);
    }
    cycles2 = cpucycles();
    cycles = cycles2-cycles1;
    printf("Original implementation runs in ................. %8lld cycles", cycles/BENCH_ROUND);
    printf("\n");
    
    cycles=0;
    cycles1 = cpucycles();
    for(i=0;i<BENCH_ROUND;i++){
        ENC_AUTH_IMP(PT2, MK2, CT_TMP, AUTH_TMP, LENGTH2);
    }
    cycles2 = cpucycles();
    cycles = cycles2-cycles1;
    printf("Improved implementation runs in ................. %8lld cycles", cycles/BENCH_ROUND);
    printf("\n");
}

  #if DEBUG_PERF
  printf("Original\n");
  printf("ctr %ld\n", tb - ta);
  printf("auth %ld\n", tc - tb);
  printf("Improved\n");
  printf("keygen %ld\n", keygen - st);
  printf("ctr %ld\n", ctr - keygen);
  printf("auth %ld\n", auth - ctr);
  #endif
    
    return 0;
}