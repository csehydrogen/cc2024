#include <cstdio>
#include <cstdint>

#define OFFSET1 1
#define OFFSET3 3
#define OFFSET5 5
#define OFFSET7 7

const uint64_t RK_CONSTS_64[8] = {0x393BB7A338CB391B,0x72766F4770977236,0xE4ECDE8EE02FE46C,0xC9D9BD1DC15EC9D8,0x93B37B3A83BC93B1,0x2767F67407792763,0x4ECEEDE80EF24EC6,0x9C9DDBD11CE59C8D};
uint64_t dup(uint8_t _mask) {
  uint64_t mask = _mask;
  return mask | (mask << 8) | (mask << 16) | (mask << 24) | (mask << 32) | (mask << 40) | (mask << 48) | (mask << 56);
}
int main() {
  for (int i = 1; i < 8; ++i) {
    printf("0x%016lX, 0x%016lX\n", dup(0xff << i), dup(0xff >> (8 - i)));
  }
  return 0;
  uint8_t(*RK_CONSTS)[8] = (uint8_t(*)[8])RK_CONSTS_64;
  for (int j = 0; j < 8; ++j) {
    printf("uint8_t RK_0_%d = MK[%d];\n", j, j);
  }
  for (int r = 1; r < 80; ++r) {
    for (int j = 0; j < 8; ++j) {
      printf("uint8_t RK_%d_%d = rol8(RK_%d_%d, %d) + %d;\n",
                 r, j,           r-1, j, j % 2 == 0 ? ((r + OFFSET1) % 8) : ((r + OFFSET5) % 8), RK_CONSTS[r & 0x7][j]
      );

    }

  }
  for (int r = 0; r < 80; ++r) {
    for (int j = 1; j < 8; ++j) {
      printf("uint8_t tmp_%d_%d = rol8(RK_%d_%d ^ (tmp_%d_%d + (RK_%d_%d ^ tmp_%d_%d)), %d);\n",
                          r+1, j-1,       r,  j,         r, j-1,     r,  j,        r, j,    j
      );
    }
    printf("uint8_t tmp_%d_7 = tmp_%d_0;\n", r+1, r);
  }
  return 0;
}