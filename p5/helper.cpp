#include <cstdio>
#include <cstdint>
#include <random>
#include <iostream>
#include "DES.h"

// hex : 01 23 45 67 89 AB CD EF
// bin : 00000001 00100011 01000101 01100111 10001001 10101011 11001101 11101111
// paper style index (right-to-left)
// 63 62 61 60 59 58 57 56  | 55 54 53 52 51 50 49 48  | ...
// DES-Python style index (left-to-right) (little-endian)
// 0  1  2  3  4  5  6  7   | 8  9  10 11 12 13 14 15  | ...
// DES-C style index (left-to-right but right-to-left inside a byte) (big-endian)
// 7  6  5  4  3  2  1  0   | 15 14 13 12 11 10 9  8   | ...
// S1        | S2           | S3 ...

// index conversion
int paper2big(int i, int n) {
  return n - 1 - (i / 8) * 8 - (7 - (i % 8));
}

int big2little(int i) {
  return (i / 8) * 8 + (7 - (i % 8));
}

int little2big(int i) {
  return (i / 8) * 8 + (7 - (i % 8));
}

std::vector<int> find_effecitve_k_bits(int output_index, int round) {
  int x = paper2big(output_index, 32);
  // keep c-style index after this
  auto y = DES_P_BOX[big2little(x)];
  x = y.byte * 8 + __builtin_ctz(y.mask); // index before P permutation
  x = big2little(x) / 4; // S-box index (0~7)
  // Sbox 7 -> key msb 6bits, ..., Sbox 0 ->  key lsb 6bits
  // -> cand = x * 6 ~ x * 6 + 5
  std::vector<int> ret;
  for (int cand = x * 6; cand < x * 6 + 6; ++cand) {
    auto y = DES_PC2_BOX[cand]; // PC2 is be indexed
    int x = y.byte * 8 + __builtin_ctz(y.mask); // index before PC2 permutation
    x = big2little(x); // le is easier to calculate here
    int offset = x >= 28 ? 28 : 0;
    x -= offset;
    for (int i = 0; i < round; ++i) {
      x = (x + DES_SHIFT_BOX[i]) % 28;
    }
    x += offset;
    y = DES_PC1_BOX[x]; // 0 ~ 56
    x = y.byte * 8 + __builtin_ctz(y.mask); // index before PC1 permutation
    ret.push_back(x);
  }
  return ret;
}

uint64_t test(uint64_t a, uint64_t b) {
  return a + b;
}

void printhex(uint64_t x) {
  for (int i = 0; i < 64; i += 8) {
    printf("%02lX", (x >> i) & 0xff);
  }
  printf("\n");
}

void printbin(uint64_t x) {
  for (int i = 0; i < 64; ++i) {
    printf("%lu", (x >> little2big(i)) & 1);
  }
  printf("\n");
}

std::vector<int> extract_lhs_bits(uint64_t pt, uint64_t ct, uint64_t *rk,
    std::vector<int> plidx, std::vector<int> phidx, std::vector<int> clidx, std::vector<int> chidx,
    std::vector<int> fidx, int round) {
  uint64_t pt_permd = 0, ct_permd = 0;
	permutation((uint8_t*)&pt, DES_IP_BOX, 8, (uint8_t*)&pt_permd);
	permutation((uint8_t*)&ct, DES_IP_BOX, 8, (uint8_t*)&ct_permd);
  std::vector<int> ret;
  for (int i : plidx) {
    ret.push_back((pt_permd >> paper2big(i, 64)) & 1);
  }
  for (int i : phidx) {
    ret.push_back((pt_permd >> paper2big(i, 32)) & 1);
  }
  for (int i : clidx) {
    ret.push_back((ct_permd >> paper2big(i, 64)) & 1);
  }
  for (int i : chidx) {
    ret.push_back((ct_permd >> paper2big(i, 32)) & 1);
  }
  uint32_t f = 0;
  if (round == 1) {
    feistel(((uint8_t*)&pt_permd) + 4, (uint8_t*)&rk[round - 1], (uint8_t*)&f);
  } else {
    feistel(((uint8_t*)&ct_permd) + 4, (uint8_t*)&rk[round - 1], (uint8_t*)&f);
  }
  for (int i : fidx) {
    ret.push_back((f >> paper2big(i, 32)) & 1);
  }
  return ret;
}

std::vector<int> extract_rhs_bits(uint64_t *rk, std::vector<std::pair<int, int>> round_idx_pair) {
  std::vector<int> ret;
  for (auto p : round_idx_pair) {
    int round = p.first;
    int i = p.second;
    ret.push_back((rk[round - 1] >> paper2big(i, 48)) & 1);
  }
  return ret;
}

#include <pybind11/pybind11.h>

void test_k_iteration() {
  std::default_random_engine gen(42);
  std::uniform_int_distribution<uint64_t> dist;
  uint64_t K = dist(gen);
  uint64_t roundKeys[16];
  DES_CreateKeys((uint8_t*)&K, (uint8_t(*)[8])roundKeys);
  std::vector<uint64_t> PTs, CTs;
  int n = 10000;
  for (int i = 0; i < n; i++) {
    uint64_t PT = dist(gen);
    uint64_t CT = 0;
    DES_Encrypt((uint8_t*)&PT, (uint8_t(*)[8])roundKeys, (uint8_t*)&CT, 4);
    PTs.push_back(PT);
    CTs.push_back(CT);
  }
  auto effkidx = find_effecitve_k_bits(15, 1);
  printf("effkidx: ");
  for (int i : effkidx) {
    printf("%d ", i);
  }
  printf("\n");
  size_t effkidx_sz = effkidx.size();
  for (int mask = 0; mask < (1 << effkidx_sz); ++mask) {
  //for (int i = 0; i < 64; ++i) {
    uint64_t newK = 0;
    for (int i = 0; i < effkidx_sz; ++i) {
      if (mask & (1 << i)) {
        newK |= 1UL << effkidx[i];
      }
    }
    //newK |= 1UL << i;
    uint64_t newRK[16];
    DES_CreateKeys((uint8_t*)&newK, (uint8_t(*)[8])newRK);
    int cnt = 0;
    for (int i = 0; i < n; ++i) {
      auto lhs_bits = extract_lhs_bits(PTs[i], CTs[i], newRK, {7, 18, 24, 29}, {15}, {15}, {7, 18, 24, 29}, {15}, 1);
    //printf("lhs_bits:");
    //for (int b : lhs_bits) {
    //  printf(" %d", b);
    //}
    //printf("\n");
      int lhs_xor = 0;
      for (int b : lhs_bits) {
        lhs_xor ^= b;
      }
      if (lhs_xor == 0) {
        cnt++;
      }
    }
    printf("cnt: %d newK: ", cnt); printbin(newK);
  }
  printf("original K: "); printbin(K);
}


void gen_dataset(pybind11::list ptlist, pybind11::list klist) {
  std::default_random_engine gen(42);
  std::uniform_int_distribution<uint64_t> dist;

  int n = 1, correct = 0;
  for (int i = 0; i < n; i++) {
    uint64_t PT = dist(gen);
    uint64_t K = dist(gen);
    //uint64_t PT = i;
    //uint64_t K = 0xdeadbeefdeadbeef + i;
    uint64_t roundKeys[16];
    DES_CreateKeys((uint8_t*)&K, (uint8_t(*)[8])roundKeys);
    //for (int i = 0; i < 16; ++i) {
    //  printf("rk[%d]: ", i);
    //  printhex(roundKeys[i]);
    //}
    uint64_t CT = 0;

    // Guide
    // for R-round attack, lookup the (R-1) round formula
    // then pass extract_lhs_bits in this order:
    // 1. PH index
    // 2. PL index
    // 3. CL index
    // 4. CH index
    // 5. PL index
    // 6. round = 1
    // for extract_rhs_bits:
    // for each K, {round + 1, index}

    // 4-round attack
    DES_Encrypt((uint8_t*)&PT, (uint8_t(*)[8])roundKeys, (uint8_t*)&CT, 4);
    auto lhs_bits = extract_lhs_bits(PT, CT, roundKeys, {7, 18, 24, 29}, {15}, {15}, {7, 18, 24, 29}, {15}, 1);
    auto rhs_bits = extract_rhs_bits(roundKeys, {{2, 22}, {4, 22}});

    // 5-round attack
    //DES_Encrypt((uint8_t*)&PT, (uint8_t(*)[8])roundKeys, (uint8_t*)&CT, 5);
    //auto lhs_bits = extract_lhs_bits(PT, CT, roundKeys, {7, 18, 24, 29}, {15}, {7, 18, 24, 29, 27, 28, 30, 31}, {15}, {15}, 1);
    //auto rhs_bits = extract_rhs_bits(roundKeys, {{2, 22}, {4, 22}, {5, 42}, {5, 43}, {5, 45}, {5, 46}});

    // 8-round attack
    //DES_Encrypt((uint8_t*)&PT, (uint8_t(*)[8])roundKeys, (uint8_t*)&CT, 8);
    //auto lhs_bits = extract_lhs_bits(PT, CT, roundKeys, {7, 18, 24}, {12, 16}, {15}, {7, 18, 24, 29}, {12, 16}, 1);
    //auto rhs_bits = extract_rhs_bits(roundKeys, {{2, 19}, {2, 23}, {4, 22}, {5, 44}, {6, 22}, {8, 22}});

    //printf("lhs_bits:");
    //for (int b : lhs_bits) {
    //  printf(" %d", b);
    //}
    //printf("\n");

    //printf("rhs_bits:");
    //for (int b : rhs_bits) {
    //  printf(" %d", b);
    //}
    //printf("\n");

    int lhs_xor = 0;
    for (int b : lhs_bits) {
      lhs_xor ^= b;
    }

    int rhs_xor = 0;
    for (int b : rhs_bits) {
      rhs_xor ^= b;
    }

    if (lhs_xor == rhs_xor) {
      correct++;
    }

    //printhex(PT);
    //printhex(K);
    //printhex(CT);
    ptlist.append(PT);
    klist.append(K);
  }
  printf("correct: %d/%d\n", correct, n);
}

PYBIND11_MODULE(helper, m) {
  m.def("test", &test);
  m.def("gen_dataset", &gen_dataset);
  m.def("test_k_iteration", &test_k_iteration);
}
