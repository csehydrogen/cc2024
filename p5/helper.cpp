#include <cstdio>
#include <cstdint>
#include <random>
#include <iostream>
#include "DES.h"

uint64_t test(uint64_t a, uint64_t b) {
  return a + b;
}

void printhex(uint64_t x) {
  for (int i = 0; i < 64; i += 8) {
    printf("%02lX", (x >> i) & 0xff);
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
    ret.push_back((pt_permd >> (63 - ((i / 8) * 8 + (7 - i % 8)))) & 1);
  }
  for (int i : phidx) {
    ret.push_back((pt_permd >> (31 - ((i / 8) * 8 + (7 - i % 8)))) & 1);
  }
  for (int i : clidx) {
    ret.push_back((ct_permd >> (63 - ((i / 8) * 8 + (7 - i % 8)))) & 1);
  }
  for (int i : chidx) {
    ret.push_back((ct_permd >> (31 - ((i / 8) * 8 + (7 - i % 8)))) & 1);
  }
  uint32_t f = 0;
  if (round == 1) {
    feistel(((uint8_t*)&pt_permd) + 4, (uint8_t*)&rk[round - 1], (uint8_t*)&f);
  } else {
    feistel(((uint8_t*)&ct_permd) + 4, (uint8_t*)&rk[round - 1], (uint8_t*)&f);
  }
  for (int i : fidx) {
    ret.push_back((f >> (31 - ((i / 8) * 8 + (7 - i % 8)))) & 1);
  }
  return ret;
}

std::vector<int> extract_rhs_bits(uint64_t *rk, std::vector<std::pair<int, int>> round_idx_pair) {
  std::vector<int> ret;
  for (auto p : round_idx_pair) {
    int round = p.first;
    int i = p.second;
    ret.push_back((rk[round - 1] >> (47 - ((i / 8) * 8 + (7 - i % 8)))) & 1);
  }
  return ret;
}

#include <pybind11/pybind11.h>
void gen_dataset(pybind11::list ptlist, pybind11::list klist) {
  std::default_random_engine gen(42);
  std::uniform_int_distribution<uint64_t> dist;

  int n = 100000, correct = 0;
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
    DES_Encrypt((uint8_t*)&PT, (uint8_t(*)[8])roundKeys, (uint8_t*)&CT, 4);

    auto lhs_bits = extract_lhs_bits(PT, CT, roundKeys, {7, 18, 24, 29}, {15}, {15}, {7, 18, 24, 29}, {15}, 1);
    auto rhs_bits = extract_rhs_bits(roundKeys, {{2, 22}, {4, 22}});

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
}
