gcc-11 contest.c -O3 -o contest && ./contest

gcc-11 contest.c -O3 -S -o - | llvm-mca -all-views -bottleneck-analysis > llvm.txt
gcc-11 -O3 -g contest.c -o contest; objdump -S contest > objdump.txt

                //__asm volatile("# LLVM-MCA-BEGIN foo":::"memory");
                //__asm volatile("# LLVM-MCA-END":::"memory");


// round-first implementation
  /*
  uint8_t RK[8];
  #pragma GCC unroll 80
  for (int r = 0; r < NUM_ROUND; r++) {
    if (r == 0) {
      #pragma GCC unroll 8
      for (int i = 0; i < 8; ++i) {
        RK[i] = MK[i];
      }
      #pragma GCC unroll 24
      for (int i = 0; i < num_enc_auth; i++) {
        CT[i * 8 + 0] = i;
        CT[i * 8 + 1] = NONCE1;
        CT[i * 8 + 2] = NONCE2;
        CT[i * 8 + 3] = NONCE3;
        CT[i * 8 + 4] = NONCE4;
        CT[i * 8 + 5] = NONCE5;
        CT[i * 8 + 6] = NONCE6;
        CT[i * 8 + 7] = NONCE7;
      }
    } else {
      RK[0] = rol8(RK[0], (r + OFFSET1) % 8) + RK_CONSTS[r & 0x7][0];
      RK[1] = rol8(RK[1], (r + OFFSET5) % 8) + RK_CONSTS[r & 0x7][1];
      RK[2] = rol8(RK[2], (r + OFFSET1) % 8) + RK_CONSTS[r & 0x7][2];
      RK[3] = rol8(RK[3], (r + OFFSET5) % 8) + RK_CONSTS[r & 0x7][3];
      RK[4] = rol8(RK[4], (r + OFFSET1) % 8) + RK_CONSTS[r & 0x7][4];
      RK[5] = rol8(RK[5], (r + OFFSET5) % 8) + RK_CONSTS[r & 0x7][5];
      RK[6] = rol8(RK[6], (r + OFFSET1) % 8) + RK_CONSTS[r & 0x7][6];
      RK[7] = rol8(RK[7], (r + OFFSET5) % 8) + RK_CONSTS[r & 0x7][7];
    }
    #pragma GCC unroll 24
    for (int i = 0; i < num_enc_auth; i++) {
      uint8_t tmp0 = CT[i * 8 + 0];
      #pragma GCC unroll 7
      for (int j = 1; j < 8; j++) {
        CT[i * 8 + j - 1] = rol8(RK[j] ^ (CT[i * 8 + j - 1] + (RK[j] ^ CT[i * 8 + j])), j);
      }
      CT[i * 8 + 7] = tmp0;
    }
  }
  */

  //original

  for (int i = 0; i < num_enc_auth; i++) {
    uint8_t tmp[8];
    tmp[0] = i;
    tmp[1] = NONCE1;
    tmp[2] = NONCE2;
    tmp[3] = NONCE3;
    tmp[4] = NONCE4;
    tmp[5] = NONCE5;
    tmp[6] = NONCE6;
    tmp[7] = NONCE7;

    #pragma GCC unroll 80
    for (int r = 0; r < NUM_ROUND; r++) {
      uint8_t tmp0 = tmp[0];
      #pragma GCC unroll 7
      for (int j = 1; j < 8; j++) {
        tmp[j - 1] = rol8(RK[r][j] ^ (tmp[j - 1] + (RK[r][j] ^ tmp[j])), j);
      }
      tmp[7] = tmp0;
    }
    #pragma GCC unroll 8
    for (int j = 0; j < 8; j++) {
      CT[i * 8 + j] = PT[i * 8 + j] ^ tmp[j];
    }
  }

  64-bit key schedule


  uint64_t rk_consts = pack64(CONSTANT0, CONSTANT1, CONSTANT2, CONSTANT3, CONSTANT4, CONSTANT5, CONSTANT6, CONSTANT7);
  uint64_t tmp = *(uint64_t*)RK;
  #pragma GCC unroll 79
  for (int i = 1; i < NUM_ROUND; i++) {
    uint64_t a = interleave(rol64(tmp, (i + OFFSET1) % 8), rol64(tmp, (i + OFFSET5) % 8));
    uint64_t b = interleave(rol64(rk_consts, (i + OFFSET3) % 8), rol64(rk_consts, (i + OFFSET7) % 8));
    tmp = bytewise_add(a, b);
    *((uint64_t*)&RK[i]) = tmp;
  }