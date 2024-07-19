#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <cstdio>
#include <cstdlib>

typedef unsigned char undefined;
typedef unsigned int uint;
typedef unsigned int    undefined4;
typedef unsigned long long    ulonglong;

void FUN_140001670(undefined *param_1,uint *param_2,int param_3) {
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint local_d8;
  uint local_d4;
  uint local_d0;
  uint local_cc;
  int local_c8;
  uint local_c4;
  uint local_c0;
  uint local_bc;
  uint local_b8;
  uint local_b4;
  uint local_b0;
  uint local_ac;
  uint local_a8;
  uint local_a4;
  ulonglong local_a0;
  undefined *local_98;
  uint *local_90;
  undefined4 local_88;
  undefined4 uStack_84;
  undefined4 uStack_80;
  undefined4 uStack_7c;
  undefined4 local_78;
  undefined4 uStack_74;
  undefined4 uStack_70;
  undefined4 uStack_6c;
  undefined4 local_68;
  undefined4 uStack_64;
  undefined4 uStack_60;
  undefined4 uStack_5c;
  undefined4 local_58;
  undefined4 uStack_54;
  undefined4 uStack_50;
  undefined4 uStack_4c;
  ulonglong local_48;
  
  uVar12 = param_2[4];
  uVar4 = param_2[5];
  uVar5 = param_2[6];
  uVar6 = param_2[7];
  uVar2 = *param_2;
  local_d8 = param_2[1];
  local_d4 = param_2[2];
  local_d0 = param_2[3];
  uVar7 = param_2[0xc];
  uVar9 = param_2[0xd];
  uVar11 = param_2[0xe];
  uVar3 = param_2[0xf];
  local_c4 = param_2[8];
  uVar1 = param_2[9];
  uVar10 = param_2[10];
  uVar8 = param_2[0xb];
  if (0 < param_3) {
    local_a0 = (ulonglong)((param_3 - 1U >> 1) + 1);
    local_c0 = uVar10;
    local_bc = uVar8;
    do {
      uVar7 = uVar2 + uVar12 ^ uVar7;
      uVar8 = uVar7 << 0x10 | uVar7 >> 0x10;
      local_ac = uVar8 + local_c4;
      uVar10 = local_ac ^ uVar12;
      uVar10 = uVar10 << 0xc | uVar10 >> 0x14;
      uVar2 = uVar10 + uVar2 + uVar12;
      uVar8 = uVar2 ^ uVar8;
      uVar13 = uVar8 << 8 | uVar8 >> 0x18;
      local_ac = local_ac + uVar13;
      uVar10 = local_ac ^ uVar10;
      local_a8 = uVar10 << 7 | uVar10 >> 0x19;
      uVar9 = local_d8 + uVar4 ^ uVar9;
      uVar10 = uVar9 << 0x10 | uVar9 >> 0x10;
      uVar1 = uVar10 + uVar1;
      uVar8 = uVar1 ^ uVar4;
      uVar8 = uVar8 << 0xc | uVar8 >> 0x14;
      local_d8 = uVar8 + local_d8 + uVar4;
      uVar10 = local_d8 ^ uVar10;
      local_b0 = uVar10 << 8 | uVar10 >> 0x18;
      uVar1 = local_b0 + uVar1;
      uVar8 = uVar1 ^ uVar8;
      uVar7 = uVar8 << 7 | uVar8 >> 0x19;
      uVar11 = local_d4 + uVar5 ^ uVar11;
      uVar12 = uVar11 << 0x10 | uVar11 >> 0x10;
      uVar10 = local_c0 + uVar12;
      uVar8 = uVar10 ^ uVar5;
      uVar9 = uVar8 << 0xc | uVar8 >> 0x14;
      local_d4 = local_d4 + uVar5 + uVar9;
      uVar12 = uVar12 ^ local_d4;
      uVar3 = uVar3 ^ local_d0 + uVar6;
      local_a4 = uVar12 << 8 | uVar12 >> 0x18;
      uVar12 = uVar3 << 0x10 | uVar3 >> 0x10;
      uVar10 = local_a4 + uVar10;
      uVar8 = local_bc + uVar12;
      uVar9 = uVar10 ^ uVar9;
      uVar4 = uVar6 ^ uVar8;
      uVar9 = uVar9 << 7 | uVar9 >> 0x19;
      uVar5 = uVar4 << 0xc | uVar4 >> 0x14;
      local_d0 = local_d0 + uVar6 + uVar5;
      uVar2 = uVar7 + uVar2;
      uVar12 = local_d0 ^ uVar12;
      uVar12 = uVar12 << 8 | uVar12 >> 0x18;
      uVar8 = uVar12 + uVar8;
      uVar12 = uVar2 ^ uVar12;
      uVar5 = uVar8 ^ uVar5;
      uVar4 = uVar12 << 0x10 | uVar12 >> 0x10;
      uVar6 = uVar5 << 7 | uVar5 >> 0x19;
      uVar10 = uVar4 + uVar10;
      uVar7 = uVar7 ^ uVar10;
      uVar12 = uVar7 << 0xc | uVar7 >> 0x14;
      uVar2 = uVar12 + uVar2;
      uVar4 = uVar2 ^ uVar4;
      uVar3 = uVar4 << 8 | uVar4 >> 0x18;
      uVar10 = uVar3 + uVar10;
      uVar12 = uVar10 ^ uVar12;
      uVar4 = uVar12 << 7 | uVar12 >> 0x19;
      local_d8 = local_d8 + uVar9;
      uVar13 = uVar13 ^ local_d8;
      uVar12 = uVar13 << 0x10 | uVar13 >> 0x10;
      uVar8 = uVar8 + uVar12;
      uVar9 = uVar8 ^ uVar9;
      uVar5 = uVar9 << 0xc | uVar9 >> 0x14;
      local_d8 = uVar5 + local_d8;
      local_d4 = uVar6 + local_d4;
      uVar7 = local_b0 ^ local_d4;
      uVar12 = local_d8 ^ uVar12;
      uVar9 = uVar7 << 0x10 | uVar7 >> 0x10;
      uVar7 = uVar12 << 8 | uVar12 >> 0x18;
      uVar8 = uVar8 + uVar7;
      local_c4 = local_ac + uVar9;
      uVar5 = uVar5 ^ uVar8;
      uVar6 = local_c4 ^ uVar6;
      uVar5 = uVar5 << 7 | uVar5 >> 0x19;
      uVar6 = uVar6 << 0xc | uVar6 >> 0x14;
      local_d4 = uVar6 + local_d4;
      local_d0 = local_a8 + local_d0;
      uVar9 = local_d4 ^ uVar9;
      uVar9 = uVar9 << 8 | uVar9 >> 0x18;
      local_c4 = local_c4 + uVar9;
      uVar12 = local_d0 ^ local_a4;
      uVar6 = local_c4 ^ uVar6;
      uVar12 = uVar12 << 0x10 | uVar12 >> 0x10;
      uVar1 = uVar1 + uVar12;
      uVar6 = uVar6 << 7 | uVar6 >> 0x19;
      uVar11 = local_a8 ^ uVar1;
      uVar13 = uVar11 << 0xc | uVar11 >> 0x14;
      local_d0 = uVar13 + local_d0;
      uVar12 = local_d0 ^ uVar12;
      uVar11 = uVar12 << 8 | uVar12 >> 0x18;
      uVar1 = uVar1 + uVar11;
      uVar13 = uVar13 ^ uVar1;
      uVar12 = uVar13 << 7 | uVar13 >> 0x19;
      local_a0 = local_a0 - 1;
      local_cc = uVar3;
      local_c0 = uVar10;
      local_bc = uVar8;
      local_b8 = uVar4;
      local_b4 = uVar5;
    } while (local_a0 != 0);
  }
  local_c8 = uVar2 + *param_2;
  ((unsigned char*)&local_88)[3] = (undefined)((uint)local_c8 >> 0x18);
  param_1[3] = ((unsigned char*)&local_88)[3];
  ((unsigned char*)&local_88)[2] = (undefined)((uint)local_c8 >> 0x10);
  param_1[2] = ((unsigned char*)&local_88)[2];
  ((unsigned char*)&local_88)[1] = (undefined)((uint)local_c8 >> 8);
  param_1[1] = ((unsigned char*)&local_88)[1];
  *param_1 = (char)local_c8;
  local_d8 = local_d8 + param_2[1];
  ((unsigned char*)&uStack_84)[3] = (undefined)(local_d8 >> 0x18);
  param_1[7] = ((unsigned char*)&uStack_84)[3];
  ((unsigned char*)&uStack_84)[2] = (undefined)(local_d8 >> 0x10);
  param_1[6] = ((unsigned char*)&uStack_84)[2];
  ((unsigned char*)&uStack_84)[1] = (undefined)(local_d8 >> 8);
  param_1[5] = ((unsigned char*)&uStack_84)[1];
  param_1[4] = (char)local_d8;
  local_d4 = local_d4 + param_2[2];
  ((unsigned char*)&uStack_80)[3] = (undefined)(local_d4 >> 0x18);
  param_1[0xb] = ((unsigned char*)&uStack_80)[3];
  ((unsigned char*)&uStack_80)[2] = (undefined)(local_d4 >> 0x10);
  param_1[10] = ((unsigned char*)&uStack_80)[2];
  ((unsigned char*)&uStack_80)[1] = (undefined)(local_d4 >> 8);
  param_1[9] = ((unsigned char*)&uStack_80)[1];
  param_1[8] = (char)local_d4;
  local_d0 = local_d0 + param_2[3];
  ((unsigned char*)&uStack_7c)[3] = (undefined)(local_d0 >> 0x18);
  param_1[0xf] = ((unsigned char*)&uStack_7c)[3];
  ((unsigned char*)&uStack_7c)[2] = (undefined)(local_d0 >> 0x10);
  param_1[0xe] = ((unsigned char*)&uStack_7c)[2];
  ((unsigned char*)&uStack_7c)[1] = (undefined)(local_d0 >> 8);
  param_1[0xd] = ((unsigned char*)&uStack_7c)[1];
  param_1[0xc] = (char)local_d0;
  local_78 = uVar12 + param_2[4];
  ((unsigned char*)&local_78)[3] = (undefined)((uint)local_78 >> 0x18);
  param_1[0x13] = ((unsigned char*)&local_78)[3];
  ((unsigned char*)&local_78)[2] = (undefined)((uint)local_78 >> 0x10);
  param_1[0x12] = ((unsigned char*)&local_78)[2];
  ((unsigned char*)&local_78)[1] = (undefined)((uint)local_78 >> 8);
  param_1[0x11] = ((unsigned char*)&local_78)[1];
  param_1[0x10] = (char)local_78;
  uStack_74 = uVar4 + param_2[5];
  ((unsigned char*)&uStack_74)[3] = (undefined)((uint)uStack_74 >> 0x18);
  param_1[0x17] = ((unsigned char*)&uStack_74)[3];
  ((unsigned char*)&uStack_74)[2] = (undefined)((uint)uStack_74 >> 0x10);
  param_1[0x16] = ((unsigned char*)&uStack_74)[2];
  ((unsigned char*)&uStack_74)[1] = (undefined)((uint)uStack_74 >> 8);
  param_1[0x15] = ((unsigned char*)&uStack_74)[1];
  param_1[0x14] = (char)uStack_74;
  uStack_70 = uVar5 + param_2[6];
  ((unsigned char*)&uStack_70)[3] = (undefined)((uint)uStack_70 >> 0x18);
  param_1[0x1b] = ((unsigned char*)&uStack_70)[3];
  ((unsigned char*)&uStack_70)[2] = (undefined)((uint)uStack_70 >> 0x10);
  param_1[0x1a] = ((unsigned char*)&uStack_70)[2];
  ((unsigned char*)&uStack_70)[1] = (undefined)((uint)uStack_70 >> 8);
  param_1[0x19] = ((unsigned char*)&uStack_70)[1];
  param_1[0x18] = (char)uStack_70;
  uStack_6c = uVar6 + param_2[7];
  ((unsigned char*)&uStack_6c)[3] = (undefined)((uint)uStack_6c >> 0x18);
  param_1[0x1f] = ((unsigned char*)&uStack_6c)[3];
  ((unsigned char*)&uStack_6c)[2] = (undefined)((uint)uStack_6c >> 0x10);
  param_1[0x1e] = ((unsigned char*)&uStack_6c)[2];
  ((unsigned char*)&uStack_6c)[1] = (undefined)((uint)uStack_6c >> 8);
  param_1[0x1d] = ((unsigned char*)&uStack_6c)[1];
  param_1[0x1c] = (char)uStack_6c;
  local_68 = local_c4 + param_2[8];
  ((unsigned char*)&local_68)[3] = (undefined)((uint)local_68 >> 0x18);
  param_1[0x23] = ((unsigned char*)&local_68)[3];
  ((unsigned char*)&local_68)[2] = (undefined)((uint)local_68 >> 0x10);
  param_1[0x22] = ((unsigned char*)&local_68)[2];
  ((unsigned char*)&local_68)[1] = (undefined)((uint)local_68 >> 8);
  param_1[0x21] = ((unsigned char*)&local_68)[1];
  param_1[0x20] = (char)local_68;
  uStack_64 = uVar1 + param_2[9];
  ((unsigned char*)&uStack_64)[3] = (undefined)((uint)uStack_64 >> 0x18);
  param_1[0x27] = ((unsigned char*)&uStack_64)[3];
  ((unsigned char*)&uStack_64)[2] = (undefined)((uint)uStack_64 >> 0x10);
  param_1[0x26] = ((unsigned char*)&uStack_64)[2];
  ((unsigned char*)&uStack_64)[1] = (undefined)((uint)uStack_64 >> 8);
  param_1[0x25] = ((unsigned char*)&uStack_64)[1];
  param_1[0x24] = (char)uStack_64;
  uStack_60 = uVar10 + param_2[10];
  ((unsigned char*)&uStack_60)[3] = (undefined)((uint)uStack_60 >> 0x18);
  param_1[0x2b] = ((unsigned char*)&uStack_60)[3];
  ((unsigned char*)&uStack_60)[2] = (undefined)((uint)uStack_60 >> 0x10);
  param_1[0x2a] = ((unsigned char*)&uStack_60)[2];
  ((unsigned char*)&uStack_60)[1] = (undefined)((uint)uStack_60 >> 8);
  param_1[0x29] = ((unsigned char*)&uStack_60)[1];
  param_1[0x28] = (char)uStack_60;
  uStack_5c = uVar8 + param_2[0xb];
  ((unsigned char*)&uStack_5c)[3] = (undefined)((uint)uStack_5c >> 0x18);
  param_1[0x2f] = ((unsigned char*)&uStack_5c)[3];
  ((unsigned char*)&uStack_5c)[2] = (undefined)((uint)uStack_5c >> 0x10);
  param_1[0x2e] = ((unsigned char*)&uStack_5c)[2];
  ((unsigned char*)&uStack_5c)[1] = (undefined)((uint)uStack_5c >> 8);
  param_1[0x2d] = ((unsigned char*)&uStack_5c)[1];
  param_1[0x2c] = (char)uStack_5c;
  local_58 = uVar7 + param_2[0xc];
  ((unsigned char*)&local_58)[3] = (undefined)((uint)local_58 >> 0x18);
  param_1[0x33] = ((unsigned char*)&local_58)[3];
  ((unsigned char*)&local_58)[2] = (undefined)((uint)local_58 >> 0x10);
  param_1[0x32] = ((unsigned char*)&local_58)[2];
  ((unsigned char*)&local_58)[1] = (undefined)((uint)local_58 >> 8);
  param_1[0x31] = ((unsigned char*)&local_58)[1];
  param_1[0x30] = (char)local_58;
  uStack_54 = uVar9 + param_2[0xd];
  ((unsigned char*)&uStack_54)[3] = (undefined)((uint)uStack_54 >> 0x18);
  param_1[0x37] = ((unsigned char*)&uStack_54)[3];
  ((unsigned char*)&uStack_54)[2] = (undefined)((uint)uStack_54 >> 0x10);
  param_1[0x36] = ((unsigned char*)&uStack_54)[2];
  ((unsigned char*)&uStack_54)[1] = (undefined)((uint)uStack_54 >> 8);
  param_1[0x35] = ((unsigned char*)&uStack_54)[1];
  param_1[0x34] = (char)uStack_54;
  uStack_50 = uVar11 + param_2[0xe];
  ((unsigned char*)&uStack_50)[3] = (undefined)((uint)uStack_50 >> 0x18);
  param_1[0x3b] = ((unsigned char*)&uStack_50)[3];
  ((unsigned char*)&uStack_50)[2] = (undefined)((uint)uStack_50 >> 0x10);
  param_1[0x3a] = ((unsigned char*)&uStack_50)[2];
  ((unsigned char*)&uStack_50)[1] = (undefined)((uint)uStack_50 >> 8);
  param_1[0x39] = ((unsigned char*)&uStack_50)[1];
  param_1[0x38] = (char)uStack_50;
  uStack_4c = uVar3 + param_2[0xf];
  ((unsigned char*)&uStack_4c)[3] = (undefined)((uint)uStack_4c >> 0x18);
  param_1[0x3f] = ((unsigned char*)&uStack_4c)[3];
  ((unsigned char*)&uStack_4c)[2] = (undefined)((uint)uStack_4c >> 0x10);
  param_1[0x3e] = ((unsigned char*)&uStack_4c)[2];
  ((unsigned char*)&uStack_4c)[1] = (undefined)((uint)uStack_4c >> 8);
  param_1[0x3d] = ((unsigned char*)&uStack_4c)[1];
  param_1[0x3c] = (char)uStack_4c;
  local_98 = param_1;
  local_90 = param_2;
  local_88 = local_c8;
  uStack_84 = local_d8;
  uStack_80 = local_d4;
  uStack_7c = local_d0;
  return;
}

struct chacha20_context
{
	uint32_t keystream32[16];
	size_t position;

	uint8_t key[32];
	uint8_t nonce[12];
	uint64_t counter;

	uint32_t state[16];
};

void chacha20_init_context(struct chacha20_context *ctx, uint8_t key[], uint8_t nounc[], uint64_t counter);

void chacha20_xor(struct chacha20_context *ctx, uint8_t *bytes, size_t n_bytes);

static uint32_t rotl32(uint32_t x, int n) 
{
	return (x << n) | (x >> (32 - n));
}

static uint32_t pack4(const uint8_t *a)
{
	uint32_t res = 0;
	res |= (uint32_t)a[0] << 0 * 8;
	res |= (uint32_t)a[1] << 1 * 8;
	res |= (uint32_t)a[2] << 2 * 8;
	res |= (uint32_t)a[3] << 3 * 8;
	return res;
}

static void unpack4(uint32_t src, uint8_t *dst) {
	dst[0] = (src >> 0 * 8) & 0xff;
	dst[1] = (src >> 1 * 8) & 0xff;
	dst[2] = (src >> 2 * 8) & 0xff;
	dst[3] = (src >> 3 * 8) & 0xff;
}

static void chacha20_init_block(struct chacha20_context *ctx, uint8_t key[], uint8_t nonce[])
{
	memcpy(ctx->key, key, sizeof(ctx->key));
	memcpy(ctx->nonce, nonce, sizeof(ctx->nonce));

	const uint8_t *magic_constant = (uint8_t*)"expand 32-byte k";
	ctx->state[0] = pack4(magic_constant + 0 * 4);
	ctx->state[1] = pack4(magic_constant + 1 * 4);
	ctx->state[2] = pack4(magic_constant + 2 * 4);
	ctx->state[3] = pack4(magic_constant + 3 * 4);
	ctx->state[4] = pack4(key + 0 * 4);
	ctx->state[5] = pack4(key + 1 * 4);
	ctx->state[6] = pack4(key + 2 * 4);
	ctx->state[7] = pack4(key + 3 * 4);
	ctx->state[8] = pack4(key + 4 * 4);
	ctx->state[9] = pack4(key + 5 * 4);
	ctx->state[10] = pack4(key + 6 * 4);
	ctx->state[11] = pack4(key + 7 * 4);
	// 64 bit counter initialized to zero by default.
	ctx->state[12] = 0;
	ctx->state[13] = pack4(nonce + 0 * 4);
	ctx->state[14] = pack4(nonce + 1 * 4);
	ctx->state[15] = pack4(nonce + 2 * 4);

	memcpy(ctx->nonce, nonce, sizeof(ctx->nonce));
}

static void chacha20_block_set_counter(struct chacha20_context *ctx, uint64_t counter)
{
	ctx->state[12] = (uint32_t)counter;
	ctx->state[13] = pack4(ctx->nonce + 0 * 4) + (uint32_t)(counter >> 32);
}

static void chacha20_block_next(struct chacha20_context *ctx) {
	// This is where the crazy voodoo magic happens.
	// Mix the bytes a lot and hope that nobody finds out how to undo it.
	for (int i = 0; i < 16; i++) ctx->keystream32[i] = ctx->state[i];

#define CHACHA20_QUARTERROUND(x, a, b, c, d) \
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16); \
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12); \
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 8); \
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 7);

	for (int i = 0; i < 10; i++) 
	{
		CHACHA20_QUARTERROUND(ctx->keystream32, 0, 4, 8, 12)
		CHACHA20_QUARTERROUND(ctx->keystream32, 1, 5, 9, 13)
		CHACHA20_QUARTERROUND(ctx->keystream32, 2, 6, 10, 14)
		CHACHA20_QUARTERROUND(ctx->keystream32, 3, 7, 11, 15)
		CHACHA20_QUARTERROUND(ctx->keystream32, 0, 5, 10, 15)
		CHACHA20_QUARTERROUND(ctx->keystream32, 1, 6, 11, 12)
		CHACHA20_QUARTERROUND(ctx->keystream32, 2, 7, 8, 13)
		CHACHA20_QUARTERROUND(ctx->keystream32, 3, 4, 9, 14)
	}

	for (int i = 0; i < 16; i++) ctx->keystream32[i] += ctx->state[i];

	uint32_t *counter = ctx->state + 12;
	// increment counter
	counter[0]++;
	if (0 == counter[0]) 
	{
		// wrap around occured, increment higher 32 bits of counter
		counter[1]++;
		// Limited to 2^64 blocks of 64 bytes each.
		// If you want to process more than 1180591620717411303424 bytes
		// you have other problems.
		// We could keep counting with counter[2] and counter[3] (nonce),
		// but then we risk reusing the nonce which is very bad.
		assert(0 != counter[1]);
	}
}

void chacha20_init_context(struct chacha20_context *ctx, uint8_t key[], uint8_t nonce[], uint64_t counter)
{
	memset(ctx, 0, sizeof(struct chacha20_context));

	chacha20_init_block(ctx, key, nonce);
	chacha20_block_set_counter(ctx, counter);

	ctx->counter = counter;
	ctx->position = 64;
}

void chacha20_xor(struct chacha20_context *ctx, uint8_t *bytes, size_t n_bytes)
{
	uint8_t *keystream8 = (uint8_t*)ctx->keystream32;
	for (size_t i = 0; i < n_bytes; i++) 
	{
		if (ctx->position >= 64) 
		{
			chacha20_block_next(ctx);
			ctx->position = 0;
		}
		bytes[i] ^= keystream8[ctx->position];
		ctx->position++;
	}
}

void dump_state(void* state, size_t nbytes) {
  for (int i = 0; i < nbytes; ++i) {
    printf("%02x ", ((uint8_t*)state)[i]);
    if (i % 16 == 15) printf("\n");
  }
  printf("\n");
}

void read_state(void* state, const char* str) {
  for (int i = 0; i < 64; i++) {
    sscanf(str + i * 3, "%02hhx", &((uint8_t*)state)[i]);
  }
}

unsigned int myseed = 0;
void mysrand(unsigned int seed) {
  myseed = seed;
}
unsigned int myrand() {
  myseed = myseed * 214013L + 2531011L;
  return myseed>>16 & 0x7FFF;
}

void init_chacha_ccstyle(chacha20_context *ctx) {
  chacha20_context init_ctx;
  uint8_t empty_key[32] = {0};
  uint8_t empty_nonce[12] = {0};
  chacha20_init_context(&init_ctx, empty_key, empty_nonce, 0);
  uint8_t iv[0x28];
  for (int i = 0; i < 0x28; ++i) {
    int iVar7 = myrand();
    char x = (char)iVar7 * (i + 1);
    iv[i] = x;
  }
  myrand(); // match cryptocontext.exe implementation
  chacha20_xor(&init_ctx, iv, 0x28);
  //dump_state(iv, 0x28);

  uint8_t iv_nonce[12] = {0};
  memcpy(&iv_nonce[4], &iv[0x20], 8);
  chacha20_init_context(ctx, &iv[0], iv_nonce, 0);
  uint8_t dummy_buf[8] = {0};
  chacha20_xor(ctx, dummy_buf, 8);
  //dump_state(main_buf, 64);
}

void test_with_seed(unsigned int seed, uint8_t key[64]) {
  mysrand(seed);
  chacha20_context dummy_ctx;
  chacha20_context main_ctx[16];
  init_chacha_ccstyle(&dummy_ctx);
  for (int i = 0; i < 16; ++i) {
    init_chacha_ccstyle(&main_ctx[i]);
  }
  chacha20_xor(&main_ctx[0], key, 64);
  for (int i = 0; i < 16; ++i) {
    chacha20_xor(&main_ctx[i], key, 64);
  }
  //dump_state(key, 64);
}

bool test_jpg(uint8_t key[64]) {
  // jpg format ff d8 ff e0
  // encrypted : 74 5c d6 69
  if (
    (0xff ^ key[myrand() % 64]) == 0x74 
    && (0xd8 ^ key[myrand() % 64]) == 0x5c
    && (0xff ^ key[myrand() % 64]) == 0xd6
    && (0xe0 ^ key[myrand() % 64]) == 0x69
    ) {
    return true;
  }
  return false;
}

void decrypt_with_seed(unsigned int seed) {
  uint8_t key[64] = {0};
  test_with_seed(seed, key);

  FILE *fin = fopen("c_contest_2024_out.jpg", "rb");
  FILE *fout = fopen("c_contest_2024.jpg", "wb");
  if (!fin || !fout) {
    printf("file open failed\n");
    return;
  }
  fseek(fin, 0, SEEK_END);
  long nbytes = ftell(fin);
  fseek(fin, 0, SEEK_SET);
  uint8_t enc[nbytes];
  fread(enc, nbytes, 1, fin);
  uint8_t rand_seq[nbytes];
  for (long i = 0; i < nbytes; ++i) {
    rand_seq[i] = myrand() % 64;
  }
  uint8_t dec[nbytes];
  for (int i = 0; i < nbytes; ++i) {
    int found_cnt = 0, found_dec = 0;
    for (int j = 0; j < 256; ++j) {
      if ((j ^ key[rand_seq[i]]) == enc[i]) {
        ++found_cnt;
        found_dec = j;
      }
    }
    if (found_cnt == 0) {
      printf("no dec found\n");
      exit(0);
    }
    if (found_cnt > 1) {
      printf("multiple dec found\n");
      exit(0);
    }
    dec[i] = found_dec;
  }
  fwrite(dec, nbytes, 1, fout);
  fclose(fin);
  fclose(fout);
}

int main() {
  for (unsigned int i = 0; i < 1 << 16; ++i) {
    unsigned int seed = ((i & 0xf) << 4) | ((i & 0xf0) << 8) | ((i & 0xf00) << 12) | ((i & 0xf000) << 16);
    int success = 0;
    uint8_t key[64] = {0};
    test_with_seed(seed, key);
    if (test_jpg(key)) {
      printf("seed: %08X\n", seed);
      decrypt_with_seed(seed);
      exit(0);
    }
  }
//  const char* old_state_str =
//"65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B "
//"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
//"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
//"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ";
//"95 26 30 FD 2F 0F 0E 68 50 75 3F C9 ED 94 E7 B8 "
//"EB A4 56 B8 E7 31 B0 4A AA 4C B4 F0 CE 3F 39 E7 "
//"01 00 00 00 00 00 00 00 6D 93 56 E8 D0 5B 39 9D ";

  //uint32_t cur_state[16];
  //uint32_t next_state[16];

  //read_state(cur_state, old_state_str);
  //printf("cur_state\n");
  //dump_state(cur_state);
  //FUN_140001670((undefined*)next_state, cur_state, 20);
  //printf("next_state\n");
  //dump_state(next_state);

  //chacha20_context ctx;
  //read_state(&ctx.state, old_state_str);
  //printf("chacha20 cur_state\n");
  //dump_state(&ctx.state);
  //chacha20_block_next(&ctx);
  //printf("chacha20 next_state\n");
  //dump_state(&ctx.keystream32);

  //mysrand(42);
  //for (int i = 0; i < 0x28 + 1; ++i) {
  //  myrand();
  //}
  //int param_2 = 0;
  //for (int iVar8 = 0; iVar8 < 0x28; ++iVar8) {
  //  int iVar7 = myrand();
  //  printf("iVar7: %X\n", iVar7);
  //  char cVar2 = (char)iVar8;
  //  char x = (char)iVar7 * (cVar2 + '\x01' + param_2);
  //  printf("%02hhX ", x);
  //  if (iVar8 % 16 == 15) printf("\n");
  //}

  // consume the first block
  return 0;
}