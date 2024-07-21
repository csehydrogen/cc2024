#include <cstdio>
#include <cstdlib>

typedef unsigned int uint;
typedef unsigned long long ulonglong;
typedef long long longlong;
typedef unsigned char byte;
typedef unsigned char undefined;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long undefined8;

void encrypt(const char *in, const char *out) {
  FILE *fin = fopen("c_contest_2024.jpg", "rb");
  FILE *fout = fopen("c_contest_2024_out.jpg", "wb");
  if (fin && fout) {
    fseek(fin, 0, SEEK_END);
    long nbytes = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    for (long i = 0; i < nbytes; ++i) {
      unsigned char x;
      fread(&x, 1, 1, fin);
      int r = rand();
      r = r & 0x8000003f;
      if ((int)r < 0) {
        r = (r - 1 | 0xffffffc0) + 1;
      }
      x = x ^ key[r];
      fwrite(&x, 1, 1, fout);
    }
    fclose(fin);
    fclose(fout);
  }
}

void decrypt() {
}

int main() {
  return 0;
}

iVar3 = FUN_140001070(local_148, &local_188);
if (iVar3 != 0) {
  uVar10 = 0;
  lVar11 = 0;
  do {
    iVar3 =
        FUN_140001070(puVar6 + (longlong)(int)uVar10 * 0x2f,
                      (int *)((longlong)pvVar7 + (longlong)(int)uVar10 * 4));
    if (iVar3 == 0)
      goto LAB_14000164d;
    uVar10 = uVar10 + 1;
  } while (uVar10 < 0x10);
  if ((puVar6 != (uint *)0x0) && (*(short *)(puVar6 + 0x2e) != 0)) {
    _local_68 = ZEXT816(0);
    param_4 = (uint *)local_68;
    param_3 = 0x40;
    local_58 = _local_68;
    _local_48 = _local_68;
    local_38 = _local_68;
    FUN_140001b90(puVar6, (uint *)local_68, 0x40, param_4);
  }
  lVar12 = 0x10;
  do {
    lVar8 = lVar11;
    if ((puVar6 != (uint *)0x0) && (*(short *)(puVar6 + 0x2e) != 0)) {
      _local_88 = ZEXT816(0);
      param_4 = (uint *)local_88;
      param_3 = 0x20;
      local_78 = _local_88;
      FUN_140001b90(puVar6, (uint *)local_88, 0x20, param_4);
    }
    do {
      uVar10 = *(uint *)(local_88 + lVar8 + 4);
      uVar1 = *(uint *)(local_88 + lVar8 + 8);
      uVar2 = *(uint *)(local_88 + lVar8 + 0xc);
      *(uint *)(local_68 + lVar8) =
          *(uint *)(local_88 + lVar8) ^ *(uint *)(local_68 + lVar8);
      *(uint *)(local_68 + lVar8 + 4) =
          uVar10 ^ *(uint *)(local_68 + lVar8 + 4);
      *(uint *)(local_68 + lVar8 + 8) = uVar1 ^ *(uint *)(local_68 + lVar8 + 8);
      *(uint *)(local_68 + lVar8 + 0xc) =
          uVar2 ^ *(uint *)(local_68 + lVar8 + 0xc);
      lVar8 = lVar8 + 0x10;
    } while (lVar8 < 0x20);
    lVar8 = lVar11;
    if ((puVar6 != (uint *)0x0) && (*(short *)(puVar6 + 0x2e) != 0)) {
      _local_88 = ZEXT816(0);
      param_4 = (uint *)local_88;
      param_3 = 0x20;
      local_78 = _local_88;
      FUN_140001b90(puVar6, (uint *)local_88, 0x20, param_4);
    }
    do {
      uVar10 = *(uint *)(local_88 + lVar8 + 4);
      uVar1 = *(uint *)(local_88 + lVar8 + 8);
      uVar2 = *(uint *)(local_88 + lVar8 + 0xc);
      *(uint *)(local_48 + lVar8) =
          *(uint *)(local_88 + lVar8) ^ *(uint *)(local_48 + lVar8);
      *(uint *)(local_48 + lVar8 + 4) =
          uVar10 ^ *(uint *)(local_48 + lVar8 + 4);
      *(uint *)(local_48 + lVar8 + 8) = uVar1 ^ *(uint *)(local_48 + lVar8 + 8);
      *(uint *)(local_48 + lVar8 + 0xc) =
          uVar2 ^ *(uint *)(local_48 + lVar8 + 0xc);
      lVar8 = lVar8 + 0x10;
    } while (lVar8 < 0x20);
    puVar6 = puVar6 + 0x2f;
    lVar12 = lVar12 + -1;
  } while (lVar12 != 0);

65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B  expand 32-byte k  
95 26 30 FD 2F 0F 0E 68 50 75 3F C9 ED 94 E7 B8  .&0ý/..hPu?Éí.ç¸  
EB A4 56 B8 E7 31 B0 4A AA 4C B4 F0 CE 3F 39 E7  ë¤V¸ç1°JªL´ðÎ?9ç  
01 00 00 00 00 00 00 00 6D 93 56 E8 D0 5B 39 9D  ........m.VèÐ[9.  
