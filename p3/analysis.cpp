#include <cstring>
#include <cstdlib>

typedef unsigned int uint;
typedef unsigned long long ulonglong;
typedef long long longlong;
typedef unsigned char byte;
typedef unsigned char undefined;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long undefined8;

ulonglong DAT_140006008 = 0x00002B992DDFA232;
longlong p_DAT_140006620[2]; // 16B buffer
longlong p_DAT_140006630[2]; // 16B buffer
longlong p_DAT_140006640[2]; // 16B buffer
longlong p_DAT_140006650[2]; // 16B buffer
longlong p_DAT_140006660[2]; // 16B buffer
const char* p_PTR_s_chacha20_140004320 = "chacha20";

void zero16(void* buf) {
  for (int i = 0; i < 16; ++i) {
    ((byte*)buf)[i] = 0;
  }
}

void fill16(void* buf, undefined4 a, undefined4 b, undefined4 c, undefined4 d) {
  ((undefined4*)buf)[0] = a;
  ((undefined4*)buf)[1] = b;
  ((undefined4*)buf)[2] = c;
  ((undefined4*)buf)[3] = d;
}

void       FUN_140001070(uint *param_1,int *param_2);
void       FUN_1400012f0(undefined8 param_1,undefined8 param_2,undefined8 param_3,uint *param_4);
void       FUN_140001b90(uint *param_1,uint *param_2,uint param_3,uint *param_4);
undefined8 FUN_140001ea0(undefined4 *param_1,undefined4 *param_2);
void       FUN_1400020f0(byte *param_1,uint param_2,uint *param_3);


void FUN_140001b90(uint *param_1,uint *param_2,uint param_3,uint *param_4)

{
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
  uint *puVar13;
  ulonglong uVar14;
  byte *pbVar15;
  uint uVar16;
  uint *puVar17;
  ulonglong uVar18;
  longlong lVar19;
  ulonglong uVar20;
  undefined auStack_98 [32];
  uint local_78 [7];
  uint uStack_5c;
  uint local_58;
  uint uStack_54;
  uint uStack_50;
  uint uStack_4c;
  uint local_48;
  uint uStack_44;
  uint uStack_40;
  undefined auStack_3c [4];
  ulonglong local_38;
  
  local_38 = DAT_140006008 ^ (ulonglong)auStack_98;
  uVar18 = (ulonglong)param_3;
  if (param_3 == 0) goto LAB_140001e6f;
  uVar11 = param_1[0x20];
  uVar20 = uVar18;
  if (uVar11 != 0) {
    if (uVar11 < param_3) {
      uVar18 = (ulonglong)uVar11;
LAB_140001be6:
      uVar12 = (uint)uVar18;
      puVar17 = param_4;
      uVar20 = uVar18;
      do {
        *(byte *)puVar17 =
             *(byte *)((ulonglong)(0x40 - uVar11) + 0x40 + (longlong)param_1) ^
             *(byte *)((longlong)param_2 + (-1 - (longlong)param_4) +
                      (longlong)(uint *)((longlong)puVar17 + 1));
        param_1[0x20] = param_1[0x20] - 1;
        uVar11 = param_1[0x20];
        uVar20 = uVar20 - 1;
        puVar17 = (uint *)((longlong)puVar17 + 1);
      } while (uVar20 != 0);
    }
    else {
      uVar12 = param_3;
      if (param_3 != 0) goto LAB_140001be6;
    }
    uVar20 = (ulonglong)(param_3 - uVar12);
    if (param_3 - uVar12 == 0) goto LAB_140001e6f;
    param_4 = (uint *)((longlong)param_4 + uVar18);
    param_2 = (uint *)((longlong)param_2 + uVar18);
  }
  puVar17 = (uint *)((longlong)param_4 + 0x3f);
LAB_140001c40:
  FUN_140001670((undefined *)local_78,param_1,param_1[0x22]);
  uVar11 = param_1[0xc] + 1;
  param_1[0xc] = uVar11;
  if (param_1[0x21] == 8) {
    if (uVar11 == 0) {
      puVar13 = param_1 + 0xd;
      *puVar13 = *puVar13 + 1;
      uVar11 = *puVar13;
      goto LAB_140001c71;
    }
  }
  else {
LAB_140001c71:
    if (uVar11 == 0) goto LAB_140001e6f;
  }
  uVar11 = (uint)uVar20;
  if (0x40 < uVar11) {
    if (((auStack_3c + 3 < param_4) || (puVar17 < local_78)) &&
       (((uint *)((longlong)param_2 + 0x3fU) < param_4 || (puVar17 < param_2)))) {
      uVar12 = param_2[1];
      uVar1 = param_2[2];
      uVar2 = param_2[3];
      uVar3 = param_2[4];
      uVar4 = param_2[5];
      uVar5 = param_2[6];
      uVar6 = param_2[7];
      *param_4 = *param_2 ^ local_78[0];
      param_4[1] = uVar12 ^ local_78[1];
      param_4[2] = uVar1 ^ local_78[2];
      param_4[3] = uVar2 ^ local_78[3];
      uVar12 = param_2[8];
      uVar1 = param_2[9];
      uVar2 = param_2[10];
      uVar7 = param_2[0xb];
      *(uint *)((longlong)puVar17 + -0x2f) = uVar3 ^ local_78[4];
      *(uint *)((longlong)puVar17 + -0x2b) = uVar4 ^ local_78[5];
      *(uint *)((longlong)puVar17 + -0x27) = uVar5 ^ local_78[6];
      *(uint *)((longlong)puVar17 + -0x23) = uVar6 ^ uStack_5c;
      uVar3 = param_2[0xc];
      uVar4 = param_2[0xd];
      uVar5 = param_2[0xe];
      uVar6 = param_2[0xf];
      *(uint *)((longlong)puVar17 + -0x1f) = uVar12 ^ local_58;
      *(uint *)((longlong)puVar17 + -0x1b) = uVar1 ^ uStack_54;
      *(uint *)((longlong)puVar17 + -0x17) = uVar2 ^ uStack_50;
      *(uint *)((longlong)puVar17 + -0x13) = uVar7 ^ uStack_4c;
      *(uint *)((longlong)puVar17 + -0xf) = uVar3 ^ local_48;
      *(uint *)((longlong)puVar17 + -0xb) = uVar4 ^ uStack_44;
      *(uint *)((longlong)puVar17 + -7) = uVar5 ^ uStack_40;
      *(uint *)((longlong)puVar17 + -3) = uVar6 ^ (uint)auStack_3c;
      uVar20 = (ulonglong)(uVar11 - 0x40);
      param_4 = param_4 + 0x10;
      puVar17 = puVar17 + 0x10;
      param_2 = param_2 + 0x10;
    }
    else {
      puVar13 = local_78;
      lVar19 = 0x40;
      do {
        *(byte *)(((longlong)puVar17 - (longlong)(auStack_3c + 3)) + (longlong)puVar13) =
             ((byte *)((longlong)puVar13 + (0x10 - (longlong)(local_78 + 4))))[(longlong)param_2]  ^
             *(byte *)puVar13;
        puVar13 = (uint *)((longlong)puVar13 + 1);
        lVar19 = lVar19 + -1;
      } while (lVar19 != 0);
      uVar20 = (ulonglong)(uVar11 - 0x40);
      param_4 = param_4 + 0x10;
      puVar17 = puVar17 + 0x10;
      param_2 = param_2 + 0x10;
    }
    goto LAB_140001c40;
  }
  uVar18 = 0;
  if (uVar11 != 0) {
    if (0x3f < uVar11) {
      uVar12 = uVar11 - 1;
      if ((((uint *)((longlong)local_78 + (ulonglong)uVar12) < param_4) ||
          ((uint *)((ulonglong)uVar12 + (longlong)param_4) < local_78)) &&
         (((uint *)((ulonglong)uVar12 + (longlong)param_2) < param_4 ||
          ((uint *)((ulonglong)uVar12 + (longlong)param_4) < param_2)))) {
        uVar12 = 0x20;
        do {
          uVar1 = *(uint *)((longlong)local_78 + uVar18 + 4);
          uVar2 = *(uint *)((longlong)local_78 + uVar18 + 8);
          uVar3 = *(uint *)((longlong)local_78 + uVar18 + 0xc);
          uVar14 = (ulonglong)(uVar12 - 0x10);
          puVar17 = (uint *)(uVar18 + (longlong)param_2);
          uVar4 = puVar17[1];
          uVar5 = puVar17[2];
          uVar6 = puVar17[3];
          uVar7 = *(uint *)((longlong)local_78 + uVar14);
          uVar8 = *(uint *)((longlong)local_78 + uVar14 + 4);
          uVar9 = *(uint *)((longlong)local_78 + uVar14 + 8);
          uVar10 = *(uint *)((longlong)local_78 + uVar14 + 0xc);
          puVar13 = (uint *)(uVar18 + (longlong)param_4);
          *puVar13 = *puVar17 ^ *(uint *)((longlong)local_78 + uVar18);
          puVar13[1] = uVar4 ^ uVar1;
          puVar13[2] = uVar5 ^ uVar2;
          puVar13[3] = uVar6 ^ uVar3;
          uVar16 = (int)uVar18 + 0x40;
          uVar18 = (ulonglong)uVar16;
          puVar17 = (uint *)(uVar14 + (longlong)param_2);
          uVar1 = puVar17[1];
          uVar2 = puVar17[2];
          uVar3 = puVar17[3];
          puVar13 = (uint *)(uVar14 + (longlong)param_4);
          *puVar13 = *puVar17 ^ uVar7;
          puVar13[1] = uVar1 ^ uVar8;
          puVar13[2] = uVar2 ^ uVar9;
          puVar13[3] = uVar3 ^ uVar10;
          uVar14 = (ulonglong)uVar12;
          uVar1 = *(uint *)((longlong)local_78 + uVar14 + 4);
          uVar2 = *(uint *)((longlong)local_78 + uVar14 + 8);
          uVar3 = *(uint *)((longlong)local_78 + uVar14 + 0xc);
          puVar17 = (uint *)(uVar14 + (longlong)param_2);
          uVar4 = puVar17[1];
          uVar5 = puVar17[2];
          uVar6 = puVar17[3];
          puVar13 = (uint *)(uVar14 + (longlong)param_4);
          *puVar13 = *puVar17 ^ *(uint *)((longlong)local_78 + uVar14);
          puVar13[1] = uVar4 ^ uVar1;
          puVar13[2] = uVar5 ^ uVar2;
          puVar13[3] = uVar6 ^ uVar3;
          uVar14 = (ulonglong)(uVar12 + 0x10);
          uVar12 = uVar12 + 0x40;
          puVar17 = (uint *)(uVar14 + (longlong)param_2);
          uVar1 = puVar17[1];
          uVar2 = puVar17[2];
          uVar3 = puVar17[3];
          uVar4 = *(uint *)((longlong)local_78 + uVar14 + 4);
          uVar5 = *(uint *)((longlong)local_78 + uVar14 + 8);
          uVar6 = *(uint *)((longlong)local_78 + uVar14 + 0xc);
          puVar13 = (uint *)(uVar14 + (longlong)param_4);
          *puVar13 = *puVar17 ^ *(uint *)((longlong)local_78 + uVar14);
          puVar13[1] = uVar1 ^ uVar4;
          puVar13[2] = uVar2 ^ uVar5;
          puVar13[3] = uVar3 ^ uVar6;
        } while (uVar16 < (uVar11 & 0xffffffc0));
        if (uVar11 <= uVar16) goto LAB_140001e43;
      }
    }
    pbVar15 = (byte *)((longlong)local_78 + uVar18);
    uVar18 = (ulonglong)(uVar11 - (int)uVar18);
    do {
      pbVar15[(longlong)param_4 - (longlong)local_78] =
           pbVar15[(longlong)param_2 - (longlong)local_78] ^ *pbVar15;
      pbVar15 = pbVar15 + 1;
      uVar18 = uVar18 - 1;
    } while (uVar18 != 0);
  }
LAB_140001e43:
  param_1[0x20] = 0x40 - uVar11;
  if (uVar11 < 0x40) {
    memcpy((void *)((longlong)param_1 + uVar20 + 0x40),(void *)((longlong)local_78 + uVar20),
           (ulonglong)(0x40 - uVar11));
  }
LAB_140001e6f:
  FUN_140002530(local_38 ^ (ulonglong)auStack_98);
  return;
}



void FUN_1400020f0(byte *param_1,uint param_2,uint *param_3)

{
  byte *pbVar1;
  int iVar2;
  undefined8 uVar3;
  undefined *puVar4;
  longlong lVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  undefined auStack_58 [32];
  undefined local_38 [16];
  undefined local_28 [16];
  undefined8 local_18;
  ulonglong local_10;
  
  local_10 = DAT_140006008 ^ (ulonglong)auStack_58;
  if (*(short *)(param_3 + 0x2e) == 0) {
    if (param_2 != 0) {
      do {
        pbVar1 = (byte *)((ulonglong)param_3[0x2d] % 0x28 + 0x8c + (longlong)param_3);
        *pbVar1 = *pbVar1 ^ *param_1;
        param_3[0x2d] = param_3[0x2d] + 1;
        param_2 = param_2 - 1;
        param_1 = param_1 + 1;
      } while (param_2 != 0);
    }
  }
  else {
    lVar5 = 0x28;
    local_18 = 0;
    //local_38 = ZEXT816(0);
    zero16(local_38);
    //local_28 = ZEXT816(0);
    zero16(local_28);
    iVar2 = FUN_140001b90(param_3,(uint *)local_38,0x28,(uint *)local_38);
    if (iVar2 == 0) {
      uVar8 = 0;
      if (param_2 != 0) {
        uVar7 = (ulonglong)param_2;
        uVar6 = uVar8;
        do {
          local_38[uVar6 % 0x28] = local_38[uVar6 % 0x28] ^ *param_1;
          uVar7 = uVar7 - 1;
          param_1 = param_1 + 1;
          uVar6 = uVar6 + 1;
        } while (uVar7 != 0);
      }
      uVar3 = FUN_140001ea0(param_3,(undefined4 *)local_38);
      if ((int)uVar3 == 0) {
        *(ulonglong *)(param_3 + 0xc) = uVar8;
        param_3[0x20] = (uint)uVar8;
        param_3[0x21] = 8;
        param_3[0xe] = (uint)local_18;
        puVar4 = local_38;
        param_3[0xf] = (uint)((ulonglong)local_18 >> 0x20);
        do {
          *puVar4 = (char)uVar8;
          puVar4 = puVar4 + 1;
          lVar5 = lVar5 + -1;
        } while (lVar5 != 0);
      }
    }
  }
  FUN_140002530(local_10 ^ (ulonglong)auStack_58);
  return;
}

undefined8 FUN_140001ea0(undefined4 *param_1,undefined4 *param_2)

{
  param_1[4] = *param_2;
  param_1[5] = param_2[1];
  param_1[6] = param_2[2];
  param_1[7] = param_2[3];
  param_1[8] = param_2[4];
  param_1[9] = param_2[5];
  param_1[10] = param_2[6];
  param_1[0xb] = param_2[7];
  *param_1 = 0x61707865;
  param_1[1] = 0x3320646e;
  param_1[2] = 0x79622d32;
  param_1[0x22] = 0x14;
  param_1[0x21] = 0;
  param_1[3] = 0x6b206574;
  return 0;
}

void FUN_140001070(uint *param_1,int *param_2)
{
  longlong lVar1;
  char cVar2;
  int iVar3;
  longlong *plVar4;
  longlong lVar5;
  undefined8 uVar6;
  undefined8 *_Memory;
  int iVar7;
  int iVar8;
  byte *pbVar9;
  undefined (*pauVar10) [16];
  undefined4 extraout_XMM0_Da;
  undefined4 extraout_XMM0_Db;
  undefined4 extraout_XMM0_Dc;
  undefined4 extraout_XMM0_Dd;
  undefined auStack_78 [32];
  byte local_58 [40];
  ulonglong local_30;
  
  local_30 = DAT_140006008 ^ (ulonglong)auStack_78;
  iVar8 = 0;
  iVar7 = iVar8;
  do {
    iVar3 = memcmp(p_DAT_140006620 + (longlong)iVar7 * 10,p_PTR_s_chacha20_140004320,0x50);
    if (iVar3 == 0) goto LAB_14000113d;
    iVar7 = iVar7 + 1;
  } while (iVar7 < 0x20);
  plVar4 = p_DAT_140006620;
  iVar7 = iVar8;
  do {
    if (*plVar4 == 0) {
      lVar5 = (longlong)iVar7;
      lVar1 = lVar5 * 0x50;
      *(undefined4 *)(p_DAT_140006620 + lVar5 * 10) = 0x400043b0;
      *(undefined4 *)((longlong)p_DAT_140006620 + lVar1 + 4) = 1;
      *(undefined4 *)(lVar1 + 0x140006628) = 0x28;
      *(undefined4 *)(lVar1 + 0x14000662c) = 0;
      lVar1 = lVar5 * 0x50;
      *(undefined4 *)(p_DAT_140006630 + lVar1) = 0x400020c0;
      *(undefined4 *)(lVar1 + 0x140006634) = 1;
      *(undefined4 *)(lVar1 + 0x140006638) = 0x400020f0;
      *(undefined4 *)(lVar1 + 0x14000663c) = 1;
      lVar1 = lVar5 * 0x50;
      *(undefined4 *)(p_DAT_140006640 + lVar1) = 0x400022b0;
      *(undefined4 *)(lVar1 + 0x140006644) = 1;
      *(undefined4 *)(lVar1 + 0x140006648) = 0x40002390;
      *(undefined4 *)(lVar1 + 0x14000664c) = 1;
      lVar1 = lVar5 * 0x50;
      *(undefined4 *)(p_DAT_140006650 + lVar1) = 0x40002410;
      *(undefined4 *)(lVar1 + 0x140006654) = 1;
      *(undefined4 *)(lVar1 + 0x140006658) = 0x40002450;
      *(undefined4 *)(lVar1 + 0x14000665c) = 1;
      lVar5 = lVar5 * 0x50;
      *(undefined4 *)(p_DAT_140006660 + lVar5) = 0x400024e0;
      *(undefined4 *)(lVar5 + 0x140006664) = 1;
      *(undefined4 *)(lVar5 + 0x140006668) = 0;
      *(undefined4 *)(lVar5 + 0x14000666c) = 0;
LAB_14000113d:
      *param_2 = iVar7;
      if (iVar7 != -1) {
        *(undefined2 *)(param_1 + 0x2e) = 0;
        pauVar10 = (undefined (*) [16])(param_1 + 0x23);
        //*pauVar10 = ZEXT816(0);
        zero16(pauVar10);
        //*(undefined (*) [16])(param_1 + 0x27) = ZEXT816(0);
        zero16((undefined (*) [16])(param_1 + 0x27));
        *(undefined8 *)(param_1 + 0x2b) = 0;
        param_1[0x2d] = 0;
        if ((*(short *)(param_1 + 0x2e) == 0) &&
           (uVar6 = FUN_140001ea0(param_1,(undefined4 *)pauVar10), (int)uVar6 == 0)) {
          *(undefined8 *)(param_1 + 0xc) = 0;
          param_1[0xe] = param_1[0x2b];
          param_1[0x20] = 0;
          param_1[0x21] = 8;
          param_1[0xf] = param_1[0x2c];
          //*pauVar10 = CONCAT412(extraout_XMM0_Dd,
          //                      CONCAT48(extraout_XMM0_Dc,
          //                               CONCAT44(extraout_XMM0_Db,extraout_XMM0_Da)));
          fill16(pauVar10, extraout_XMM0_Da, extraout_XMM0_Db, extraout_XMM0_Dc, extraout_XMM0_Dd);
          //pauVar10[1] = CONCAT412(extraout_XMM0_Dd,
          //                        CONCAT48(extraout_XMM0_Dc,
          //                                 CONCAT44(extraout_XMM0_Db,extraout_XMM0_Da)));
          fill16(pauVar10 + 1, extraout_XMM0_Da, extraout_XMM0_Db, extraout_XMM0_Dc, extraout_XMM0_Dd);
          *(undefined8 *)pauVar10[2] = 0;
          *(undefined2 *)(param_1 + 0x2e) = 1;
          param_1[0x2d] = 0;
        }
        pbVar9 = local_58;
        do {
          iVar7 = rand();
          cVar2 = (char)iVar8;
          iVar8 = iVar8 + 1;
          *pbVar9 = (char)iVar7 * (cVar2 + '\x01' + *(char *)param_2);
          pbVar9 = pbVar9 + 1;
        } while (iVar8 < 0x28);
        FUN_1400020f0(local_58,0x28,param_1);
        iVar7 = rand();
        _Memory = (undefined8 *)malloc((longlong)(iVar7 % 0x100 + 9));
        if ((_Memory != (undefined8 *)0x0) && (*(short *)(param_1 + 0x2e) != 0)) {
          *_Memory = 0;
          FUN_140001b90(param_1,(uint *)_Memory,8,(uint *)_Memory);
        }
        free(_Memory);
      }
      goto LAB_1400012d7;
    }
    iVar7 = iVar7 + 1;
    plVar4 = plVar4 + 10;
  } while ((longlong)plVar4 < 0x140007020);
  *param_2 = -1;
LAB_1400012d7:
  FUN_140002530(local_30 ^ (ulonglong)auStack_78);
  return;
}

void FUN_1400012f0(undefined8 param_1,undefined8 param_2,undefined8 param_3,uint *param_4)
{
  const int nproc = 64;
  uint uVar1;
  uint uVar2;
  int iVar3;
  FILE *pFVar4;
  ulonglong uVar5;
  uint *puVar6;
  void *pvVar7;
  longlong lVar8;
  FILE *_File;
  ulonglong uVar9;
  uint uVar10;
  longlong lVar11;
  longlong lVar12;
  ulonglong uVar13;
  undefined auStack_1a8 [32];
  int local_188;
  byte local_184 [4];
  _SYSTEM_INFO local_180;
  uint local_148 [48];
  undefined local_88 [8];
  uint auStack_80 [2];
  undefined local_78 [16];
  undefined local_68 [8];
  uint auStack_60 [2];
  undefined local_58 [16];
  undefined local_48 [8];
  uint auStack_40 [2];
  undefined local_38 [16];
  ulonglong local_28;
  
  local_28 = DAT_140006008 ^ (ulonglong)auStack_1a8;
  pFVar4 = fopen("c_contest_2024.jpg","rb");
  if (pFVar4 != (FILE *)0x0) {
    fclose(pFVar4);
    uVar5 = _time64((__time64_t *)0x0);
    srand((uint)uVar5 & 0xf0f0f0f0);
    GetSystemInfo(&local_180);
    uVar13 = (ulonglong)(nproc + 0x10) * 0x44f0;
    // uVar13 = 0000000000158B00 = 1411840 = (core + 16) * 17648
    uVar9 = uVar13 & 0xffffffff;
    if ((int)(uVar13 >> 0x20) != 0) {
      uVar9 = 0xffffffffffffffff;
    }
    puVar6 = (uint *)malloc(uVar9);
    // puVar6 = (core + 16) * 17648 bytes buffer
    uVar13 = (ulonglong)(nproc + 0x10) * 4;
    uVar9 = uVar13 & 0xffffffff;
    if ((int)(uVar13 >> 0x20) != 0) {
      uVar9 = 0xffffffffffffffff;
    }
    pvVar7 = malloc(uVar9);
    // puVar7 = (core + 16) * 4 bytes buffer
    iVar3 = FUN_140001070(local_148,&local_188);
    if (iVar3 != 0) {
      uVar10 = 0;
      lVar11 = 0;
      do {
        iVar3 = FUN_140001070(puVar6 + (longlong)(int)uVar10 * 0x2f,
                              (int *)((longlong)pvVar7 + (longlong)(int)uVar10 * 4));
        if (iVar3 == 0) goto LAB_14000164d;
        uVar10 = uVar10 + 1;
      } while (uVar10 < 0x10);
      if ((puVar6 != (uint *)0x0) && (*(short *)(puVar6 + 0x2e) != 0)) {
        _local_68 = ZEXT816(0);
        param_4 = (uint *)local_68;
        param_3 = 0x40;
        local_58 = _local_68;
        _local_48 = _local_68;
        local_38 = _local_68;
        FUN_140001b90(puVar6,(uint *)local_68,0x40,param_4);
      }
      lVar12 = 0x10;
      do {
        lVar8 = lVar11;
        if ((puVar6 != (uint *)0x0) && (*(short *)(puVar6 + 0x2e) != 0)) {
          _local_88 = ZEXT816(0);
          param_4 = (uint *)local_88;
          param_3 = 0x20;
          local_78 = _local_88;
          FUN_140001b90(puVar6,(uint *)local_88,0x20,param_4);
        }
        do {
          uVar10 = *(uint *)(local_88 + lVar8 + 4);
          uVar1 = *(uint *)(local_88 + lVar8 + 8);
          uVar2 = *(uint *)(local_88 + lVar8 + 0xc);
          *(uint *)(local_68 + lVar8) = *(uint *)(local_88 + lVar8) ^ *(uint *)(local_68 + lVar8) ;
          *(uint *)(local_68 + lVar8 + 4) = uVar10 ^ *(uint *)(local_68 + lVar8 + 4);
          *(uint *)(local_68 + lVar8 + 8) = uVar1 ^ *(uint *)(local_68 + lVar8 + 8);
          *(uint *)(local_68 + lVar8 + 0xc) = uVar2 ^ *(uint *)(local_68 + lVar8 + 0xc);
          lVar8 = lVar8 + 0x10;
        } while (lVar8 < 0x20);
        lVar8 = lVar11;
        if ((puVar6 != (uint *)0x0) && (*(short *)(puVar6 + 0x2e) != 0)) {
          _local_88 = ZEXT816(0);
          param_4 = (uint *)local_88;
          param_3 = 0x20;
          local_78 = _local_88;
          FUN_140001b90(puVar6,(uint *)local_88,0x20,param_4);
        }
        do {
          uVar10 = *(uint *)(local_88 + lVar8 + 4);
          uVar1 = *(uint *)(local_88 + lVar8 + 8);
          uVar2 = *(uint *)(local_88 + lVar8 + 0xc);
          *(uint *)(local_48 + lVar8) = *(uint *)(local_88 + lVar8) ^ *(uint *)(local_48 + lVar8) ;
          *(uint *)(local_48 + lVar8 + 4) = uVar10 ^ *(uint *)(local_48 + lVar8 + 4);
          *(uint *)(local_48 + lVar8 + 8) = uVar1 ^ *(uint *)(local_48 + lVar8 + 8);
          *(uint *)(local_48 + lVar8 + 0xc) = uVar2 ^ *(uint *)(local_48 + lVar8 + 0xc);
          lVar8 = lVar8 + 0x10;
        } while (lVar8 < 0x20);
        puVar6 = puVar6 + 0x2f;
        lVar12 = lVar12 + -1;
      } while (lVar12 != 0);
      FUN_140001010(&DAT_140004308,uVar5 & 0xffffffff,param_3,param_4);
      do {
        FUN_140001010("%02X ",(ulonglong)(byte)local_68[lVar11],param_3,param_4);
        lVar11 = lVar11 + 1;
      } while (lVar11 < 0x40);
      puts("");
      pFVar4 = fopen("c_contest_2024.jpg","rb");
      _File = fopen("c_contest_2024_out.jpg","wb");
      if ((pFVar4 != (FILE *)0x0) && (_File != (FILE *)0x0)) {
        fseek(pFVar4,0,2);
        uVar10 = ftell(pFVar4);
        uVar13 = (ulonglong)uVar10;
        fseek(pFVar4,0,0);
        if (0 < (int)uVar10) {
          do {
            fread(local_184,1,1,pFVar4);
            uVar10 = rand();
            RAND_MAX;
            uVar10 = uVar10 & 0x8000003f;
            //
            uVar10 = uVar10 % 64;
            if ((int)uVar10 < 0) {
              uVar10 = (uVar10 - 1 | 0xffffffc0) + 1;
            }
            local_184[0] = local_184[0] ^ local_68[(int)uVar10];
            fwrite(local_184,1,1,_File);
            uVar13 = uVar13 - 1;
          } while (uVar13 != 0);
        }
        fclose(pFVar4);
        fclose(_File);
      }
    }
  }
LAB_14000164d:
  FUN_140002530(local_28 ^ (ulonglong)auStack_1a8);
  return;
}

int main() {
  //FUN_1400012f0(...);
  return 0;
}