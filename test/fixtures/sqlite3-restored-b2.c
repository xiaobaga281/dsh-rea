/*
 * Function-level restoration draft, batch 2: seventeen more sqlite3.dll
 * internals (stratified sample: switch-heavy, loop+write, size tiers S/M/L).
 *
 * The bodies are reconstructed from the target's decompilation (offsets,
 * flags and call sites preserved); helper calls are declared with guessed
 * prototypes because their bodies are out of scope for this review. This is a
 * review draft, not a claim about the original sqlite3 source.
 *
 * Function provenance (target dist/corpus/sqlite3.dll, Ghidra 12.1.4 PUBLIC,
 * decompilation from the cached cap-200 inventory, sampled by
 * dist/m1-sample.mjs):
 *   FUN_1800013f2 rva=0x13f2 size=5     FUN_180002545 rva=0x2545 size=5
 *   FUN_180008510 rva=0x8510 size=243   FUN_180008640 rva=0x8640 size=211
 *   FUN_180008750 rva=0x8750 size=219   FUN_180008870 rva=0x8870 size=186
 *   FUN_1800089d0 rva=0x89d0 size=1094  FUN_180008f30 rva=0x8f30 size=246
 *   FUN_1800090e0 rva=0x90e0 size=146   FUN_1800091a0 rva=0x91a0 size=183
 *   FUN_180009290 rva=0x9290 size=736   FUN_180009e80 rva=0x9e80 size=479
 *   FUN_18000a1e0 rva=0xa1e0 size=1236  FUN_18000a8f0 rva=0xa8f0 size=255
 *   FUN_18000ab70 rva=0xab70 size=441   FUN_18000ada0 rva=0xada0 size=731
 *   FUN_18000bfd0 rva=0xbfd0 size=513
 *
 * Ghidra type spellings that are plain C are written out (uint -> unsigned
 * int, byte -> unsigned char, ulonglong -> unsigned long long); the
 * decompiler-only types keep their names via typedefs, except the generic
 * function-pointer type `code`, renamed `callback` here. Stubs are defined
 * with
 * an empty parameter list on purpose: the decompiler prints varying call
 * shapes for the same out-of-scope callee, and C11 unchecked declarations
 * accept every printed shape without inventing casts at the call sites.
 */

#include <stdbool.h>

typedef unsigned long long undefined8;
typedef unsigned int undefined4;
typedef unsigned short undefined2;
typedef unsigned char undefined1;
typedef long long longlong;
typedef long long callback();
typedef unsigned int int3;
typedef unsigned long long uint7;

/* Measured toolchain/data globals of the target (placeholder values; only the
   read/write shape is part of this review). */
longlong DAT_1802e01d0;
longlong DAT_1802e9160;
longlong DAT_1802e90e8;
longlong DAT_1802e90a0;
longlong DAT_1802e7c00;
undefined8 DAT_18029bb08;
undefined8 DAT_18029baf8;
undefined8 DAT_18029bae8;
undefined8 DAT_18029bab8;
undefined8 DAT_18029baa8;
undefined8 DAT_18029ba98;
void (*DAT_1802e0250)();
void (*DAT_1802e0260)();
void (*DAT_1802e01f8)();
longlong (*DAT_1802e0208)();
char DAT_180297714;
char DAT_1802906c4;
char DAT_18028fe24;
char DAT_1802906dc;
char DAT_180293f5c;
char DAT_180293f60;
undefined8 DAT_180289aa8;
undefined1 DAT_180289960[64];
undefined4 DAT_180289abc;
char *PTR_DAT_18028a520[8];
undefined4 MXCSR;

/* Concatenation intrinsics the decompiler prints for register pairs. */
#define CONCAT71(high, low) ((((unsigned long long)(high)) << 8) | ((unsigned long long)(low) & 0xff))
#define CONCAT31(high, low) ((((unsigned int)(high)) << 8) | ((unsigned int)(low) & 0xff))

/* Out-of-scope callees: stubbed so the review draft links. Their bodies are
   not part of this review, only the call shape is. */
undefined8 FUN_1801d4a00() { return 0; }
undefined4 FUN_18004a500() { return 0; }
unsigned int FUN_1800d16d0() { return 0; }
int FUN_1801b3ab0() { return 0; }
int FUN_1801d3dc0() { return 0; }
int FUN_1800d06f0() { return 0; }
int FUN_1800d0260() { return 0; }
int FUN_1800d7870() { return 0; }
int FUN_18017cf10() { return 0; }
int FUN_1800b8200() { return 0; }
int FUN_180164440() { return 0; }
int FUN_18009b640() { return 0; }
int FUN_1801b0d60() { return 0; }
longlong FUN_1801a0960() { return 0; }
longlong FUN_1801cf2e0() { return 0; }
undefined8 FUN_18017d560() { return 0; }
undefined8 FUN_180144d00() { return 0; }
undefined8 sqlite3_mprintf() { return 0; }
undefined8 sqlite3_errmsg() { return 0; }
undefined8 sqlite3_value_blob() { return 0; }
void FUN_1800cc830() { }
void FUN_1801a25a0() { }
void FUN_18017bdf0() { }
void FUN_1800d04e0() { }
void FUN_1800cea20() { }
void FUN_1800d4950() { }
int FUN_180142b20() { return 0; }
void FUN_180144af0() { }
void FUN_180166b60() { }
void FUN_18016d360() { }
void FUN_180161300() { }
void FUN_18005f5e0() { }
void thunk_FUN_18027dbe0() { }
void FUN_1801d6740() { }
void FUN_1800dab40() { }
void FUN_1800ecc90() { }
void FUN_180148920() { }
void FUN_1800a0a10() { }
void sqlite3_free() { }
void sqlite3_log() { }
void sqlite3_snprintf() { }
void sqlite3_str_appendf() { }
int sqlite3_initialize() { return 0; }
int sqlite3_declare_vtab() { return 0; }
int sqlite3_step() { return 0; }
int sqlite3_finalize() { return 0; }
int sqlite3_reset() { return 0; }

int main(void) { return 0; }

unsigned long long FUN_1800013f2(unsigned long long param_1)
{
  return param_1 | 0x8000000000000;
}

void FUN_180002545(undefined4 param_1)
{
  MXCSR = param_1;
  return;
}

int FUN_180008510(longlong *param_1, int param_2)
{
  unsigned short uVar1;
  longlong lVar2;
  undefined4 uVar3;
  int *piVar4;
  int iVar5;

  if (param_1 == (longlong *)0x0) {
LAB_180008574:
    piVar4 = (int *)&DAT_180289aa8;
  }
  else {
    if (*(longlong *)(*param_1 + 0x18) != 0) {
      (*DAT_1802e0250)();
    }
    if (((param_1[0x14] == 0) || ((int)(unsigned int)*(unsigned short *)(param_1 + 0x18) <= param_2)) ||
       (param_2 < 0)) {
      lVar2 = *param_1;
      *(undefined4 *)(lVar2 + 0x50) = 0x19;
      FUN_180148920(lVar2,0x19);
      goto LAB_180008574;
    }
    piVar4 = (int *)((longlong)param_2 * 0x38 + param_1[0x14]);
  }
  uVar1 = *(unsigned short *)(piVar4 + 5);
  uVar3 = 0;
  if ((uVar1 & 2) != 0) {
    if (*(char *)((longlong)piVar4 + 0x16) == '\x02') {
      iVar5 = piVar4[4];
      goto LAB_1800085c0;
    }
    if (*(char *)((longlong)piVar4 + 0x16) != '\x01') {
      iVar5 = piVar4[4];
      goto LAB_1800085c0;
    }
  }
  if ((uVar1 & 0x10) == 0) {
    if ((uVar1 & 1) == 0) {
      iVar5 = FUN_1801d3dc0(piVar4,2);
    }
    else {
      iVar5 = 0;
    }
  }
  else {
    iVar5 = piVar4[4];
    if ((uVar1 >> 10 & 1) != 0) {
      iVar5 = iVar5 + *piVar4;
    }
  }
LAB_1800085c0:
  if (param_1 != (longlong *)0x0) {
    if ((*(char *)(*param_1 + 0x67) != '\0') || (*(int *)((longlong)param_1 + 0x34) != 0)) {
      uVar3 = FUN_18004a500();
    }
    *(undefined4 *)((longlong)param_1 + 0x34) = uVar3;
    if (*(longlong *)(*param_1 + 0x18) != 0) {
      (*DAT_1802e0260)();
    }
  }
  return iVar5;
}

undefined1 FUN_180008640(longlong *param_1, int param_2)
{
  undefined1 uVar1;
  longlong lVar2;
  undefined4 uVar3;
  undefined8 *puVar4;

  if (param_1 == (longlong *)0x0) {
    return DAT_180289960[DAT_180289abc & 0x3f];
  }
  if (*(longlong *)(*param_1 + 0x18) != 0) {
    (*DAT_1802e0250)();
  }
  if (((param_1[0x14] == 0) || ((int)(unsigned int)*(unsigned short *)(param_1 + 0x18) <= param_2)) || (param_2 < 0)
     ) {
    lVar2 = *param_1;
    *(undefined4 *)(lVar2 + 0x50) = 0x19;
    FUN_180148920(lVar2,0x19);
    puVar4 = &DAT_180289aa8;
  }
  else {
    puVar4 = (undefined8 *)((longlong)param_2 * 0x38 + param_1[0x14]);
  }
  uVar1 = DAT_180289960[*(unsigned short *)((longlong)puVar4 + 0x14) & 0x3f];
  if ((*(char *)(*param_1 + 0x67) == '\0') && (*(int *)((longlong)param_1 + 0x34) == 0)) {
    uVar3 = 0;
  }
  else {
    uVar3 = FUN_18004a500();
  }
  *(undefined4 *)((longlong)param_1 + 0x34) = uVar3;
  if (*(longlong *)(*param_1 + 0x18) != 0) {
    (*DAT_1802e0260)();
  }
  return uVar1;
}

undefined4 FUN_180008750(longlong *param_1)
{
  longlong lVar1;
  int iVar2;
  undefined4 uVar3;

  if (param_1 == (longlong *)0x0) {
    return 0;
  }
  lVar1 = *param_1;
  if (lVar1 == 0) {
    sqlite3_log(0x15,"API called with finalized prepared statement");
    sqlite3_log(0x15,"%s at line %d of [%.10s]","misuse",0x16173,
                "96c92aba00c8375bc32fafcdf12429c58bd8aabfcadab6683e35bbb9cdebf19e");
    return 0x15;
  }
  if (*(longlong *)(lVar1 + 0x18) != 0) {
    (*DAT_1802e0250)();
  }
  if (0 < param_1[0x17]) {
    FUN_1800cc830(lVar1,param_1);
  }
  iVar2 = FUN_1801b3ab0(param_1);
  FUN_1801a25a0(param_1);
  if ((*(char *)(lVar1 + 0x67) == '\0') && (iVar2 == 0)) {
    uVar3 = 0;
  }
  else {
    uVar3 = FUN_18004a500(lVar1,iVar2);
  }
  FUN_18017bdf0(lVar1);
  return uVar3;
}

undefined4 FUN_180008870(longlong *param_1)
{
  longlong lVar1;
  int iVar2;
  undefined4 uVar3;

  if (param_1 == (longlong *)0x0) {
    return 0;
  }
  lVar1 = *param_1;
  if (*(longlong *)(lVar1 + 0x18) != 0) {
    (*DAT_1802e0250)();
  }
  if (0 < param_1[0x17]) {
    FUN_1800cc830(lVar1,param_1);
  }
  iVar2 = FUN_1801b3ab0(param_1);
  uVar3 = 0;
  *(undefined1 *)((longlong)param_1 + 199) = 1;
  *(undefined4 *)((longlong)param_1 + 0x34) = 0;
  param_1[7] = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  param_1[10] = 0;
  *(undefined4 *)(param_1 + 6) = 0xffffffff;
  *(undefined2 *)((longlong)param_1 + 0xc4) = 0xff02;
  *(undefined4 *)((longlong)param_1 + 0x2c) = 1;
  if ((*(char *)(lVar1 + 0x67) != '\0') || (iVar2 != 0)) {
    uVar3 = FUN_18004a500(lVar1,iVar2);
  }
  if (*(longlong *)(lVar1 + 0x18) != 0) {
    (*DAT_1802e0260)();
  }
  return uVar3;
}

undefined8 FUN_1800089d0(longlong *param_1, int param_2, undefined8 param_3, undefined8 param_4,
                         undefined8 *param_5)
{
  unsigned short uVar1;
  int *piVar2;
  int iVar3;
  unsigned int uVar4;
  longlong lVar5;
  char *pcVar6;
  undefined8 uVar7;
  undefined8 *puVar8;
  int iVar9;
  unsigned long long uVar10;
  unsigned long long uVar11;
  int local_res10[2];

  FUN_1800d04e0();
  if (param_2 == 0) {
    return 0;
  }
  uVar10 = 0;
  param_1[0x18] = 0;
  param_1[0x19] = 0;
  param_1[0x1a] = 0;
  *(undefined4 *)(param_1 + 0x1c) = 0;
  param_1[0x1d] = 0;
  param_1[0x1e] = 0;
  param_1[0x1f] = 0;
  param_1[0x20] = 0;
  param_1[0x1b] = param_1[6];
  *(undefined4 *)((longlong)param_1 + 0xe4) = 1;
  iVar3 = FUN_1800d06f0(*param_5);
  piVar2 = (int *)*param_5;
  if (iVar3 == 0) {
    uVar11 = uVar10;
    if (piVar2 != (int *)0x0) {
      if (((*(unsigned short *)(piVar2 + 5) & 0x202) == 0x202) &&
         (*(char *)((longlong)piVar2 + 0x16) == '\x01')) {
        uVar11 = *(unsigned long long *)(piVar2 + 2);
      }
      else if ((*(unsigned short *)(piVar2 + 5) & 1) == 0) {
        uVar11 = FUN_1801d4a00(piVar2,1);
      }
      else {
        uVar11 = 0;
      }
    }
    param_1[0x1a] = uVar11;
    piVar2 = (int *)*param_5;
    uVar1 = *(unsigned short *)(piVar2 + 5);
    if (((uVar1 & 2) == 0) || (*(char *)((longlong)piVar2 + 0x16) != '\x01')) {
      if ((uVar1 & 0x10) == 0) {
        if ((uVar1 & 1) == 0) {
          iVar3 = FUN_1801d3dc0(piVar2,1);
        }
        else {
          iVar3 = 0;
        }
      }
      else {
        iVar3 = piVar2[4];
        if ((uVar1 >> 10 & 1) != 0) {
          iVar3 = iVar3 + *piVar2;
        }
      }
    }
    else {
      iVar3 = piVar2[4];
    }
    *(int *)(param_1 + 0x1c) = iVar3;
    if (param_1[0x1a] == 0) {
      *(undefined8 *)((longlong)param_1 + 0xc) = 0;
      return 0;
    }
    iVar3 = FUN_1800d0260(param_1 + 0x18,0);
    if (iVar3 != 0) {
      if (*(char *)((longlong)param_1 + 0xef) != '\0') {
        return 7;
      }
      sqlite3_free(*(undefined8 *)(*param_1 + 0x10));
      uVar7 = sqlite3_mprintf("malformed JSON");
      goto LAB_180008c1f;
    }
  }
  else {
    uVar1 = *(unsigned short *)(piVar2 + 5);
    if (((uVar1 & 2) == 0) || (*(char *)((longlong)piVar2 + 0x16) != '\x01')) {
      if ((uVar1 & 0x10) == 0) {
        if ((uVar1 & 1) == 0) {
          iVar3 = FUN_1801d3dc0(piVar2,1);
        }
        else {
          iVar3 = 0;
        }
      }
      else {
        iVar3 = piVar2[4];
        if ((uVar1 >> 10 & 1) != 0) {
          iVar3 = iVar3 + *piVar2;
        }
      }
    }
    else {
      iVar3 = piVar2[4];
    }
    *(int *)(param_1 + 0x19) = iVar3;
    lVar5 = sqlite3_value_blob(*param_5);
    param_1[0x18] = lVar5;
  }
  if (param_2 == 3) {
    lVar5 = param_5[1];
    if (lVar5 == 0) {
      return 0;
    }
    if (((*(unsigned short *)(lVar5 + 0x14) & 0x202) == 0x202) && (*(char *)(lVar5 + 0x16) == '\x01')) {
      pcVar6 = *(char **)(lVar5 + 8);
    }
    else {
      if ((*(unsigned short *)(lVar5 + 0x14) & 1) != 0) {
        return 0;
      }
      pcVar6 = (char *)FUN_1801d4a00(lVar5,1);
    }
    if (pcVar6 == (char *)0x0) {
      return 0;
    }
    if (*pcVar6 != '$') {
      sqlite3_free(*(undefined8 *)(*param_1 + 0x10));
      uVar7 = sqlite3_mprintf("bad JSON path: %Q",pcVar6);
LAB_180008c1f:
      *(undefined8 *)(*param_1 + 0x10) = uVar7;
      FUN_1800d04e0(param_1);
      if (*(longlong *)(*param_1 + 0x10) != 0) {
        return 1;
      }
      return 7;
    }
    lVar5 = -1;
    do {
      lVar5 = lVar5 + 1;
    } while (pcVar6[lVar5] != '\0');
    *(unsigned int *)((longlong)param_1 + 0x14) = (unsigned int)lVar5 & 0x3fffffff;
    if (pcVar6[1] == '\0') {
      *(undefined1 *)(param_1 + 3) = 0;
      uVar4 = 0;
    }
    else {
      uVar4 = FUN_1800d16d0(param_1 + 0x18,0,pcVar6 + 1,0);
      uVar10 = (unsigned long long)uVar4;
      if (0xfffffffc < uVar4) {
        if (uVar4 == 0xfffffffe) {
          *(undefined8 *)((longlong)param_1 + 0xc) = 0;
          *(undefined1 *)(param_1 + 3) = 0;
          return 0;
        }
        sqlite3_free(*(undefined8 *)(*param_1 + 0x10));
        uVar7 = sqlite3_mprintf("bad JSON path: %Q",pcVar6);
        *(undefined8 *)(*param_1 + 0x10) = uVar7;
        FUN_1800d04e0(param_1);
        if (*(longlong *)(*param_1 + 0x10) != 0) {
          return 1;
        }
        return 7;
      }
      if (*(unsigned int *)((longlong)param_1 + 0xfc) == 0) {
        *(undefined1 *)(param_1 + 3) = 0xb;
      }
      else {
        *(undefined1 *)(param_1 + 3) = 0xc;
        uVar4 = *(unsigned int *)((longlong)param_1 + 0xfc);
      }
    }
    *(unsigned int *)((longlong)param_1 + 0xc) = uVar4;
    FUN_1800cea20(param_1 + 7,pcVar6,*(undefined4 *)((longlong)param_1 + 0x14));
    uVar11 = uVar10;
  }
  else {
    *(undefined4 *)((longlong)param_1 + 0xc) = 0;
    *(undefined4 *)((longlong)param_1 + 0x14) = 1;
    uVar11 = 0;
    *(undefined1 *)(param_1 + 3) = 0;
    if (param_1[10] + 1U < (unsigned long long)param_1[9]) {
      *(undefined1 *)(param_1[10] + param_1[8]) = 0x24;
      param_1[10] = param_1[10] + 1;
    }
    else {
      FUN_1800d4950(param_1 + 7,&DAT_180297714,1);
      uVar11 = uVar10;
    }
  }
  *(undefined4 *)((longlong)param_1 + 0x1c) = 0;
  iVar9 = (int)uVar11;
  iVar3 = FUN_1800d7870(param_1 + 0x18,uVar11,local_res10);
  *(int *)(param_1 + 2) = local_res10[0] + iVar3 + iVar9;
  if ((10 < (*(unsigned char *)(uVar11 + param_1[0x18]) & 0xf)) &&
     (*(char *)((longlong)param_1 + 0x19) == '\0')) {
    *(int *)((longlong)param_1 + 0xc) = iVar3 + iVar9;
    *(unsigned char *)(param_1 + 3) = *(unsigned char *)(uVar11 + param_1[0x18]) & 0xf;
    if (param_1[6] == 0) {
      puVar8 = (undefined8 *)FUN_18017d560(0x18);
    }
    else {
      puVar8 = (undefined8 *)FUN_180144d00(param_1[6],0x18);
    }
    if (puVar8 == (undefined8 *)0x0) {
      param_1[5] = 0;
      return 7;
    }
    *puVar8 = 0;
    puVar8[1] = 0;
    param_1[5] = (longlong)puVar8;
    *(undefined4 *)((longlong)param_1 + 0x1c) = 1;
    *(undefined4 *)(param_1 + 4) = 1;
    puVar8[2] = 0;
    *(int *)(param_1[5] + 8) = (int)param_1[2];
    *(undefined4 *)param_1[5] = *(undefined4 *)((longlong)param_1 + 0xc);
    *(int *)(param_1[5] + 4) = iVar9;
  }
  return 0;
}

undefined4 FUN_180008f30(longlong param_1, undefined8 param_2, undefined4 param_3, undefined4 param_4,
                         undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8)
{
  int iVar1;
  undefined4 uVar2;
  longlong lVar3;

  if (*(longlong *)(param_1 + 0x18) != 0) {
    (*DAT_1802e0250)();
  }
  lVar3 = FUN_1801a0960(param_1,param_2,0xffffffff,2);
  uVar2 = 0;
  iVar1 = FUN_180142b20(param_1,lVar3,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0);
  if (lVar3 != 0) {
    FUN_180144af0(param_1,lVar3);
  }
  if ((*(char *)(param_1 + 0x67) != '\0') || (iVar1 != 0)) {
    uVar2 = FUN_18004a500(param_1,iVar1);
  }
  if (*(longlong *)(param_1 + 0x18) != 0) {
    (*DAT_1802e0260)();
  }
  return uVar2;
}

undefined8 FUN_1800090e0(longlong param_1)
{
  int iVar1;

  if (param_1 != 0) {
    FUN_180166b60(*(undefined8 *)(param_1 + 0x20));
    FUN_18016d360(*(undefined8 *)(param_1 + 0x28));
    FUN_180161300(*(undefined8 *)(param_1 + 0x18));
    if (DAT_1802e01d0 == 0) {
      (*DAT_1802e01f8)(param_1);
    }
    else {
      if (DAT_1802e9160 != 0) {
        (*DAT_1802e0250)();
      }
      iVar1 = (*DAT_1802e0208)(param_1);
      DAT_1802e90e8 = DAT_1802e90e8 + -1;
      DAT_1802e90a0 = DAT_1802e90a0 - iVar1;
      (*DAT_1802e01f8)(param_1);
      if (DAT_1802e9160 != 0) {
        (*DAT_1802e0260)();
        return 0;
      }
    }
  }
  return 0;
}

int FUN_1800091a0(longlong param_1)
{
  undefined8 *puVar1;
  int iVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined8 uVar6;

  puVar1 = *(undefined8 **)(param_1 + 0x18);
  uVar4 = puVar1[2];
  uVar3 = puVar1[1];
  uVar5 = uVar3;
  uVar6 = uVar4;
  iVar2 = FUN_18009b640(*puVar1,0,
                        "DROP TABLE IF EXISTS %Q.\'%q_data\';DROP TABLE IF EXISTS %Q.\'%q_idx\';DROP TABLE IF EXISTS %Q.\'%q_config\';"
                        ,uVar3,uVar4,uVar3,uVar4,uVar3,uVar4);
  if ((iVar2 == 0) &&
     ((*(int *)(puVar1 + 0xb) == 0 ||
      (iVar2 = FUN_18009b640(*puVar1,0,"DROP TABLE IF EXISTS %Q.\'%q_docsize\';",puVar1[1],puVar1[2]
                             ,uVar3,uVar4,uVar5,uVar6), iVar2 == 0)))) {
    if (*(int *)(puVar1 + 8) != 0) goto LAB_18000923d;
    iVar2 = FUN_18009b640(*puVar1,0,"DROP TABLE IF EXISTS %Q.\'%q_content\';",puVar1[1],puVar1[2],
                          uVar3,uVar4,uVar5,uVar6);
  }
  if (iVar2 != 0) {
    return iVar2;
  }
LAB_18000923d:
  FUN_1800a0a10(param_1);
  return 0;
}

int FUN_180009290(undefined8 param_1, undefined8 *param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 *param_5, undefined8 *param_6)
{
  longlong lVar1;
  unsigned int uVar2;
  int iVar3;
  int iVar4;
  unsigned long long uVar5;
  undefined8 *puVar6;
  unsigned long long uVar7;
  unsigned long long uVar8;
  char cVar9;
  int iVar10;
  undefined8 uVar11;
  unsigned int uVar12;
  undefined1 auStack_168[32];
  undefined8 local_148;
  undefined1 *local_140;
  unsigned int local_138[2];
  unsigned int local_130;
  unsigned short local_12c;
  undefined8 *local_120;
  undefined1 local_118[208];
  unsigned long long local_48;

  local_48 = DAT_1802e7c00 ^ (unsigned long long)auStack_168;
  local_140 = local_118;
  iVar10 = 0;
  uVar7 = 0xffffffffffffffff;
  local_120 = param_5;
  local_148 = 0;
  local_138[0] = 200;
  local_130 = 0;
  local_12c = 0;
  uVar8 = 0xffffffffffffffff;
  do {
    uVar5 = uVar8 + 1;
    lVar1 = uVar8 + 1;
    uVar8 = uVar5;
  } while ("CREATE TABLE x"[lVar1] != '\0');
  uVar2 = (unsigned int)uVar5 & 0x3fffffff;
  if (uVar2 < 200) {
    if ((uVar5 & 0x3fffffff) != 0) {
      local_130 = uVar2;
      thunk_FUN_18027dbe0(local_118,"CREATE TABLE x",uVar2);
    }
  }
  else {
    FUN_18005f5e0(&local_148,"CREATE TABLE x",uVar2);
  }
  uVar2 = (unsigned int)*(unsigned char *)((longlong)param_2 + 10);
  if (*(char *)((longlong)param_2 + 0xb) != '\0') {
    uVar11 = 0x28;
    do {
      sqlite3_str_appendf(&local_148,"%c\"%s\"",uVar11,(&PTR_DAT_18028a520)[(int)uVar2]);
      iVar10 = iVar10 + 1;
      uVar2 = uVar2 + 1;
      uVar11 = 0x2c;
    } while (iVar10 < (int)(unsigned int)*(unsigned char *)((longlong)param_2 + 0xb));
    param_5 = local_120;
    if (iVar10 != 0) goto LAB_1800093ac;
  }
  sqlite3_str_appendf(&local_148,"(\"%s\"",*param_2);
  iVar10 = 1;
LAB_1800093ac:
  cVar9 = '\0';
  if ((*(unsigned char *)((longlong)param_2 + 9) & 0x20) != 0) {
    uVar8 = 0xffffffffffffffff;
    do {
      uVar5 = uVar8 + 1;
      lVar1 = uVar8 + 1;
      uVar8 = uVar5;
    } while (",arg HIDDEN"[lVar1] != '\0');
    uVar2 = (unsigned int)uVar5 & 0x3fffffff;
    uVar12 = local_130 + uVar2;
    if (uVar12 < (unsigned int)local_138[0]) {
      if ((uVar5 & 0x3fffffff) != 0) {
        local_130 = uVar12;
        thunk_FUN_18027dbe0(local_140 + (uVar12 - uVar2),",arg HIDDEN",uVar2);
      }
    }
    else {
      FUN_18005f5e0(&local_148,",arg HIDDEN",uVar2);
    }
    cVar9 = '\x01';
  }
  if ((*(unsigned char *)((longlong)param_2 + 9) & 0xc0) != 0) {
    do {
      uVar8 = uVar7 + 1;
      lVar1 = uVar7 + 1;
      uVar7 = uVar8;
    } while (",schema HIDDEN"[lVar1] != '\0');
    uVar12 = (unsigned int)uVar8 & 0x3fffffff;
    uVar2 = local_130 + uVar12;
    if (uVar2 < (unsigned int)local_138[0]) {
      if ((uVar8 & 0x3fffffff) != 0) {
        local_130 = uVar2;
        thunk_FUN_18027dbe0(local_140 + (uVar2 - uVar12),",schema HIDDEN",uVar12);
      }
    }
    else {
      FUN_18005f5e0(&local_148,",schema HIDDEN",uVar12);
    }
    cVar9 = cVar9 + '\x01';
  }
  if (local_130 + 1 < (unsigned int)local_138[0]) {
    local_140[local_130] = 0x29;
    local_130 = local_130 + 1;
  }
  else {
    FUN_18005f5e0(&local_148,&DAT_1802906c4,1);
  }
  if (local_140 != (undefined1 *)0x0) {
    local_140[local_130] = 0;
    if ((local_138[1] != 0) && ((local_12c & 0x400) == 0)) {
      FUN_1801cf2e0(&local_148);
    }
  }
  iVar3 = sqlite3_declare_vtab(param_1,local_118);
  if (iVar3 == 0) {
    iVar4 = sqlite3_initialize();
    if (iVar4 != 0) {
      *param_5 = 0;
      return 7;
    }
    puVar6 = (undefined8 *)FUN_18017d560();
    if (puVar6 == (undefined8 *)0x0) {
      *param_5 = 0;
      return 7;
    }
    *puVar6 = 0;
    puVar6[1] = 0;
    puVar6[2] = 0;
    *(undefined4 *)((longlong)puVar6 + 0x2a) = 0;
    *(undefined2 *)((longlong)puVar6 + 0x2e) = 0;
    puVar6[4] = (longlong)param_2;
    puVar6[3] = param_1;
    *(char *)((longlong)puVar6 + 0x29) = (char)iVar10;
    *(char *)(puVar6 + 5) = cVar9;
  }
  else {
    uVar11 = sqlite3_errmsg(param_1);
    uVar11 = sqlite3_mprintf(&DAT_18028fe24,uVar11);
    *param_6 = uVar11;
    puVar6 = (undefined8 *)0x0;
  }
  *param_5 = (longlong)puVar6;
  return iVar3;
}

undefined8 *FUN_180009e80(undefined4 *param_1)
{
  unsigned short uVar1;
  longlong lVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  int iVar6;
  undefined8 *puVar7;

  if (param_1 != (undefined4 *)0x0) {
    iVar6 = sqlite3_initialize();
    if (iVar6 == 0) {
      puVar7 = (undefined8 *)FUN_18017d560(0x38);
      if (puVar7 != (undefined8 *)0x0) {
        *puVar7 = 0;
        puVar7[1] = 0;
        puVar7[2] = 0;
        puVar7[3] = 0;
        puVar7[4] = 0;
        puVar7[5] = 0;
        puVar7[6] = 0;
        uVar3 = param_1[1];
        uVar4 = param_1[2];
        uVar5 = param_1[3];
        *(undefined4 *)puVar7 = *param_1;
        *(undefined4 *)((longlong)puVar7 + 4) = uVar3;
        *(undefined4 *)(puVar7 + 1) = uVar4;
        *(undefined4 *)((longlong)puVar7 + 0xc) = uVar5;
        puVar7[2] = *(undefined8 *)(param_1 + 4);
        uVar1 = *(unsigned short *)((longlong)puVar7 + 0x14);
        puVar7[3] = 0;
        *(unsigned short *)((longlong)puVar7 + 0x14) = uVar1 & 0xefff;
        if ((uVar1 & 0x12) == 0) {
          if ((uVar1 & 1) != 0) {
            *(unsigned short *)((longlong)puVar7 + 0x14) = uVar1 & 0xe5ff;
          }
        }
        else {
          *(unsigned short *)((longlong)puVar7 + 0x14) = uVar1 & 0xcfff | 0x4000;
          iVar6 = FUN_1801b0d60(puVar7);
          if (iVar6 != 0) {
            if (((*(unsigned short *)((longlong)puVar7 + 0x14) & 0x9000) != 0) ||
               (*(int *)(puVar7 + 4) != 0)) {
              FUN_1801d6740(puVar7);
            }
            lVar2 = puVar7[3];
            if (lVar2 != 0) {
              if (puVar7 < *(undefined8 **)(lVar2 + 0x208)) {
                if (*(undefined8 **)(lVar2 + 0x1f8) <= puVar7) {
                  *puVar7 = *(undefined8 *)(lVar2 + 0x1f0);
                  *(undefined8 **)(lVar2 + 0x1f0) = puVar7;
                  return (undefined8 *)0x0;
                }
                if (*(undefined8 **)(lVar2 + 0x200) <= puVar7) {
                  *puVar7 = *(undefined8 *)(lVar2 + 0x1e0);
                  *(undefined8 **)(lVar2 + 0x1e0) = puVar7;
                  return (undefined8 *)0x0;
                }
              }
              if (*(longlong *)(lVar2 + 800) != 0) {
                FUN_1800dab40(lVar2,puVar7);
                return (undefined8 *)0x0;
              }
            }
            if (DAT_1802e01d0 == 0) {
              (*DAT_1802e01f8)(puVar7);
            }
            else {
              if (DAT_1802e9160 != 0) {
                (*DAT_1802e0250)();
              }
              iVar6 = (*DAT_1802e0208)(puVar7);
              DAT_1802e90e8 = DAT_1802e90e8 + -1;
              DAT_1802e90a0 = DAT_1802e90a0 - iVar6;
              (*DAT_1802e01f8)(puVar7);
              if (DAT_1802e9160 != 0) {
                (*DAT_1802e0260)();
                return (undefined8 *)0x0;
              }
            }
            return (undefined8 *)0x0;
          }
        }
        return puVar7;
      }
    }
  }
  return (undefined8 *)0x0;
}

undefined8 FUN_18000a1e0(longlong param_1, int *param_2)
{
  char cVar1;
  int iVar2;
  longlong lVar3;
  int *piVar4;
  bool bVar5;
  bool bVar6;
  bool bVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  undefined8 uVar10;
  undefined8 uVar11;
  undefined8 uVar12;
  undefined1 uVar13;
  int iVar14;
  undefined8 uVar15;
  longlong lVar16;
  longlong lVar17;
  int iVar18;
  undefined1 *puVar19;
  unsigned long long uVar20;
  longlong lVar21;
  unsigned long long uVar22;
  int iVar23;
  unsigned int uVar24;
  unsigned long long uVar25;
  unsigned long long uVar26;
  unsigned long long uVar27;
  unsigned long long uVar28;
  unsigned long long uVar29;
  unsigned int local_res18;
  int local_58;
  int local_50;

  uVar20 = 0;
  lVar3 = *(longlong *)(param_1 + 0x18);
  bVar5 = false;
  local_58 = 0;
  iVar2 = *(int *)(lVar3 + 0x18);
  local_50 = 0;
  bVar7 = false;
  bVar6 = false;
  if (*(int *)(lVar3 + 0x80) != 0) {
    uVar15 = sqlite3_mprintf("recursively defined fts5 content table");
    *(undefined8 *)(param_1 + 0x10) = uVar15;
    return 1;
  }
  iVar18 = *param_2 * 8 + 1;
  iVar14 = sqlite3_initialize();
  if (((iVar14 != 0) || (iVar18 < 1)) || (lVar16 = FUN_18017d560((longlong)iVar18), lVar16 == 0)) {
    return 7;
  }
  iVar18 = *param_2;
  local_res18 = 0;
  *(longlong *)(param_2 + 0xc) = lVar16;
  param_2[0xe] = 1;
  uVar22 = uVar20;
  uVar25 = uVar20;
  uVar26 = uVar20;
  uVar27 = uVar20;
  uVar28 = uVar20;
  if (iVar18 < 1) {
LAB_18000a4a3:
    iVar14 = (int)uVar22;
    uVar20 = 0;
    if (0 < iVar18) {
      puVar19 = (undefined1 *)(iVar14 + lVar16);
      uVar26 = uVar20;
      uVar27 = uVar20;
      uVar28 = uVar20;
      uVar29 = uVar20;
      do {
        lVar17 = *(longlong *)(param_2 + 2);
        if ((*(int *)(uVar20 + lVar17) < 0) && (*(char *)(uVar20 + 5 + lVar17) != '\0')) {
          cVar1 = *(char *)(uVar20 + 4 + lVar17);
          if ((cVar1 - 8U & 0xf7) == 0) {
            if ((int)uVar28 == 0) {
              *puVar19 = 0x3c;
              uVar28 = 1;
              goto LAB_18000a526;
            }
          }
          else if (((cVar1 == '\x04') || (cVar1 == ' ')) && ((int)uVar29 == 0)) {
            *puVar19 = 0x3e;
            uVar29 = 1;
LAB_18000a526:
            uVar22 = (unsigned long long)((int)uVar22 + 1);
            puVar19 = puVar19 + 1;
            uVar24 = (int)uVar25 + 1;
            uVar25 = (unsigned long long)uVar24;
            *(unsigned int *)(uVar26 + *(longlong *)(param_2 + 8)) = uVar24;
          }
        }
        iVar14 = (int)uVar22;
        uVar24 = (int)uVar27 + 1;
        uVar27 = (unsigned long long)uVar24;
        uVar20 = uVar20 + 0xc;
        uVar26 = uVar26 + 8;
      } while ((int)uVar24 < *param_2);
      local_50 = (int)uVar28;
      local_58 = (int)uVar29;
    }
  }
  else {
    do {
      uVar24 = (unsigned int)uVar20;
      lVar17 = *(longlong *)(param_2 + 2);
      cVar1 = *(char *)(uVar26 + 4 + lVar17);
      iVar18 = *(int *)(uVar26 + lVar17);
      iVar14 = (int)uVar22;
      iVar23 = (int)uVar25;
      if ((cVar1 == '@') || ((cVar1 == '\x02' && (iVar2 <= iVar18)))) {
        if ((*(char *)(uVar26 + 5 + lVar17) == '\0') || (iVar18 < 0)) {
          param_2[0x10] = -0x3a819b66;
          param_2[0x11] = 0x4a511b0e;
          *(undefined1 *)(iVar14 + lVar16) = 0;
          return 0;
        }
        if (iVar18 == iVar2 + 1) {
          if (bVar6) goto LAB_18000a476;
          *(undefined1 *)(uVar28 + lVar16) = 0x72;
          bVar6 = true;
        }
        else {
          bVar7 = true;
          lVar21 = (iVar14 + 1) + lVar16;
          *(undefined1 *)(uVar28 + lVar16) = 0x4d;
          sqlite3_snprintf(6,lVar21,&DAT_1802906dc);
          lVar17 = -1;
          do {
            lVar17 = lVar17 + 1;
          } while (*(char *)(lVar17 + lVar21) != '\0');
          lVar16 = lVar16 + lVar17;
          uVar24 = local_res18;
        }
        uVar22 = (unsigned long long)(iVar14 + 1);
        uVar25 = (unsigned long long)(iVar23 + 1U);
        uVar28 = uVar28 + 1;
        *(unsigned int *)(*(longlong *)(param_2 + 8) + uVar27) = iVar23 + 1U;
        *(undefined1 *)(*(longlong *)(param_2 + 8) + 4 + uVar27) = 1;
      }
      else if (*(char *)(uVar26 + 5 + lVar17) != '\0') {
        if ((-1 < iVar18) && (iVar18 < iVar2)) {
          if (*(int *)(lVar3 + 0x84) == 0x42) {
            uVar24 = local_res18;
            if (cVar1 == 'B') {
LAB_18000a377:
              uVar13 = 0x47;
              if (*(char *)(uVar26 + 4 + lVar17) == 'A') {
                uVar13 = 0x4c;
              }
              uVar22 = (unsigned long long)(iVar14 + 1U);
              *(undefined1 *)(uVar28 + lVar16) = uVar13;
              uVar28 = uVar28 + 1;
              lVar21 = (int)(iVar14 + 1U) + lVar16;
              sqlite3_snprintf(6,lVar21,&DAT_1802906dc);
              lVar17 = -1;
              do {
                lVar17 = lVar17 + 1;
              } while (*(char *)(lVar17 + lVar21) != '\0');
              lVar16 = lVar16 + lVar17;
              uVar25 = (unsigned long long)(iVar23 + 1U);
              *(unsigned int *)(*(longlong *)(param_2 + 8) + uVar27) = iVar23 + 1U;
              uVar24 = local_res18;
              goto LAB_18000a476;
            }
          }
          else {
            uVar24 = local_res18;
            if ((*(int *)(lVar3 + 0x84) == 0x41) && ((unsigned char)(cVar1 + 0xbfU) < 2)) goto LAB_18000a377;
          }
        }
        if (((!bVar5) && (*(char *)(uVar26 + 4 + lVar17) == '\x02')) && (iVar18 < 0)) {
          *(undefined1 *)(uVar28 + lVar16) = 0x3d;
          uVar22 = (unsigned long long)(iVar14 + 1);
          uVar28 = uVar28 + 1;
          uVar25 = (unsigned long long)(iVar23 + 1U);
          bVar5 = true;
          *(unsigned int *)(*(longlong *)(param_2 + 8) + uVar27) = iVar23 + 1U;
        }
      }
LAB_18000a476:
      iVar14 = (int)uVar22;
      iVar18 = *param_2;
      local_res18 = uVar24 + 1;
      uVar20 = (unsigned long long)local_res18;
      uVar26 = uVar26 + 0xc;
      uVar27 = uVar27 + 8;
    } while ((int)local_res18 < iVar18);
    if (!bVar5) goto LAB_18000a4a3;
  }
  *(undefined1 *)(iVar14 + lVar16) = 0;
  if (param_2[4] == 1) {
    piVar4 = *(int **)(param_2 + 6);
    if ((*piVar4 == *(int *)(lVar3 + 0x18) + 1) && (bVar7)) {
      uVar24 = 0x20;
    }
    else {
      if ((*piVar4 != -1) || (((char)piVar4[1] != '\0' && (*(int *)(lVar3 + 0x5c) != 0))))
      goto LAB_18000a5bc;
      uVar24 = 0x40;
    }
    param_2[0xf] = 1;
    if ((char)piVar4[1] != '\0') {
      uVar24 = uVar24 | 0x80;
    }
  }
  else {
LAB_18000a5bc:
    uVar24 = 0;
  }
  uVar12 = DAT_18029bb08;
  uVar11 = DAT_18029baf8;
  uVar10 = DAT_18029bae8;
  uVar9 = DAT_18029bab8;
  uVar8 = DAT_18029baa8;
  uVar15 = DAT_18029ba98;
  if (bVar5) {
    if (bVar7) {
      param_2[10] = uVar24;
      param_2[0x10] = 0;
      param_2[0x11] = 0x40590000;
    }
    else {
      param_2[0x14] = param_2[0x14] | 1;
      param_2[10] = uVar24;
      param_2[0x10] = 0;
      param_2[0x11] = 0x40240000;
    }
  }
  else {
    if (local_50 == 0) {
      if (local_58 == 0) {
        if (bVar7) {
          param_2[10] = uVar24;
          *(undefined8 *)(param_2 + 0x10) = uVar9;
          return 0;
        }
        param_2[10] = uVar24;
        *(undefined8 *)(param_2 + 0x10) = uVar12;
        return 0;
      }
    }
    else if (local_58 != 0) {
      if (bVar7) {
        param_2[10] = uVar24;
        *(undefined8 *)(param_2 + 0x10) = uVar15;
        return 0;
      }
      param_2[10] = uVar24;
      *(undefined8 *)(param_2 + 0x10) = uVar10;
      return 0;
    }
    if (bVar7) {
      param_2[10] = uVar24;
      *(undefined8 *)(param_2 + 0x10) = uVar8;
    }
    else {
      param_2[10] = uVar24;
      *(undefined8 *)(param_2 + 0x10) = uVar11;
    }
  }
  return 0;
}

void FUN_18000a8f0(longlong param_1, int param_2, undefined8 param_3, callback *param_4)
{
  longlong *plVar1;
  int *piVar2;

  plVar1 = *(longlong **)(param_1 + 0x18);
  piVar2 = (int *)plVar1[0x25];
  do {
    if (piVar2 == (int *)0x0) {
      if (*plVar1 == 0) {
        piVar2 = (int *)FUN_18017d560(0x20);
      }
      else {
        piVar2 = (int *)FUN_180144d00(*plVar1,0x20);
      }
      if (piVar2 == (int *)0x0) {
        if (param_4 != (callback *)0x0) {
          (*param_4)(param_3);
        }
      }
      else {
        piVar2[0] = 0;
        piVar2[1] = 0;
        piVar2[2] = 0;
        piVar2[3] = 0;
        piVar2[4] = 0;
        piVar2[5] = 0;
        piVar2[6] = 0;
        piVar2[7] = 0;
        *piVar2 = *(int *)(param_1 + 0x20);
        piVar2[1] = param_2;
        *(longlong *)(piVar2 + 6) = plVar1[0x25];
        plVar1[0x25] = (longlong)piVar2;
        if (*(int *)(param_1 + 0x24) == 0) {
          *(undefined4 *)(param_1 + 0x24) = 0xffffffff;
        }
LAB_18000a9bc:
        *(undefined8 *)(piVar2 + 2) = param_3;
        *(callback **)(piVar2 + 4) = param_4;
      }
      return;
    }
    if ((piVar2[1] == param_2) && ((*piVar2 == *(int *)(param_1 + 0x20) || (param_2 < 0)))) {
      if (*(callback **)(piVar2 + 4) != (callback *)0x0) {
        (**(callback **)(piVar2 + 4))(*(undefined8 *)(piVar2 + 2));
        *(undefined8 *)(piVar2 + 2) = param_3;
        *(callback **)(piVar2 + 4) = param_4;
        return;
      }
      goto LAB_18000a9bc;
    }
    piVar2 = *(int **)(piVar2 + 6);
  } while( true );
}

undefined8 FUN_18000ab70(longlong param_1, longlong param_2, longlong param_3, callback *param_4)
{
  char cVar1;
  char cVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  int iVar5;
  char *pcVar6;
  undefined8 *puVar7;
  longlong lVar8;
  longlong lVar9;

  if (*(longlong *)(param_1 + 0x18) != 0) {
    (*DAT_1802e0250)();
  }
  puVar4 = *(undefined8 **)(param_1 + 0x328);
  puVar3 = (undefined8 *)(param_1 + 0x328);
  do {
    puVar7 = puVar4;
    if (puVar7 == (undefined8 *)0x0) {
      if (param_3 != 0) {
        lVar9 = -1;
        do {
          lVar8 = lVar9;
          lVar9 = lVar8 + 1;
        } while (*(char *)(param_2 + 1 + lVar8) != '\0');
        iVar5 = sqlite3_initialize();
        if ((iVar5 != 0) ||
           (puVar7 = (undefined8 *)FUN_18017d560(lVar8 + 0x22), puVar7 == (undefined8 *)0x0)) {
          if (param_4 != (callback *)0x0) {
            (*param_4)(param_3);
          }
          if (*(longlong *)(param_1 + 0x18) != 0) {
            (*DAT_1802e0260)();
          }
          return 7;
        }
        thunk_FUN_18027dbe0(puVar7 + 3,param_2,lVar8 + 2);
        *puVar7 = *(undefined8 *)(param_1 + 0x328);
        *(undefined8 **)(param_1 + 0x328) = puVar7;
LAB_18000ac50:
        puVar7[1] = param_3;
        puVar7[2] = (longlong)param_4;
      }
LAB_18000ac58:
      if (*(longlong *)(param_1 + 0x18) != 0) {
        (*DAT_1802e0260)();
      }
      return 0;
    }
    pcVar6 = (char *)(puVar7 + 3);
    lVar9 = param_2 - (longlong)pcVar6;
    do {
      cVar1 = *pcVar6;
      cVar2 = pcVar6[lVar9];
      if (cVar1 != cVar2) break;
      pcVar6 = pcVar6 + 1;
    } while (cVar2 != '\0');
    if (cVar1 == cVar2) {
      if ((callback *)puVar7[2] != (callback *)0x0) {
        (*(callback *)puVar7[2])(puVar7[1]);
      }
      if (param_3 != 0) goto LAB_18000ac50;
      *puVar3 = *puVar7;
      if (DAT_1802e01d0 == 0) {
        (*DAT_1802e01f8)(puVar7);
      }
      else {
        if (DAT_1802e9160 != 0) {
          (*DAT_1802e0250)();
        }
        iVar5 = (*DAT_1802e0208)(puVar7);
        DAT_1802e90e8 = DAT_1802e90e8 + -1;
        DAT_1802e90a0 = DAT_1802e90a0 - iVar5;
        (*DAT_1802e01f8)(puVar7);
        if (DAT_1802e9160 != 0) {
          (*DAT_1802e0260)();
        }
      }
      goto LAB_18000ac58;
    }
    puVar4 = (undefined8 *)*puVar7;
    puVar3 = puVar7;
  } while( true );
}

int FUN_18000ada0(longlong *param_1, undefined8 param_2, undefined8 param_3, int param_4,
                  longlong param_5)
{
  unsigned short uVar1;
  longlong lVar2;
  int iVar3;
  int iVar4;
  longlong lVar5;
  undefined8 uVar6;
  unsigned int uVar7;
  longlong lVar8;
  longlong *plVar9;
  longlong lVar10;
  unsigned int uVar11;
  undefined8 local_48;
  longlong local_40;
  unsigned int local_38;
  int local_34;
  unsigned int local_30;
  unsigned short local_2c;

  lVar2 = *param_1;
  FUN_1800ecc90();
  lVar8 = 0;
  uVar7 = 0;
  if (0 < param_4) {
    plVar9 = param_1 + (unsigned long long)(~(unsigned int)(*(unsigned char *)(*(longlong *)(lVar2 + 0x20) + 9) >> 5) & 1) + 3;
    do {
      lVar5 = *(longlong *)(param_5 + lVar8 * 8);
      if (lVar5 != 0) {
        uVar1 = *(unsigned short *)(lVar5 + 0x14);
        if (((uVar1 & 0x202) == 0x202) && (*(char *)(lVar5 + 0x16) == '\x01')) {
          lVar5 = *(longlong *)(lVar5 + 8);
        }
        else {
          if ((uVar1 & 1) != 0) goto LAB_18000ae52;
          lVar5 = FUN_1801d4a00(lVar5,CONCAT71((uint7)(unsigned char)(uVar1 >> 8),1));
        }
        if (lVar5 != 0) {
          lVar5 = sqlite3_mprintf(&DAT_18028fe24,lVar5);
          *plVar9 = lVar5;
          if (lVar5 == 0) {
            return 7;
          }
        }
      }
LAB_18000ae52:
      lVar8 = lVar8 + 1;
      plVar9 = plVar9 + 1;
    } while (lVar8 < param_4);
  }
  local_34 = *(int *)(*(longlong *)(lVar2 + 0x18) + 0x8c);
  local_40 = 0;
  local_48 = 0;
  local_38 = 0;
  local_30 = 0;
  local_2c = 0;
  lVar8 = -1;
  do {
    lVar10 = lVar8 + 1;
    lVar5 = lVar8 + 1;
    lVar8 = lVar10;
  } while ("PRAGMA "[lVar5] != '\0');
  FUN_18005f5e0(&local_48,"PRAGMA ",(unsigned int)lVar10 & 0x3fffffff);
  if (param_1[4] != 0) {
    sqlite3_str_appendf(&local_48,&DAT_180293f5c);
  }
  lVar8 = **(longlong **)(lVar2 + 0x20);
  if (lVar8 != 0) {
    lVar5 = -1;
    do {
      lVar5 = lVar5 + 1;
    } while (*(char *)(lVar8 + lVar5) != '\0');
    uVar7 = (unsigned int)lVar5 & 0x3fffffff;
  }
  uVar11 = local_30 + uVar7;
  if (uVar11 < local_38) {
    if (uVar7 != 0) {
      local_30 = uVar11;
      thunk_FUN_18027dbe0((unsigned long long)(uVar11 - uVar7) + local_40,lVar8,uVar7);
    }
  }
  else {
    FUN_18005f5e0(&local_48,lVar8,uVar7);
  }
  if (param_1[3] != 0) {
    sqlite3_str_appendf(&local_48,&DAT_180293f60);
  }
  if (local_40 != 0) {
    *(undefined1 *)((unsigned long long)local_30 + local_40) = 0;
    lVar8 = local_40;
    if ((local_34 != 0) && ((local_2c & 0x400) == 0)) {
      lVar8 = FUN_1801cf2e0(&local_48);
    }
    if (lVar8 != 0) {
      plVar9 = param_1 + 1;
      iVar3 = FUN_18017cf10(*(undefined8 *)(lVar2 + 0x18),lVar8,0xffffffff,0x80,0,plVar9,0);
      if (DAT_1802e01d0 == 0) {
        (*DAT_1802e01f8)(lVar8);
      }
      else {
        if (DAT_1802e9160 != 0) {
          (*DAT_1802e0250)();
        }
        iVar4 = (*DAT_1802e0208)(lVar8);
        DAT_1802e90e8 = DAT_1802e90e8 + -1;
        DAT_1802e90a0 = DAT_1802e90a0 - iVar4;
        (*DAT_1802e01f8)(lVar8);
        if (DAT_1802e9160 != 0) {
          (*DAT_1802e0260)();
        }
      }
      if (iVar3 == 0) {
        param_1[2] = param_1[2] + 1;
        iVar3 = sqlite3_step(*plVar9);
        if (iVar3 != 100) {
          iVar3 = sqlite3_finalize(*plVar9);
          *plVar9 = 0;
          FUN_1800ecc90(param_1);
          return iVar3;
        }
        return 0;
      }
      uVar6 = sqlite3_errmsg(*(undefined8 *)(lVar2 + 0x18));
      uVar6 = sqlite3_mprintf(&DAT_18028fe24,uVar6);
      *(undefined8 *)(lVar2 + 0x10) = uVar6;
      return iVar3;
    }
  }
  return 7;
}

int FUN_18000bfd0(longlong *param_1)
{
  longlong lVar1;
  longlong lVar2;
  longlong lVar3;
  undefined8 *puVar4;
  bool bVar5;
  int iVar6;
  longlong lVar7;
  undefined8 uVar8;
  unsigned long long uVar9;
  unsigned int uVar10;
  unsigned long long uVar11;

  uVar9 = 0;
  bVar5 = false;
  if ((((int)param_1[4] == 1) && (*(int *)(*(longlong *)(*param_1 + 0x18) + 0x5c) != 0)) &&
     (lVar1 = param_1[8], uVar11 = uVar9, 0 < *(int *)(lVar1 + 0x1c))) {
    do {
      for (lVar7 = *(longlong *)(uVar11 + *(longlong *)(lVar1 + 0x20)) + 0x20; lVar7 != 0;
          lVar7 = *(longlong *)(lVar7 + 0x20)) {
        if ((*(longlong *)(lVar7 + 0x18) != 0) &&
           (lVar2 = *(longlong *)(*(longlong *)(lVar7 + 0x18) + 0x18), lVar2 != 0)) {
          *(undefined4 *)(lVar2 + 8) = 0;
        }
      }
      uVar10 = (int)uVar9 + 1;
      uVar9 = (unsigned long long)uVar10;
      uVar11 = uVar11 + 8;
    } while ((int)uVar10 < *(int *)(lVar1 + 0x1c));
  }
  iVar6 = (int)param_1[4];
  if (2 < iVar6) {
    if (iVar6 == 3) {
      *(unsigned int *)(param_1 + 10) = *(unsigned int *)(param_1 + 10) | 1;
    }
    else {
      if (iVar6 == 4) {
        iVar6 = FUN_1800b8200(param_1);
        return iVar6;
      }
      puVar4 = *(undefined8 **)(*param_1 + 0x18);
      *(int *)(puVar4 + 0x10) = *(int *)(puVar4 + 0x10) + 1;
      iVar6 = sqlite3_step(param_1[7]);
      *(int *)(puVar4 + 0x10) = *(int *)(puVar4 + 0x10) + -1;
      if (iVar6 != 100) {
        *(unsigned int *)(param_1 + 10) = *(unsigned int *)(param_1 + 10) | 1;
        iVar6 = sqlite3_reset(param_1[7]);
        if (iVar6 == 0) {
          return 0;
        }
        uVar8 = sqlite3_errmsg(*puVar4);
        uVar8 = sqlite3_mprintf(&DAT_18028fe24,uVar8);
        *(undefined8 *)(*param_1 + 0x10) = uVar8;
        return iVar6;
      }
    }
    return 0;
  }
  if ((*(unsigned char *)(param_1 + 10) & 0x20) != 0) {
    lVar1 = *(longlong *)(*(longlong *)(param_1[8] + 0x10) + 0x18);
    iVar6 = FUN_180164440(param_1[8],*(undefined8 *)(*param_1 + 0x20),lVar1,
                          *(undefined4 *)((longlong)param_1 + 0x24));
    if ((iVar6 == 0) &&
       (bVar5 = false, lVar1 != *(longlong *)(*(longlong *)(param_1[8] + 0x10) + 0x18))) {
      bVar5 = true;
    }
    uVar10 = *(unsigned int *)(param_1 + 10);
    *(unsigned int *)(param_1 + 10) = uVar10 & 0xffffffdf | 0x4e;
    if (*(int *)(*(longlong *)(param_1[8] + 0x10) + 4) != 0) {
      bVar5 = true;
      *(unsigned int *)(param_1 + 10) = uVar10 & 0xffffffdf | 0x4f;
    }
    if (iVar6 != 0) {
      return iVar6;
    }
    if (bVar5) {
      return 0;
    }
  }
  lVar1 = param_1[8];
  lVar7 = param_1[6];
  lVar2 = *(longlong *)(lVar1 + 0x10);
  do {
    iVar6 = (**(callback **)(lVar2 + 0x10))(lVar1,lVar2,0,0);
  } while (*(int *)(lVar2 + 8) != 0);
  lVar3 = *(longlong *)(lVar2 + 0x18);
  if (*(int *)(lVar1 + 0x18) == 0) {
    if (lVar3 < lVar7) goto LAB_18000c12a;
    bVar5 = lVar7 < lVar3;
  }
  else {
    if (lVar7 < lVar3) goto LAB_18000c12a;
    bVar5 = lVar3 < lVar7;
  }
  if (bVar5) {
    *(undefined4 *)(lVar2 + 4) = 1;
  }
LAB_18000c12a:
  *(unsigned int *)(param_1 + 10) =
       *(unsigned int *)(param_1 + 10) | *(unsigned int *)(*(longlong *)(param_1[8] + 0x10) + 4) | 0x4e;
  return iVar6;
}
