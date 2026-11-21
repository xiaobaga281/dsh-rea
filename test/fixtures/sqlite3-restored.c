/*
 * Function-level restoration draft for nine sqlite3.dll internals.
 *
 * The bodies are reconstructed from the target's decompilation (offsets,
 * flags and call sites preserved); helper calls are declared with guessed
 * prototypes because their bodies are out of scope for this review. This is a
 * review draft, not a claim about the original sqlite3 source.
 *
 * Function provenance (target dist/corpus/sqlite3.dll, Ghidra 12.1.4 PUBLIC,
 * decompilation printed by scripts/recon-restore.mjs from the cached inventory):
 *   FUN_1800096b0 rva=0x96b0 size=8    FUN_1800096c0 rva=0x96c0 size=23
 *   FUN_1800096e0 rva=0x96e0 size=75   FUN_180009070 rva=0x9070 size=87
 *   FUN_180009740 rva=0x9740 size=3    FUN_1800097f0 rva=0x97f0 size=38
 *   FUN_180009750 rva=0x9750 size=118  FUN_180009820 rva=0x9820 size=89
 *   FUN_1800099a0 rva=0x99a0 size=79
 */

#include <math.h>

typedef unsigned long long undefined8;
typedef unsigned int undefined4;
typedef unsigned short undefined2;
typedef unsigned char undefined1;
typedef long long longlong;

long long unresolved_helper(void);
void convert_helper(double, double *, unsigned int, unsigned char);
void small_helper(void);
undefined8 FUN_1801d4a00(longlong, undefined4);
int FUN_1801b0690(longlong);
void FUN_1801352e0(double, double *, undefined4, undefined1);

/* Out-of-scope callees: stubbed so the review draft links. Their bodies are not
   part of this review, only the call shape is. */
long long unresolved_helper(void) { return 0; }
void convert_helper(double a, double *b, unsigned int c, unsigned char d)
{
  (void)a; (void)b; (void)c; (void)d;
}
void small_helper(void) { }
undefined8 FUN_1801d4a00(longlong a, undefined4 b) { (void)a; (void)b; return 0; }
int FUN_1801b0690(longlong a) { (void)a; return 0; }
void FUN_1801352e0(double a, double *b, undefined4 c, undefined1 d)
{
  (void)a; (void)b; (void)c; (void)d;
}

/* Doubles the decompiler reads from the target's constant pool; values are
   placeholders, only the read shape is part of this review. */
double DAT_18029bd28 = 0.0;
double DAT_18029bbf8 = 0.0;

int main(void) { return 0; }

undefined8 FUN_1800096c0(longlong param_1)
{
  if ((param_1 != 0) && ((*(unsigned char *)(param_1 + 200) & 3) == 0)) {
    return 0;
  }
  return 1;
}

void FUN_180009740(void)
{
  return;
}

undefined4 FUN_1800096b0(longlong param_1)
{
  return *(unsigned int *)(*(long long *)(param_1 + 0x10) + 0x10);
}

void FUN_180009070(void)
{
  small_helper();
  return;
}

undefined8 FUN_1800096e0(longlong param_1, longlong param_2)
{
  undefined8 uVar1;

  if (*(short *)(param_1 + 0x20) != *(short *)(param_2 + 0x20)) {
    return 1;
  }
  if (*(int *)(param_2 + 0x11c) != 0) {
    *(unsigned int *)(param_2 + 200) = (*(unsigned int *)(param_2 + 200) & 0xfffffffd) | 1;
  }
  if (*(int *)(param_1 + 0x11c) != 0) {
    *(unsigned int *)(param_1 + 200) = (*(unsigned int *)(param_1 + 200) & 0xfffffffd) | 1;
  }
  uVar1 = unresolved_helper();
  return uVar1;
}

double FUN_1800097f0(double *param_1)
{
  unsigned short uVar1;
  double adStackX_8[4];

  uVar1 = *(unsigned short *)((longlong)param_1 + 0x14);
  if ((uVar1 & 8) != 0) {
    return *param_1;
  }
  if ((uVar1 & 0x24) != 0) {
    return (double)(longlong)*param_1;
  }
  if ((uVar1 & 0x12) == 0) {
    return 0.0;
  }
  adStackX_8[0] = 0.0;
  convert_helper(param_1[1], adStackX_8, *(unsigned int *)(param_1 + 2),
                 *(unsigned char *)((longlong)param_1 + 0x16));
  return adStackX_8[0];
}

undefined8 FUN_180009750(longlong param_1)
{
  undefined2 uVar1;
  int iVar2;
  undefined8 uVar3;

  uVar1 = *(undefined2 *)(param_1 + 0x14);
  if ((uVar1 & 0x12) == 0) {
    if (((uVar1 & 0x202) == 0x202) && (*(char *)(param_1 + 0x16) == '\x01')) {
      return *(undefined8 *)(param_1 + 8);
    }
    if ((uVar1 & 1) == 0) {
      uVar3 = FUN_1801d4a00(param_1, 0x201);
      return uVar3;
    }
  }
  else {
    if (((uVar1 >> 10 & 1) != 0) && (iVar2 = FUN_1801b0690(param_1), iVar2 != 0)) {
      return 0;
    }
    *(undefined2 *)(param_1 + 0x14) = *(undefined2 *)(param_1 + 0x14) | 0x10;
    if (*(int *)(param_1 + 0x10) != 0) {
      return *(undefined8 *)(param_1 + 8);
    }
  }
  return 0;
}

double FUN_180009820(double *param_1)
{
  double dVar1;
  undefined2 uVar2;
  double dVar3;
  double adStackX_8[4];

  uVar2 = *(undefined2 *)((longlong)param_1 + 0x14);
  if ((uVar2 & 0x24) != 0) {
    return *param_1;
  }
  if ((uVar2 & 8) == 0) {
    if (((uVar2 & 0x12) != 0) && (param_1[1] != 0.0)) {
      adStackX_8[0] = 0.0;
      FUN_1801352e0(param_1[1], adStackX_8, *(undefined4 *)(param_1 + 2),
                    *(undefined1 *)((longlong)param_1 + 0x16));
      return adStackX_8[0];
    }
    dVar3 = 0.0;
  }
  else {
    dVar1 = *param_1;
    if (dVar1 < DAT_18029bd28) {
      return -0.0;
    }
    dVar3 = NAN;
    if (dVar1 <= DAT_18029bbf8) {
      return (double)(longlong)dVar1;
    }
  }
  return dVar3;
}

undefined8 FUN_1800099a0(undefined8 *param_1, longlong param_2)
{
  char cVar1;
  char cVar2;
  char *pcVar3;

  if ((((*(undefined2 *)((longlong)param_1 + 0x14) & 0xfbf) == 0xa01) && (param_2 != 0)) &&
      (*(char *)((longlong)param_1 + 0x17) == 'p')) {
    pcVar3 = (char *)*param_1;
    param_2 = param_2 - (longlong)pcVar3;
    do {
      cVar1 = *pcVar3;
      cVar2 = pcVar3[param_2];
      if (cVar1 != cVar2) break;
      pcVar3 = pcVar3 + 1;
    } while (cVar2 != '\0');
    if (cVar1 == cVar2) {
      return param_1[1];
    }
  }
  return 0;
}
