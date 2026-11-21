/*
 * Function-level restoration draft, batch 2: four more 7zr.exe (7-Zip
 * standalone console, 32-bit PE) internals.
 *
 * Stratified sample (dist/m1-sample.mjs): switch-heavy + loop+write + small
 * tier, including the window's hard register-variable shapes (unaff_EBP,
 * extraout_ECX/EDX) and the SEH frame slot (ExceptionList) the first batch
 * avoided.
 *
 * The bodies are reconstructed from the target's decompilation (offsets,
 * flags and call sites preserved); helper calls are declared with guessed
 * prototypes because their bodies are out of scope for this review. This is a
 * review draft, not a claim about the original 7-Zip source.
 *
 * Function provenance (target dist/corpus/7zr.exe, Ghidra 12.1.4 PUBLIC,
 * decompilation from the cached cap-24 inventory):
 *   FUN_00401000 rva=0x1000 size=172  FUN_004010ac rva=0x10ac size=195
 *   FUN_0040116f rva=0x116f size=72   FUN_0040125a rva=0x125a size=400
 *
 * The target is a 32-bit build; the review build compiles as x86_64 where
 * __fastcall does not exist, so the specifier is dropped. unaff_EBP /
 * extraout_ECX / extraout_EDX are the decompiler's names for values carried in
 * registers across the real 32-bit frame; they are kept as plain locals here,
 * and ExceptionList is the SEH registration slot, kept as a plain global.
 */

#include <stdbool.h>

typedef unsigned long long undefined8;
typedef unsigned int undefined4;
typedef unsigned short undefined2;
typedef unsigned char undefined1;
typedef unsigned int int3;

void *ExceptionList;

#define CONCAT31(high, low) ((((unsigned int)(high)) << 8) | ((unsigned int)(low) & 0xff))

/* Out-of-scope callees: stubbed so the review draft links. Their bodies are
   not part of this review, only the call shape is. */
undefined8 FUN_00471a90() { return 0; }
void FUN_0040304e() { }
void FUN_0040356e() { }
void FUN_00403523() { }
void FUN_00401519() { }
void FUN_00402f36() { }
void FUN_00441b0f() { }
void FUN_0040154a() { }
void FUN_0040311e() { }
int FUN_00401ea5() { return 0; }
undefined2 FUN_00402576() { return 0; }
void FUN_00402cfb() { }
void FUN_004030ba() { }
int FUN_00402369() { return 0; }
void FUN_00402f79() { }
undefined8 FUN_004027c0() { return 0; }
void FUN_0040273f() { }

int main(void) { return 0; }

bool FUN_00401000(int *param_1, int *param_2, undefined4 *param_3)
{
  short sVar1;
  int iVar2;
  bool bVar3;
  int iVar4;
  unsigned int uVar5;

  param_2[1] = 0;
  bVar3 = false;
  uVar5 = 0;
  *(undefined2 *)*param_2 = 0;
  param_3[1] = 0;
  *(undefined2 *)*param_3 = 0;
  if (param_1[1] != 0) {
    do {
      sVar1 = *(short *)(*param_1 + uVar5 * 2);
      if (((sVar1 == 0x20) || (sVar1 == 9)) && (!bVar3)) {
        FUN_004030ba(param_3,(short *)(*param_1 + 2 + uVar5 * 2));
        break;
      }
      if (sVar1 == 0x22) {
        bVar3 = !bVar3;
      }
      else {
        if (param_2[2] == param_2[1]) {
          FUN_00402cfb(param_2);
        }
        iVar4 = param_2[1];
        iVar2 = *param_2;
        *(short *)(iVar2 + iVar4 * 2) = sVar1;
        iVar4 = iVar4 + 1;
        *(undefined2 *)(iVar2 + iVar4 * 2) = 0;
        param_2[1] = iVar4;
      }
      uVar5 = uVar5 + 1;
    } while (uVar5 < (unsigned int)param_1[1]);
  }
  return uVar5 != 0;
}

void FUN_004010ac(void)
{
  bool bVar1;
  undefined4 *extraout_ECX;
  int *extraout_EDX;
  int unaff_EBP;

  FUN_00471a90();
  FUN_0040304e((void *)(unaff_EBP + -0x24),extraout_ECX);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  FUN_0040356e((int *)(unaff_EBP + -0x24));
  FUN_00403523((undefined4 *)(unaff_EBP + -0x24));
  FUN_00401519(extraout_EDX);
  while( true ) {
    FUN_00402f36((undefined4 *)(unaff_EBP + -0x30));
    *(undefined1 *)(unaff_EBP + -4) = 1;
    FUN_00402f36((undefined4 *)(unaff_EBP + -0x18));
    *(undefined1 *)(unaff_EBP + -4) = 2;
    bVar1 = FUN_00401000((int *)(unaff_EBP + -0x24),(int *)(unaff_EBP + -0x30),
                         (undefined4 *)(unaff_EBP + -0x18));
    if (bVar1) {
      FUN_00441b0f(extraout_EDX);
      FUN_0040154a();
    }
    if (*(int *)(unaff_EBP + -0x14) == 0) break;
    FUN_0040311e((void *)(unaff_EBP + -0x24),(undefined4 *)(unaff_EBP + -0x18));
    FUN_00401ea5(*(void **)(unaff_EBP + -0x18));
    *(undefined1 *)(unaff_EBP + -4) = 0;
    FUN_00401ea5(*(void **)(unaff_EBP + -0x30));
  }
  FUN_00401ea5(*(void **)(unaff_EBP + -0x18));
  FUN_00401ea5(*(void **)(unaff_EBP + -0x30));
  FUN_00401ea5(*(void **)(unaff_EBP + -0x24));
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}

undefined4 *FUN_0040116f(void)
{
  undefined4 *extraout_ECX;
  int unaff_EBP;

  FUN_00471a90();
  *(undefined4 **)(unaff_EBP + -0x10) = extraout_ECX;
  *extraout_ECX = 0;
  extraout_ECX[1] = 0;
  extraout_ECX[2] = 0;
  extraout_ECX[3] = 0;
  extraout_ECX[4] = 0xffffffff;
  *(undefined4 *)(unaff_EBP + -4) = 0;
  FUN_0040273f(extraout_ECX + 5);
  *(undefined1 *)(unaff_EBP + -4) = 1;
  FUN_00402f36(extraout_ECX + 8);
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return extraout_ECX;
}

unsigned int FUN_0040125a(void)
{
  unsigned char bVar1;
  char cVar2;
  unsigned short uVar3;
  int *piVar4;
  unsigned char *pbVar5;
  undefined2 uVar6;
  short *psVar7;
  unsigned int uVar8;
  undefined4 extraout_ECX;
  int iVar9;
  int unaff_EBP;
  int iVar10;
  int iVar11;
  bool bVar12;
  char *pcVar13;

  psVar7 = (short *)FUN_00471a90();
  piVar4 = *(int **)(unaff_EBP + 8);
  iVar11 = 0;
  *(undefined4 *)(unaff_EBP + -0x10) = extraout_ECX;
  if ((piVar4[1] != 0) && (psVar7 = (short *)*piVar4, *psVar7 == 0x2d)) {
    *(undefined4 *)(unaff_EBP + -0x18) = 0xffffffff;
    *(undefined4 *)(unaff_EBP + 8) = 0;
    if (*(int *)(unaff_EBP + 0x10) == 0) {
LAB_004012e5:
      pcVar13 = "Unknown switch:";
    }
    else {
      *(undefined4 *)(unaff_EBP + -0x14) = *(undefined4 *)(unaff_EBP + 0xc);
      do {
        iVar10 = 0;
        pbVar5 = (unsigned char *)**(undefined4 **)(unaff_EBP + -0x14);
        bVar1 = *pbVar5;
        while (bVar1 != 0) {
          iVar10 = iVar10 + 1;
          bVar1 = pbVar5[iVar10];
        }
        if (((*(int *)(unaff_EBP + -0x18) < iVar10) && (iVar10 + 1U <= (unsigned int)piVar4[1])) &&
           (uVar6 = FUN_00402576((unsigned short *)(*piVar4 + 2),pbVar5), (char)uVar6 != '\0')) {
          iVar11 = *(int *)(unaff_EBP + 8);
          *(int *)(unaff_EBP + -0x18) = iVar10;
        }
        *(int *)(unaff_EBP + 8) = *(int *)(unaff_EBP + 8) + 1;
        *(int *)(unaff_EBP + -0x14) = *(int *)(unaff_EBP + -0x14) + 0xc;
      } while (*(unsigned int *)(unaff_EBP + 8) < *(unsigned int *)(unaff_EBP + 0x10));
      if (*(int *)(unaff_EBP + -0x18) < 0) goto LAB_004012e5;
      iVar9 = *(int *)(unaff_EBP + -0x18) + 1;
      pcVar13 = (char *)(**(int **)(unaff_EBP + -0x10) + iVar11 * 0x14);
      iVar10 = *(int *)(unaff_EBP + 0xc) + iVar11 * 0xc;
      if ((*(char *)(*(int *)(unaff_EBP + 0xc) + 5 + iVar11 * 0xc) == '\0') && (*pcVar13 != '\0')) {
        pcVar13 = "Multiple instances for switch:";
      }
      else {
        *pcVar13 = '\x01';
        *(int *)(unaff_EBP + 0x10) = piVar4[1] - iVar9;
        if ((unsigned int)*(unsigned char *)(iVar10 + 6) <= *(unsigned int *)(unaff_EBP + 0x10)) {
          pcVar13[1] = '\0';
          pcVar13[4] = -1;
          pcVar13[5] = -1;
          pcVar13[6] = -1;
          pcVar13[7] = -1;
          cVar2 = *(char *)(iVar10 + 4);
          if (cVar2 == '\x01') {
            if (*(int *)(unaff_EBP + 0x10) == 1) {
              bVar12 = *(short *)(*piVar4 + iVar9 * 2) == 0x2d;
              iVar10 = CONCAT31((int3)((unsigned int)*piVar4 >> 8),bVar12);
              pcVar13[1] = bVar12;
              if (!bVar12) goto LAB_0040136e;
            }
            else {
LAB_004013c2:
              if (iVar9 != piVar4[1]) {
                pcVar13 = "Too long switch:";
                goto LAB_004013cc;
              }
            }
          }
          else {
            if (cVar2 != '\x02') {
              if ((cVar2 != '\x03') || (*(int *)(unaff_EBP + 0x10) != 1)) goto LAB_004013c2;
              uVar3 = *(unsigned short *)(*piVar4 + iVar9 * 2);
              if (uVar3 < 0x80) {
                iVar10 = FUN_00402369(*(char **)(iVar10 + 8),(char)uVar3);
                *(int *)(pcVar13 + 4) = iVar10;
                if (-1 < iVar10) goto LAB_004013a5;
              }
LAB_0040136e:
              pcVar13 = "Incorrect switch postfix:";
              goto LAB_004013cc;
            }
            FUN_00402f79((void *)(unaff_EBP + -0x24),(short *)(*piVar4 + iVar9 * 2));
            *(undefined4 *)(unaff_EBP + -4) = 0;
            FUN_00441b0f(pcVar13 + 8);
            FUN_0040154a();
            iVar10 = FUN_00401ea5(*(void **)(unaff_EBP + -0x24));
          }
LAB_004013a5:
          uVar8 = CONCAT31((int3)((unsigned int)iVar10 >> 8),1);
          goto LAB_004013d9;
        }
        pcVar13 = "Too short switch:";
      }
    }
LAB_004013cc:
    psVar7 = (short *)FUN_004027c0((void *)(*(int *)(unaff_EBP + -0x10) + 0x14),pcVar13);
  }
  uVar8 = (unsigned int)psVar7 & 0xffffff00;
LAB_004013d9:
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return uVar8;
}
