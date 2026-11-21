/*
 * Function-level restoration draft for two 7zr.exe (7-Zip standalone console,
 * 32-bit PE) internals.
 *
 * The bodies are reconstructed from the target's decompilation (offsets, flags
 * and call sites preserved); helper calls are declared with guessed prototypes
 * because their bodies are out of scope for this review. This is a review
 * draft, not a claim about the original 7-Zip source.
 *
 * Function provenance (target dist/corpus/7zr.exe, Ghidra 12.1.4 PUBLIC,
 * decompilation printed by scripts/recon-restore.mjs from the cached inventory):
 *   FUN_00401207 rva=0x1207 size=75 cfg blocks=8 edges=14 conditionals=5
 *   FUN_00401519 rva=0x1519 size=49 cfg blocks=7 edges=11 conditionals=4 loops=1
 *
 * The target is a 32-bit build, so Ghidra prints __thiscall/__fastcall on the
 * originals. The review build compiles as x86_64 where those conventions do
 * not exist; the macros keep the declaration honest on i386 and vanish
 * elsewhere without changing the reviewed bodies.
 */

typedef unsigned int undefined4;

#if defined(__i386__)
#define RESTORED_THISCALL __attribute__((thiscall))
#define RESTORED_FASTCALL __attribute__((fastcall))
#else
#define RESTORED_THISCALL
#define RESTORED_FASTCALL
#endif

/* Out-of-scope callees: stubbed so the review draft links. Their bodies are
   not part of this review, only the call shape is (FUN_00471ab6 also receives
   FUN_00401252 as a callback argument). */
void FUN_00401252(void *param_1);
void FUN_00401ea5(void *param_1);
int FUN_00471ab6(void *param_1, undefined4 param_2, int param_3, void *param_4);

void FUN_00401252(void *param_1) { (void)param_1; }
void FUN_00401ea5(void *param_1) { (void)param_1; }
int FUN_00471ab6(void *param_1, undefined4 param_2, int param_3, void *param_4)
{
  (void)param_1; (void)param_2; (void)param_3; (void)param_4;
  return 0;
}

int main(void) { return 0; }

int * RESTORED_THISCALL FUN_00401207(void *param_1, unsigned char param_2)
{
  int *piVar1;

  if ((param_2 & 2) == 0) {
    FUN_00401252(param_1);
    piVar1 = (int *)param_1;
    if ((param_2 & 1) != 0) {
      FUN_00401ea5(param_1);
    }
  }
  else {
    piVar1 = (int *)((unsigned int)param_1 - 4);
    FUN_00471ab6(param_1, 0x14, *piVar1, FUN_00401252);
    if ((param_2 & 1) != 0) {
      FUN_00401ea5(piVar1);
    }
  }
  return piVar1;
}

void RESTORED_FASTCALL FUN_00401519(int *param_1)
{
  undefined4 *puVar1;
  int iVar2;

  iVar2 = param_1[1];
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    puVar1 = *(undefined4 **)(*(undefined4 *)param_1 + iVar2 * 4);
    if (puVar1 != (undefined4 *)0x0) {
      FUN_00401ea5((void *)*puVar1);
      FUN_00401ea5(puVar1);
    }
  }
  param_1[1] = 0;
  return;
}
