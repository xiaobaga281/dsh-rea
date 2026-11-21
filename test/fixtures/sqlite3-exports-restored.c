/*
 * Function-level restoration draft: two real sqlite3.dll EXPORT functions,
 * requested by their export names — the first gate run that exercises the
 * export-name overlay (lib/ghidra-local.js applyExportNames), closing the
 * "0 export symbol names in the window" gap recorded as plan §13 residual #8.
 *
 * Provenance (target dist/corpus/sqlite3.dll,
 * sha256 579fe388f0b930225492c18669f4930c00e3abef515a6328f29f8c2bc5eceefe,
 * Ghidra 12.1.4 PUBLIC, decompilation from the cached cap-200 inventory,
 * overlay 151/200 export names applied, both via /INCREMENTAL jmp thunks):
 *   sqlite3_value_int  rva=0x9820  size=89  (listedAs FUN_180009820)
 *   sqlite3_stricmp    rva=0x15a00 size=77  (listedAs FUN_180015a00)
 *
 * The bodies are reconstructed from the target's decompilation only (flag
 * masks, bounds and call sites preserved); out-of-scope callees are stubbed
 * and the two decompiler-visible bound doubles keep their DAT_ names. This is
 * a review draft, not a claim about the original sqlite3 source.
 */

#include <stdbool.h>

typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long long undefined8;
typedef long long longlong;

/* Out-of-scope callee: the Vdbe real-value conversion helper (call shape only). */
void FUN_1801352e0(double a, void *b, undefined4 c, undefined1 d) { (void)a; (void)b; (void)c; (void)d; }

/* Decompiler-visible bound doubles and the case-fold table, kept by name. */
static const double DAT_18029bd28 = -2147483649.0;
static const double DAT_18029bbf8 = 2147483648.0;
static const unsigned char DAT_180288720[256] = { 0 };

int main(void) { return 0; }

/* ======================================================================
 * Target sqlite3_value_int @0x9820 (size 89): value-type flags at +0x14
 * gate the union read; 0x24 = float/int direct, 8 = int-valued with range
 * clamps, 0x12 = text needing the Vdbe conversion helper.
 * ====================================================================== */
double sqlite3_value_int(double *param_1)
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
    dVar3 = __builtin_nan("");
    if (dVar1 <= DAT_18029bbf8) {
      return (double)(longlong)dVar1;
    }
  }
  return dVar3;
}

/* ======================================================================
 * Target sqlite3_stricmp @0x15a00 (size 77): null handling, then the
 * case-fold-table comparison loop (pointer-difference indexing).
 * ====================================================================== */
int sqlite3_stricmp(undefined1 *param_1, longlong param_2)
{
  undefined1 bVar1;

  if (param_1 == (undefined1 *)0x0) {
    return -(int)(param_2 != 0);
  }
  if (param_2 != 0) {
    param_2 = param_2 - (longlong)param_1;
    do {
      bVar1 = *param_1;
      if (bVar1 == param_1[param_2]) {
        if (bVar1 == 0) {
          return 0;
        }
      }
      else if ((int)(undefined1)DAT_180288720[bVar1] - (int)(undefined1)DAT_180288720[param_1[param_2]]
               != 0) {
        return (int)(undefined1)DAT_180288720[bVar1] - (int)(undefined1)DAT_180288720[param_1[param_2]];
      }
      param_1 = param_1 + 1;
    } while (true);
  }
  return 1;
}
