/*
 * Function-level restoration draft: al-khaser v1.1.0 x64 — the first
 * function-level closed loop against a REAL, currently-maintained adversarial
 * anti-analysis binary (official GitHub release binary, not a self-built
 * specimen).
 *
 * Provenance (target dist/corpus-adv/al-khaser_x64.exe,
 * sha256 0cd8a40ff7ceef9c1368446d6ead91549681e88fdfa0f9f5a63c03fe38420baf,
 * Ghidra 12.1.4 PUBLIC, decompilation from the cached cap-200 inventory,
 * cache file 3481c49f601e4f3a…):
 *   FUN_140018a14 rva=0x18a14 size=175  (CRT security-cookie init)
 *   FUN_1400184ec rva=0x184ec size=661  (cpuid/XCR0 CPU-feature detection)
 *   FUN_1400187f0 rva=0x187f0 size=331  (security-failure report path)
 *
 * The bodies are reconstructed from the target's decompilation only (constants,
 * bit tests, branch shapes and call sites preserved); out-of-scope callees are
 * stubbed because their bodies are not part of this review. unaff_retaddr in
 * FUN_1400187f0 is the decompiler's name for the return address slot; it is
 * kept as a plain local. This is a review draft, not a claim about the
 * original al-khaser source.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned long long undefined8;
typedef unsigned int undefined4;
typedef unsigned char undefined1;
typedef long long longlong;

/* Target globals (Ghidra DAT_* slots), kept as plain globals. */
static unsigned long long DAT_14002c008;
static undefined8 DAT_14002c010;
static unsigned int DAT_14002c014;
static unsigned long long DAT_14002c018;
static unsigned long long DAT_14002c020;
static unsigned long long DAT_14002c040;
static unsigned long long DAT_14002c080;
static unsigned int DAT_140045014;
static unsigned int DAT_140045018;

/* ---- WinAPI surface used by the reviewed functions (real imports). ---- */
typedef union { struct { unsigned int LowPart; unsigned int HighPart; }; unsigned long long QuadPart; } ADV_LARGE_INTEGER;
typedef struct { unsigned int dwLowDateTime; unsigned int dwHighDateTime; } ADV_FILETIME;
typedef struct { unsigned long long LowPart; long long HighPart; } ADV_LUID;

void GetSystemTimeAsFileTime(ADV_FILETIME *out);
unsigned int GetCurrentThreadId(void);
unsigned int GetCurrentProcessId(void);
int QueryPerformanceCounter(ADV_LARGE_INTEGER *out);
int IsProcessorFeaturePresent(unsigned int feature);
int IsDebuggerPresent(void);

/* ---- Out-of-scope callees: stubbed; only the call shape is reviewed. ---- */
static void RtlCaptureContext(undefined1 *context) { (void)context; }
static void *RtlLookupFunctionEntry(unsigned long long pc, unsigned long long *imageBase,
                                    void *historyTable) {
  (void)pc; (void)imageBase; (void)historyTable; return (void *)0;
}
static void RtlVirtualUnwind(unsigned int handlerType, unsigned long long imageBase,
                             unsigned long long pc, void *functionEntry,
                             undefined1 *context, void *handlerData, void **establisherFrame,
                             void *contextPointers) {
  (void)handlerType; (void)imageBase; (void)pc; (void)functionEntry; (void)context;
  (void)handlerData; (void)establisherFrame; (void)contextPointers;
}
static int UnhandledExceptionFilter(void *pointers) { (void)pointers; return 0; }
static void SetUnhandledExceptionFilter(void *filter) { (void)filter; }
static void FUN_1400187e4(void) { }

static undefined1 local_4d8_storage[152];
static undefined1 local_res18_storage[8];
static undefined1 local_res20_storage[8];

/* cpuid / xgetbv helpers: the target's decompilation shows these as helper
   calls (cpuid_basic_info(0), cpuid(0x24), xinuse(0), …); the draft keeps the
   same one-call-per-leaf shape. */
typedef struct { unsigned int eax; unsigned int ebx; unsigned int ecx; unsigned int edx; } ADV_CPUID;

static ADV_CPUID adv_cpuid(unsigned int leaf) {
  ADV_CPUID regs;
  __asm__ __volatile__("cpuid"
                       : "=a"(regs.eax), "=b"(regs.ebx), "=c"(regs.ecx), "=d"(regs.edx)
                       : "a"(leaf), "c"(0u));
  return regs;
}

static unsigned long long adv_xinuse(void) {
  unsigned int lo;
  unsigned int hi;
  __asm__ __volatile__("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0u));
  return ((unsigned long long)hi << 32) | lo;
}

/* ======================================================================
 * Target FUN_140018a14 @0x18a14 (size 175): CRT security-cookie init.
 * ====================================================================== */
void FUN_140018a14(void)
{
  unsigned int DVar1;
  ADV_FILETIME local_res8;
  ADV_LARGE_INTEGER local_res10;
  ADV_FILETIME local_18;

  if (DAT_14002c040 == 0x2b992ddfa232) {
    local_res8.dwLowDateTime = 0;
    local_res8.dwHighDateTime = 0;
    GetSystemTimeAsFileTime(&local_res8);
    local_18 = local_res8;
    DVar1 = GetCurrentThreadId();
    *(unsigned long long *)&local_18 ^= (unsigned long long)DVar1;
    DVar1 = GetCurrentProcessId();
    *(unsigned long long *)&local_18 ^= (unsigned long long)DVar1;
    QueryPerformanceCounter(&local_res10);
    DAT_14002c040 = ((unsigned long long)local_res10.LowPart << 0x20
        ^ ((unsigned long long)local_res10.HighPart << 32 | local_res10.LowPart)
        ^ *(unsigned long long *)&local_18
        ^ (unsigned long long)(uintptr_t)&local_18) & 0xffffffffffff;
    if (DAT_14002c040 == 0x2b992ddfa232) {
      DAT_14002c040 = 0x2b992ddfa233;
    }
  }
  DAT_14002c080 = ~DAT_14002c040;
  return;
}

/* ======================================================================
 * Target FUN_1400184ec @0x184ec (size 661): cpuid/XCR0 CPU-feature
 * detection (vendor/model gates, leaf 7 / leaf 0x24 features, XCR0 masks).
 * ====================================================================== */
undefined8 FUN_1400184ec(void)
{
  ADV_CPUID basic;
  ADV_CPUID version;
  ADV_CPUID leaf7;
  ADV_CPUID leaf7b;
  ADV_CPUID leaf24;
  unsigned int edx1;
  unsigned int model;
  unsigned int ebx7;
  unsigned int ecx7;
  unsigned int ecx7b;
  unsigned int ebx24;
  unsigned long long xcr0;
  unsigned long long xcr0Masked;
  unsigned long long cookie;
  unsigned int cookieFlags;

  basic = adv_cpuid(0);
  version = adv_cpuid(1);
  edx1 = version.edx;
  if ((basic.ecx == 0x49656e69 && basic.edx == 0x6c65746e) && basic.ebx == 0x756e6547) {
    model = version.eax & 0xfff3ff0;
    DAT_14002c018 = 0x8000;
    DAT_14002c020 = 0xffffffffffffffffULL;
    if (((model == 0x106c0) || (model == 0x20660)) || (model == 0x20670)) {
      DAT_140045018 = DAT_140045018 | 1;
    } else if (model - 0x30650 < 0x21) {
      if (((0x100010001ULL >> ((model - 0x30650) & 0x3f)) & 1) != 0) {
        DAT_140045018 = DAT_140045018 | 1;
      }
    }
  }
  ebx7 = 0;
  ecx7 = 0;
  ecx7b = 0;
  ebx24 = 0;
  if (6 < basic.eax) {
    leaf7 = adv_cpuid(7);
    ebx7 = leaf7.ebx;
    ecx7 = leaf7.ecx;
    if ((ebx7 >> 9 & 1) != 0) {
      DAT_140045018 = DAT_140045018 | 2;
    }
    if (0 < leaf7.eax) {
      leaf7b = adv_cpuid(7);
      ecx7b = leaf7b.ecx;
    }
    if (0x23 < basic.eax) {
      leaf24 = adv_cpuid(0x24);
      ebx24 = leaf24.ebx;
    }
  }
  DAT_14002c010 = 1;
  DAT_14002c014 = 2;
  cookie = DAT_14002c008 & 0xfffffffffffffffeULL;
  if ((edx1 >> 0x14 & 1) != 0) {
    DAT_14002c010 = 2;
    DAT_14002c014 = 6;
    cookie = DAT_14002c008 & 0xffffffffffffffeeULL;
  }
  DAT_14002c008 = cookie;
  if ((edx1 >> 0x1b & 1) != 0) {
    xcr0 = adv_xinuse();
    xcr0Masked = xcr0 & 0xffffffffULL;
    if (((edx1 >> 0x1c & 1) != 0) && ((xcr0Masked & 6) == 6)) {
      DAT_14002c010 = 3;
      cookie = DAT_14002c008;
      cookieFlags = DAT_14002c014 | 8;
      if ((ebx7 & 0x20) != 0) {
        DAT_14002c010 = 5;
        cookie = DAT_14002c008 & 0xfffffffffffffffdULL;
        cookieFlags = DAT_14002c014 | 0x28;
        if (((ebx7 & 0xd0030000) == 0xd0030000) && ((xcr0Masked & 0xe0) == 0xe0)) {
          DAT_14002c014 = DAT_14002c014 | 0x68;
          DAT_14002c010 = 6;
          cookie = DAT_14002c008 & 0xffffffffffffffd9ULL;
          cookieFlags = DAT_14002c014;
        }
      }
      DAT_14002c014 = cookieFlags;
      DAT_14002c008 = cookie;
      if ((ecx7 >> 0x17 & 1) != 0) {
        DAT_14002c008 = DAT_14002c008 & 0xfffffffffeffffffULL;
      }
      if (((ecx7b >> 0x13 & 1) != 0) && ((xcr0Masked & 0xe0) == 0xe0)) {
        DAT_140045014 = ebx24 & 0x400ff;
        DAT_14002c008 = ~((unsigned long long)((ebx24 >> 0x10) & 6) | 0x1000029ULL) & DAT_14002c008;
        if (1 < (unsigned char)DAT_140045014) {
          DAT_14002c008 = DAT_14002c008 & 0xffffffffffffffbfULL;
        }
      }
    }
    if (((ecx7b >> 0x15 & 1) != 0) && ((xcr0 >> 0x13 & 1) != 0)) {
      DAT_14002c008 = DAT_14002c008 & 0xffffffffffffff7fULL;
    }
  }
  return 0;
}

/* ======================================================================
 * Target FUN_1400187f0 @0x187f0 (size 331): security-failure report path.
 * Transcribed through the decompiler's stack-window view (the puVar4 offset
 * writes and return-address markers are part of the observed structure).
 * ====================================================================== */
typedef void (*ADV_CODE)(undefined4);

void FUN_1400187f0(undefined4 param_1)
{
  ADV_CODE pcVar1;
  int BVar2;
  long long LVar3;
  void *FunctionEntry;
  undefined8 unaff_retaddr;
  unsigned long long local_res10;
  undefined1 local_res18[8];
  undefined1 local_res20[8];
  undefined1 auStack_5c8[8];
  undefined1 auStack_5c0[232];
  undefined1 local_4d8[152];
  undefined1 *local_440;
  undefined1 *puVar4;
  unsigned long long local_3e0;

  puVar4 = auStack_5c8;
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    /* swi(0x29): the fastfail trap (int 0x29) the decompiler shows here */
    __asm__ __volatile__("int $0x29");
    puVar4 = auStack_5c0;
  }
  *(undefined8 *)(puVar4 + -8) = 0x140018824;
  FUN_1400187e4();
  *(undefined8 *)(puVar4 + -8) = 0x140018835;
  memset(local_4d8, 0, 0x4d0);
  *(undefined8 *)(puVar4 + -8) = 0x14001883f;
  RtlCaptureContext(local_4d8);
  *(undefined8 *)(puVar4 + -8) = 0x140018859;
  FunctionEntry = RtlLookupFunctionEntry(local_3e0, &local_res10, (void *)0);
  if (FunctionEntry != (void *)0) {
    *(undefined8 *)(puVar4 + 0x38) = 0;
    *(undefined1 **)(puVar4 + 0x30) = local_res18;
    *(undefined1 **)(puVar4 + 0x28) = local_res20;
    *(undefined1 **)(puVar4 + 0x20) = local_4d8;
    *(undefined8 *)(puVar4 + -8) = 0x14001889d;
    RtlVirtualUnwind(0, local_res10, local_3e0, FunctionEntry,
                     *(undefined1 **)(puVar4 + 0x20), *(void **)(puVar4 + 0x28),
                     (void **)*(void ***)(puVar4 + 0x30),
                     (void **)*(void ***)(puVar4 + 0x38));
  }
  local_440 = (undefined1 *)&param_1 + 8;
  *(undefined8 *)(puVar4 + -8) = 0x1400188cf;
  memset(puVar4 + 0x50, 0, 0x98);
  *(undefined8 *)(puVar4 + 0x60) = unaff_retaddr;
  *(undefined4 *)(puVar4 + 0x50) = 0x40000015;
  *(undefined4 *)(puVar4 + 0x54) = 1;
  *(undefined8 *)(puVar4 + -8) = 0x1400188f1;
  BVar2 = IsDebuggerPresent();
  *(undefined1 **)(puVar4 + 0x40) = puVar4 + 0x50;
  *(undefined1 **)(puVar4 + 0x48) = local_4d8;
  *(undefined8 *)(puVar4 + -8) = 0x14001890e;
  SetUnhandledExceptionFilter((void *)0);
  *(undefined8 *)(puVar4 + -8) = 0x140018919;
  LVar3 = UnhandledExceptionFilter((void *)(puVar4 + 0x40));
  if ((LVar3 == 0) && (BVar2 != 1)) {
    *(undefined8 *)(puVar4 + -8) = 0x14001892a;
    FUN_1400187e4();
  }
  return;
}


/* ======================================================================
 * Target tls_callback_0 @0xdde0 (size 172): the TLS callback al-khaser uses
 * as an anti-analysis hook point - lazily creates two events, marks
 * thread/process attach with 0xdeadbeef and signals the event.
 * ====================================================================== */
static int DAT_140045088;
static void *DAT_1400450b8;
static void *DAT_1400450c0;
static unsigned int DAT_14004509c;
static unsigned int DAT_1400450c8;

void CreateEventW_stub(void);
int SetEvent(void *handle);
void OutputDebugStringW(const wchar_t *text);

__attribute__((import_name("CreateEventW")))
void *CreateEventW(void *attrs, int manualReset, int initialState, const wchar_t *name);

void tls_callback_0(undefined8 param_1, int param_2)
{
  if (DAT_140045088 == 0) {
    DAT_140045088 = 1;
    DAT_1400450b8 = CreateEventW((void *)0, 0, 0, (const wchar_t *)0);
    DAT_1400450c0 = CreateEventW((void *)0, 0, 0, (const wchar_t *)0);
  }
  if (param_2 == 2) {
    OutputDebugStringW(L"TLS callback: thread attach");
    DAT_14004509c = 0xdeadbeef;
    SetEvent(DAT_1400450b8);
    return;
  }
  if (param_2 == 1) {
    OutputDebugStringW(L"TLS callback: process attach");
    DAT_1400450c8 = 0xdeadbeef;
    SetEvent(DAT_1400450c0);
    return;
  }
  return;
}

/* ======================================================================
 * Target FUN_14000a210 @0xa210 (size 114): CRT wstring teardown - the
 * heap-guard shape (0xfff threshold, 0x1f slack check, _invoke_watson path)
 * with the SSO fields reset to the small-buffer state (7/0/0).
 * ====================================================================== */
static void _invoke_watson_stub(void) { }

void FUN_14000a210(longlong *param_1)
{
  void *pvVar1;
  void *memory;

  if (7 < (unsigned long long)param_1[3]) {
    pvVar1 = (void *)*param_1;
    memory = pvVar1;
    if ((0xfff < param_1[3] * 2 + 2U) &&
        (memory = *(void **)((longlong)pvVar1 + -8),
         0x1f < (unsigned long long)((longlong)pvVar1 + (-8 - (longlong)memory)))) {
      _invoke_watson_stub();
    }
    free(memory);
  }
  param_1[3] = 7;
  param_1[2] = 0;
  *(unsigned short *)param_1 = 0;
  return;
}

int main(void) { return 0; }

