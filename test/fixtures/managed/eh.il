// test/fixtures/managed/eh.il
//
// Exception-handling fixture for test/managed.test.js. Assembled at test time
// with the system ilasm.exe; the output is only ever parsed as bytes, never
// executed. Its purpose is ground truth for the CIL layer's exception-clause
// parser (lib/cil.js): one method carrying one .try with a catch and a
// finally, so clause count, kinds and bounds are asserted against real ilasm
// output instead of a hand-built byte guess.
//
// Expected CIL shape (asserted by the tests):
//   Main: tiny/fat body, 2 EH clauses (one catch of System.Exception, one
//   finally), instruction stream fully decodable, leave.s/endfinally/ret
//   present.

.assembly eh
{
    .ver 1:0:0:0
}

.assembly extern mscorlib
{
    .publickeytoken = (B7 7A 5C 56 19 34 E0 89)
    .ver 4:0:0:0
}

.module eh.exe

.class public auto ansi EhProg extends [mscorlib]System.Object
{
    .method public hidebysig static void Main() cil managed
    {
        .entrypoint
        .maxstack 1
        .locals init ([0] class [mscorlib]System.Exception ex)
        nop
        nop
        leave.s DONE
        DONE: ret
        .try {
            nop
            leave.s AFTERTRY
        }
        catch [mscorlib]System.Exception {
            stloc.0
            leave.s AFTERTRY
        }
        AFTERTRY: nop
        .try {
            nop
            leave.s AFTERFIN
        }
        finally {
            nop
            endfinally
        }
        AFTERFIN: ret
    }
}
