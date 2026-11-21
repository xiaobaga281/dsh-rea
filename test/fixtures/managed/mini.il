// test/fixtures/managed/mini.il
//
// Deterministic minimal managed fixture for test/managed.test.js. Assembled at
// test time with the system ilasm.exe (Framework64, falling back to Framework);
// the output is only ever parsed as bytes, never executed.
//
// Expected metadata (asserted by the tests):
//   assembly 'mini' 1.0.0.0, module 'mini.exe'
//   TypeDef 3 rows: <Module>, Program, Helper
//   MethodDef 3 rows: Main, .ctor, GetSeed
//   Field 1 row (seed); AssemblyRef 1 (mscorlib); MemberRef 1 (System.Object::.ctor)
//   #US stream contains "dsh-rea managed fixture"
//   no strong-name signature: CLR header slots +24 and +32 are both zero

.assembly mini
{
    .ver 1:0:0:0
}

.assembly extern mscorlib
{
    .publickeytoken = (B7 7A 5C 56 19 34 E0 89)
    .ver 4:0:0:0
}

.module mini.exe

.class public auto ansi Program extends [mscorlib]System.Object
{
    .method public hidebysig static void Main() cil managed
    {
        .entrypoint
        .maxstack 1
        ldstr "dsh-rea managed fixture"
        pop
        ret
    }
}

.class public auto ansi Helper extends [mscorlib]System.Object
{
    .field private static int32 seed

    .method public hidebysig specialname rtspecialname instance void .ctor() cil managed
    {
        .maxstack 8
        ldarg.0
        call instance void [mscorlib]System.Object::.ctor()
        ret
    }

    .method public hidebysig static int32 GetSeed() cil managed
    {
        .maxstack 1
        ldsfld int32 Helper::seed
        ret
    }
}
