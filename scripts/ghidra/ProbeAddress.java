// dsh-rea headless probe / decompiler.
//
// Runs inside Ghidra, prints one machine-readable line so the host never has to
// parse prose or localized messages.
//
//   ProbeAddress.java <rva> probe [code|pointer]
//   ProbeAddress.java <rva> decompile
//
// `rva` is relative to the image base, because that is stable across the
// preferred-base changes a hardened sample may apply at load time.

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;

public class ProbeAddress extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("PROBE {\"ok\":false,\"error\":\"no address\"}");
            return;
        }
        long rva = Long.decode(args[0].startsWith("0x") ? args[0] : "0x" + args[0]);
        String mode = args.length > 1 ? args[1] : "probe";
        String kind = args.length > 2 ? args[2] : "code";

        Address base = currentProgram.getImageBase();
        Address address = base.add(rva);
        Memory memory = currentProgram.getMemory();
        MemoryBlock block = memory.getBlock(address);
        FunctionManager functions = currentProgram.getFunctionManager();

        if ("decompile".equals(mode)) {
            decompile(address, rva, block, functions);
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("PROBE {");
        sb.append("\"ok\":true");
        sb.append(",\"address\":\"").append(address).append("\"");
        sb.append(",\"rva\":\"0x").append(Long.toHexString(rva)).append("\"");
        sb.append(",\"kind\":\"").append(kind).append("\"");
        sb.append(",\"block\":\"").append(block == null ? "" : esc(block.getName())).append("\"");
        sb.append(",\"executable\":").append(block != null && block.isExecute());
        sb.append(",\"initialized\":").append(block != null && block.isInitialized());
        sb.append(",\"imageBase\":\"0x").append(Long.toHexString(base.getOffset())).append("\"");

        if ("pointer".equals(kind)) {
            if (block != null && block.isInitialized()) {
                long target = 0;
                for (int i = 0; i < 4; i++) {
                    target |= ((long) (memory.getByte(address.add(i)) & 0xff)) << (8 * i);
                }
                Address targetAddress = base.add(target);
                MemoryBlock targetBlock = memory.getBlock(targetAddress);
                Function targetFunction = functions.getFunctionAt(targetAddress);
                Symbol targetSymbol = currentProgram.getSymbolTable().getPrimarySymbol(targetAddress);
                sb.append(",\"pointer\":\"0x").append(Long.toHexString(target)).append("\"");
                sb.append(",\"pointerBlock\":\"")
                        .append(targetBlock == null ? "" : esc(targetBlock.getName())).append("\"");
                sb.append(",\"pointerExecutable\":")
                        .append(targetBlock != null && targetBlock.isExecute());
                sb.append(",\"pointerFunction\":\"")
                        .append(targetFunction == null ? "" : esc(targetFunction.getName())).append("\"");
                sb.append(",\"pointerSymbol\":\"")
                        .append(targetSymbol == null ? "" : esc(targetSymbol.getName())).append("\"");
            } else {
                sb.append(",\"pointer\":null");
            }
        } else {
            Function function = functions.getFunctionAt(address);
            Function containing = functions.getFunctionContaining(address);
            // A TLS callback is a symbol before it is a function: Ghidra records
            // the entry from the TLS directory but does not always define a
            // function body there, so `function` alone reads as "nothing here".
            Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
            Data data = currentProgram.getListing().getDataAt(address);
            sb.append(",\"functionStart\":").append(function != null);
            sb.append(",\"function\":\"").append(function == null ? "" : esc(function.getName())).append("\"");
            sb.append(",\"containing\":\"")
                    .append(containing == null ? "" : esc(containing.getName())).append("\"");
            sb.append(",\"symbol\":\"").append(symbol == null ? "" : esc(symbol.getName())).append("\"");
            sb.append(",\"data\":\"").append(data == null ? "" : esc(data.toString())).append("\"");
        }
        sb.append("}");
        println(sb.toString());
    }

    private void decompile(Address address, long rva, MemoryBlock block, FunctionManager functions)
            throws Exception {
        Function function = functions.getFunctionAt(address);
        if (function == null) {
            function = functions.getFunctionContaining(address);
        }
        if (function == null) {
            // A TLS callback, a dispatcher target or an entry the analyzer did
            // not follow has no function body yet. Disassemble from the address
            // and let Ghidra decide the extent - that is the manual step an
            // analyst performs before decompiling anything.
            Address start = address;
            if (block != null && block.isExecute()) {
                DisassembleCommand disassemble = new DisassembleCommand(start, null, true);
                disassemble.applyTo(currentProgram, monitor);
                CreateFunctionCmd create = new CreateFunctionCmd(start);
                create.applyTo(currentProgram, monitor);
                function = functions.getFunctionAt(start);
            }
        }
        if (function == null) {
            println("PROBE {\"ok\":false,\"error\":\"no-function\",\"rva\":\"0x"
                    + Long.toHexString(rva) + "\",\"block\":\""
                    + (block == null ? "" : esc(block.getName())) + "\"}");
            return;
        }
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(currentProgram);
            DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
            if (results == null || !results.decompileCompleted()) {
                println("PROBE {\"ok\":false,\"error\":\"decompile-failed\",\"function\":\""
                        + esc(function.getName()) + "\"}");
                return;
            }
            String c = results.getDecompiledFunction() == null
                    ? null : results.getDecompiledFunction().getC();
            println("PROBE {\"ok\":true,\"function\":\"" + esc(function.getName())
                    + "\",\"entry\":\"" + function.getEntryPoint()
                    + "\",\"rva\":\"0x" + Long.toHexString(rva) + "\"}");
            println("DECOMPILE_BEGIN " + function.getName());
            println(c == null ? "(no body)" : c);
            println("DECOMPILE_END");
        } finally {
            decompiler.dispose();
        }
    }

    private static String esc(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
