// dsh-rea headless probe / decompiler.
//
// Runs inside Ghidra, prints one machine-readable line so the host never has to
// parse prose or localized messages.
//
//   ProbeAddress.java <rva> probe [code|pointer]
//   ProbeAddress.java <rva> decompile
//   ProbeAddress.java 0 list [pageSize] [cursor]
//
// `rva` is relative to the image base, because that is stable across the
// preferred-base changes a hardened sample may apply at load time.

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

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

        if ("list".equals(mode)) {
            listFunctions(functions, memory, args);
            return;
        }
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

    /**
     * Enumerate functions and dump their pseudocode, bounded.
     *
     * The entry-only tier was honest but thin: a twenty-line entry tells nothing
     * about the other ninety functions. This walks the executable functions in
     * address order, skips thunks, and prints one metadata line per function
     * followed by its body, so the host can compare a rebuilt binary function by
     * function without parsing prose.
     */
    private void listFunctions(FunctionManager functions, Memory memory, String[] args) throws Exception {
        int pageSize = 48;
        int cursor = 0;
        if (args.length > 2) {
            try {
                pageSize = Math.max(1, Math.min(200, Integer.parseInt(args[2])));
            } catch (NumberFormatException ignored) {
                // the caller's default is the safe bound
            }
        }
        if (args.length > 3) {
            try {
                cursor = Integer.parseInt(args[3]);
            } catch (NumberFormatException error) {
                println("LIST_DONE {\"ok\":false,\"error\":\"invalid cursor\"}");
                return;
            }
        }
        List<Function> ordered = new ArrayList<>();
        FunctionIterator iterator = functions.getFunctions(true);
        while (iterator.hasNext()) {
            Function function = iterator.next();
            if (function.isThunk()) {
                continue;
            }
            MemoryBlock block = memory.getBlock(function.getEntryPoint());
            if (block == null || !block.isExecute()) {
                continue;
            }
            ordered.add(function);
        }
        ordered.sort(Comparator.comparingLong(function -> function.getEntryPoint().getOffset()));
        int total = ordered.size();
        if (cursor < 0 || cursor > total) {
            println("LIST_DONE {\"ok\":false,\"error\":\"cursor outside inventory\"}");
            return;
        }
        int end = Math.min(total, cursor + pageSize);
        List<Function> selected = new ArrayList<>(ordered.subList(cursor, end));
        println("LIST {\"total\":" + total + ",\"cursor\":" + cursor
                + ",\"pageSize\":" + pageSize + ",\"emitted\":" + selected.size() + "}");
        DecompInterface decompiler = new DecompInterface();
        int failed = 0;
        final int perFunctionSeconds = 8;
        // SQLite's amalgamation contains 20-35 KB functions. Eight seconds is
        // enough for ordinary code but cuts these off; measured standalone
        // runs complete in 23 s and 56 s. Give only large bodies the extra
        // ceiling so the page budget stays predictable.
        final int largeFunctionSeconds = 90;
        final long largeFunctionBytes = 8_192;
        final long budgetMs = 240_000;
        long started = System.currentTimeMillis();
        boolean timeStopped = false;
        int emitted = 0;
        try {
            decompiler.openProgram(currentProgram);
            for (Function function : selected) {
                if (System.currentTimeMillis() - started > budgetMs) {
                    timeStopped = true;
                    break;
                }
                emitted++;
                long functionRva = function.getEntryPoint().getOffset()
                        - currentProgram.getImageBase().getOffset();
                println("FUNCTION {\"name\":\"" + esc(function.getName())
                        + "\",\"entry\":\"" + function.getEntryPoint()
                        + "\",\"rva\":\"0x" + Long.toHexString(functionRva)
                        + "\",\"size\":" + function.getBody().getNumAddresses()
                        + ",\"cfg\":" + cfgJson(function)
                        + ",\"calls\":" + callsJson(function)
                        + ",\"references\":" + referencesJson(function)
                        + ",\"referencesTruncated\":" + referencesTruncated(function) + "}");
                int seconds = function.getBody().getNumAddresses() >= largeFunctionBytes
                        ? largeFunctionSeconds : perFunctionSeconds;
                DecompileResults results = decompiler.decompileFunction(function, seconds, monitor);
                if (results == null || !results.decompileCompleted()) {
                    failed++;
                    println("(decompile failed)");
                } else {
                    String c = results.getDecompiledFunction() == null
                            ? null : results.getDecompiledFunction().getC();
                    println(c == null ? "(no body)" : c);
                }
                println("FUNCTION_END");
            }
        } finally {
            decompiler.dispose();
        }
        int reached = cursor + emitted;
        Integer resumeCursor = reached < total ? reached : null;
        boolean complete = !timeStopped && failed == 0 && reached == total;
        println("LIST_DONE {\"ok\":true,\"total\":" + total + ",\"cursor\":" + cursor
                + ",\"pageSize\":" + pageSize + ",\"emitted\":" + emitted
                + ",\"failed\":" + failed + ",\"nextCursor\":"
                + (resumeCursor == null ? "null" : resumeCursor)
                + ",\"inventoryComplete\":" + complete
                + ",\"truncated\":" + !complete
                + ",\"timeStopped\":" + timeStopped + ",\"budgetMs\":" + budgetMs + "}");
    }

    private String functionIdentity(Function function) {
        long rva = function.getEntryPoint().getOffset() - currentProgram.getImageBase().getOffset();
        return "{\"name\":\"" + esc(function.getName()) + "\",\"rva\":\"0x"
                + Long.toHexString(rva) + "\"}";
    }

    private String callsJson(Function function) {
        StringBuilder json = new StringBuilder("{");
        json.append(functionListJson(function.getCalledFunctions(monitor), "callees"));
        json.append(',');
        json.append(functionListJson(function.getCallingFunctions(monitor), "callers"));
        return json.append("}").toString();
    }

    private String functionListJson(Set<Function> source, String key) {
        List<Function> ordered = new ArrayList<>(source == null ? Collections.emptyList() : source);
        ordered.sort(Comparator.comparingLong(function -> function.getEntryPoint().getOffset()));
        StringBuilder json = new StringBuilder("\"").append(key).append("\":[");
        for (int i = 0; i < Math.min(32, ordered.size()); i++) {
            if (i > 0) json.append(',');
            json.append(functionIdentity(ordered.get(i)));
        }
        return json.append("],\"").append(key).append("Limited\":")
                .append(ordered.size() > 32).toString();
    }

    private int referenceLimit() {
        return 32;
    }

    private boolean referencesTruncated(Function function) {
        ReferenceManager manager = currentProgram.getReferenceManager();
        int count = 0;
        var sources = manager.getReferenceSourceIterator(function.getBody(), true);
        while (sources.hasNext()) {
            for (Reference reference : manager.getReferencesFrom(sources.next())) {
                if (reference.isMemoryReference() && ++count > referenceLimit()) return true;
            }
        }
        return false;
    }

    private String referencesJson(Function function) {
        ReferenceManager manager = currentProgram.getReferenceManager();
        List<Reference> references = new ArrayList<>();
        var sources = manager.getReferenceSourceIterator(function.getBody(), true);
        while (sources.hasNext() && references.size() <= referenceLimit()) {
            Address from = sources.next();
            for (Reference reference : manager.getReferencesFrom(from)) {
                if (reference.isMemoryReference()) references.add(reference);
                if (references.size() > referenceLimit()) break;
            }
        }
        references.sort(Comparator.comparing(Reference::getFromAddress));
        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < Math.min(referenceLimit(), references.size()); i++) {
            if (i > 0) json.append(',');
            Reference reference = references.get(i);
            Address to = reference.getToAddress();
            long fromRva = reference.getFromAddress().getOffset() - currentProgram.getImageBase().getOffset();
            long toRva = to.getOffset() - currentProgram.getImageBase().getOffset();
            Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(to);
            Data data = currentProgram.getListing().getDataContaining(to);
            json.append("{\"fromRva\":\"0x").append(Long.toHexString(fromRva))
                    .append("\",\"toRva\":\"0x").append(Long.toHexString(toRva))
                    .append("\",\"type\":\"").append(esc(reference.getReferenceType().getName()))
                    .append("\",\"operand\":").append(reference.getOperandIndex())
                    .append(",\"targetName\":\"").append(symbol == null ? "" : esc(symbol.getName()))
                    .append("\"");
            if (data != null && data.hasStringValue()) {
                json.append(",\"string\":\"").append(esc(data.getDefaultValueRepresentation())).append("\"");
            }
            json.append('}');
        }
        return json.append(']').toString();
    }

    /**
     * Control-flow shape of one function: basic blocks, edges, branch blocks,
     * back edges (loops) and the widest fan-out (switch-like dispatch).
     *
     * Two compilations of the same source can differ in text but agree on
     * shape; a function with a different shape is a real structural mismatch
     * even when the decompiler prints the same variable names.
     */
    private String cfgJson(Function function) {
        try {
            BasicBlockModel model = new BasicBlockModel(currentProgram);
            CodeBlockIterator blocks = model.getCodeBlocksContaining(function.getBody(), monitor);
            int blockCount = 0;
            int edges = 0;
            int conditionals = 0;
            int loops = 0;
            int maxFanout = 0;
            while (blocks.hasNext()) {
                CodeBlock block = blocks.next();
                blockCount++;
                long blockStart = block.getFirstStartAddress().getOffset();
                CodeBlockReferenceIterator destinations = block.getDestinations(monitor);
                int fanout = 0;
                while (destinations.hasNext()) {
                    CodeBlockReference reference = destinations.next();
                    edges++;
                    fanout++;
                    Address destination = reference.getDestinationAddress();
                    if (destination != null && destination.getOffset() < blockStart) {
                        loops++;
                    }
                }
                if (fanout > 1) {
                    conditionals++;
                }
                if (fanout > maxFanout) {
                    maxFanout = fanout;
                }
            }
            return "{\"blocks\":" + blockCount + ",\"edges\":" + edges
                    + ",\"conditionals\":" + conditionals + ",\"loops\":" + loops
                    + ",\"maxFanout\":" + maxFanout + "}";
        } catch (Exception error) {
            return "null";
        }
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
