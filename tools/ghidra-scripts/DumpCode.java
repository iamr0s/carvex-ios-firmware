// Targeted Ghidra export for firmware research.
// Usage:
//   -postScript DumpCode.java fn:0xADDR [fn:0xADDR ...]
//   -postScript DumpCode.java range:0xSTART:0xEND [range:0xSTART:0xEND ...]
// @category CarPlay.Research
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.util.regex.Pattern;

public class DumpCode extends GhidraScript {
    private Function resolveFunction(String text) throws Exception {
        Address address = toAddr(text);
        Function function = getFunctionAt(address);
        if (function != null) {
            return function;
        }
        disassemble(address);
        return getFunctionAt(address);
    }

    private void dumpFunction(DecompInterface decompiler, String text) throws Exception {
        Function function = resolveFunction(text);
        if (function == null) {
            println("FUNCTION_NOT_FOUND " + text);
            return;
        }
        println("=== FUNCTION " + function.getName()
                + " entry=" + function.getEntryPoint()
                + " body=" + function.getBody().getMinAddress()
                + ".." + function.getBody().getMaxAddress());
        DecompileResults result = decompiler.decompileFunction(function, 120, monitor);
        if (result.getDecompiledFunction() == null) {
            println("DECOMPILE_FAILED " + result.getErrorMessage());
            return;
        }
        println(result.getDecompiledFunction().getC());
    }

    private void dumpRange(String startText, String endText) throws Exception {
        Address start = toAddr(startText);
        Address end = toAddr(endText);
        println("=== RANGE " + start + ".." + end);
        InstructionIterator instructions = currentProgram.getListing().getInstructions(start, true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            if (instruction.getAddress().compareTo(end) > 0) {
                break;
            }
            println(instruction.getAddress() + "  " + instruction);
        }
    }

    private void findSymbols(String expression) {
        Pattern pattern = Pattern.compile(expression, Pattern.CASE_INSENSITIVE);
        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        int count = 0;
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (!pattern.matcher(symbol.getName()).find()) {
                continue;
            }
            Function function = getFunctionAt(symbol.getAddress());
            println("SYMBOL " + symbol.getAddress()
                    + " function=" + (function == null ? "-" : function.getName())
                    + " name=" + symbol.getName());
            count++;
        }
        println("SYMBOL_COUNT " + count + " expression=" + expression);
    }

    @Override
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(false);
        if (!decompiler.openProgram(currentProgram)) {
            println("DECOMPILER_OPEN_FAILED " + decompiler.getLastMessage());
            return;
        }
        for (String argument : getScriptArgs()) {
            if (argument.startsWith("fn:")) {
                dumpFunction(decompiler, argument.substring(3));
            } else if (argument.startsWith("range:")) {
                String[] parts = argument.split(":", 3);
                if (parts.length != 3) {
                    println("BAD_RANGE " + argument);
                    continue;
                }
                dumpRange(parts[1], parts[2]);
            } else if (argument.startsWith("find:")) {
                findSymbols(argument.substring(5));
            } else {
                println("BAD_ARGUMENT " + argument);
            }
        }
        decompiler.dispose();
    }
}
