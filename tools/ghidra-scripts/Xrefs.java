// 打印指向给定地址的所有引用（代码引用与数据引用），并给出所在函数。
// 用法： -postScript Xrefs.java 0xADDR [0xADDR ...]
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

public class Xrefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        ReferenceManager rm = currentProgram.getReferenceManager();
        for (String a : args) {
            Address addr = toAddr(a);
            println("== target " + addr);
            ReferenceIterator it = rm.getReferencesTo(addr);
            int n = 0;
            while (it.hasNext()) {
                Reference r = it.next();
                Function f = getFunctionContaining(r.getFromAddress());
                println("XREF " + r.getFromAddress() + " type=" + r.getReferenceType()
                        + " func=" + (f == null ? "(无)" : f.getName()));
                n++;
            }
            println("count=" + n);
        }
    }
}
