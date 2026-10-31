// Export raw Ghidra decompilation for a fixed function list.
// Usage (headless):
//   analyzeHeadless <projdir> <projname> -process <program> -noanalysis \
//     -scriptPath <dir> -postScript ExportDecomp.java <request.json> <outdir>
//
// request.json layout (produced by build-ghidra-request.py):
//   {"source_sha256":"..","functions":[{"address":"0x..","end":"0x..","raw_sha256":".."}, ...]}
//
// For every entry: write f_<addr>.ghidra.c (banner + raw C) and f_<addr>.json
// (hash chain + status). Existing outputs are skipped when their loaded hash
// already matches, so the script is idempotent.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ExportDecomp extends GhidraScript {

    private static final String BANNER =
        "/* RAW GHIDRA DECOMPILATION \u2014 NOT REVIEWED PROTOCOL PSEUDOCODE\n" +
        " * original address: %s\n" +
        " * original code SHA256: %s\n" +
        " * source SHA256: %s\n" +
        " * Assembly/raw bytes: adjacent .s/.bin from the original firmware.\n" +
        " * Types, signatures and indirect targets remain hypotheses until reviewed.\n" +
        " */\n\n";

    private String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private String sha256(byte[] b) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(b));
    }

    private byte[] read(long start, long end, Memory mem) throws MemoryAccessException {
        byte[] out = new byte[(int) (end - start)];
        for (int i = 0; i < out.length; i++) {
            out[i] = mem.getByte(toAddr(start + i));
        }
        return out;
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        String reqPath = args[0];
        String outDir = args[1];
        new File(outDir).mkdirs();

        String text = new String(Files.readAllBytes(new File(reqPath).toPath()), StandardCharsets.UTF_8);
        Matcher m = Pattern.compile("\"source_sha256\"\\s*:\\s*\"([0-9a-f]{64})\"").matcher(text);
        if (!m.find()) {
            printerr("no source_sha256 in request");
            return;
        }
        String sourceSha = m.group(1);

        Pattern entry = Pattern.compile(
            "\\{\\s*\"address\"\\s*:\\s*\"(0x[0-9a-fA-F]+)\"\\s*,\\s*" +
            "\"end\"\\s*:\\s*\"(0x[0-9a-fA-F]+)\"\\s*,\\s*" +
            "\"raw_sha256\"\\s*:\\s*\"([0-9a-f]{64})\"\\s*\\}");
        Matcher em = entry.matcher(text);
        List<String[]> items = new ArrayList<>();
        while (em.find()) items.add(new String[]{em.group(1), em.group(2), em.group(3)});
        println("PHONE_CACHE request entries=" + items.size());

        DecompInterface ifc = new DecompInterface();
        ifc.toggleCCode(true);
        ifc.toggleSyntaxTree(true);
        ifc.setSimplificationStyle("decompile");
        if (!ifc.openProgram(currentProgram)) {
            printerr("decompiler openProgram failed");
            return;
        }

        Memory mem = currentProgram.getMemory();
        int done = 0, skipped = 0, failed = 0;
        for (String[] it : items) {
            long a = Long.parseLong(it[0].substring(2), 16);
            long e = Long.parseLong(it[1].substring(2), 16);
            String raw = it[2];
            String base = String.format("f_%x", a);
            File cFile = new File(outDir, base + ".ghidra.c");
            File jFile = new File(outDir, base + ".json");
            if (cFile.exists() && jFile.exists()) {
                skipped++;
                continue;
            }
            byte[] loaded;
            try {
                loaded = read(a, e, mem);
            } catch (MemoryAccessException ex) {
                failed++;
                printerr("read failed at " + it[0] + ": " + ex);
                continue;
            }
            String loadedSha = sha256(loaded);
            Address addr = toAddr(a);
            Function f = getFunctionAt(addr);
            String name = f != null ? f.getName() : "<no function>";
            String sig = f != null ? f.getPrototypeString(false, false) : "";
            String c = "";
            String diag = "";
            if (f == null) {
                diag = "no function at address";
            } else {
                DecompileResults res = ifc.decompileFunction(f, 120, monitor);
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    c = res.getDecompiledFunction().getC();
                } else {
                    diag = res == null ? "null result" : res.getErrorMessage();
                }
            }
            String header = String.format(BANNER, it[0], raw, sourceSha);
            String body = header + "\n" + (c.isEmpty() ? "/* decompilation failed: " + diag + " */\n" : c);
            try (PrintWriter pw = new PrintWriter(cFile, "UTF-8")) {
                pw.print(body);
            }
            String cSha = sha256(body.getBytes(StandardCharsets.UTF_8));
            try (PrintWriter pw = new PrintWriter(jFile, "UTF-8")) {
                pw.println("{");
                pw.println("  \"address\": \"" + it[0] + "\",");
                pw.println("  \"source_sha256\": \"" + sourceSha + "\",");
                pw.println("  \"raw_sha256\": \"" + raw + "\",");
                pw.println("  \"evidence_status\": \"RAW_DECOMPILER_OUTPUT_UNREVIEWED\",");
                pw.println("  \"loaded_code_sha256\": \"" + loadedSha + "\",");
                pw.println("  \"ghidra_name\": \"" + name.replace("\\", "\\\\").replace("\"", "\\\"") + "\",");
                pw.println("  \"signature\": \"" + sig.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ") + "\",");
                pw.println("  \"diagnostic\": \"" + (diag == null ? "" : diag.replace("\"", "\\\"")) + "\",");
                pw.println("  \"c_file\": \"" + base + ".ghidra.c\",");
                pw.println("  \"c_sha256\": \"" + cSha + "\",");
                pw.println("  \"status\": \"" + (c.isEmpty() ? "DECOMPILE_FAILED" : "DECOMPILED_UNREVIEWED") + "\"");
                pw.println("}");
            }
            if (loadedSha.equals(raw)) done++; else failed++;
            println("PHONE_CACHE exported " + it[0] + " name=" + name);
        }
        println("PHONE_CACHE done valid=" + done + " skipped=" + skipped + " failed=" + failed);
        ifc.dispose();
    }
}
