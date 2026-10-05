package nesy;

/**
 * Taint API used by generated drivers. Tai-e treats the RESULT of every method below as a
 * taint source (see config/taint/driver-sources.yml), so the bodies are irrelevant.
 */
public final class Taint {
    private Taint() {}
    public static String src() { return new String("nesy-tainted"); }
    public static byte[] srcBytes() { return src().getBytes(); }
    public static java.io.InputStream srcStream() { return new java.io.ByteArrayInputStream(srcBytes()); }
    public static java.io.File srcFile() { return new java.io.File(src()); }
}
