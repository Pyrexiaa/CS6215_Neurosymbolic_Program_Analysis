package nesy;

public class NesyDriver {
    public static void main(String[] args) {
        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(new java.io.File("/tmp/ztzip.zip"), nesy.Taint.src(), new java.io.File("/tmp/out"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(new java.io.File("/tmp/ztzip.zip"), nesy.Taint.src(), new java.io.File("/tmp/out"), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(nesy.Taint.srcStream(), nesy.Taint.src(), new java.io.File("/tmp/out"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(new java.util.zip.ZipFile("/tmp/ztzip.zip"), nesy.Taint.src(), new java.io.File("/tmp/out"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(new java.io.File("/tmp/ztzip.zip"), nesy.Taint.src());
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(new java.io.File("/tmp/ztzip.zip"), nesy.Taint.src(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(nesy.Taint.srcStream(), nesy.Taint.src());
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(new java.util.zip.ZipFile("/tmp/ztzip.zip"), nesy.Taint.src());
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.getCompressionMethodOfEntry(new java.io.File("/tmp/ztzip.zip"), nesy.Taint.src());
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcFile(), new java.io.File("/tmp/out"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcFile(), new java.io.File("/tmp/out"), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcFile(), new java.io.File("/tmp/out"), (org.zeroturnaround.zip.NameMapper) null);
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcFile(), new java.io.File("/tmp/out"), (org.zeroturnaround.zip.NameMapper) null, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcStream(), new java.io.File("/tmp/out"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcStream(), new java.io.File("/tmp/out"), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcStream(), new java.io.File("/tmp/out"), (org.zeroturnaround.zip.NameMapper) null);
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcStream(), new java.io.File("/tmp/out"), (org.zeroturnaround.zip.NameMapper) null, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unwrap(nesy.Taint.srcFile(), new java.io.File("/tmp/out"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unwrap(nesy.Taint.srcFile(), new java.io.File("/tmp/out"), (org.zeroturnaround.zip.NameMapper) null);
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unwrap(nesy.Taint.srcStream(), new java.io.File("/tmp/out"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unwrap(nesy.Taint.srcStream(), new java.io.File("/tmp/out"), (org.zeroturnaround.zip.NameMapper) null);
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.explode(nesy.Taint.srcFile());
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unexplode(nesy.Taint.srcFile());
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unexplode(nesy.Taint.srcFile(), 0);
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.replaceEntry(new java.io.File("/tmp/ztzip.zip"), nesy.Taint.src(), nesy.Taint.srcBytes());
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.replaceEntry(new java.io.File("/tmp/ztzip.zip"), nesy.Taint.src(), nesy.Taint.srcBytes(), 0);
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.replaceEntry(new java.io.File("/tmp/ztzip.zip"), nesy.Taint.src(), nesy.Taint.srcBytes(), new java.io.File("/tmp/out"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.replaceEntry(new java.io.File("/tmp/ztzip.zip"), nesy.Taint.src(), new java.io.File("/tmp/out"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.replaceEntry(new java.io.File("/tmp/ztzip.zip"), nesy.Taint.src(), new java.io.File("/tmp/out"), new java.io.File("/tmp/out"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.transformEntry(new java.io.File("/tmp/ztzip.zip"), nesy.Taint.src(), (org.zeroturnaround.zip.transform.ZipEntryTransformer) null, new java.io.File("/tmp/out"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.entryEquals(new java.io.File("/tmp/ztzip.zip"), new java.io.File("/tmp/ztzip2.zip"), nesy.Taint.src());
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.entryEquals(new java.io.File("/tmp/ztzip.zip"), new java.io.File("/tmp/ztzip2.zip"), nesy.Taint.src(), nesy.Taint.src());
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.entryEquals(new java.util.zip.ZipFile("/tmp/ztzip.zip"), new java.util.zip.ZipFile("/tmp/ztzip2.zip"), nesy.Taint.src(), nesy.Taint.src());
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.handle(new java.io.File("/tmp/ztzip.zip"), nesy.Taint.src(), (org.zeroturnaround.zip.ZipEntryCallback) null);
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.handle(nesy.Taint.srcStream(), nesy.Taint.src(), (org.zeroturnaround.zip.ZipEntryCallback) null);
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.extra.AsiExtraField field = new org.zeroturnaround.zip.extra.AsiExtraField();
            field.setLinkedFile(nesy.Taint.src());
        } catch (Throwable t) {}
    }
}