package nesy;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.zip.ZipFile;

public class NesyDriver {
    public static void main(String[] args) {
        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(new File("/tmp/zt-zip-test.zip"), nesy.Taint.src(), new File("/tmp/out"));
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(new File("/tmp/zt-zip-test.zip"), nesy.Taint.src(), new File("/tmp/out"), Charset.forName("UTF-8"));
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(nesy.Taint.srcStream(), nesy.Taint.src(), new File("/tmp/out"));
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(new ZipFile("/tmp/zt-zip-test.zip"), nesy.Taint.src(), new File("/tmp/out"));
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(new File("/tmp/zt-zip-test.zip"), nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(new File("/tmp/zt-zip-test.zip"), nesy.Taint.src(), Charset.forName("UTF-8"));
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(nesy.Taint.srcStream(), nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(new ZipFile("/tmp/zt-zip-test.zip"), nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcFile(), new File("/tmp/out"));
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcFile(), new File("/tmp/out"), Charset.forName("UTF-8"));
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcFile(), new File("/tmp/out"), (org.zeroturnaround.zip.NameMapper) null);
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcFile(), new File("/tmp/out"), (org.zeroturnaround.zip.NameMapper) null, Charset.forName("UTF-8"));
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcStream(), new File("/tmp/out"));
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcStream(), new File("/tmp/out"), Charset.forName("UTF-8"));
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcStream(), new File("/tmp/out"), (org.zeroturnaround.zip.NameMapper) null);
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcStream(), new File("/tmp/out"), (org.zeroturnaround.zip.NameMapper) null, Charset.forName("UTF-8"));
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.unwrap(nesy.Taint.srcFile(), new File("/tmp/out"));
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.unwrap(nesy.Taint.srcFile(), new File("/tmp/out"), (org.zeroturnaround.zip.NameMapper) null);
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.unwrap(nesy.Taint.srcStream(), new File("/tmp/out"));
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.unwrap(nesy.Taint.srcStream(), new File("/tmp/out"), (org.zeroturnaround.zip.NameMapper) null);
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
            org.zeroturnaround.zip.ZipUtil.replaceEntry(new File("/tmp/zt-zip-test.zip"), nesy.Taint.src(), nesy.Taint.srcBytes());
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.replaceEntry(new File("/tmp/zt-zip-test.zip"), nesy.Taint.src(), nesy.Taint.srcBytes(), 0);
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.replaceEntry(new File("/tmp/zt-zip-test.zip"), nesy.Taint.src(), nesy.Taint.srcBytes(), new File("/tmp/zt-zip-test.zip"));
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.replaceEntry(new File("/tmp/zt-zip-test.zip"), nesy.Taint.src(), new File("/tmp/zt-zip-test.zip"));
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.replaceEntry(new File("/tmp/zt-zip-test.zip"), nesy.Taint.src(), new File("/tmp/zt-zip-test.zip"), new File("/tmp/zt-zip-test.zip"));
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.transformEntry(new File("/tmp/zt-zip-test.zip"), nesy.Taint.src(), null, new File("/tmp/out"));
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.handle(new File("/tmp/zt-zip-test.zip"), nesy.Taint.src(), null);
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.handle(nesy.Taint.srcStream(), nesy.Taint.src(), null);
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.getCompressionMethodOfEntry(new File("/tmp/zt-zip-test.zip"), nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.entryEquals(new File("/tmp/zt-zip-test.zip"), new File("/tmp/zt-zip-test.zip"), nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.entryEquals(new File("/tmp/zt-zip-test.zip"), new File("/tmp/zt-zip-test.zip"), nesy.Taint.src(), nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.entryEquals(new ZipFile("/tmp/zt-zip-test.zip"), new ZipFile("/tmp/zt-zip-test.zip"), nesy.Taint.src(), nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.addOrReplaceEntries(new File("/tmp/zt-zip-test.zip"), new org.zeroturnaround.zip.ZipEntrySource[]{null}, new File("/tmp/out"));
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.addOrReplaceEntries(new File("/tmp/zt-zip-test.zip"), new org.zeroturnaround.zip.ZipEntrySource[]{null});
        } catch (Throwable t) {}

        try {
            org.zeroturnaround.zip.ZipUtil.BackslashUnpacker unpacker = new org.zeroturnaround.zip.ZipUtil.BackslashUnpacker(new File("/tmp/out"));
            unpacker.process(nesy.Taint.srcStream(), null);
        } catch (Throwable t) {}
    }
}