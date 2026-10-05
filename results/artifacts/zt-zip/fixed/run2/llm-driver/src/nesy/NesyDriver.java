package nesy;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.zip.ZipFile;

public class NesyDriver {
    public static void main(String[] args) {
        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(new java.io.File("/tmp/zip.zip"), nesy.Taint.src(), new java.io.File("/tmp/out"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(new java.io.File("/tmp/zip.zip"), nesy.Taint.src(), new java.io.File("/tmp/out"), Charset.forName("UTF-8"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(nesy.Taint.srcStream(), nesy.Taint.src(), new java.io.File("/tmp/out"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(new ZipFile("/tmp/zip.zip"), nesy.Taint.src(), new java.io.File("/tmp/out"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(new java.io.File("/tmp/zip.zip"), nesy.Taint.src());
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(new java.io.File("/tmp/zip.zip"), nesy.Taint.src(), Charset.forName("UTF-8"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(nesy.Taint.srcStream(), nesy.Taint.src());
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpackEntry(new ZipFile("/tmp/zip.zip"), nesy.Taint.src());
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcFile(), new java.io.File("/tmp/out"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcFile(), new java.io.File("/tmp/out"), Charset.forName("UTF-8"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcFile(), new java.io.File("/tmp/out"), (org.zeroturnaround.zip.NameMapper) null);
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcFile(), new java.io.File("/tmp/out"), (org.zeroturnaround.zip.NameMapper) null, Charset.forName("UTF-8"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcStream(), new java.io.File("/tmp/out"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcStream(), new java.io.File("/tmp/out"), Charset.forName("UTF-8"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcStream(), new java.io.File("/tmp/out"), (org.zeroturnaround.zip.NameMapper) null);
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.unpack(nesy.Taint.srcStream(), new java.io.File("/tmp/out"), (org.zeroturnaround.zip.NameMapper) null, Charset.forName("UTF-8"));
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
            org.zeroturnaround.zip.ZipUtil.replaceEntry(new java.io.File("/tmp/zip.zip"), nesy.Taint.src(), nesy.Taint.srcBytes());
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.replaceEntry(new java.io.File("/tmp/zip.zip"), nesy.Taint.src(), nesy.Taint.srcBytes(), 0);
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.replaceEntry(new java.io.File("/tmp/zip.zip"), nesy.Taint.src(), nesy.Taint.srcBytes(), new java.io.File("/tmp/out"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.replaceEntry(new java.io.File("/tmp/zip.zip"), nesy.Taint.src(), new java.io.File("/tmp/in"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.replaceEntry(new java.io.File("/tmp/zip.zip"), nesy.Taint.src(), new java.io.File("/tmp/in"), new java.io.File("/tmp/out"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.transformEntry(new java.io.File("/tmp/zip.zip"), nesy.Taint.src(), null, new java.io.File("/tmp/out"));
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.handle(new java.io.File("/tmp/zip.zip"), nesy.Taint.src(), null);
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.handle(nesy.Taint.srcStream(), nesy.Taint.src(), null);
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.getCompressionMethodOfEntry(new java.io.File("/tmp/zip.zip"), nesy.Taint.src());
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.entryEquals(new java.io.File("/tmp/zip1.zip"), new java.io.File("/tmp/zip2.zip"), nesy.Taint.src());
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.entryEquals(new java.io.File("/tmp/zip1.zip"), new java.io.File("/tmp/zip2.zip"), nesy.Taint.src(), nesy.Taint.src());
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.ZipUtil.entryEquals(new ZipFile("/tmp/zip1.zip"), new ZipFile("/tmp/zip2.zip"), nesy.Taint.src(), nesy.Taint.src());
        } catch (Throwable t) {}
        try {
            org.zeroturnaround.zip.extra.AsiExtraField field = new org.zeroturnaround.zip.extra.AsiExtraField();
            field.setLinkedFile(nesy.Taint.src());
        } catch (Throwable t) {}
    }
}