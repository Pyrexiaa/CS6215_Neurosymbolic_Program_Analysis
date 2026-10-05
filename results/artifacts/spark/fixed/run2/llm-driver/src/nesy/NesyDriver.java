package nesy;

import java.io.File;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;

public class NesyDriver {
    public static void main(String[] args) {
        try {
            javax.servlet.ServletRequest req = null;
            javax.servlet.ServletResponse resp = null;
            javax.servlet.FilterChain chain = null;
            spark.servlet.SparkFilter instance0 = new spark.servlet.SparkFilter();
            instance0.doFilter(req, resp, chain);
        } catch (Throwable t) {}

        try {
            javax.servlet.ServletRequest req = null;
            javax.servlet.ServletResponse resp = null;
            javax.servlet.FilterChain chain = null;
            spark.servlet.SparkFilter instance1 = new spark.servlet.SparkFilter();
            instance1.doFilter(req, resp, chain);
        } catch (Throwable t) {}

        try {
            java.io.File result2 = spark.utils.ResourceUtils.getFile(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            java.io.File result3 = spark.utils.ResourceUtils.getFile((java.net.URI) null);
        } catch (Throwable t) {}

        try {
            java.io.File result4 = spark.utils.ResourceUtils.getFile((java.net.URL) null);
        } catch (Throwable t) {}

        try {
            java.io.File result5 = spark.utils.ResourceUtils.getFile((java.net.URI) null, nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            java.io.File result6 = spark.utils.ResourceUtils.getFile((java.net.URL) null, nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            spark.staticfiles.DirectoryTraversal instance7 = new spark.staticfiles.DirectoryTraversal();
            instance7.protectAgainstInClassPath(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            java.lang.String result8 = spark.utils.StringUtils.applyRelativePath("/safe/dir", nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            java.lang.String result9 = spark.utils.StringUtils.getFilename(nesy.Taint.src());
        } catch (Throwable t) {}
    }
}