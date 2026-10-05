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
            spark.staticfiles.StaticFilesConfiguration sfc = new spark.staticfiles.StaticFilesConfiguration();
            spark.http.matching.MatcherFilter mf = new spark.http.matching.MatcherFilter(
                null,
                sfc,
                false, false);
            mf.doFilter(req, resp, chain);
        } catch (Throwable t) {}

        try {
            javax.servlet.ServletRequest req = null;
            javax.servlet.ServletResponse resp = null;
            javax.servlet.FilterChain chain = null;
            spark.servlet.SparkFilter sf = new spark.servlet.SparkFilter();
            sf.doFilter(req, resp, chain);
        } catch (Throwable t) {}

        try {
            String method = null;
            org.eclipse.jetty.server.Request jettyReq = null;
            javax.servlet.http.HttpServletRequest httpReq = null;
            javax.servlet.http.HttpServletResponse httpResp = null;
            spark.embeddedserver.jetty.JettyHandler jh = new spark.embeddedserver.jetty.JettyHandler(null);
            jh.doHandle(method, jettyReq, httpReq, httpResp);
        } catch (Throwable t) {}

        try {
            java.io.File res = spark.utils.ResourceUtils.getFile(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            java.io.File res = spark.utils.ResourceUtils.getFile((java.net.URI) null);
        } catch (Throwable t) {}

        try {
            java.io.File res = spark.utils.ResourceUtils.getFile((java.net.URL) null);
        } catch (Throwable t) {}

        try {
            java.io.File res = spark.utils.ResourceUtils.getFile((java.net.URI) null, nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            java.io.File res = spark.utils.ResourceUtils.getFile((java.net.URL) null, nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            java.lang.String res = spark.resource.AbstractResourceHandler.addPaths("/static", nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            java.lang.String res = spark.utils.StringUtils.applyRelativePath("/base", nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            spark.Spark.externalStaticFileLocation(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            spark.Spark.staticFileLocation(nesy.Taint.src());
        } catch (Throwable t) {}
    }
}