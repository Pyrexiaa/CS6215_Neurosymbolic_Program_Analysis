package nesy;

import java.io.File;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.eclipse.jetty.server.Request;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class NesyDriver {
    public static void main(String[] args) {
        try {
            // MatcherFilter.doFilter
            spark.http.matching.MatcherFilter mf = new spark.http.matching.MatcherFilter(
                new spark.route.Routes() {
                    public void init() {
                        // No-op
                    }
                },
                new spark.staticfiles.StaticFilesConfiguration(),
                false, false
            );
            mf.doFilter((ServletRequest) null, (ServletResponse) null, (FilterChain) null);
        } catch (Throwable t) {}

        try {
            // SparkFilter.doFilter
            spark.servlet.SparkFilter sf = new spark.servlet.SparkFilter();
            sf.doFilter((ServletRequest) null, (ServletResponse) null, (FilterChain) null);
        } catch (Throwable t) {}

        try {
            // JettyHandler.doHandle
            spark.embeddedserver.jetty.JettyHandler jh = new spark.embeddedserver.jetty.JettyHandler((javax.servlet.Filter) null);
            jh.doHandle("", (Request) null, (HttpServletRequest) null, (HttpServletResponse) null);
        } catch (Throwable t) {}

        try {
            // ResourceUtils.getFile(URI, String)
            spark.utils.ResourceUtils.getFile(new URI("http://example.com"), nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            // ResourceUtils.getFile(URL, String)
            spark.utils.ResourceUtils.getFile(new URL("http://example.com"), nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            // ResourceUtils.getFile(String)
            spark.utils.ResourceUtils.getFile(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            // ResourceUtils.getFile(URI)
            spark.utils.ResourceUtils.getFile(new URI("http://example.com"));
        } catch (Throwable t) {}

        try {
            // ResourceUtils.getFile(URL)
            spark.utils.ResourceUtils.getFile(new URL("http://example.com"));
        } catch (Throwable t) {}

        try {
            // StringUtils.applyRelativePath
            spark.utils.StringUtils.applyRelativePath("/base", nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            // StringUtils.getFilename
            spark.utils.StringUtils.getFilename(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            // SimpleRouteMatcher.parseValidateAddRoute
            spark.route.SimpleRouteMatcher srm = new spark.route.SimpleRouteMatcher();
            srm.parseValidateAddRoute(nesy.Taint.src(), "GET", null);
        } catch (Throwable t) {}

        try {
            // AbstractResourceHandler.addPaths
            spark.resource.AbstractResourceHandler.addPaths("/static", nesy.Taint.src());
        } catch (Throwable t) {}
    }
}