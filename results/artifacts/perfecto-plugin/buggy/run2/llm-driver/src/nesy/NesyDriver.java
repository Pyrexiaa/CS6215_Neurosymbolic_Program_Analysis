package nesy;

import java.io.File;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

public class NesyDriver {
    public static void main(String[] args) {
        try {
            // Entry: doCheckPerfectoConnectLocation
            io.plugins.perfecto.PerfectoBuildWrapper.DescriptorImpl desc1 = new io.plugins.perfecto.PerfectoBuildWrapper.DescriptorImpl();
            desc1.doCheckPerfectoConnectLocation(nesy.Taint.src(), null);
        } catch (Throwable t) {}

        try {
            // Entry: doCheckPerfectoConnectFile
            io.plugins.perfecto.PerfectoBuildWrapper.DescriptorImpl desc2 = new io.plugins.perfecto.PerfectoBuildWrapper.DescriptorImpl();
            desc2.doCheckPerfectoConnectFile(nesy.Taint.src(), null);
        } catch (Throwable t) {}

        try {
            // Entry: setUp (Plugin hook)
            // Note: setUp requires AbstractBuild, Launcher, BuildListener. 
            // We cannot easily instantiate these without Jenkins core, but we can call setters first.
            // We will focus on the setters that configure the wrapper.
        } catch (Throwable t) {}

        try {
            // Entry: setPerfectoConnectLocation
            io.plugins.perfecto.PerfectoBuildWrapper wrapper1 = new io.plugins.perfecto.PerfectoBuildWrapper(
                null, null, null, null, null, null, null, null
            );
            wrapper1.setPerfectoConnectLocation(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            // Entry: setPerfectoConnectFile
            io.plugins.perfecto.PerfectoBuildWrapper wrapper2 = new io.plugins.perfecto.PerfectoBuildWrapper(
                null, null, null, null, null, null, null, null
            );
            wrapper2.setPerfectoConnectFile(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            // Entry: setPcParameters
            io.plugins.perfecto.PerfectoBuildWrapper wrapper3 = new io.plugins.perfecto.PerfectoBuildWrapper(
                null, null, null, null, null, null, null, null
            );
            wrapper3.setPcParameters(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            // Entry: setTunnelIdCustomName
            io.plugins.perfecto.PerfectoBuildWrapper wrapper4 = new io.plugins.perfecto.PerfectoBuildWrapper(
                null, null, null, null, null, null, null, null
            );
            wrapper4.setTunnelIdCustomName(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            // Entry: setSecurityToken
            io.plugins.perfecto.PerfectoBuildWrapper wrapper5 = new io.plugins.perfecto.PerfectoBuildWrapper(
                null, null, null, null, null, null, null, null
            );
            wrapper5.setSecurityToken(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            // Entry: setCredentialId
            io.plugins.perfecto.PerfectoBuildWrapper wrapper6 = new io.plugins.perfecto.PerfectoBuildWrapper(
                null, null, null, null, null, null, null, null
            );
            wrapper6.setCredentialId(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            // Entry: doAuthenticate
            io.plugins.perfecto.credentials.PerfectoCredentials.DescriptorImpl desc3 = new io.plugins.perfecto.credentials.PerfectoCredentials.DescriptorImpl();
            desc3.doAuthenticate(nesy.Taint.src(), nesy.Taint.src(), nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            // Entry: doCheckApiKey
            io.plugins.perfecto.credentials.PerfectoCredentials.DescriptorImpl desc4 = new io.plugins.perfecto.credentials.PerfectoCredentials.DescriptorImpl();
            desc4.doCheckApiKey(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            // Entry: doCheckCloudName
            io.plugins.perfecto.credentials.PerfectoCredentials.DescriptorImpl desc5 = new io.plugins.perfecto.credentials.PerfectoCredentials.DescriptorImpl();
            desc5.doCheckCloudName(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            // Entry: doCheckUserName
            io.plugins.perfecto.credentials.PerfectoCredentials.DescriptorImpl desc6 = new io.plugins.perfecto.credentials.PerfectoCredentials.DescriptorImpl();
            desc6.doCheckUserName(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            // Entry: doCheckCredentialId
            io.plugins.perfecto.PerfectoBuildWrapper.DescriptorImpl desc7 = new io.plugins.perfecto.PerfectoBuildWrapper.DescriptorImpl();
            desc7.doCheckCredentialId(null, nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            // Entry: doFillCredentialIdItems
            io.plugins.perfecto.PerfectoBuildWrapper.DescriptorImpl desc8 = new io.plugins.perfecto.PerfectoBuildWrapper.DescriptorImpl();
            desc8.doFillCredentialIdItems(null, nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            // Entry: testAuthentication
            io.plugins.perfecto.credentials.PerfectoCredentials.testAuthentication(
                nesy.Taint.src(), nesy.Taint.src(), nesy.Taint.src()
            );
        } catch (Throwable t) {}

        try {
            // Entry: migrateToCredentials
            io.plugins.perfecto.credentials.PerfectoCredentials.migrateToCredentials(
                nesy.Taint.src(), nesy.Taint.src(), nesy.Taint.src(), nesy.Taint.src()
            );
        } catch (Throwable t) {}

        try {
            // Entry: getCredentialsById
            io.plugins.perfecto.credentials.PerfectoCredentials.getCredentialsById(null, nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            // Entry: outputEnvironmentVariable
            Map<String, String> env = new HashMap<>();
            io.plugins.perfecto.PerfectoEnvironmentUtil.outputEnvironmentVariable(
                env, nesy.Taint.src(), nesy.Taint.src(), false
            );
        } catch (Throwable t) {}
    }
}