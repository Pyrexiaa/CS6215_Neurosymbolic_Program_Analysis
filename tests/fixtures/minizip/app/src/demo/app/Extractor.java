package demo.app;

import com.acme.util.Archive;
import com.acme.util.Shell;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/** Mini subject with one real Zip Slip, one sanitised variant, and one command injection. */
public class Extractor {

    /** VULNERABLE (CWE-22): entry name is joined to destDir without checks. */
    public void extract(String archivePath, String destDir) throws IOException {
        Archive archive = new Archive(archivePath);
        for (int i = 0; i < archive.size(); i++) {
            String name = archive.entryName(i);
            File out = new File(destDir, name);
            write(out, archive.entryBytes(i));
        }
    }

    /** SAFE: canonical path is checked against destDir. */
    public void extractSafely(String archivePath, String destDir) throws IOException {
        Archive archive = new Archive(archivePath);
        File root = new File(destDir).getCanonicalFile();
        for (int i = 0; i < archive.size(); i++) {
            String name = archive.entryName(i);
            File out = new File(root, name).getCanonicalFile();
            if (!out.getPath().startsWith(root.getPath() + File.separator)) {
                throw new IOException("Entry outside target dir: " + name);
            }
            write(out, archive.entryBytes(i));
        }
    }

    /** VULNERABLE (CWE-78): user-provided tool name is passed to a shell. */
    public int runHook(String hookName) {
        String cmd = "sh hooks/" + hookName;
        return Shell.run(cmd);
    }

    private void write(File out, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write(data);
        }
    }
}
