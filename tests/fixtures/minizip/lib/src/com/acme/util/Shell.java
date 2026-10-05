package com.acme.util;

/** Fake third-party helper that runs a shell command. */
public class Shell {
    public static int run(String command) {
        try { return Runtime.getRuntime().exec(command).waitFor(); }
        catch (Exception e) { return -1; }
    }
}
