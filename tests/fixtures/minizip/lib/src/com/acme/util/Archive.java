package com.acme.util;

/** Fake third-party archive reader: entry names come from an untrusted archive. */
public class Archive {
    private final String path;
    public Archive(String path) { this.path = path; }
    public int size() { return 1; }
    /** Returns the name stored inside the archive (attacker controlled). */
    public String entryName(int i) { return "entry" + i; }
    public byte[] entryBytes(int i) { return new byte[0]; }
}
