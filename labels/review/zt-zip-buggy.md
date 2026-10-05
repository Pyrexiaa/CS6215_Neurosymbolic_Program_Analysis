# Labelling pack: zt-zip / buggy

115 frozen sampled rows. Evidence uses the exact raw source and sink in the chosen run record. Existing labels remain unverified and are unchanged. A canonical key may still group different drivers or routes; inspect the attacker model before reusing a label. Original packets are retained in results/history/pre-evidence-refresh.tar.gz.

---

## 1/115 flow_id ed4d903a40 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow ed4d903a40
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1250/result => <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>@L57/1
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L1250] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>[9@L57] invokespecial file.<init>(dir, %v11)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>
file: org/zeroturnaround/zip/ZTFileUtil.java
   50 | 
   51 |   private static void innerListFiles(File dir, Collection<File> accumulator, FileFilter filter) {
   52 | 
   53 |     String[] filenames = dir.list();
   54 | 
   55 |     if (filenames != null) {
   56 |       for (int i = 0; i < filenames.length; i++) {
   57 |         File file = new File(dir, filenames[i]);
   58 |         if (file.isDirectory()) {
   59 |           innerListFiles(file, accumulator, filter);
   60 |         }
   61 |         else {
   62 |           if (filter != null && filter.accept(file)) {
   63 |             accumulator.add(file);
   64 |           }
   65 |         }
   66 |       }
   67 |     }
   68 |   }
   69 | }

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
```

---

## 2/115 flow_id 2c93fcaeda (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 2c93fcaeda
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1250/result => <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>@L61/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L1250] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>[7@L61] invokespecial copy.<init>(%v5)/0
fixed methods on this flow (GT): Unwraper.process
reported by: iris-like run0, v1 run0, v2 run0, v3 run0, v3-noV2 run0, v3-noV3 run0, v3-noval run0, v4 run0
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>
file: org/zeroturnaround/zip/ZipEntryUtil.java
   58 |    * @return copy of the original entry, but with the given name
   59 |    */
   60 |   static ZipEntry copy(ZipEntry original, String newName) {
   61 |     ZipEntry copy = new ZipEntry(newName == null ? original.getName() : newName);
   62 |     if (original.getCrc() != -1) {
   63 |       copy.setCrc(original.getCrc());
   64 |     }
   65 |     if (original.getMethod() != -1) {
   66 |       copy.setMethod(original.getMethod());
   67 |     }
   68 |     if (original.getSize() >= 0) {
   69 |       copy.setSize(original.getSize());
   70 |     }
   71 |     if (original.getExtra() != null) {
   72 |       copy.setExtra(original.getExtra());
   73 |     }
   74 | 
   75 |     copy.setComment(original.getComment());
   76 |     copy.setTime(original.getTime());
   77 |     return copy;
   78 |   }
   79 | 
   80 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
```

---

## 3/115 flow_id 48172fd182 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 48172fd182
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1258/result => <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>@L61/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[24@L1258] %v24 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>[7@L61] invokespecial copy.<init>(%v5)/0
fixed methods on this flow (GT): Unwraper.process
reported by: iris-like run0, v1 run0, v2 run0, v3 run0, v3-noV2 run0, v3-noV3 run0, v3-noval run0, v4 run0
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry fromFile(java.lang.String,java.io.File)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry fromFile(java.lang.String,java.io.File)>
file: org/zeroturnaround/zip/ZipEntryUtil.java
  141 |    * @return newly created Zip entry
  142 |    */
  143 |   static ZipEntry fromFile(String name, File file) {
  144 |     ZipEntry zipEntry = new ZipEntry(name);
  145 |     if (!file.isDirectory()) {
  146 |       zipEntry.setSize(file.length());
  147 |     }
  148 |     zipEntry.setTime(file.lastModified());
  149 | 
  150 |     ZTFilePermissions permissions = ZTFilePermissionsUtil.getDefaultStategy().getPermissions(file);
  151 |     if (permissions != null) {
  152 |       ZipEntryUtil.setZTFilePermissions(zipEntry, permissions);
  153 |     }
  154 |     return zipEntry;
  155 |   }
  156 | 
  157 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
 1278 |     }
 1279 | 
 1280 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>
file: org/zeroturnaround/zip/ZipEntryUtil.java
   58 |    * @return copy of the original entry, but with the given name
   59 |    */
   60 |   static ZipEntry copy(ZipEntry original, String newName) {
   61 |     ZipEntry copy = new ZipEntry(newName == null ? original.getName() : newName);
   62 |     if (original.getCrc() != -1) {
   63 |       copy.setCrc(original.getCrc());
   64 |     }
   65 |     if (original.getMethod() != -1) {
   66 |       copy.setMethod(original.getMethod());
   67 |     }
   68 |     if (original.getSize() >= 0) {
   69 |       copy.setSize(original.getSize());
   70 |     }
   71 |     if (original.getExtra() != null) {
   72 |       copy.setExtra(original.getExtra());
   73 |     }
   74 | 
   75 |     copy.setComment(original.getComment());
   76 |     copy.setTime(original.getTime());
   77 |     return copy;
   78 |   }
   79 | 
   80 |   /**
```

---

## 4/115 flow_id d694052c21 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow d694052c21
key        : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1150/result => <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1214/0
source     : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1150] %v7 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[19@L1214] invokespecial file.<init>(parentDirectory, %v22)/0
fixed methods on this flow (GT): Unpacker.process
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtils: void copy(java.io.InputStream,java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtils: void copy(java.io.InputStream,java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtils.java
   51 |    * @throws java.io.IOException if file is not found or copying fails
   52 |    */
   53 |   public static void copy(InputStream in, File file) throws IOException {
   54 |     OutputStream out = new BufferedOutputStream(new FileOutputStream(file));
   55 |     try {
   56 |       IOUtils.copy(in, out);
   57 |     }
   58 |     finally {
   59 |       IOUtils.closeQuietly(out);
   60 |     }
   61 |   }
   62 | 
   63 |   /**
   64 |    * Find a non-existing file in the same directory using the same name as prefix.
```

---

## 5/115 flow_id 60eda43e2b (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 60eda43e2b
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1250/result => <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1214/1
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L1250] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[19@L1214] invokespecial file.<init>(parentDirectory, %v22)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
```

---

## 6/115 flow_id 3e0dff1d0a (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 3e0dff1d0a
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1250/result => <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1220/1
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L1250] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[30@L1220] invokespecial destFile.<init>(parentDirectory, %v27)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
```

---

## 7/115 flow_id 74f8b2218d (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 74f8b2218d
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1258/result => <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1220/1
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[24@L1258] %v24 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[30@L1220] invokespecial destFile.<init>(parentDirectory, %v27)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
 1278 |     }
 1279 | 
 1280 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
```

---

## 8/115 flow_id 739dd783a9 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 739dd783a9
key        : DRIVER => <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1152/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[168@L69] %v105 = invokestatic nesy.Taint.srcFile()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[7@L1152] invokespecial file.<init>(%v11, name)/0
fixed methods on this flow (GT): Unpacker.process
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[168@L69] %v105 = invokestatic nesy.Taint.srcFile()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v105}
3. VarNode{<org.zeroturnaround.zip.ZipUtil: void explode(java.io.File)>/zip}
4. VarNode{<org.zeroturnaround.zip.ZipUtil: void unpack(java.io.File,java.io.File)>/outputDir}
5. VarNode{<org.zeroturnaround.zip.ZipUtil: void unpack(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper)>/outputDir}
6. VarNode{<org.zeroturnaround.zip.ZipUtil$Unpacker: void <init>(java.io.File,org.zeroturnaround.zip.NameMapper)>/outputDir}
7. InstanceFieldNode{NewObj{<org.zeroturnaround.zip.ZipUtil: void unpack(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper)>[3@L996] new org.zeroturnaround.zip.ZipUtil$Unpacker}.<org.zeroturnaround.zip.ZipUtil$Unpacker: java.io.File outputDir>}
8. VarNode{<org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>/%v11}
9. <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[7@L1152] invokespecial file.<init>(%v11, name)/0

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void explode(java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 1301 |   public static void explode(File zip) {
 1302 |     try {
 1303 |       // Find a new unique name is the same directory
 1304 |       File tempFile = FileUtils.getTempFileFor(zip);
 1305 | 
 1306 |       // Rename the archive
 1307 |       FileUtils.moveFile(zip, tempFile);
 1308 | 
 1309 |       // Unpack it
 1310 |       unpack(tempFile, zip);
 1311 | 
 1312 |       // Delete the archive
 1313 |       if (!tempFile.delete()) {
 1314 |         throw new IOException("Unable to delete file: " + tempFile);
 1315 |       }
 1316 |     }
 1317 |     catch (IOException e) {
 1318 |       throw ZipExceptionUtil.rethrow(e);
 1319 |     }
 1320 |   }
 1321 | 
 1322 |   /* Compressing single entries to ZIP files. */
 1323 | 

### <org.zeroturnaround.zip.ZipUtil: void unpack(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
  936 |    *          output directory (created automatically if not found).
  937 |    */
  938 |   public static void unpack(File zip, final File outputDir) {
  939 |     unpack(zip, outputDir, IdentityNameMapper.INSTANCE);
  940 |   }
  941 | 
  942 |   /**
  943 |    * Unpacks a ZIP file to the given directory using a specific Charset

### <org.zeroturnaround.zip.ZipUtil: void unpack(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper)>
file: org/zeroturnaround/zip/ZipUtil.java
  992 |    *          call-back for renaming the entries.
  993 |    */
  994 |   public static void unpack(File zip, File outputDir, NameMapper mapper) {
  995 |     log.debug("Extracting '{}' into '{}'.", zip, outputDir);
  996 |     iterate(zip, new Unpacker(outputDir, mapper));
  997 |   }
  998 | 
  999 |   /**
 1000 |    * Unwraps a ZIP file to the given directory shaving of root dir.

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void <init>(java.io.File,org.zeroturnaround.zip.NameMapper)>
file: org/zeroturnaround/zip/ZipUtil.java
 1141 |     private final File outputDir;
 1142 |     private final NameMapper mapper;
 1143 | 
 1144 |     public Unpacker(File outputDir, NameMapper mapper) {
 1145 |       this.outputDir = outputDir;
 1146 |       this.mapper = mapper;
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**
```

---

## 9/115 flow_id d1baeffd89 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow d1baeffd89
key        : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>@L77/result => <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1152/1
source     : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>[4@L77] %v5 = invokevirtual original.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[7@L1152] invokespecial file.<init>(%v11, name)/1
fixed methods on this flow (GT): Unpacker.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>
file: org/zeroturnaround/zip/ZipEntryUtil.java
   58 |    * @return copy of the original entry, but with the given name
   59 |    */
   60 |   static ZipEntry copy(ZipEntry original, String newName) {
   61 |     ZipEntry copy = new ZipEntry(newName == null ? original.getName() : newName);
   62 |     if (original.getCrc() != -1) {
   63 |       copy.setCrc(original.getCrc());
   64 |     }
   65 |     if (original.getMethod() != -1) {
   66 |       copy.setMethod(original.getMethod());
   67 |     }
   68 |     if (original.getSize() >= 0) {
   69 |       copy.setSize(original.getSize());
   70 |     }
   71 |     if (original.getExtra() != null) {
   72 |       copy.setExtra(original.getExtra());
   73 |     }
   74 | 
   75 |     copy.setComment(original.getComment());
   76 |     copy.setTime(original.getTime());
   77 |     return copy;
   78 |   }
   79 | 
   80 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
 1278 |     }
 1279 | 
 1280 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
```

---

## 10/115 flow_id ee08e9f40e (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow ee08e9f40e
key        : <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2573/result => <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1152/1
source     : <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2573] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[7@L1152] invokespecial file.<init>(%v11, name)/1
fixed methods on this flow (GT): Unpacker.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2570 |         final Set<String> names = new HashSet<String>();
 2571 |         iterate(zip, new ZipEntryCallback() {
 2572 |           public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2573 |             if (names.add(zipEntry.getName())) {
 2574 |               ZipEntrySource entry = (ZipEntrySource) entryByPath.remove(zipEntry.getName());
 2575 |               if (entry != null) {
 2576 |                 addEntry(entry, out);
 2577 |               }
 2578 |               else {
 2579 |                 ZipEntryUtil.copyEntry(zipEntry, in, out);
 2580 |               }
 2581 |             }
 2582 |             else if (log.isDebugEnabled()) {
 2583 |               log.debug("Duplicate entry: {}", zipEntry.getName());
 2584 |             }
 2585 |           }
 2586 |         });
 2587 |       }
 2588 |       finally {

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
 1278 |     }
 1279 | 
 1280 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
```

---

## 11/115 flow_id 34f85de0cf (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 34f85de0cf
key        : DRIVER => <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1260/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[213@L49] %v132 = invokestatic nesy.Taint.srcFile()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[30@L1260] invokespecial file.<init>(%v28, name)/0
fixed methods on this flow (GT): Unwraper.process
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[213@L49] %v132 = invokestatic nesy.Taint.srcFile()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v132}
3. VarNode{<org.zeroturnaround.zip.ZipUtil: void unwrap(java.io.File,java.io.File)>/outputDir}
4. VarNode{<org.zeroturnaround.zip.ZipUtil: void unwrap(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper)>/outputDir}
5. VarNode{<org.zeroturnaround.zip.ZipUtil$Unwraper: void <init>(java.io.File,org.zeroturnaround.zip.NameMapper)>/outputDir}
6. InstanceFieldNode{NewObj{<org.zeroturnaround.zip.ZipUtil: void unwrap(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper)>[3@L1031] new org.zeroturnaround.zip.ZipUtil$Unwraper}.<org.zeroturnaround.zip.ZipUtil$Unwraper: java.io.File outputDir>}
7. VarNode{<org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>/%v28}
8. <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[30@L1260] invokespecial file.<init>(%v28, name)/0

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void unwrap(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 1009 |    *          output directory (created automatically if not found).
 1010 |    */
 1011 |   public static void unwrap(File zip, final File outputDir) {
 1012 |     unwrap(zip, outputDir, IdentityNameMapper.INSTANCE);
 1013 |   }
 1014 | 
 1015 |   /**
 1016 |    * Unwraps a ZIP file to the given directory shaving of root dir.

### <org.zeroturnaround.zip.ZipUtil: void unwrap(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper)>
file: org/zeroturnaround/zip/ZipUtil.java
 1027 |    *          call-back for renaming the entries.
 1028 |    */
 1029 |   public static void unwrap(File zip, File outputDir, NameMapper mapper) {
 1030 |     log.debug("Unwrapping '{}' into '{}'.", zip, outputDir);
 1031 |     iterate(zip, new Unwraper(outputDir, mapper));
 1032 |   }
 1033 | 
 1034 |   /**
 1035 |    * Unpacks a ZIP stream to the given directory.

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void <init>(java.io.File,org.zeroturnaround.zip.NameMapper)>
file: org/zeroturnaround/zip/ZipUtil.java
 1241 |     private final NameMapper mapper;
 1242 |     private String rootDir;
 1243 | 
 1244 |     public Unwraper(File outputDir, NameMapper mapper) {
 1245 |       this.outputDir = outputDir;
 1246 |       this.mapper = mapper;
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
```

---

## 12/115 flow_id fb14f31121 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow fb14f31121
key        : <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2573/result => <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1260/1
source     : <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2573] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[30@L1260] invokespecial file.<init>(%v28, name)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2570 |         final Set<String> names = new HashSet<String>();
 2571 |         iterate(zip, new ZipEntryCallback() {
 2572 |           public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2573 |             if (names.add(zipEntry.getName())) {
 2574 |               ZipEntrySource entry = (ZipEntrySource) entryByPath.remove(zipEntry.getName());
 2575 |               if (entry != null) {
 2576 |                 addEntry(entry, out);
 2577 |               }
 2578 |               else {
 2579 |                 ZipEntryUtil.copyEntry(zipEntry, in, out);
 2580 |               }
 2581 |             }
 2582 |             else if (log.isDebugEnabled()) {
 2583 |               log.debug("Duplicate entry: {}", zipEntry.getName());
 2584 |             }
 2585 |           }
 2586 |         });
 2587 |       }
 2588 |       finally {

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
 1278 |     }
 1279 | 
 1280 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
```

---

## 13/115 flow_id 4814d0d133 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 4814d0d133
key        : <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2888/result => <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1260/1
source     : <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2888] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[30@L1260] invokespecial file.<init>(%v28, name)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2885 |     }
 2886 | 
 2887 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2888 |       if (names.add(zipEntry.getName())) {
 2889 |         ZipEntryTransformer entry = (ZipEntryTransformer) entryByPath.remove(zipEntry.getName());
 2890 |         if (entry != null) {
 2891 |           entry.transform(in, zipEntry, out);
 2892 |         }
 2893 |         else {
 2894 |           ZipEntryUtil.copyEntry(zipEntry, in, out);
 2895 |         }
 2896 |       }
 2897 |       else if (log.isDebugEnabled()) {
 2898 |         log.debug("Duplicate entry: {}", zipEntry.getName());
 2899 |       }
 2900 |     }
 2901 | 
 2902 |     /**
 2903 |      * @return <code>true</code> if at least one entry was replaced.

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
 1278 |     }
 1279 | 
 1280 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
```

---

## 14/115 flow_id d15307a6a1 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow d15307a6a1
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1250/result => <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1260/1
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L1250] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[30@L1260] invokespecial file.<init>(%v28, name)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
 1278 |     }
 1279 | 
 1280 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
```

---

## 15/115 flow_id babb2444b9 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow babb2444b9
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>@L511/result => <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1260/1
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>[25@L511] %v24 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[30@L1260] invokespecial file.<init>(%v28, name)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
 1278 |     }
 1279 | 
 1280 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>
file: org/zeroturnaround/zip/ZipUtil.java
  490 |    * @see #iterate(File, ZipInfoCallback)
  491 |    */
  492 |   public static void iterate(File zip, ZipEntryCallback action, Charset charset) {
  493 |     ZipFile zf = null;
  494 |     try {
  495 |       if (charset == null) {
  496 |         zf = new ZipFile(zip);
  497 |       }
  498 |       else {
  499 |         zf = new ZipFile(zip, charset);
  500 |       }
  501 | 
  502 |       Enumeration<? extends ZipEntry> en = zf.entries();
  503 |       while (en.hasMoreElements()) {
  504 |         ZipEntry e = (ZipEntry) en.nextElement();
  505 | 
  506 |         InputStream is = zf.getInputStream(e);
  507 |         try {
  508 |           action.process(is, e);
  509 |         }
  510 |         catch (IOException ze) {
  511 |           throw new ZipException("Failed to process zip entry '" + e.getName() + "' with action " + action, ze);
  512 |         }
  513 |         catch (ZipBreakException ex) {
  514 |           break;
  515 |         }
  516 |         finally {
  517 |           IOUtils.closeQuietly(is);
  518 |         }
  519 |       }
  520 |     }
  521 |     catch (IOException e) {
  522 |       throw ZipExceptionUtil.rethrow(e);
  523 |     }
  524 |     finally {
  525 |       closeQuietly(zf);
  526 |     }
  527 |   }
  528 | 
  529 |   /**
  530 |    * Reads the given ZIP file and executes the given action for each given entry.
```

---

## 16/115 flow_id d1e6342fe3 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow d1e6342fe3
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.InputStream,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>@L715/result => <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1260/1
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.InputStream,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>[12@L715] %v14 = invokevirtual entry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[30@L1260] invokespecial file.<init>(%v28, name)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.InputStream,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
 1278 |     }
 1279 | 
 1280 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.InputStream,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>
file: org/zeroturnaround/zip/ZipUtil.java
  703 |    */
  704 |   public static void iterate(InputStream is, ZipEntryCallback action, Charset charset) {
  705 |     try {
  706 |       ZipInputStream in = null;
  707 |       try {
  708 |         in = newCloseShieldZipInputStream(is, charset);
  709 |         ZipEntry entry;
  710 |         while ((entry = in.getNextEntry()) != null) {
  711 |           try {
  712 |             action.process(in, entry);
  713 |           }
  714 |           catch (IOException ze) {
  715 |             throw new ZipException("Failed to process zip entry '" + entry.getName() + " with action " + action, ze);
  716 |           }
  717 |           catch (ZipBreakException ex) {
  718 |             break;
  719 |           }
  720 |         }
  721 |       }
  722 |       finally {
  723 |         if (in != null) {
  724 |           in.close();
  725 |         }
  726 |       }
  727 |     }
  728 |     catch (IOException e) {
  729 |       throw ZipExceptionUtil.rethrow(e);
  730 |     }
  731 |   }
  732 | 
  733 |   /**
  734 |    * See {@link #iterate(InputStream, ZipEntryCallback, Charset)}. This method
```

---

## 17/115 flow_id 3ab17beab9 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 3ab17beab9
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1258/result => <org.zeroturnaround.zip.ZipUtil: boolean transformEntries(java.io.File,org.zeroturnaround.zip.transform.ZipEntryTransformerEntry[],java.io.File)>@L2781/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[24@L1258] %v24 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: boolean transformEntries(java.io.File,org.zeroturnaround.zip.transform.ZipEntryTransformerEntry[],java.io.File)>[24@L2781] invokespecial %v27.<init>(destZip)/0
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: boolean transformEntries(java.io.File,org.zeroturnaround.zip.transform.ZipEntryTransformerEntry[],java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
 1278 |     }
 1279 | 
 1280 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil: boolean transformEntries(java.io.File,org.zeroturnaround.zip.transform.ZipEntryTransformerEntry[],java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 2774 |    * @return <code>true</code> if at least one entry was replaced.
 2775 |    */
 2776 |   public static boolean transformEntries(File zip, ZipEntryTransformerEntry[] entries, File destZip) {
 2777 |     if (log.isDebugEnabled())
 2778 |       log.debug("Copying '" + zip + "' to '" + destZip + "' and transforming entries " + Arrays.asList(entries) + ".");
 2779 | 
 2780 |     try {
 2781 |       ZipOutputStream out = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(destZip)));
 2782 |       try {
 2783 |         TransformerZipEntryCallback action = new TransformerZipEntryCallback(Arrays.asList(entries), out);
 2784 |         iterate(zip, action);
 2785 |         return action.found();
 2786 |       }
 2787 |       finally {
 2788 |         IOUtils.closeQuietly(out);
 2789 |       }
 2790 |     }
 2791 |     catch (IOException e) {
 2792 |       throw ZipExceptionUtil.rethrow(e);
 2793 |     }
 2794 |   }
 2795 | 
```

---

## 18/115 flow_id 0f350ed5e9 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 0f350ed5e9
key        : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1150/result => <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>@L1721/0
source     : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1150] %v7 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>[26@L1721] invokespecial %v25.<init>(%v32)/0
fixed methods on this flow (GT): Unpacker.process
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>
file: org/zeroturnaround/zip/ZipUtil.java
 1713 |    *          if true, but directory to pack doesn't have any files, throw an exception.
 1714 |    */
 1715 |   private static void pack(File dir, ZipOutputStream out, NameMapper mapper, String pathPrefix, boolean mustHaveChildren) throws IOException {
 1716 |     String[] filenames = dir.list();
 1717 |     if (filenames == null) {
 1718 |       if (!dir.exists()) {
 1719 |         throw new ZipException("Given file '" + dir + "' doesn't exist!");
 1720 |       }
 1721 |       throw new IOException("Given file is not a directory '" + dir + "'");
 1722 |     }
 1723 | 
 1724 |     if (mustHaveChildren && filenames.length == 0) {
 1725 |       throw new ZipException("Given directory '" + dir + "' doesn't contain any files!");
 1726 |     }
 1727 | 
 1728 |     for (int i = 0; i < filenames.length; i++) {
 1729 |       String filename = filenames[i];
 1730 |       File file = new File(dir, filename);
 1731 |       boolean isDir = file.isDirectory();
 1732 |       String path = pathPrefix + file.getName(); // NOSONAR
 1733 |       if (isDir) {
 1734 |         path += PATH_SEPARATOR; // NOSONAR
 1735 |       }
 1736 | 
 1737 |       // Create a ZIP entry
 1738 |       String name = mapper.map(path);
 1739 |       if (name != null) {
 1740 |         ZipEntry zipEntry = ZipEntryUtil.fromFile(name, file);
 1741 | 
 1742 |         out.putNextEntry(zipEntry);
 1743 | 
 1744 |         // Copy the file content
 1745 |         if (!isDir) {
 1746 |           FileUtils.copy(file, out);
 1747 |         }
 1748 | 
 1749 |         out.closeEntry();
 1750 |       }
 1751 | 
 1752 |       // Traverse the directory
 1753 |       if (isDir) {
 1754 |         pack(file, out, mapper, path, false);
 1755 |       }
 1756 |     }
 1757 |   }
 1758 | 
 1759 |   /**
 1760 |    * Repacks a provided ZIP file into a new ZIP with a given compression level.
```

---

## 19/115 flow_id ab4f1829ce (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow ab4f1829ce
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1250/result => <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>@L1721/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L1250] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>[26@L1721] invokespecial %v25.<init>(%v32)/0
fixed methods on this flow (GT): Unwraper.process
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>
file: org/zeroturnaround/zip/ZipUtil.java
 1713 |    *          if true, but directory to pack doesn't have any files, throw an exception.
 1714 |    */
 1715 |   private static void pack(File dir, ZipOutputStream out, NameMapper mapper, String pathPrefix, boolean mustHaveChildren) throws IOException {
 1716 |     String[] filenames = dir.list();
 1717 |     if (filenames == null) {
 1718 |       if (!dir.exists()) {
 1719 |         throw new ZipException("Given file '" + dir + "' doesn't exist!");
 1720 |       }
 1721 |       throw new IOException("Given file is not a directory '" + dir + "'");
 1722 |     }
 1723 | 
 1724 |     if (mustHaveChildren && filenames.length == 0) {
 1725 |       throw new ZipException("Given directory '" + dir + "' doesn't contain any files!");
 1726 |     }
 1727 | 
 1728 |     for (int i = 0; i < filenames.length; i++) {
 1729 |       String filename = filenames[i];
 1730 |       File file = new File(dir, filename);
 1731 |       boolean isDir = file.isDirectory();
 1732 |       String path = pathPrefix + file.getName(); // NOSONAR
 1733 |       if (isDir) {
 1734 |         path += PATH_SEPARATOR; // NOSONAR
 1735 |       }
 1736 | 
 1737 |       // Create a ZIP entry
 1738 |       String name = mapper.map(path);
 1739 |       if (name != null) {
 1740 |         ZipEntry zipEntry = ZipEntryUtil.fromFile(name, file);
 1741 | 
 1742 |         out.putNextEntry(zipEntry);
 1743 | 
 1744 |         // Copy the file content
 1745 |         if (!isDir) {
 1746 |           FileUtils.copy(file, out);
 1747 |         }
 1748 | 
 1749 |         out.closeEntry();
 1750 |       }
 1751 | 
 1752 |       // Traverse the directory
 1753 |       if (isDir) {
 1754 |         pack(file, out, mapper, path, false);
 1755 |       }
 1756 |     }
 1757 |   }
 1758 | 
 1759 |   /**
 1760 |    * Repacks a provided ZIP file into a new ZIP with a given compression level.
```

---

## 20/115 flow_id 6740406fc7 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 6740406fc7
key        : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1150/result => <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>@L1730/0
source     : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1150] %v7 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>[47@L1730] invokespecial file.<init>(dir, filename)/0
fixed methods on this flow (GT): Unpacker.process
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 1363 |    *          ZIP file that will be created or overwritten.
 1364 |    */
 1365 |   public static void pack(File rootDir, File zip) {
 1366 |     pack(rootDir, zip, DEFAULT_COMPRESSION_LEVEL);
 1367 |   }
 1368 | 
 1369 |   /**
 1370 |    * Compresses the given directory and all its sub-directories into a ZIP file.

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>
file: org/zeroturnaround/zip/ZipUtil.java
 1713 |    *          if true, but directory to pack doesn't have any files, throw an exception.
 1714 |    */
 1715 |   private static void pack(File dir, ZipOutputStream out, NameMapper mapper, String pathPrefix, boolean mustHaveChildren) throws IOException {
 1716 |     String[] filenames = dir.list();
 1717 |     if (filenames == null) {
 1718 |       if (!dir.exists()) {
 1719 |         throw new ZipException("Given file '" + dir + "' doesn't exist!");
 1720 |       }
 1721 |       throw new IOException("Given file is not a directory '" + dir + "'");
 1722 |     }
 1723 | 
 1724 |     if (mustHaveChildren && filenames.length == 0) {
 1725 |       throw new ZipException("Given directory '" + dir + "' doesn't contain any files!");
 1726 |     }
 1727 | 
 1728 |     for (int i = 0; i < filenames.length; i++) {
 1729 |       String filename = filenames[i];
 1730 |       File file = new File(dir, filename);
 1731 |       boolean isDir = file.isDirectory();
 1732 |       String path = pathPrefix + file.getName(); // NOSONAR
 1733 |       if (isDir) {
 1734 |         path += PATH_SEPARATOR; // NOSONAR
 1735 |       }
 1736 | 
 1737 |       // Create a ZIP entry
 1738 |       String name = mapper.map(path);
 1739 |       if (name != null) {
 1740 |         ZipEntry zipEntry = ZipEntryUtil.fromFile(name, file);
 1741 | 
 1742 |         out.putNextEntry(zipEntry);
 1743 | 
 1744 |         // Copy the file content
 1745 |         if (!isDir) {
 1746 |           FileUtils.copy(file, out);
 1747 |         }
 1748 | 
 1749 |         out.closeEntry();
 1750 |       }
 1751 | 
 1752 |       // Traverse the directory
 1753 |       if (isDir) {
 1754 |         pack(file, out, mapper, path, false);
 1755 |       }
 1756 |     }
 1757 |   }
 1758 | 
 1759 |   /**
 1760 |    * Repacks a provided ZIP file into a new ZIP with a given compression level.
```

---

## 21/115 flow_id f43e958b05 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow f43e958b05
key        : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1150/result => <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>@L1730/1
source     : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1150] %v7 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>[47@L1730] invokespecial file.<init>(dir, filename)/1
fixed methods on this flow (GT): Unpacker.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry fromFile(java.lang.String,java.io.File)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry fromFile(java.lang.String,java.io.File)>
file: org/zeroturnaround/zip/ZipEntryUtil.java
  141 |    * @return newly created Zip entry
  142 |    */
  143 |   static ZipEntry fromFile(String name, File file) {
  144 |     ZipEntry zipEntry = new ZipEntry(name);
  145 |     if (!file.isDirectory()) {
  146 |       zipEntry.setSize(file.length());
  147 |     }
  148 |     zipEntry.setTime(file.lastModified());
  149 | 
  150 |     ZTFilePermissions permissions = ZTFilePermissionsUtil.getDefaultStategy().getPermissions(file);
  151 |     if (permissions != null) {
  152 |       ZipEntryUtil.setZTFilePermissions(zipEntry, permissions);
  153 |     }
  154 |     return zipEntry;
  155 |   }
  156 | 
  157 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>
file: org/zeroturnaround/zip/ZipUtil.java
 1713 |    *          if true, but directory to pack doesn't have any files, throw an exception.
 1714 |    */
 1715 |   private static void pack(File dir, ZipOutputStream out, NameMapper mapper, String pathPrefix, boolean mustHaveChildren) throws IOException {
 1716 |     String[] filenames = dir.list();
 1717 |     if (filenames == null) {
 1718 |       if (!dir.exists()) {
 1719 |         throw new ZipException("Given file '" + dir + "' doesn't exist!");
 1720 |       }
 1721 |       throw new IOException("Given file is not a directory '" + dir + "'");
 1722 |     }
 1723 | 
 1724 |     if (mustHaveChildren && filenames.length == 0) {
 1725 |       throw new ZipException("Given directory '" + dir + "' doesn't contain any files!");
 1726 |     }
 1727 | 
 1728 |     for (int i = 0; i < filenames.length; i++) {
 1729 |       String filename = filenames[i];
 1730 |       File file = new File(dir, filename);
 1731 |       boolean isDir = file.isDirectory();
 1732 |       String path = pathPrefix + file.getName(); // NOSONAR
 1733 |       if (isDir) {
 1734 |         path += PATH_SEPARATOR; // NOSONAR
 1735 |       }
 1736 | 
 1737 |       // Create a ZIP entry
 1738 |       String name = mapper.map(path);
 1739 |       if (name != null) {
 1740 |         ZipEntry zipEntry = ZipEntryUtil.fromFile(name, file);
 1741 | 
 1742 |         out.putNextEntry(zipEntry);
 1743 | 
 1744 |         // Copy the file content
 1745 |         if (!isDir) {
 1746 |           FileUtils.copy(file, out);
 1747 |         }
 1748 | 
 1749 |         out.closeEntry();
 1750 |       }
 1751 | 
 1752 |       // Traverse the directory
 1753 |       if (isDir) {
 1754 |         pack(file, out, mapper, path, false);
 1755 |       }
 1756 |     }
 1757 |   }
 1758 | 
 1759 |   /**
 1760 |    * Repacks a provided ZIP file into a new ZIP with a given compression level.
```

---

## 22/115 flow_id 415eb55af9 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 415eb55af9
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1250/result => <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>@L1730/1
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L1250] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>[47@L1730] invokespecial file.<init>(dir, filename)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>
file: org/zeroturnaround/zip/ZipUtil.java
 1713 |    *          if true, but directory to pack doesn't have any files, throw an exception.
 1714 |    */
 1715 |   private static void pack(File dir, ZipOutputStream out, NameMapper mapper, String pathPrefix, boolean mustHaveChildren) throws IOException {
 1716 |     String[] filenames = dir.list();
 1717 |     if (filenames == null) {
 1718 |       if (!dir.exists()) {
 1719 |         throw new ZipException("Given file '" + dir + "' doesn't exist!");
 1720 |       }
 1721 |       throw new IOException("Given file is not a directory '" + dir + "'");
 1722 |     }
 1723 | 
 1724 |     if (mustHaveChildren && filenames.length == 0) {
 1725 |       throw new ZipException("Given directory '" + dir + "' doesn't contain any files!");
 1726 |     }
 1727 | 
 1728 |     for (int i = 0; i < filenames.length; i++) {
 1729 |       String filename = filenames[i];
 1730 |       File file = new File(dir, filename);
 1731 |       boolean isDir = file.isDirectory();
 1732 |       String path = pathPrefix + file.getName(); // NOSONAR
 1733 |       if (isDir) {
 1734 |         path += PATH_SEPARATOR; // NOSONAR
 1735 |       }
 1736 | 
 1737 |       // Create a ZIP entry
 1738 |       String name = mapper.map(path);
 1739 |       if (name != null) {
 1740 |         ZipEntry zipEntry = ZipEntryUtil.fromFile(name, file);
 1741 | 
 1742 |         out.putNextEntry(zipEntry);
 1743 | 
 1744 |         // Copy the file content
 1745 |         if (!isDir) {
 1746 |           FileUtils.copy(file, out);
 1747 |         }
 1748 | 
 1749 |         out.closeEntry();
 1750 |       }
 1751 | 
 1752 |       // Traverse the directory
 1753 |       if (isDir) {
 1754 |         pack(file, out, mapper, path, false);
 1755 |       }
 1756 |     }
 1757 |   }
 1758 | 
 1759 |   /**
 1760 |    * Repacks a provided ZIP file into a new ZIP with a given compression level.
```

---

## 23/115 flow_id 74ecb948b5 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 74ecb948b5
key        : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1150/result => <org.zeroturnaround.zip.ZipUtil: void removeEntries(java.io.File,java.lang.String[],java.io.File)>@L2270/0
source     : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1150] %v7 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void removeEntries(java.io.File,java.lang.String[],java.io.File)>[25@L2270] invokespecial %v26.<init>(destZip)/0
fixed methods on this flow (GT): Unpacker.process
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void removeEntry(java.io.File,java.lang.String,java.io.File)>, <org.zeroturnaround.zip.ZipUtil: void removeEntries(java.io.File,java.lang.String[],java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil: void removeEntry(java.io.File,java.lang.String,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 2228 |    * @since 1.7
 2229 |    */
 2230 |   public static void removeEntry(File zip, String path, File destZip) {
 2231 |     removeEntries(zip, new String[] { path }, destZip);
 2232 |   }
 2233 | 
 2234 |   /**
 2235 |    * Changes an existing ZIP file: removes entry with a given path.

### <org.zeroturnaround.zip.ZipUtil: void removeEntries(java.io.File,java.lang.String[],java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 2261 |    * @since 1.7
 2262 |    */
 2263 |   public static void removeEntries(File zip, String[] paths, File destZip) {
 2264 |     if (log.isDebugEnabled()) {
 2265 |       log.debug("Copying '" + zip + "' to '" + destZip + "' and removing paths " + Arrays.asList(paths) + ".");
 2266 |     }
 2267 | 
 2268 |     ZipOutputStream out = null;
 2269 |     try {
 2270 |       out = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(destZip)));
 2271 |       copyEntries(zip, out, new HashSet<String>(Arrays.asList(paths)));
 2272 |     }
 2273 |     catch (IOException e) {
 2274 |       throw ZipExceptionUtil.rethrow(e);
 2275 |     }
 2276 |     finally {
 2277 |       IOUtils.closeQuietly(out);
 2278 |     }
 2279 |   }
 2280 | 
 2281 |   /**
 2282 |    * Changes an existing ZIP file: removes entries with given paths.
```

---

## 24/115 flow_id 1c4601d1da (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 1c4601d1da
key        : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1150/result => <org.zeroturnaround.zip.ZipUtil: void repack(java.io.File,int)>@L1826/0
source     : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1150] %v7 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void repack(java.io.File,int)>[12@L1826] invokespecial %v6.<init>(%v11)/0
fixed methods on this flow (GT): Unpacker.process
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void repack(java.io.File,int)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil: void repack(java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1817 |    */
 1818 |   public static void repack(File zip, int compressionLevel) {
 1819 |     try {
 1820 |       File tmpZip = FileUtils.getTempFileFor(zip);
 1821 | 
 1822 |       repack(zip, tmpZip, compressionLevel);
 1823 | 
 1824 |       // Delete original zip
 1825 |       if (!zip.delete()) {
 1826 |         throw new IOException("Unable to delete the file: " + zip);
 1827 |       }
 1828 | 
 1829 |       // Rename the archive
 1830 |       FileUtils.moveFile(tmpZip, zip);
 1831 |     }
 1832 |     catch (IOException e) {
 1833 |       throw ZipExceptionUtil.rethrow(e);
 1834 |     }
 1835 |   }
 1836 | 
 1837 |   /**
 1838 |    * RepackZipEntryCallback used in repacking methods.
```

---

## 25/115 flow_id b399f320f5 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow b399f320f5
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1250/result => <org.zeroturnaround.zip.commons.FileExistsException: void <init>(java.lang.String)>@L48/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L1250] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileExistsException: void <init>(java.lang.String)>[0@L48] invokespecial this.<init>(message)/0
fixed methods on this flow (GT): Unwraper.process
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileExistsException: void <init>(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileExistsException: void <init>(java.lang.String)>
file: org/zeroturnaround/zip/commons/FileExistsException.java
   45 |      * @param message The error message
   46 |      */
   47 |     public FileExistsException(String message) {
   48 |         super(message);
   49 |     }
   50 | 
   51 |     /**
   52 |      * Construct an instance with the specified file.
```

---

## 26/115 flow_id 48c4911853 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 48c4911853
key        : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1150/result => <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>@L75/1
source     : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1150] %v7 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>[15@L75] invokespecial result.<init>(parent, %v16)/1
fixed methods on this flow (GT): Unpacker.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry fromFile(java.lang.String,java.io.File)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>, <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry fromFile(java.lang.String,java.io.File)>
file: org/zeroturnaround/zip/ZipEntryUtil.java
  141 |    * @return newly created Zip entry
  142 |    */
  143 |   static ZipEntry fromFile(String name, File file) {
  144 |     ZipEntry zipEntry = new ZipEntry(name);
  145 |     if (!file.isDirectory()) {
  146 |       zipEntry.setSize(file.length());
  147 |     }
  148 |     zipEntry.setTime(file.lastModified());
  149 | 
  150 |     ZTFilePermissions permissions = ZTFilePermissionsUtil.getDefaultStategy().getPermissions(file);
  151 |     if (permissions != null) {
  152 |       ZipEntryUtil.setZTFilePermissions(zipEntry, permissions);
  153 |     }
  154 |     return zipEntry;
  155 |   }
  156 | 
  157 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>
file: org/zeroturnaround/zip/ZipUtil.java
 1713 |    *          if true, but directory to pack doesn't have any files, throw an exception.
 1714 |    */
 1715 |   private static void pack(File dir, ZipOutputStream out, NameMapper mapper, String pathPrefix, boolean mustHaveChildren) throws IOException {
 1716 |     String[] filenames = dir.list();
 1717 |     if (filenames == null) {
 1718 |       if (!dir.exists()) {
 1719 |         throw new ZipException("Given file '" + dir + "' doesn't exist!");
 1720 |       }
 1721 |       throw new IOException("Given file is not a directory '" + dir + "'");
 1722 |     }
 1723 | 
 1724 |     if (mustHaveChildren && filenames.length == 0) {
 1725 |       throw new ZipException("Given directory '" + dir + "' doesn't contain any files!");
 1726 |     }
 1727 | 
 1728 |     for (int i = 0; i < filenames.length; i++) {
 1729 |       String filename = filenames[i];
 1730 |       File file = new File(dir, filename);
 1731 |       boolean isDir = file.isDirectory();
 1732 |       String path = pathPrefix + file.getName(); // NOSONAR
 1733 |       if (isDir) {
 1734 |         path += PATH_SEPARATOR; // NOSONAR
 1735 |       }
 1736 | 
 1737 |       // Create a ZIP entry
 1738 |       String name = mapper.map(path);
 1739 |       if (name != null) {
 1740 |         ZipEntry zipEntry = ZipEntryUtil.fromFile(name, file);
 1741 | 
 1742 |         out.putNextEntry(zipEntry);
 1743 | 
 1744 |         // Copy the file content
 1745 |         if (!isDir) {
 1746 |           FileUtils.copy(file, out);
 1747 |         }
 1748 | 
 1749 |         out.closeEntry();
 1750 |       }
 1751 | 
 1752 |       // Traverse the directory
 1753 |       if (isDir) {
 1754 |         pack(file, out, mapper, path, false);
 1755 |       }
 1756 |     }
 1757 |   }
 1758 | 
 1759 |   /**
 1760 |    * Repacks a provided ZIP file into a new ZIP with a given compression level.

### <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtils.java
   67 |    * @return a non-existing file in the same directory using the same name as prefix.
   68 |    */
   69 |   public static File getTempFileFor(File file) {
   70 |     File parent = file.getParentFile();
   71 |     String name = file.getName();
   72 |     File result;
   73 |     int index = 0;
   74 |     do {
   75 |       result = new File(parent, name + "_" + index++);
   76 |     }
   77 |     while (result.exists());
   78 |     return result;
   79 |   }
   80 | }
```

---

## 27/115 flow_id 02f3d795d7 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 02f3d795d7
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1250/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>@L1081/1
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L1250] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>[18@L1081] invokespecial %v11.<init>(canonicalDir, %v12)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File)>, <org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File,int)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void deleteDirectory(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 1875 |    * @see #pack(File, File)
 1876 |    */
 1877 |   public static void unexplode(File dir) {
 1878 |     unexplode(dir, DEFAULT_COMPRESSION_LEVEL);
 1879 |   }
 1880 | 
 1881 |   /**
 1882 |    * Compresses a given directory in its own location.

### <org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1895 |   public static void unexplode(File dir, int compressionLevel) {
 1896 |     try {
 1897 |       // Find a new unique name is the same directory
 1898 |       File zip = FileUtils.getTempFileFor(dir);
 1899 | 
 1900 |       // Pack it
 1901 |       pack(dir, zip, compressionLevel);
 1902 | 
 1903 |       // Delete the directory
 1904 |       FileUtils.deleteDirectory(dir);
 1905 | 
 1906 |       // Rename the archive
 1907 |       FileUtils.moveFile(zip, dir);
 1908 |     }
 1909 |     catch (IOException e) {
 1910 |       throw ZipExceptionUtil.rethrow(e);
 1911 |     }
 1912 |   }
 1913 | 
 1914 |   /**
 1915 |    * Compresses the given entries into an output stream.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
 1067 |    * @since 2.0
 1068 |    */
 1069 |   public static boolean isSymlink(File file) throws IOException {
 1070 |     if (file == null) {
 1071 |       throw new NullPointerException("File must not be null");
 1072 |     }
 1073 |     if (FilenameUtils.isSystemWindows()) {
 1074 |       return false;
 1075 |     }
 1076 |     File fileInCanonicalDir = null;
 1077 |     if (file.getParent() == null) {
 1078 |       fileInCanonicalDir = file;
 1079 |     } else {
 1080 |       File canonicalDir = file.getParentFile().getCanonicalFile();
 1081 |       fileInCanonicalDir = new File(canonicalDir, file.getName());
 1082 |     }
 1083 | 
 1084 |     if (fileInCanonicalDir.getCanonicalFile().equals(fileInCanonicalDir.getAbsoluteFile())) {
 1085 |       return false;
 1086 |     } else {
 1087 |       return true;
 1088 |     }
 1089 |   }
 1090 | }

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void deleteDirectory(java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  644 |    * @throws IOException in case deletion is unsuccessful
  645 |    */
  646 |   public static void deleteDirectory(File directory) throws IOException {
  647 |     if (!directory.exists()) {
  648 |       return;
  649 |     }
  650 | 
  651 |     if (!isSymlink(directory)) {
  652 |       cleanDirectory(directory);
  653 |     }
  654 | 
  655 |     if (!directory.delete()) {
  656 |       String message =
  657 |           "Unable to delete directory " + directory + ".";
  658 |       throw new IOException(message);
  659 |     }
  660 |   }
  661 | 
  662 |   /**
  663 |    * Deletes a file, never throwing an exception. If file is a directory, delete it and all sub-directories.
```

---

## 28/115 flow_id 86b6e051d0 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 86b6e051d0
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1250/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: java.io.FileInputStream openInputStream(java.io.File)>@L137/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L1250] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: java.io.FileInputStream openInputStream(java.io.File)>[14@L137] invokespecial %v4.<init>(%v11)/0
fixed methods on this flow (GT): Unwraper.process
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: java.io.FileInputStream openInputStream(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: java.io.FileInputStream openInputStream(java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  132 |    * @since 1.3
  133 |    */
  134 |   public static FileInputStream openInputStream(File file) throws IOException {
  135 |     if (file.exists()) {
  136 |       if (file.isDirectory()) {
  137 |         throw new IOException("File '" + file + "' exists but is a directory");
  138 |       }
  139 |       if (file.canRead() == false) {
  140 |         throw new IOException("File '" + file + "' cannot be read");
  141 |       }
  142 |     } else {
  143 |       throw new FileNotFoundException("File '" + file + "' does not exist");
  144 |     }
  145 |     return new FileInputStream(file);
  146 |   }
  147 | 
  148 |   //-----------------------------------------------------------------------
```

---

## 29/115 flow_id 0643dc06c1 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 0643dc06c1
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1258/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: java.io.FileInputStream openInputStream(java.io.File)>@L137/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[24@L1258] %v24 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: java.io.FileInputStream openInputStream(java.io.File)>[14@L137] invokespecial %v4.<init>(%v11)/0
fixed methods on this flow (GT): Unwraper.process
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: java.io.FileInputStream openInputStream(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
 1278 |     }
 1279 | 
 1280 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: java.io.FileInputStream openInputStream(java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  132 |    * @since 1.3
  133 |    */
  134 |   public static FileInputStream openInputStream(File file) throws IOException {
  135 |     if (file.exists()) {
  136 |       if (file.isDirectory()) {
  137 |         throw new IOException("File '" + file + "' exists but is a directory");
  138 |       }
  139 |       if (file.canRead() == false) {
  140 |         throw new IOException("File '" + file + "' cannot be read");
  141 |       }
  142 |     } else {
  143 |       throw new FileNotFoundException("File '" + file + "' does not exist");
  144 |     }
  145 |     return new FileInputStream(file);
  146 |   }
  147 | 
  148 |   //-----------------------------------------------------------------------
```

---

## 30/115 flow_id 61155145e3 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 61155145e3
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1258/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>@L574/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[24@L1258] %v24 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>[54@L574] invokespecial %v38.<init>(%v48)/0
fixed methods on this flow (GT): Unwraper.process
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
 1278 |     }
 1279 | 
 1280 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  558 |    */
  559 |   public static void copyDirectory(File srcDir, File destDir,
  560 |       FileFilter filter, boolean preserveFileDate) throws IOException {
  561 |     if (srcDir == null) {
  562 |       throw new NullPointerException("Source must not be null");
  563 |     }
  564 |     if (destDir == null) {
  565 |       throw new NullPointerException("Destination must not be null");
  566 |     }
  567 |     if (srcDir.exists() == false) {
  568 |       throw new FileNotFoundException("Source '" + srcDir + "' does not exist");
  569 |     }
  570 |     if (srcDir.isDirectory() == false) {
  571 |       throw new IOException("Source '" + srcDir + "' exists but is not a directory");
  572 |     }
  573 |     if (srcDir.getCanonicalPath().equals(destDir.getCanonicalPath())) {
  574 |       throw new IOException("Source '" + srcDir + "' and destination '" + destDir + "' are the same");
  575 |     }
  576 | 
  577 |     // Cater for destination being directory within the source directory (see IO-141)
  578 |     List<String> exclusionList = null;
  579 |     if (destDir.getCanonicalPath().startsWith(srcDir.getCanonicalPath())) {
  580 |       File[] srcFiles = filter == null ? srcDir.listFiles() : srcDir.listFiles(filter);
  581 |       if (srcFiles != null && srcFiles.length > 0) {
  582 |         exclusionList = new ArrayList<String>(srcFiles.length);
  583 |         for (File srcFile : srcFiles) {
  584 |           File copiedFile = new File(destDir, srcFile.getName());
  585 |           exclusionList.add(copiedFile.getCanonicalPath());
  586 |         }
  587 |       }
  588 |     }
  589 |     doCopyDirectory(srcDir, destDir, filter, preserveFileDate, exclusionList);
  590 |   }
  591 | 
  592 |   /**
  593 |    * Internal copy directory method.
```

---

## 31/115 flow_id 2a9c9db75c (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 2a9c9db75c
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1250/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>@L392/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L1250] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>[35@L392] invokespecial %v20.<init>(%v27)/0
fixed methods on this flow (GT): Unwraper.process
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  379 |    */
  380 |   public static void copyFile(File srcFile, File destFile,
  381 |       boolean preserveFileDate) throws IOException {
  382 |     if (srcFile == null) {
  383 |       throw new NullPointerException("Source must not be null");
  384 |     }
  385 |     if (destFile == null) {
  386 |       throw new NullPointerException("Destination must not be null");
  387 |     }
  388 |     if (srcFile.exists() == false) {
  389 |       throw new FileNotFoundException("Source '" + srcFile + "' does not exist");
  390 |     }
  391 |     if (srcFile.isDirectory()) {
  392 |       throw new IOException("Source '" + srcFile + "' exists but is a directory");
  393 |     }
  394 |     if (srcFile.getCanonicalPath().equals(destFile.getCanonicalPath())) {
  395 |       throw new IOException("Source '" + srcFile + "' and destination '" + destFile + "' are the same");
  396 |     }
  397 |     File parentFile = destFile.getParentFile();
  398 |     if (parentFile != null) {
  399 |       if (!parentFile.mkdirs() && !parentFile.isDirectory()) {
  400 |         throw new IOException("Destination '" + parentFile + "' directory cannot be created");
  401 |       }
  402 |     }
  403 |     if (destFile.exists() && destFile.canWrite() == false) {
  404 |       throw new IOException("Destination '" + destFile + "' exists but is read-only");
  405 |     }
  406 |     doCopyFile(srcFile, destFile, preserveFileDate);
  407 |   }
  408 | 
  409 |   /**
  410 |    * Internal copy file method.
```

---

## 32/115 flow_id d2d353c920 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow d2d353c920
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1258/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>@L392/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[24@L1258] %v24 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>[35@L392] invokespecial %v20.<init>(%v27)/0
fixed methods on this flow (GT): Unwraper.process
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
 1278 |     }
 1279 | 
 1280 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  379 |    */
  380 |   public static void copyFile(File srcFile, File destFile,
  381 |       boolean preserveFileDate) throws IOException {
  382 |     if (srcFile == null) {
  383 |       throw new NullPointerException("Source must not be null");
  384 |     }
  385 |     if (destFile == null) {
  386 |       throw new NullPointerException("Destination must not be null");
  387 |     }
  388 |     if (srcFile.exists() == false) {
  389 |       throw new FileNotFoundException("Source '" + srcFile + "' does not exist");
  390 |     }
  391 |     if (srcFile.isDirectory()) {
  392 |       throw new IOException("Source '" + srcFile + "' exists but is a directory");
  393 |     }
  394 |     if (srcFile.getCanonicalPath().equals(destFile.getCanonicalPath())) {
  395 |       throw new IOException("Source '" + srcFile + "' and destination '" + destFile + "' are the same");
  396 |     }
  397 |     File parentFile = destFile.getParentFile();
  398 |     if (parentFile != null) {
  399 |       if (!parentFile.mkdirs() && !parentFile.isDirectory()) {
  400 |         throw new IOException("Destination '" + parentFile + "' directory cannot be created");
  401 |       }
  402 |     }
  403 |     if (destFile.exists() && destFile.canWrite() == false) {
  404 |       throw new IOException("Destination '" + destFile + "' exists but is read-only");
  405 |     }
  406 |     doCopyFile(srcFile, destFile, preserveFileDate);
  407 |   }
  408 | 
  409 |   /**
  410 |    * Internal copy file method.
```

---

## 33/115 flow_id 78242982df (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 78242982df
key        : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1150/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>@L400/0
source     : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1150] %v7 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>[70@L400] invokespecial %v45.<init>(%v52)/0
fixed methods on this flow (GT): Unpacker.process
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  379 |    */
  380 |   public static void copyFile(File srcFile, File destFile,
  381 |       boolean preserveFileDate) throws IOException {
  382 |     if (srcFile == null) {
  383 |       throw new NullPointerException("Source must not be null");
  384 |     }
  385 |     if (destFile == null) {
  386 |       throw new NullPointerException("Destination must not be null");
  387 |     }
  388 |     if (srcFile.exists() == false) {
  389 |       throw new FileNotFoundException("Source '" + srcFile + "' does not exist");
  390 |     }
  391 |     if (srcFile.isDirectory()) {
  392 |       throw new IOException("Source '" + srcFile + "' exists but is a directory");
  393 |     }
  394 |     if (srcFile.getCanonicalPath().equals(destFile.getCanonicalPath())) {
  395 |       throw new IOException("Source '" + srcFile + "' and destination '" + destFile + "' are the same");
  396 |     }
  397 |     File parentFile = destFile.getParentFile();
  398 |     if (parentFile != null) {
  399 |       if (!parentFile.mkdirs() && !parentFile.isDirectory()) {
  400 |         throw new IOException("Destination '" + parentFile + "' directory cannot be created");
  401 |       }
  402 |     }
  403 |     if (destFile.exists() && destFile.canWrite() == false) {
  404 |       throw new IOException("Destination '" + destFile + "' exists but is read-only");
  405 |     }
  406 |     doCopyFile(srcFile, destFile, preserveFileDate);
  407 |   }
  408 | 
  409 |   /**
  410 |    * Internal copy file method.
```

---

## 34/115 flow_id 9fc173b41f (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 9fc173b41f
key        : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1150/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>@L404/0
source     : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1150] %v7 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>[85@L404] invokespecial %v55.<init>(%v62)/0
fixed methods on this flow (GT): Unpacker.process
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  379 |    */
  380 |   public static void copyFile(File srcFile, File destFile,
  381 |       boolean preserveFileDate) throws IOException {
  382 |     if (srcFile == null) {
  383 |       throw new NullPointerException("Source must not be null");
  384 |     }
  385 |     if (destFile == null) {
  386 |       throw new NullPointerException("Destination must not be null");
  387 |     }
  388 |     if (srcFile.exists() == false) {
  389 |       throw new FileNotFoundException("Source '" + srcFile + "' does not exist");
  390 |     }
  391 |     if (srcFile.isDirectory()) {
  392 |       throw new IOException("Source '" + srcFile + "' exists but is a directory");
  393 |     }
  394 |     if (srcFile.getCanonicalPath().equals(destFile.getCanonicalPath())) {
  395 |       throw new IOException("Source '" + srcFile + "' and destination '" + destFile + "' are the same");
  396 |     }
  397 |     File parentFile = destFile.getParentFile();
  398 |     if (parentFile != null) {
  399 |       if (!parentFile.mkdirs() && !parentFile.isDirectory()) {
  400 |         throw new IOException("Destination '" + parentFile + "' directory cannot be created");
  401 |       }
  402 |     }
  403 |     if (destFile.exists() && destFile.canWrite() == false) {
  404 |       throw new IOException("Destination '" + destFile + "' exists but is read-only");
  405 |     }
  406 |     doCopyFile(srcFile, destFile, preserveFileDate);
  407 |   }
  408 | 
  409 |   /**
  410 |    * Internal copy file method.
```

---

## 35/115 flow_id 590f695498 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 590f695498
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1250/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>@L404/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L1250] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>[85@L404] invokespecial %v55.<init>(%v62)/0
fixed methods on this flow (GT): Unwraper.process
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  379 |    */
  380 |   public static void copyFile(File srcFile, File destFile,
  381 |       boolean preserveFileDate) throws IOException {
  382 |     if (srcFile == null) {
  383 |       throw new NullPointerException("Source must not be null");
  384 |     }
  385 |     if (destFile == null) {
  386 |       throw new NullPointerException("Destination must not be null");
  387 |     }
  388 |     if (srcFile.exists() == false) {
  389 |       throw new FileNotFoundException("Source '" + srcFile + "' does not exist");
  390 |     }
  391 |     if (srcFile.isDirectory()) {
  392 |       throw new IOException("Source '" + srcFile + "' exists but is a directory");
  393 |     }
  394 |     if (srcFile.getCanonicalPath().equals(destFile.getCanonicalPath())) {
  395 |       throw new IOException("Source '" + srcFile + "' and destination '" + destFile + "' are the same");
  396 |     }
  397 |     File parentFile = destFile.getParentFile();
  398 |     if (parentFile != null) {
  399 |       if (!parentFile.mkdirs() && !parentFile.isDirectory()) {
  400 |         throw new IOException("Destination '" + parentFile + "' directory cannot be created");
  401 |       }
  402 |     }
  403 |     if (destFile.exists() && destFile.canWrite() == false) {
  404 |       throw new IOException("Destination '" + destFile + "' exists but is read-only");
  405 |     }
  406 |     doCopyFile(srcFile, destFile, preserveFileDate);
  407 |   }
  408 | 
  409 |   /**
  410 |    * Internal copy file method.
```

---

## 36/115 flow_id 24b11421a9 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 24b11421a9
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1250/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void deleteDirectory(java.io.File)>@L658/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L1250] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void deleteDirectory(java.io.File)>[18@L658] invokespecial %v13.<init>(message)/0
fixed methods on this flow (GT): Unwraper.process
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void deleteDirectory(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void deleteDirectory(java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  644 |    * @throws IOException in case deletion is unsuccessful
  645 |    */
  646 |   public static void deleteDirectory(File directory) throws IOException {
  647 |     if (!directory.exists()) {
  648 |       return;
  649 |     }
  650 | 
  651 |     if (!isSymlink(directory)) {
  652 |       cleanDirectory(directory);
  653 |     }
  654 | 
  655 |     if (!directory.delete()) {
  656 |       String message =
  657 |           "Unable to delete directory " + directory + ".";
  658 |       throw new IOException(message);
  659 |     }
  660 |   }
  661 | 
  662 |   /**
  663 |    * Deletes a file, never throwing an exception. If file is a directory, delete it and all sub-directories.
```

---

## 37/115 flow_id a1f6b97521 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow a1f6b97521
key        : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1150/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>@L612/0
source     : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1150] %v7 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>[29@L612] invokespecial %v22.<init>(%v29)/0
fixed methods on this flow (GT): Unpacker.process
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  603 |   private static void doCopyDirectory(File srcDir, File destDir, FileFilter filter,
  604 |       boolean preserveFileDate, List<String> exclusionList) throws IOException {
  605 |     // recurse
  606 |     File[] srcFiles = filter == null ? srcDir.listFiles() : srcDir.listFiles(filter);
  607 |     if (srcFiles == null) {  // null if abstract pathname does not denote a directory, or if an I/O error occurs
  608 |       throw new IOException("Failed to list contents of " + srcDir);
  609 |     }
  610 |     if (destDir.exists()) {
  611 |       if (destDir.isDirectory() == false) {
  612 |         throw new IOException("Destination '" + destDir + "' exists but is not a directory");
  613 |       }
  614 |     } else {
  615 |       if (!destDir.mkdirs() && !destDir.isDirectory()) {
  616 |         throw new IOException("Destination '" + destDir + "' directory cannot be created");
  617 |       }
  618 |     }
  619 |     if (destDir.canWrite() == false) {
  620 |       throw new IOException("Destination '" + destDir + "' cannot be written to");
  621 |     }
  622 |     for (File srcFile : srcFiles) {
  623 |       File dstFile = new File(destDir, srcFile.getName());
  624 |       if (exclusionList == null || !exclusionList.contains(srcFile.getCanonicalPath())) {
  625 |         if (srcFile.isDirectory()) {
  626 |           doCopyDirectory(srcFile, dstFile, filter, preserveFileDate, exclusionList);
  627 |         } else {
  628 |           doCopyFile(srcFile, dstFile, preserveFileDate);
  629 |         }
  630 |       }
  631 |     }
  632 | 
  633 |     // Do this last, as the above has probably affected directory metadata
  634 |     if (preserveFileDate) {
  635 |       destDir.setLastModified(srcDir.lastModified());
  636 |     }
  637 |   }
  638 | 
  639 |   //-----------------------------------------------------------------------
  640 |   /**
```

---

## 38/115 flow_id 9618dd4786 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 9618dd4786
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1250/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>@L620/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L1250] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>[57@L620] invokespecial %v41.<init>(%v48)/0
fixed methods on this flow (GT): Unwraper.process
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  603 |   private static void doCopyDirectory(File srcDir, File destDir, FileFilter filter,
  604 |       boolean preserveFileDate, List<String> exclusionList) throws IOException {
  605 |     // recurse
  606 |     File[] srcFiles = filter == null ? srcDir.listFiles() : srcDir.listFiles(filter);
  607 |     if (srcFiles == null) {  // null if abstract pathname does not denote a directory, or if an I/O error occurs
  608 |       throw new IOException("Failed to list contents of " + srcDir);
  609 |     }
  610 |     if (destDir.exists()) {
  611 |       if (destDir.isDirectory() == false) {
  612 |         throw new IOException("Destination '" + destDir + "' exists but is not a directory");
  613 |       }
  614 |     } else {
  615 |       if (!destDir.mkdirs() && !destDir.isDirectory()) {
  616 |         throw new IOException("Destination '" + destDir + "' directory cannot be created");
  617 |       }
  618 |     }
  619 |     if (destDir.canWrite() == false) {
  620 |       throw new IOException("Destination '" + destDir + "' cannot be written to");
  621 |     }
  622 |     for (File srcFile : srcFiles) {
  623 |       File dstFile = new File(destDir, srcFile.getName());
  624 |       if (exclusionList == null || !exclusionList.contains(srcFile.getCanonicalPath())) {
  625 |         if (srcFile.isDirectory()) {
  626 |           doCopyDirectory(srcFile, dstFile, filter, preserveFileDate, exclusionList);
  627 |         } else {
  628 |           doCopyFile(srcFile, dstFile, preserveFileDate);
  629 |         }
  630 |       }
  631 |     }
  632 | 
  633 |     // Do this last, as the above has probably affected directory metadata
  634 |     if (preserveFileDate) {
  635 |       destDir.setLastModified(srcDir.lastModified());
  636 |     }
  637 |   }
  638 | 
  639 |   //-----------------------------------------------------------------------
  640 |   /**
```

---

## 39/115 flow_id c83c5a0248 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow c83c5a0248
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1258/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>@L620/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[24@L1258] %v24 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>[57@L620] invokespecial %v41.<init>(%v48)/0
fixed methods on this flow (GT): Unwraper.process
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
 1278 |     }
 1279 | 
 1280 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  603 |   private static void doCopyDirectory(File srcDir, File destDir, FileFilter filter,
  604 |       boolean preserveFileDate, List<String> exclusionList) throws IOException {
  605 |     // recurse
  606 |     File[] srcFiles = filter == null ? srcDir.listFiles() : srcDir.listFiles(filter);
  607 |     if (srcFiles == null) {  // null if abstract pathname does not denote a directory, or if an I/O error occurs
  608 |       throw new IOException("Failed to list contents of " + srcDir);
  609 |     }
  610 |     if (destDir.exists()) {
  611 |       if (destDir.isDirectory() == false) {
  612 |         throw new IOException("Destination '" + destDir + "' exists but is not a directory");
  613 |       }
  614 |     } else {
  615 |       if (!destDir.mkdirs() && !destDir.isDirectory()) {
  616 |         throw new IOException("Destination '" + destDir + "' directory cannot be created");
  617 |       }
  618 |     }
  619 |     if (destDir.canWrite() == false) {
  620 |       throw new IOException("Destination '" + destDir + "' cannot be written to");
  621 |     }
  622 |     for (File srcFile : srcFiles) {
  623 |       File dstFile = new File(destDir, srcFile.getName());
  624 |       if (exclusionList == null || !exclusionList.contains(srcFile.getCanonicalPath())) {
  625 |         if (srcFile.isDirectory()) {
  626 |           doCopyDirectory(srcFile, dstFile, filter, preserveFileDate, exclusionList);
  627 |         } else {
  628 |           doCopyFile(srcFile, dstFile, preserveFileDate);
  629 |         }
  630 |       }
  631 |     }
  632 | 
  633 |     // Do this last, as the above has probably affected directory metadata
  634 |     if (preserveFileDate) {
  635 |       destDir.setLastModified(srcDir.lastModified());
  636 |     }
  637 |   }
  638 | 
  639 |   //-----------------------------------------------------------------------
  640 |   /**
```

---

## 40/115 flow_id 9d3d2d4f5e (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 9d3d2d4f5e
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1258/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>@L623/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[24@L1258] %v24 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>[65@L623] invokespecial dstFile.<init>(destDir, %v52)/0
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
 1278 |     }
 1279 | 
 1280 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  603 |   private static void doCopyDirectory(File srcDir, File destDir, FileFilter filter,
  604 |       boolean preserveFileDate, List<String> exclusionList) throws IOException {
  605 |     // recurse
  606 |     File[] srcFiles = filter == null ? srcDir.listFiles() : srcDir.listFiles(filter);
  607 |     if (srcFiles == null) {  // null if abstract pathname does not denote a directory, or if an I/O error occurs
  608 |       throw new IOException("Failed to list contents of " + srcDir);
  609 |     }
  610 |     if (destDir.exists()) {
  611 |       if (destDir.isDirectory() == false) {
  612 |         throw new IOException("Destination '" + destDir + "' exists but is not a directory");
  613 |       }
  614 |     } else {
  615 |       if (!destDir.mkdirs() && !destDir.isDirectory()) {
  616 |         throw new IOException("Destination '" + destDir + "' directory cannot be created");
  617 |       }
  618 |     }
  619 |     if (destDir.canWrite() == false) {
  620 |       throw new IOException("Destination '" + destDir + "' cannot be written to");
  621 |     }
  622 |     for (File srcFile : srcFiles) {
  623 |       File dstFile = new File(destDir, srcFile.getName());
  624 |       if (exclusionList == null || !exclusionList.contains(srcFile.getCanonicalPath())) {
  625 |         if (srcFile.isDirectory()) {
  626 |           doCopyDirectory(srcFile, dstFile, filter, preserveFileDate, exclusionList);
  627 |         } else {
  628 |           doCopyFile(srcFile, dstFile, preserveFileDate);
  629 |         }
  630 |       }
  631 |     }
  632 | 
  633 |     // Do this last, as the above has probably affected directory metadata
  634 |     if (preserveFileDate) {
  635 |       destDir.setLastModified(srcDir.lastModified());
  636 |     }
  637 |   }
  638 | 
  639 |   //-----------------------------------------------------------------------
  640 |   /**
```

---

## 41/115 flow_id 7923a0aeb7 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 7923a0aeb7
key        : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1150/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>@L623/1
source     : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1150] %v7 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>[65@L623] invokespecial dstFile.<init>(destDir, %v52)/1
fixed methods on this flow (GT): Unpacker.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtils: void copy(java.io.InputStream,java.io.File)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtils: void copy(java.io.InputStream,java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtils.java
   51 |    * @throws java.io.IOException if file is not found or copying fails
   52 |    */
   53 |   public static void copy(InputStream in, File file) throws IOException {
   54 |     OutputStream out = new BufferedOutputStream(new FileOutputStream(file));
   55 |     try {
   56 |       IOUtils.copy(in, out);
   57 |     }
   58 |     finally {
   59 |       IOUtils.closeQuietly(out);
   60 |     }
   61 |   }
   62 | 
   63 |   /**
   64 |    * Find a non-existing file in the same directory using the same name as prefix.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  603 |   private static void doCopyDirectory(File srcDir, File destDir, FileFilter filter,
  604 |       boolean preserveFileDate, List<String> exclusionList) throws IOException {
  605 |     // recurse
  606 |     File[] srcFiles = filter == null ? srcDir.listFiles() : srcDir.listFiles(filter);
  607 |     if (srcFiles == null) {  // null if abstract pathname does not denote a directory, or if an I/O error occurs
  608 |       throw new IOException("Failed to list contents of " + srcDir);
  609 |     }
  610 |     if (destDir.exists()) {
  611 |       if (destDir.isDirectory() == false) {
  612 |         throw new IOException("Destination '" + destDir + "' exists but is not a directory");
  613 |       }
  614 |     } else {
  615 |       if (!destDir.mkdirs() && !destDir.isDirectory()) {
  616 |         throw new IOException("Destination '" + destDir + "' directory cannot be created");
  617 |       }
  618 |     }
  619 |     if (destDir.canWrite() == false) {
  620 |       throw new IOException("Destination '" + destDir + "' cannot be written to");
  621 |     }
  622 |     for (File srcFile : srcFiles) {
  623 |       File dstFile = new File(destDir, srcFile.getName());
  624 |       if (exclusionList == null || !exclusionList.contains(srcFile.getCanonicalPath())) {
  625 |         if (srcFile.isDirectory()) {
  626 |           doCopyDirectory(srcFile, dstFile, filter, preserveFileDate, exclusionList);
  627 |         } else {
  628 |           doCopyFile(srcFile, dstFile, preserveFileDate);
  629 |         }
  630 |       }
  631 |     }
  632 | 
  633 |     // Do this last, as the above has probably affected directory metadata
  634 |     if (preserveFileDate) {
  635 |       destDir.setLastModified(srcDir.lastModified());
  636 |     }
  637 |   }
  638 | 
  639 |   //-----------------------------------------------------------------------
  640 |   /**
```

---

## 42/115 flow_id 418972a9e1 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 418972a9e1
key        : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1150/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>@L419/0
source     : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1150] %v7 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>[14@L419] invokespecial %v17.<init>(%v24)/0
fixed methods on this flow (GT): Unpacker.process
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  415 |    * @throws IOException if an error occurs
  416 |    */
  417 |   private static void doCopyFile(File srcFile, File destFile, boolean preserveFileDate) throws IOException {
  418 |     if (destFile.exists() && destFile.isDirectory()) {
  419 |       throw new IOException("Destination '" + destFile + "' exists but is a directory");
  420 |     }
  421 | 
  422 |     FileInputStream fis = null;
  423 |     FileOutputStream fos = null;
  424 |     FileChannel input = null;
  425 |     FileChannel output = null;
  426 |     try {
  427 |       fis = new FileInputStream(srcFile);
  428 |       fos = new FileOutputStream(destFile);
  429 |       input  = fis.getChannel();
  430 |       output = fos.getChannel();
  431 |       long size = input.size();
  432 |       long pos = 0;
  433 |       long count = 0;
  434 |       while (pos < size) {
  435 |         count = size - pos > FILE_COPY_BUFFER_SIZE ? FILE_COPY_BUFFER_SIZE : size - pos;
  436 |         pos += output.transferFrom(input, pos, count);
  437 |       }
  438 |     } finally {
  439 |       IOUtils.closeQuietly(output);
  440 |       IOUtils.closeQuietly(fos);
  441 |       IOUtils.closeQuietly(input);
  442 |       IOUtils.closeQuietly(fis);
  443 |     }
  444 | 
  445 |     if (srcFile.length() != destFile.length()) {
  446 |       throw new IOException("Failed to copy full contents from '" +
  447 |           srcFile + "' to '" + destFile + "'");
  448 |     }
  449 |     if (preserveFileDate) {
  450 |       destFile.setLastModified(srcFile.lastModified());
  451 |     }
  452 |   }
  453 | 
  454 |   /**
  455 |    * Copies a whole directory to a new location preserving the file dates.
```

---

## 43/115 flow_id 08eef1ae7b (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 08eef1ae7b
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1258/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>@L419/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[24@L1258] %v24 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>[14@L419] invokespecial %v17.<init>(%v24)/0
fixed methods on this flow (GT): Unwraper.process
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
 1278 |     }
 1279 | 
 1280 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  415 |    * @throws IOException if an error occurs
  416 |    */
  417 |   private static void doCopyFile(File srcFile, File destFile, boolean preserveFileDate) throws IOException {
  418 |     if (destFile.exists() && destFile.isDirectory()) {
  419 |       throw new IOException("Destination '" + destFile + "' exists but is a directory");
  420 |     }
  421 | 
  422 |     FileInputStream fis = null;
  423 |     FileOutputStream fos = null;
  424 |     FileChannel input = null;
  425 |     FileChannel output = null;
  426 |     try {
  427 |       fis = new FileInputStream(srcFile);
  428 |       fos = new FileOutputStream(destFile);
  429 |       input  = fis.getChannel();
  430 |       output = fos.getChannel();
  431 |       long size = input.size();
  432 |       long pos = 0;
  433 |       long count = 0;
  434 |       while (pos < size) {
  435 |         count = size - pos > FILE_COPY_BUFFER_SIZE ? FILE_COPY_BUFFER_SIZE : size - pos;
  436 |         pos += output.transferFrom(input, pos, count);
  437 |       }
  438 |     } finally {
  439 |       IOUtils.closeQuietly(output);
  440 |       IOUtils.closeQuietly(fos);
  441 |       IOUtils.closeQuietly(input);
  442 |       IOUtils.closeQuietly(fis);
  443 |     }
  444 | 
  445 |     if (srcFile.length() != destFile.length()) {
  446 |       throw new IOException("Failed to copy full contents from '" +
  447 |           srcFile + "' to '" + destFile + "'");
  448 |     }
  449 |     if (preserveFileDate) {
  450 |       destFile.setLastModified(srcFile.lastModified());
  451 |     }
  452 |   }
  453 | 
  454 |   /**
  455 |    * Copies a whole directory to a new location preserving the file dates.
```

---

## 44/115 flow_id 22b5bf0985 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 22b5bf0985
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1250/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>@L428/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L1250] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>[24@L428] invokespecial %v26.<init>(destFile)/0
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: boolean operateInPlace(java.io.File,org.zeroturnaround.zip.ZipUtil$InPlaceAction)>, <org.zeroturnaround.zip.ZipUtil: boolean replaceEntries(java.io.File,org.zeroturnaround.zip.ZipEntrySource[])>, <org.zeroturnaround.zip.ZipUtil: boolean replaceEntry(java.io.File,java.lang.String,byte[])>, <org.zeroturnaround.zip.ZipUtil: boolean replaceEntry(java.io.File,java.lang.String,byte[],int)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil: boolean operateInPlace(java.io.File,org.zeroturnaround.zip.ZipUtil$InPlaceAction)>
file: org/zeroturnaround/zip/ZipUtil.java
 3286 |    * @return result of the action
 3287 |    */
 3288 |   private static boolean operateInPlace(File src, InPlaceAction action) {
 3289 |     File tmp = null;
 3290 |     try {
 3291 |       tmp = File.createTempFile("zt-zip-tmp", ".zip");
 3292 |       boolean result = action.act(tmp);
 3293 |       if (result) { // else nothing changes
 3294 |         FileUtils.forceDelete(src);
 3295 |         FileUtils.moveFile(tmp, src);
 3296 |       }
 3297 |       return result;
 3298 |     }
 3299 |     catch (IOException e) {
 3300 |       throw ZipExceptionUtil.rethrow(e);
 3301 |     }
 3302 |     finally {
 3303 |       FileUtils.deleteQuietly(tmp);
 3304 |     }
 3305 |   }
 3306 | 
 3307 | }

### <org.zeroturnaround.zip.ZipUtil: boolean replaceEntries(java.io.File,org.zeroturnaround.zip.ZipEntrySource[])>
file: org/zeroturnaround/zip/ZipUtil.java
 2605 |    * @return <code>true</code> if at least one entry was replaced.
 2606 |    */
 2607 |   public static boolean replaceEntries(final File zip, final ZipEntrySource[] entries) {
 2608 |     return operateInPlace(zip, new InPlaceAction() {
 2609 |       public boolean act(File tmpFile) {
 2610 |         return replaceEntries(zip, entries, tmpFile);
 2611 |       }

### <org.zeroturnaround.zip.ZipUtil: boolean replaceEntry(java.io.File,java.lang.String,byte[])>
file: org/zeroturnaround/zip/ZipUtil.java
 2485 |    * @return <code>true</code> if the entry was replaced.
 2486 |    */
 2487 |   public static boolean replaceEntry(final File zip, final String path, final byte[] bytes) {
 2488 |     return operateInPlace(zip, new InPlaceAction() {
 2489 |       public boolean act(File tmpFile) {
 2490 |         return replaceEntry(zip, new ByteSource(path, bytes), tmpFile);
 2491 |       }

### <org.zeroturnaround.zip.ZipUtil: boolean replaceEntry(java.io.File,java.lang.String,byte[],int)>
file: org/zeroturnaround/zip/ZipUtil.java
 2507 |    */
 2508 |   public static boolean replaceEntry(final File zip, final String path, final byte[] bytes,
 2509 |       final int compressionMethod) {
 2510 |     return operateInPlace(zip, new InPlaceAction() {
 2511 |       public boolean act(File tmpFile) {
 2512 |         return replaceEntry(zip, new ByteSource(path, bytes, compressionMethod), tmpFile);
 2513 |       }

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  415 |    * @throws IOException if an error occurs
  416 |    */
  417 |   private static void doCopyFile(File srcFile, File destFile, boolean preserveFileDate) throws IOException {
  418 |     if (destFile.exists() && destFile.isDirectory()) {
  419 |       throw new IOException("Destination '" + destFile + "' exists but is a directory");
  420 |     }
  421 | 
  422 |     FileInputStream fis = null;
  423 |     FileOutputStream fos = null;
  424 |     FileChannel input = null;
  425 |     FileChannel output = null;
  426 |     try {
  427 |       fis = new FileInputStream(srcFile);
  428 |       fos = new FileOutputStream(destFile);
  429 |       input  = fis.getChannel();
  430 |       output = fos.getChannel();
  431 |       long size = input.size();
  432 |       long pos = 0;
  433 |       long count = 0;
  434 |       while (pos < size) {
  435 |         count = size - pos > FILE_COPY_BUFFER_SIZE ? FILE_COPY_BUFFER_SIZE : size - pos;
  436 |         pos += output.transferFrom(input, pos, count);
  437 |       }
  438 |     } finally {
  439 |       IOUtils.closeQuietly(output);
  440 |       IOUtils.closeQuietly(fos);
  441 |       IOUtils.closeQuietly(input);
  442 |       IOUtils.closeQuietly(fis);
  443 |     }
  444 | 
  445 |     if (srcFile.length() != destFile.length()) {
  446 |       throw new IOException("Failed to copy full contents from '" +
  447 |           srcFile + "' to '" + destFile + "'");
  448 |     }
  449 |     if (preserveFileDate) {
  450 |       destFile.setLastModified(srcFile.lastModified());
  451 |     }
  452 |   }
  453 | 
  454 |   /**
  455 |    * Copies a whole directory to a new location preserving the file dates.
```

---

## 45/115 flow_id 532e552526 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 532e552526
key        : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1150/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>@L446/0
source     : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1150] %v7 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>[69@L446] invokespecial %v37.<init>(%v47)/0
fixed methods on this flow (GT): Unpacker.process
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  415 |    * @throws IOException if an error occurs
  416 |    */
  417 |   private static void doCopyFile(File srcFile, File destFile, boolean preserveFileDate) throws IOException {
  418 |     if (destFile.exists() && destFile.isDirectory()) {
  419 |       throw new IOException("Destination '" + destFile + "' exists but is a directory");
  420 |     }
  421 | 
  422 |     FileInputStream fis = null;
  423 |     FileOutputStream fos = null;
  424 |     FileChannel input = null;
  425 |     FileChannel output = null;
  426 |     try {
  427 |       fis = new FileInputStream(srcFile);
  428 |       fos = new FileOutputStream(destFile);
  429 |       input  = fis.getChannel();
  430 |       output = fos.getChannel();
  431 |       long size = input.size();
  432 |       long pos = 0;
  433 |       long count = 0;
  434 |       while (pos < size) {
  435 |         count = size - pos > FILE_COPY_BUFFER_SIZE ? FILE_COPY_BUFFER_SIZE : size - pos;
  436 |         pos += output.transferFrom(input, pos, count);
  437 |       }
  438 |     } finally {
  439 |       IOUtils.closeQuietly(output);
  440 |       IOUtils.closeQuietly(fos);
  441 |       IOUtils.closeQuietly(input);
  442 |       IOUtils.closeQuietly(fis);
  443 |     }
  444 | 
  445 |     if (srcFile.length() != destFile.length()) {
  446 |       throw new IOException("Failed to copy full contents from '" +
  447 |           srcFile + "' to '" + destFile + "'");
  448 |     }
  449 |     if (preserveFileDate) {
  450 |       destFile.setLastModified(srcFile.lastModified());
  451 |     }
  452 |   }
  453 | 
  454 |   /**
  455 |    * Copies a whole directory to a new location preserving the file dates.
```

---

## 46/115 flow_id 2979233ddb (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 2979233ddb
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1250/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>@L446/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L1250] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>[69@L446] invokespecial %v37.<init>(%v47)/0
fixed methods on this flow (GT): Unwraper.process
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  415 |    * @throws IOException if an error occurs
  416 |    */
  417 |   private static void doCopyFile(File srcFile, File destFile, boolean preserveFileDate) throws IOException {
  418 |     if (destFile.exists() && destFile.isDirectory()) {
  419 |       throw new IOException("Destination '" + destFile + "' exists but is a directory");
  420 |     }
  421 | 
  422 |     FileInputStream fis = null;
  423 |     FileOutputStream fos = null;
  424 |     FileChannel input = null;
  425 |     FileChannel output = null;
  426 |     try {
  427 |       fis = new FileInputStream(srcFile);
  428 |       fos = new FileOutputStream(destFile);
  429 |       input  = fis.getChannel();
  430 |       output = fos.getChannel();
  431 |       long size = input.size();
  432 |       long pos = 0;
  433 |       long count = 0;
  434 |       while (pos < size) {
  435 |         count = size - pos > FILE_COPY_BUFFER_SIZE ? FILE_COPY_BUFFER_SIZE : size - pos;
  436 |         pos += output.transferFrom(input, pos, count);
  437 |       }
  438 |     } finally {
  439 |       IOUtils.closeQuietly(output);
  440 |       IOUtils.closeQuietly(fos);
  441 |       IOUtils.closeQuietly(input);
  442 |       IOUtils.closeQuietly(fis);
  443 |     }
  444 | 
  445 |     if (srcFile.length() != destFile.length()) {
  446 |       throw new IOException("Failed to copy full contents from '" +
  447 |           srcFile + "' to '" + destFile + "'");
  448 |     }
  449 |     if (preserveFileDate) {
  450 |       destFile.setLastModified(srcFile.lastModified());
  451 |     }
  452 |   }
  453 | 
  454 |   /**
  455 |    * Copies a whole directory to a new location preserving the file dates.
```

---

## 47/115 flow_id 48114b0278 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 48114b0278
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1258/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceDelete(java.io.File)>@L793/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[24@L1258] %v24 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceDelete(java.io.File)>[25@L793] invokespecial %v18.<init>(message)/0
fixed methods on this flow (GT): Unwraper.process
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceDelete(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
 1278 |     }
 1279 | 
 1280 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceDelete(java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  780 |    * @throws IOException in case deletion is unsuccessful
  781 |    */
  782 |   public static void forceDelete(File file) throws IOException {
  783 |     if (file.isDirectory()) {
  784 |       deleteDirectory(file);
  785 |     } else {
  786 |       boolean filePresent = file.exists();
  787 |       if (!file.delete()) {
  788 |         if (!filePresent){
  789 |           throw new FileNotFoundException("File does not exist: " + file);
  790 |         }
  791 |         String message =
  792 |             "Unable to delete file: " + file;
  793 |         throw new IOException(message);
  794 |       }
  795 |     }
  796 |   }
  797 | 
  798 |   /**
  799 |    * Schedules a file to be deleted when JVM exits.
```

---

## 48/115 flow_id f4f3fde40b (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow f4f3fde40b
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1250/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceMkdir(java.io.File)>@L898/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L1250] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceMkdir(java.io.File)>[27@L898] invokespecial %v20.<init>(message#1)/0
fixed methods on this flow (GT): Unwraper.process
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceMkdir(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceMkdir(java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  878 |    * @throws IOException if the directory cannot be created or the file already exists but is not a directory
  879 |    */
  880 |   public static void forceMkdir(File directory) throws IOException {
  881 |     if (directory.exists()) {
  882 |       if (!directory.isDirectory()) {
  883 |         String message =
  884 |             "File "
  885 |                 + directory
  886 |                 + " exists and is "
  887 |                 + "not a directory. Unable to create directory.";
  888 |         throw new IOException(message);
  889 |       }
  890 |     } else {
  891 |       if (!directory.mkdirs()) {
  892 |         // Double-check that some other thread or process hasn't made
  893 |         // the directory in the background
  894 |         if (!directory.isDirectory())
  895 |         {
  896 |           String message =
  897 |               "Unable to create directory " + directory;
  898 |           throw new IOException(message);
  899 |         }
  900 |       }
  901 |     }
  902 |   }
  903 | 
  904 |   //-----------------------------------------------------------------------
  905 |   /**
```

---

## 49/115 flow_id 48f4bb9683 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 48f4bb9683
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1258/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveDirectory(java.io.File,java.io.File)>@L993/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[24@L1258] %v24 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveDirectory(java.io.File,java.io.File)>[35@L993] invokespecial %v19.<init>(%v26)/0
fixed methods on this flow (GT): Unwraper.process
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveDirectory(java.io.File,java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
 1278 |     }
 1279 | 
 1280 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveDirectory(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  980 |    * @since 1.4
  981 |    */
  982 |   public static void moveDirectory(File srcDir, File destDir) throws IOException {
  983 |     if (srcDir == null) {
  984 |       throw new NullPointerException("Source must not be null");
  985 |     }
  986 |     if (destDir == null) {
  987 |       throw new NullPointerException("Destination must not be null");
  988 |     }
  989 |     if (!srcDir.exists()) {
  990 |       throw new FileNotFoundException("Source '" + srcDir + "' does not exist");
  991 |     }
  992 |     if (!srcDir.isDirectory()) {
  993 |       throw new IOException("Source '" + srcDir + "' is not a directory");
  994 |     }
  995 |     if (destDir.exists()) {
  996 |       throw new FileExistsException("Destination '" + destDir + "' already exists");
  997 |     }
  998 |     boolean rename = srcDir.renameTo(destDir);
  999 |     if (!rename) {
 1000 |       if (destDir.getCanonicalPath().startsWith(srcDir.getCanonicalPath())) {
 1001 |         throw new IOException("Cannot move directory: "+srcDir+" to a subdirectory of itself: "+destDir);
 1002 |       }
 1003 |       copyDirectory( srcDir, destDir );
 1004 |       deleteDirectory( srcDir );
 1005 |       if (srcDir.exists()) {
 1006 |         throw new IOException("Failed to delete original directory '" + srcDir +
 1007 |             "' after copy to '" + destDir + "'");
 1008 |       }
 1009 |     }
 1010 |   }
 1011 | 
 1012 |   /**
 1013 |    * Moves a file.
```

---

## 50/115 flow_id bda5542c85 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow bda5542c85
key        : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1150/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveDirectory(java.io.File,java.io.File)>@L1001/0
source     : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1150] %v7 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveDirectory(java.io.File,java.io.File)>[66@L1001] invokespecial %v40.<init>(%v48)/0
fixed methods on this flow (GT): Unpacker.process
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveDirectory(java.io.File,java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveDirectory(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  980 |    * @since 1.4
  981 |    */
  982 |   public static void moveDirectory(File srcDir, File destDir) throws IOException {
  983 |     if (srcDir == null) {
  984 |       throw new NullPointerException("Source must not be null");
  985 |     }
  986 |     if (destDir == null) {
  987 |       throw new NullPointerException("Destination must not be null");
  988 |     }
  989 |     if (!srcDir.exists()) {
  990 |       throw new FileNotFoundException("Source '" + srcDir + "' does not exist");
  991 |     }
  992 |     if (!srcDir.isDirectory()) {
  993 |       throw new IOException("Source '" + srcDir + "' is not a directory");
  994 |     }
  995 |     if (destDir.exists()) {
  996 |       throw new FileExistsException("Destination '" + destDir + "' already exists");
  997 |     }
  998 |     boolean rename = srcDir.renameTo(destDir);
  999 |     if (!rename) {
 1000 |       if (destDir.getCanonicalPath().startsWith(srcDir.getCanonicalPath())) {
 1001 |         throw new IOException("Cannot move directory: "+srcDir+" to a subdirectory of itself: "+destDir);
 1002 |       }
 1003 |       copyDirectory( srcDir, destDir );
 1004 |       deleteDirectory( srcDir );
 1005 |       if (srcDir.exists()) {
 1006 |         throw new IOException("Failed to delete original directory '" + srcDir +
 1007 |             "' after copy to '" + destDir + "'");
 1008 |       }
 1009 |     }
 1010 |   }
 1011 | 
 1012 |   /**
 1013 |    * Moves a file.
```

---

## 51/115 flow_id 01f520544d (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 01f520544d
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1250/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveDirectory(java.io.File,java.io.File)>@L1006/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L1250] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveDirectory(java.io.File,java.io.File)>[84@L1006] invokespecial %v50.<init>(%v60)/0
fixed methods on this flow (GT): Unwraper.process
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveDirectory(java.io.File,java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveDirectory(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  980 |    * @since 1.4
  981 |    */
  982 |   public static void moveDirectory(File srcDir, File destDir) throws IOException {
  983 |     if (srcDir == null) {
  984 |       throw new NullPointerException("Source must not be null");
  985 |     }
  986 |     if (destDir == null) {
  987 |       throw new NullPointerException("Destination must not be null");
  988 |     }
  989 |     if (!srcDir.exists()) {
  990 |       throw new FileNotFoundException("Source '" + srcDir + "' does not exist");
  991 |     }
  992 |     if (!srcDir.isDirectory()) {
  993 |       throw new IOException("Source '" + srcDir + "' is not a directory");
  994 |     }
  995 |     if (destDir.exists()) {
  996 |       throw new FileExistsException("Destination '" + destDir + "' already exists");
  997 |     }
  998 |     boolean rename = srcDir.renameTo(destDir);
  999 |     if (!rename) {
 1000 |       if (destDir.getCanonicalPath().startsWith(srcDir.getCanonicalPath())) {
 1001 |         throw new IOException("Cannot move directory: "+srcDir+" to a subdirectory of itself: "+destDir);
 1002 |       }
 1003 |       copyDirectory( srcDir, destDir );
 1004 |       deleteDirectory( srcDir );
 1005 |       if (srcDir.exists()) {
 1006 |         throw new IOException("Failed to delete original directory '" + srcDir +
 1007 |             "' after copy to '" + destDir + "'");
 1008 |       }
 1009 |     }
 1010 |   }
 1011 | 
 1012 |   /**
 1013 |    * Moves a file.
```

---

## 52/115 flow_id c16044cdd5 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow c16044cdd5
key        : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1150/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>@L1036/0
source     : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1150] %v7 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>[35@L1036] invokespecial %v19.<init>(%v26)/0
fixed methods on this flow (GT): Unpacker.process
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
 1023 |    * @since 1.4
 1024 |    */
 1025 |   public static void moveFile(File srcFile, File destFile) throws IOException {
 1026 |     if (srcFile == null) {
 1027 |       throw new NullPointerException("Source must not be null");
 1028 |     }
 1029 |     if (destFile == null) {
 1030 |       throw new NullPointerException("Destination must not be null");
 1031 |     }
 1032 |     if (!srcFile.exists()) {
 1033 |       throw new FileNotFoundException("Source '" + srcFile + "' does not exist");
 1034 |     }
 1035 |     if (srcFile.isDirectory()) {
 1036 |       throw new IOException("Source '" + srcFile + "' is a directory");
 1037 |     }
 1038 |     if (destFile.exists()) {
 1039 |       throw new FileExistsException("Destination '" + destFile + "' already exists");
 1040 |     }
 1041 |     if (destFile.isDirectory()) {
 1042 |       throw new IOException("Destination '" + destFile + "' is a directory");
 1043 |     }
 1044 |     boolean rename = srcFile.renameTo(destFile);
 1045 |     if (!rename) {
 1046 |       copyFile( srcFile, destFile );
 1047 |       if (!srcFile.delete()) {
 1048 |         FileUtils.deleteQuietly(destFile);
 1049 |         throw new IOException("Failed to delete original file '" + srcFile +
 1050 |             "' after copy to '" + destFile + "'");
 1051 |       }
 1052 |     }
 1053 |   }
 1054 | 
 1055 |   /**
 1056 |    * Determines whether the specified file is a Symbolic Link rather than an actual file.
```

---

## 53/115 flow_id 31eeb62312 (priority 1)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 31eeb62312
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1258/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>@L1049/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[24@L1258] %v24 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>[81@L1049] invokespecial %v47.<init>(%v57)/0
fixed methods on this flow (GT): Unwraper.process
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());
 1278 |     }
 1279 | 
 1280 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
 1023 |    * @since 1.4
 1024 |    */
 1025 |   public static void moveFile(File srcFile, File destFile) throws IOException {
 1026 |     if (srcFile == null) {
 1027 |       throw new NullPointerException("Source must not be null");
 1028 |     }
 1029 |     if (destFile == null) {
 1030 |       throw new NullPointerException("Destination must not be null");
 1031 |     }
 1032 |     if (!srcFile.exists()) {
 1033 |       throw new FileNotFoundException("Source '" + srcFile + "' does not exist");
 1034 |     }
 1035 |     if (srcFile.isDirectory()) {
 1036 |       throw new IOException("Source '" + srcFile + "' is a directory");
 1037 |     }
 1038 |     if (destFile.exists()) {
 1039 |       throw new FileExistsException("Destination '" + destFile + "' already exists");
 1040 |     }
 1041 |     if (destFile.isDirectory()) {
 1042 |       throw new IOException("Destination '" + destFile + "' is a directory");
 1043 |     }
 1044 |     boolean rename = srcFile.renameTo(destFile);
 1045 |     if (!rename) {
 1046 |       copyFile( srcFile, destFile );
 1047 |       if (!srcFile.delete()) {
 1048 |         FileUtils.deleteQuietly(destFile);
 1049 |         throw new IOException("Failed to delete original file '" + srcFile +
 1050 |             "' after copy to '" + destFile + "'");
 1051 |       }
 1052 |     }
 1053 |   }
 1054 | 
 1055 |   /**
 1056 |    * Determines whether the specified file is a Symbolic Link rather than an actual file.
```

---

## 54/115 flow_id 2036eec71b (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 2036eec71b
key        : DRIVER => <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>@L57/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[264@L59] %v163 = invokestatic nesy.Taint.srcFile()/result
sink       : <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>[9@L57] invokespecial file.<init>(dir, %v11)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[264@L59] %v163 = invokestatic nesy.Taint.srcFile()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v163}
3. VarNode{<org.zeroturnaround.zip.ZTFileUtil: java.util.Collection listFiles(java.io.File)>/dir}
4. VarNode{<org.zeroturnaround.zip.ZTFileUtil: java.util.Collection listFiles(java.io.File,java.io.FileFilter)>/dir}
5. VarNode{<org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>/dir}
6. <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>[9@L57] invokespecial file.<init>(dir, %v11)/0

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZTFileUtil: java.util.Collection listFiles(java.io.File)>
file: org/zeroturnaround/zip/ZTFileUtil.java
   25 |   }
   26 | 
   27 |   public static Collection<File> listFiles(File dir) {
   28 |     return listFiles(dir, null);
   29 |   }
   30 |   
   31 |   public static Collection<File> listFiles(File dir, FileFilter filter) {

### <org.zeroturnaround.zip.ZTFileUtil: java.util.Collection listFiles(java.io.File,java.io.FileFilter)>
file: org/zeroturnaround/zip/ZTFileUtil.java
   29 |   }
   30 |   
   31 |   public static Collection<File> listFiles(File dir, FileFilter filter) {
   32 |     Collection<File> accumulator = new ArrayList<File>();
   33 | 
   34 |     if (dir.isFile()) {
   35 |       return accumulator;
   36 |     }
   37 |     
   38 |     if (filter == null) {
   39 |       // Set default filter to accept any file
   40 |       filter = new FileFilter() {
   41 |         public boolean accept(File pathname) {
   42 |           return true;
   43 |         }
   44 |       };
   45 |     }
   46 | 
   47 |     innerListFiles(dir, accumulator, filter);
   48 |     return accumulator;
   49 |   }
   50 | 
   51 |   private static void innerListFiles(File dir, Collection<File> accumulator, FileFilter filter) {

### <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>
file: org/zeroturnaround/zip/ZTFileUtil.java
   50 | 
   51 |   private static void innerListFiles(File dir, Collection<File> accumulator, FileFilter filter) {
   52 | 
   53 |     String[] filenames = dir.list();
   54 | 
   55 |     if (filenames != null) {
   56 |       for (int i = 0; i < filenames.length; i++) {
   57 |         File file = new File(dir, filenames[i]);
   58 |         if (file.isDirectory()) {
   59 |           innerListFiles(file, accumulator, filter);
   60 |         }
   61 |         else {
   62 |           if (filter != null && filter.accept(file)) {
   63 |             accumulator.add(file);
   64 |           }
   65 |         }
   66 |       }
   67 |     }
   68 |   }
   69 | }
```

---

## 55/115 flow_id 1e0b97a066 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 1e0b97a066
key        : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>@L77/result => <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>@L57/1
source     : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>[4@L77] %v5 = invokevirtual original.getName()/result
sink       : <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>[9@L57] invokespecial file.<init>(dir, %v11)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>, <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>
file: org/zeroturnaround/zip/ZTFileUtil.java
   50 | 
   51 |   private static void innerListFiles(File dir, Collection<File> accumulator, FileFilter filter) {
   52 | 
   53 |     String[] filenames = dir.list();
   54 | 
   55 |     if (filenames != null) {
   56 |       for (int i = 0; i < filenames.length; i++) {
   57 |         File file = new File(dir, filenames[i]);
   58 |         if (file.isDirectory()) {
   59 |           innerListFiles(file, accumulator, filter);
   60 |         }
   61 |         else {
   62 |           if (filter != null && filter.accept(file)) {
   63 |             accumulator.add(file);
   64 |           }
   65 |         }
   66 |       }
   67 |     }
   68 |   }
   69 | }

### <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>
file: org/zeroturnaround/zip/ZipEntryUtil.java
   58 |    * @return copy of the original entry, but with the given name
   59 |    */
   60 |   static ZipEntry copy(ZipEntry original, String newName) {
   61 |     ZipEntry copy = new ZipEntry(newName == null ? original.getName() : newName);
   62 |     if (original.getCrc() != -1) {
   63 |       copy.setCrc(original.getCrc());
   64 |     }
   65 |     if (original.getMethod() != -1) {
   66 |       copy.setMethod(original.getMethod());
   67 |     }
   68 |     if (original.getSize() >= 0) {
   69 |       copy.setSize(original.getSize());
   70 |     }
   71 |     if (original.getExtra() != null) {
   72 |       copy.setExtra(original.getExtra());
   73 |     }
   74 | 
   75 |     copy.setComment(original.getComment());
   76 |     copy.setTime(original.getTime());
   77 |     return copy;
   78 |   }
   79 | 
   80 |   /**
```

---

## 56/115 flow_id 5b9053b93d (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 5b9053b93d
key        : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1196/result => <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>@L57/1
source     : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[4@L1196] %v9 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>[9@L57] invokespecial file.<init>(dir, %v11)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtils: void copy(java.io.InputStream,java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>
file: org/zeroturnaround/zip/ZTFileUtil.java
   50 | 
   51 |   private static void innerListFiles(File dir, Collection<File> accumulator, FileFilter filter) {
   52 | 
   53 |     String[] filenames = dir.list();
   54 | 
   55 |     if (filenames != null) {
   56 |       for (int i = 0; i < filenames.length; i++) {
   57 |         File file = new File(dir, filenames[i]);
   58 |         if (file.isDirectory()) {
   59 |           innerListFiles(file, accumulator, filter);
   60 |         }
   61 |         else {
   62 |           if (filter != null && filter.accept(file)) {
   63 |             accumulator.add(file);
   64 |           }
   65 |         }
   66 |       }
   67 |     }
   68 |   }
   69 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtils: void copy(java.io.InputStream,java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtils.java
   51 |    * @throws java.io.IOException if file is not found or copying fails
   52 |    */
   53 |   public static void copy(InputStream in, File file) throws IOException {
   54 |     OutputStream out = new BufferedOutputStream(new FileOutputStream(file));
   55 |     try {
   56 |       IOUtils.copy(in, out);
   57 |     }
   58 |     finally {
   59 |       IOUtils.closeQuietly(out);
   60 |     }
   61 |   }
   62 | 
   63 |   /**
   64 |    * Find a non-existing file in the same directory using the same name as prefix.
```

---

## 57/115 flow_id a45bc7b078 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow a45bc7b078
key        : <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>@L3028/result => <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>@L57/1
source     : <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>[36@L3028] path = invokevirtual e1.getName()/result
sink       : <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>[9@L57] invokespecial file.<init>(dir, %v11)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run1, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>, <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>
file: org/zeroturnaround/zip/ZTFileUtil.java
   50 | 
   51 |   private static void innerListFiles(File dir, Collection<File> accumulator, FileFilter filter) {
   52 | 
   53 |     String[] filenames = dir.list();
   54 | 
   55 |     if (filenames != null) {
   56 |       for (int i = 0; i < filenames.length; i++) {
   57 |         File file = new File(dir, filenames[i]);
   58 |         if (file.isDirectory()) {
   59 |           innerListFiles(file, accumulator, filter);
   60 |         }
   61 |         else {
   62 |           if (filter != null && filter.accept(file)) {
   63 |             accumulator.add(file);
   64 |           }
   65 |         }
   66 |       }
   67 |     }
   68 |   }
   69 | }

### <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 3000 |   }
 3001 | 
 3002 |   private static boolean archiveEqualsInternal(File f1, File f2) throws IOException {
 3003 |     ZipFile zf1 = null;
 3004 |     ZipFile zf2 = null;
 3005 |     try {
 3006 |       zf1 = new ZipFile(f1);
 3007 |       zf2 = new ZipFile(f2);
 3008 | 
 3009 |       // Check the number of entries
 3010 |       if (zf1.size() != zf2.size()) {
 3011 |         log.debug("Number of entries changed (" + zf1.size() + " vs " + zf2.size() + ").");
 3012 |         return false;
 3013 |       }
 3014 |       /*
 3015 |        * As there are same number of entries in both archives we can traverse
 3016 |        * all entries of one of the archives and get the corresponding entries
 3017 |        * from the other archive.
 3018 |        *
 3019 |        * If a corresponding entry is missing from the second archive the
 3020 |        * archives are different and we finish the comparison.
 3021 |        *
 3022 |        * We guarantee that no entry of the second archive is skipped as there
 3023 |        * are same number of unique entries in both archives.
 3024 |        */
 3025 |       Enumeration<? extends ZipEntry> en = zf1.entries();
 3026 |       while (en.hasMoreElements()) {
 3027 |         ZipEntry e1 = (ZipEntry) en.nextElement();
 3028 |         String path = e1.getName();
 3029 |         ZipEntry e2 = zf2.getEntry(path);
      | ... (lines omitted) ...
 3035 | 
 3036 |         // Check the content
 3037 |         InputStream is1 = null;
 3038 |         InputStream is2 = null;
 3039 |         try {
 3040 |           is1 = zf1.getInputStream(e1);
 3041 |           is2 = zf2.getInputStream(e2);
 3042 | 
 3043 |           if (!IOUtils.contentEquals(is1, is2)) {
 3044 |             log.debug("Entry '{}' content changed.", path);
 3045 |             return false;
 3046 |           }
 3047 |         }
 3048 |         finally {
 3049 |           IOUtils.closeQuietly(is1);
 3050 |           IOUtils.closeQuietly(is2);
 3051 |         }
 3052 |       }
 3053 |     }
 3054 |     finally {
 3055 |       closeQuietly(zf1);
 3056 |       closeQuietly(zf2);
 3057 |     }
 3058 | 
 3059 |     log.debug("Archives are the same.");
 3060 | 
 3061 |     return true;
 3062 |   }
 3063 | 
 3064 |   /**
```

---

## 58/115 flow_id 19eeaf5bac (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 19eeaf5bac
key        : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>@L313/result => <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>@L61/0
source     : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>[9@L313] o = invokeinterface elems.nextElement()/result
sink       : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>[7@L61] invokespecial copy.<init>(%v5)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, v1 run0, v2 run0, v3 run0, v3-noV2 run0, v3-noV3 run0, v3-noval run0, v4 run0
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>
file: org/zeroturnaround/zip/ZipEntryUtil.java
   58 |    * @return copy of the original entry, but with the given name
   59 |    */
   60 |   static ZipEntry copy(ZipEntry original, String newName) {
   61 |     ZipEntry copy = new ZipEntry(newName == null ? original.getName() : newName);
   62 |     if (original.getCrc() != -1) {
   63 |       copy.setCrc(original.getCrc());
   64 |     }
   65 |     if (original.getMethod() != -1) {
   66 |       copy.setMethod(original.getMethod());
   67 |     }
   68 |     if (original.getSize() >= 0) {
   69 |       copy.setSize(original.getSize());
   70 |     }
   71 |     if (original.getExtra() != null) {
   72 |       copy.setExtra(original.getExtra());
   73 |     }
   74 | 
   75 |     copy.setComment(original.getComment());
   76 |     copy.setTime(original.getTime());
   77 |     return copy;
   78 |   }
   79 | 
   80 |   /**
```

---

## 59/115 flow_id 5cfaba2c16 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 5cfaba2c16
key        : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>@L313/result => <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1214/1
source     : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>[9@L313] o = invokeinterface elems.nextElement()/result
sink       : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[19@L1214] invokespecial file.<init>(parentDirectory, %v22)/1
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**
```

---

## 60/115 flow_id da9b2d6db6 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow da9b2d6db6
key        : <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>@L3028/result => <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1214/1
source     : <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>[36@L3028] path = invokevirtual e1.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[19@L1214] invokespecial file.<init>(parentDirectory, %v22)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 3000 |   }
 3001 | 
 3002 |   private static boolean archiveEqualsInternal(File f1, File f2) throws IOException {
 3003 |     ZipFile zf1 = null;
 3004 |     ZipFile zf2 = null;
 3005 |     try {
 3006 |       zf1 = new ZipFile(f1);
 3007 |       zf2 = new ZipFile(f2);
 3008 | 
 3009 |       // Check the number of entries
 3010 |       if (zf1.size() != zf2.size()) {
 3011 |         log.debug("Number of entries changed (" + zf1.size() + " vs " + zf2.size() + ").");
 3012 |         return false;
 3013 |       }
 3014 |       /*
 3015 |        * As there are same number of entries in both archives we can traverse
 3016 |        * all entries of one of the archives and get the corresponding entries
 3017 |        * from the other archive.
 3018 |        *
 3019 |        * If a corresponding entry is missing from the second archive the
 3020 |        * archives are different and we finish the comparison.
 3021 |        *
 3022 |        * We guarantee that no entry of the second archive is skipped as there
 3023 |        * are same number of unique entries in both archives.
 3024 |        */
 3025 |       Enumeration<? extends ZipEntry> en = zf1.entries();
 3026 |       while (en.hasMoreElements()) {
 3027 |         ZipEntry e1 = (ZipEntry) en.nextElement();
 3028 |         String path = e1.getName();
 3029 |         ZipEntry e2 = zf2.getEntry(path);
      | ... (lines omitted) ...
 3035 | 
 3036 |         // Check the content
 3037 |         InputStream is1 = null;
 3038 |         InputStream is2 = null;
 3039 |         try {
 3040 |           is1 = zf1.getInputStream(e1);
 3041 |           is2 = zf2.getInputStream(e2);
 3042 | 
 3043 |           if (!IOUtils.contentEquals(is1, is2)) {
 3044 |             log.debug("Entry '{}' content changed.", path);
 3045 |             return false;
 3046 |           }
 3047 |         }
 3048 |         finally {
 3049 |           IOUtils.closeQuietly(is1);
 3050 |           IOUtils.closeQuietly(is2);
 3051 |         }
 3052 |       }
 3053 |     }
 3054 |     finally {
 3055 |       closeQuietly(zf1);
 3056 |       closeQuietly(zf2);
 3057 |     }
 3058 | 
 3059 |     log.debug("Archives are the same.");
 3060 | 
 3061 |     return true;
 3062 |   }
 3063 | 
 3064 |   /**
```

---

## 61/115 flow_id 25748d280d (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 25748d280d
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>@L585/result => <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1220/0
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>[28@L585] %v25 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[30@L1220] invokespecial destFile.<init>(parentDirectory, %v27)/0
fixed methods on this flow (GT): -
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>
file: org/zeroturnaround/zip/ZipUtil.java
  563 |    * @see #iterate(File, String[], ZipInfoCallback)
  564 |    */
  565 |   public static void iterate(File zip, String[] entryNames, ZipEntryCallback action, Charset charset) {
  566 |     ZipFile zf = null;
  567 |     try {
  568 |       if (charset == null) {
  569 |         zf = new ZipFile(zip);
  570 |       }
  571 |       else {
  572 |         zf = new ZipFile(zip, charset);
  573 |       }
  574 | 
  575 |       for (int i = 0; i < entryNames.length; i++) {
  576 |         ZipEntry e = zf.getEntry(entryNames[i]);
  577 |         if (e == null) {
  578 |           continue;
  579 |         }
  580 |         InputStream is = zf.getInputStream(e);
  581 |         try {
  582 |           action.process(is, e);
  583 |         }
  584 |         catch (IOException ze) {
  585 |           throw new ZipException("Failed to process zip entry '" + e.getName() + " with action " + action, ze);
  586 |         }
  587 |         catch (ZipBreakException ex) {
  588 |           break;
  589 |         }
  590 |         finally {
  591 |           IOUtils.closeQuietly(is);
  592 |         }
  593 |       }
  594 |     }
  595 |     catch (IOException e) {
  596 |       throw ZipExceptionUtil.rethrow(e);
  597 |     }
  598 |     finally {
  599 |       closeQuietly(zf);
  600 |     }
  601 |   }
  602 | 
  603 |   /**
  604 |    * Scans the given ZIP file and executes the given action for each entry.
```

---

## 62/115 flow_id c9c4f56e52 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow c9c4f56e52
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipInfoCallback)>@L673/result => <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1220/0
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipInfoCallback)>[21@L673] %v20 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[30@L1220] invokespecial destFile.<init>(parentDirectory, %v27)/0
fixed methods on this flow (GT): -
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipInfoCallback)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipInfoCallback)>
file: org/zeroturnaround/zip/ZipUtil.java
  657 |    * @see #iterate(File, String[], ZipEntryCallback)
  658 |    */
  659 |   public static void iterate(File zip, String[] entryNames, ZipInfoCallback action) {
  660 |     ZipFile zf = null;
  661 |     try {
  662 |       zf = new ZipFile(zip);
  663 | 
  664 |       for (int i = 0; i < entryNames.length; i++) {
  665 |         ZipEntry e = zf.getEntry(entryNames[i]);
  666 |         if (e == null) {
  667 |           continue;
  668 |         }
  669 |         try {
  670 |           action.process(e);
  671 |         }
  672 |         catch (IOException ze) {
  673 |           throw new ZipException("Failed to process zip entry '" + e.getName() + " with action " + action, ze);
  674 |         }
  675 |         catch (ZipBreakException ex) {
  676 |           break;
  677 |         }
  678 |       }
  679 |     }
  680 |     catch (IOException e) {
  681 |       throw ZipExceptionUtil.rethrow(e);
  682 |     }
  683 |     finally {
  684 |       closeQuietly(zf);
  685 |     }
  686 |   }
  687 | 
  688 |   /**
  689 |    * Reads the given ZIP stream and executes the given action for each entry.
```

---

## 63/115 flow_id 06a09df0ea (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 06a09df0ea
key        : <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2336/result => <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1220/1
source     : <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L2336] entryName = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[30@L1220] invokespecial destFile.<init>(parentDirectory, %v27)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2333 |     final Set<String> names = new HashSet<String>();
 2334 |     iterate(is, new ZipEntryCallback() {
 2335 |       public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2336 |         String entryName = zipEntry.getName();
 2337 |         if (names.add(entryName)) {
 2338 |           ZipEntryUtil.copyEntry(zipEntry, in, out);
 2339 |         }
 2340 |         else if (log.isDebugEnabled()) {
 2341 |           log.debug("Duplicate entry: {}", entryName);
 2342 |         }
 2343 |       }
 2344 |     });
 2345 |   }
 2346 | 

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**
```

---

## 64/115 flow_id 5119e2850e (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 5119e2850e
key        : <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2573/result => <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1220/1
source     : <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2573] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[30@L1220] invokespecial destFile.<init>(parentDirectory, %v27)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2570 |         final Set<String> names = new HashSet<String>();
 2571 |         iterate(zip, new ZipEntryCallback() {
 2572 |           public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2573 |             if (names.add(zipEntry.getName())) {
 2574 |               ZipEntrySource entry = (ZipEntrySource) entryByPath.remove(zipEntry.getName());
 2575 |               if (entry != null) {
 2576 |                 addEntry(entry, out);
 2577 |               }
 2578 |               else {
 2579 |                 ZipEntryUtil.copyEntry(zipEntry, in, out);
 2580 |               }
 2581 |             }
 2582 |             else if (log.isDebugEnabled()) {
 2583 |               log.debug("Duplicate entry: {}", zipEntry.getName());
 2584 |             }
 2585 |           }
 2586 |         });
 2587 |       }
 2588 |       finally {

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**
```

---

## 65/115 flow_id 1362f4fee7 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 1362f4fee7
key        : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2639/result => <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1220/1
source     : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2639] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[30@L1220] invokespecial destFile.<init>(parentDirectory, %v27)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2636 |         final Set<String> names = new HashSet<String>();
 2637 |         iterate(zip, new ZipEntryCallback() {
 2638 |           public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2639 |             if (names.add(zipEntry.getName())) {
 2640 |               ZipEntrySource entry = (ZipEntrySource) entryByPath.remove(zipEntry.getName());
 2641 |               if (entry != null) {
 2642 |                 addEntry(entry, out);
 2643 |               }
 2644 |               else {
 2645 |                 ZipEntryUtil.copyEntry(zipEntry, in, out);
 2646 |               }
 2647 |             }
 2648 |             else if (log.isDebugEnabled()) {
 2649 |               log.debug("Duplicate entry: {}", zipEntry.getName());
 2650 |             }
 2651 |           }
 2652 |         });
 2653 | 
 2654 |         // Add new entries

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**
```

---

## 66/115 flow_id 07b6964565 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 07b6964565
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>@L511/result => <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1220/1
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>[25@L511] %v24 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[30@L1220] invokespecial destFile.<init>(parentDirectory, %v27)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>
file: org/zeroturnaround/zip/ZipUtil.java
  490 |    * @see #iterate(File, ZipInfoCallback)
  491 |    */
  492 |   public static void iterate(File zip, ZipEntryCallback action, Charset charset) {
  493 |     ZipFile zf = null;
  494 |     try {
  495 |       if (charset == null) {
  496 |         zf = new ZipFile(zip);
  497 |       }
  498 |       else {
  499 |         zf = new ZipFile(zip, charset);
  500 |       }
  501 | 
  502 |       Enumeration<? extends ZipEntry> en = zf.entries();
  503 |       while (en.hasMoreElements()) {
  504 |         ZipEntry e = (ZipEntry) en.nextElement();
  505 | 
  506 |         InputStream is = zf.getInputStream(e);
  507 |         try {
  508 |           action.process(is, e);
  509 |         }
  510 |         catch (IOException ze) {
  511 |           throw new ZipException("Failed to process zip entry '" + e.getName() + "' with action " + action, ze);
  512 |         }
  513 |         catch (ZipBreakException ex) {
  514 |           break;
  515 |         }
  516 |         finally {
  517 |           IOUtils.closeQuietly(is);
  518 |         }
  519 |       }
  520 |     }
  521 |     catch (IOException e) {
  522 |       throw ZipExceptionUtil.rethrow(e);
  523 |     }
  524 |     finally {
  525 |       closeQuietly(zf);
  526 |     }
  527 |   }
  528 | 
  529 |   /**
  530 |    * Reads the given ZIP file and executes the given action for each given entry.
```

---

## 67/115 flow_id 6efe189826 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 6efe189826
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipInfoCallback)>@L673/result => <org.zeroturnaround.zip.ZipUtil: void addEntries(java.io.File,org.zeroturnaround.zip.ZipEntrySource[],java.io.File)>@L2131/0
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipInfoCallback)>[21@L673] %v20 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void addEntries(java.io.File,org.zeroturnaround.zip.ZipEntrySource[],java.io.File)>[24@L2131] invokespecial %v25.<init>(destZip)/0
fixed methods on this flow (GT): -
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: void addEntries(java.io.File,org.zeroturnaround.zip.ZipEntrySource[],java.io.File)>, <org.zeroturnaround.zip.ZipUtil: void addEntry(java.io.File,java.lang.String,byte[],java.io.File)>, <org.zeroturnaround.zip.ZipUtil: void addEntry(java.io.File,java.lang.String,byte[],java.io.File,int)>, <org.zeroturnaround.zip.ZipUtil: void addEntry(java.io.File,java.lang.String,java.io.File,java.io.File)>, <org.zeroturnaround.zip.ZipUtil: void addEntry(java.io.File,org.zeroturnaround.zip.ZipEntrySource,java.io.File)>, <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipInfoCallback)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void addEntries(java.io.File,org.zeroturnaround.zip.ZipEntrySource[],java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 2122 |    *          new ZIP file created.
 2123 |    */
 2124 |   public static void addEntries(File zip, ZipEntrySource[] entries, File destZip) {
 2125 |     if (log.isDebugEnabled()) {
 2126 |       log.debug("Copying '" + zip + "' to '" + destZip + "' and adding " + Arrays.asList(entries) + ".");
 2127 |     }
 2128 | 
 2129 |     OutputStream destOut = null;
 2130 |     try {
 2131 |       destOut = new BufferedOutputStream(new FileOutputStream(destZip));
 2132 |       addEntries(zip, entries, destOut);
 2133 |     }
 2134 |     catch (IOException e) {
 2135 |       ZipExceptionUtil.rethrow(e);
 2136 |     }
 2137 |     finally {
 2138 |       IOUtils.closeQuietly(destOut);
 2139 |     }
 2140 |   }
 2141 | 
 2142 |   /**
 2143 |    * Copies an existing ZIP file and appends it with new entries.

### <org.zeroturnaround.zip.ZipUtil: void addEntry(java.io.File,java.lang.String,byte[],java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 2019 |    *          new ZIP file created.
 2020 |    */
 2021 |   public static void addEntry(File zip, String path, byte[] bytes, File destZip) {
 2022 |     addEntry(zip, new ByteSource(path, bytes), destZip);
 2023 |   }
 2024 | 
 2025 |   /**
 2026 |    * Copies an existing ZIP file and appends it with one new entry.

### <org.zeroturnaround.zip.ZipUtil: void addEntry(java.io.File,java.lang.String,byte[],java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 2037 |    *          the new compression method (<code>ZipEntry.STORED</code> or <code>ZipEntry.DEFLATED</code>).
 2038 |    */
 2039 |   public static void addEntry(File zip, String path, byte[] bytes, File destZip, final int compressionMethod) {
 2040 |     addEntry(zip, new ByteSource(path, bytes, compressionMethod), destZip);
 2041 |   }
 2042 | 
 2043 |   /**
 2044 |    * Changes a zip file, adds one new entry in-place.

### <org.zeroturnaround.zip.ZipUtil: void addEntry(java.io.File,java.lang.String,java.io.File,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 1984 |    *          new ZIP file created.
 1985 |    */
 1986 |   public static void addEntry(File zip, String path, File file, File destZip) {
 1987 |     addEntry(zip, new FileSource(path, file), destZip);
 1988 |   }
 1989 | 
 1990 |   /**
 1991 |    * Changes a zip file, adds one new entry in-place.

### <org.zeroturnaround.zip.ZipUtil: void addEntry(java.io.File,org.zeroturnaround.zip.ZipEntrySource,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 2091 |    *          new ZIP file created.
 2092 |    */
 2093 |   public static void addEntry(File zip, ZipEntrySource entry, File destZip) {
 2094 |     addEntries(zip, new ZipEntrySource[] { entry }, destZip);
 2095 |   }
 2096 | 
 2097 |   /**
 2098 |    * Changes a zip file, adds one new entry in-place.

### <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipInfoCallback)>
file: org/zeroturnaround/zip/ZipUtil.java
  657 |    * @see #iterate(File, String[], ZipEntryCallback)
  658 |    */
  659 |   public static void iterate(File zip, String[] entryNames, ZipInfoCallback action) {
  660 |     ZipFile zf = null;
  661 |     try {
  662 |       zf = new ZipFile(zip);
  663 | 
  664 |       for (int i = 0; i < entryNames.length; i++) {
  665 |         ZipEntry e = zf.getEntry(entryNames[i]);
  666 |         if (e == null) {
  667 |           continue;
  668 |         }
  669 |         try {
  670 |           action.process(e);
  671 |         }
  672 |         catch (IOException ze) {
  673 |           throw new ZipException("Failed to process zip entry '" + e.getName() + " with action " + action, ze);
  674 |         }
  675 |         catch (ZipBreakException ex) {
  676 |           break;
  677 |         }
  678 |       }
  679 |     }
  680 |     catch (IOException e) {
  681 |       throw ZipExceptionUtil.rethrow(e);
  682 |     }
  683 |     finally {
  684 |       closeQuietly(zf);
  685 |     }
  686 |   }
  687 | 
  688 |   /**
  689 |    * Reads the given ZIP stream and executes the given action for each entry.
```

---

## 68/115 flow_id 73a0023a0a (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 73a0023a0a
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.InputStream,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>@L715/result => <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>@L1721/0
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.InputStream,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>[12@L715] %v14 = invokevirtual entry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>[26@L1721] invokespecial %v25.<init>(%v32)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.InputStream,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.InputStream,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>
file: org/zeroturnaround/zip/ZipUtil.java
  703 |    */
  704 |   public static void iterate(InputStream is, ZipEntryCallback action, Charset charset) {
  705 |     try {
  706 |       ZipInputStream in = null;
  707 |       try {
  708 |         in = newCloseShieldZipInputStream(is, charset);
  709 |         ZipEntry entry;
  710 |         while ((entry = in.getNextEntry()) != null) {
  711 |           try {
  712 |             action.process(in, entry);
  713 |           }
  714 |           catch (IOException ze) {
  715 |             throw new ZipException("Failed to process zip entry '" + entry.getName() + " with action " + action, ze);
  716 |           }
  717 |           catch (ZipBreakException ex) {
  718 |             break;
  719 |           }
  720 |         }
  721 |       }
  722 |       finally {
  723 |         if (in != null) {
  724 |           in.close();
  725 |         }
  726 |       }
  727 |     }
  728 |     catch (IOException e) {
  729 |       throw ZipExceptionUtil.rethrow(e);
  730 |     }
  731 |   }
  732 | 
  733 |   /**
  734 |    * See {@link #iterate(InputStream, ZipEntryCallback, Charset)}. This method

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>
file: org/zeroturnaround/zip/ZipUtil.java
 1713 |    *          if true, but directory to pack doesn't have any files, throw an exception.
 1714 |    */
 1715 |   private static void pack(File dir, ZipOutputStream out, NameMapper mapper, String pathPrefix, boolean mustHaveChildren) throws IOException {
 1716 |     String[] filenames = dir.list();
 1717 |     if (filenames == null) {
 1718 |       if (!dir.exists()) {
 1719 |         throw new ZipException("Given file '" + dir + "' doesn't exist!");
 1720 |       }
 1721 |       throw new IOException("Given file is not a directory '" + dir + "'");
 1722 |     }
 1723 | 
 1724 |     if (mustHaveChildren && filenames.length == 0) {
 1725 |       throw new ZipException("Given directory '" + dir + "' doesn't contain any files!");
 1726 |     }
 1727 | 
 1728 |     for (int i = 0; i < filenames.length; i++) {
 1729 |       String filename = filenames[i];
 1730 |       File file = new File(dir, filename);
 1731 |       boolean isDir = file.isDirectory();
 1732 |       String path = pathPrefix + file.getName(); // NOSONAR
 1733 |       if (isDir) {
 1734 |         path += PATH_SEPARATOR; // NOSONAR
 1735 |       }
 1736 | 
 1737 |       // Create a ZIP entry
 1738 |       String name = mapper.map(path);
 1739 |       if (name != null) {
 1740 |         ZipEntry zipEntry = ZipEntryUtil.fromFile(name, file);
 1741 | 
 1742 |         out.putNextEntry(zipEntry);
 1743 | 
 1744 |         // Copy the file content
 1745 |         if (!isDir) {
 1746 |           FileUtils.copy(file, out);
 1747 |         }
 1748 | 
 1749 |         out.closeEntry();
 1750 |       }
 1751 | 
 1752 |       // Traverse the directory
 1753 |       if (isDir) {
 1754 |         pack(file, out, mapper, path, false);
 1755 |       }
 1756 |     }
 1757 |   }
 1758 | 
 1759 |   /**
 1760 |    * Repacks a provided ZIP file into a new ZIP with a given compression level.
```

---

## 69/115 flow_id f4602ef5f9 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow f4602ef5f9
key        : DRIVER => <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>@L1730/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[282@L63] %v173 = invokestatic nesy.Taint.srcFile()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>[47@L1730] invokespecial file.<init>(dir, filename)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v4 run0, v4 run1, v4 run2

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[282@L63] %v173 = invokestatic nesy.Taint.srcFile()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v173}
3. VarNode{<org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File)>/dir}
4. VarNode{<org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File,int)>/dir}
5. VarNode{<org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,int)>/rootDir}
6. VarNode{<org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper,int)>/sourceDir}
7. VarNode{<org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>/dir}
8. <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>[47@L1730] invokespecial file.<init>(dir, filename)/0

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 1875 |    * @see #pack(File, File)
 1876 |    */
 1877 |   public static void unexplode(File dir) {
 1878 |     unexplode(dir, DEFAULT_COMPRESSION_LEVEL);
 1879 |   }
 1880 | 
 1881 |   /**
 1882 |    * Compresses a given directory in its own location.

### <org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1895 |   public static void unexplode(File dir, int compressionLevel) {
 1896 |     try {
 1897 |       // Find a new unique name is the same directory
 1898 |       File zip = FileUtils.getTempFileFor(dir);
 1899 | 
 1900 |       // Pack it
 1901 |       pack(dir, zip, compressionLevel);
 1902 | 
 1903 |       // Delete the directory
 1904 |       FileUtils.deleteDirectory(dir);
 1905 | 
 1906 |       // Rename the archive
 1907 |       FileUtils.moveFile(zip, dir);
 1908 |     }
 1909 |     catch (IOException e) {
 1910 |       throw ZipExceptionUtil.rethrow(e);
 1911 |     }
 1912 |   }
 1913 | 
 1914 |   /**
 1915 |    * Compresses the given entries into an output stream.

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1380 |    *          compression level
 1381 |    */
 1382 |   public static void pack(File rootDir, File zip, int compressionLevel) {
 1383 |     pack(rootDir, zip, IdentityNameMapper.INSTANCE, compressionLevel);
 1384 |   }
 1385 | 
 1386 |   /**
 1387 |    * Compresses the given directory and all its sub-directories into a ZIP file.

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1581 |    *          compression level
 1582 |    */
 1583 |   public static void pack(File sourceDir, File targetZip, NameMapper mapper, int compressionLevel) {
 1584 |     log.debug("Compressing '{}' into '{}'.", sourceDir, targetZip);
 1585 |     if (!sourceDir.exists()) {
 1586 |       throw new ZipException("Given file '" + sourceDir + "' doesn't exist!");
 1587 |     }
 1588 |     ZipOutputStream out = null;
 1589 |     try {
 1590 |       out = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(targetZip)));
 1591 |       out.setLevel(compressionLevel);
 1592 |       pack(sourceDir, out, mapper, "", true);
 1593 |     }
 1594 |     catch (IOException e) {
 1595 |       throw ZipExceptionUtil.rethrow(e);
 1596 |     }
 1597 |     finally {
 1598 |       IOUtils.closeQuietly(out);
 1599 |     }
 1600 |   }
 1601 | 
 1602 |   /**
 1603 |    * Compresses the given directory and all of its sub-directories into the passed in

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>
file: org/zeroturnaround/zip/ZipUtil.java
 1713 |    *          if true, but directory to pack doesn't have any files, throw an exception.
 1714 |    */
 1715 |   private static void pack(File dir, ZipOutputStream out, NameMapper mapper, String pathPrefix, boolean mustHaveChildren) throws IOException {
 1716 |     String[] filenames = dir.list();
 1717 |     if (filenames == null) {
 1718 |       if (!dir.exists()) {
 1719 |         throw new ZipException("Given file '" + dir + "' doesn't exist!");
 1720 |       }
 1721 |       throw new IOException("Given file is not a directory '" + dir + "'");
 1722 |     }
 1723 | 
 1724 |     if (mustHaveChildren && filenames.length == 0) {
 1725 |       throw new ZipException("Given directory '" + dir + "' doesn't contain any files!");
 1726 |     }
 1727 | 
 1728 |     for (int i = 0; i < filenames.length; i++) {
 1729 |       String filename = filenames[i];
 1730 |       File file = new File(dir, filename);
 1731 |       boolean isDir = file.isDirectory();
 1732 |       String path = pathPrefix + file.getName(); // NOSONAR
 1733 |       if (isDir) {
 1734 |         path += PATH_SEPARATOR; // NOSONAR
 1735 |       }
 1736 | 
 1737 |       // Create a ZIP entry
 1738 |       String name = mapper.map(path);
 1739 |       if (name != null) {
 1740 |         ZipEntry zipEntry = ZipEntryUtil.fromFile(name, file);
 1741 | 
 1742 |         out.putNextEntry(zipEntry);
 1743 | 
 1744 |         // Copy the file content
 1745 |         if (!isDir) {
 1746 |           FileUtils.copy(file, out);
 1747 |         }
 1748 | 
 1749 |         out.closeEntry();
 1750 |       }
 1751 | 
 1752 |       // Traverse the directory
 1753 |       if (isDir) {
 1754 |         pack(file, out, mapper, path, false);
 1755 |       }
 1756 |     }
 1757 |   }
 1758 | 
 1759 |   /**
 1760 |    * Repacks a provided ZIP file into a new ZIP with a given compression level.
```

---

## 70/115 flow_id 76936cc3b2 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 76936cc3b2
key        : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>@L313/result => <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>@L1730/1
source     : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>[9@L313] o = invokeinterface elems.nextElement()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>[47@L1730] invokespecial file.<init>(dir, filename)/1
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>
file: org/zeroturnaround/zip/ZipUtil.java
 1713 |    *          if true, but directory to pack doesn't have any files, throw an exception.
 1714 |    */
 1715 |   private static void pack(File dir, ZipOutputStream out, NameMapper mapper, String pathPrefix, boolean mustHaveChildren) throws IOException {
 1716 |     String[] filenames = dir.list();
 1717 |     if (filenames == null) {
 1718 |       if (!dir.exists()) {
 1719 |         throw new ZipException("Given file '" + dir + "' doesn't exist!");
 1720 |       }
 1721 |       throw new IOException("Given file is not a directory '" + dir + "'");
 1722 |     }
 1723 | 
 1724 |     if (mustHaveChildren && filenames.length == 0) {
 1725 |       throw new ZipException("Given directory '" + dir + "' doesn't contain any files!");
 1726 |     }
 1727 | 
 1728 |     for (int i = 0; i < filenames.length; i++) {
 1729 |       String filename = filenames[i];
 1730 |       File file = new File(dir, filename);
 1731 |       boolean isDir = file.isDirectory();
 1732 |       String path = pathPrefix + file.getName(); // NOSONAR
 1733 |       if (isDir) {
 1734 |         path += PATH_SEPARATOR; // NOSONAR
 1735 |       }
 1736 | 
 1737 |       // Create a ZIP entry
 1738 |       String name = mapper.map(path);
 1739 |       if (name != null) {
 1740 |         ZipEntry zipEntry = ZipEntryUtil.fromFile(name, file);
 1741 | 
 1742 |         out.putNextEntry(zipEntry);
 1743 | 
 1744 |         // Copy the file content
 1745 |         if (!isDir) {
 1746 |           FileUtils.copy(file, out);
 1747 |         }
 1748 | 
 1749 |         out.closeEntry();
 1750 |       }
 1751 | 
 1752 |       // Traverse the directory
 1753 |       if (isDir) {
 1754 |         pack(file, out, mapper, path, false);
 1755 |       }
 1756 |     }
 1757 |   }
 1758 | 
 1759 |   /**
 1760 |    * Repacks a provided ZIP file into a new ZIP with a given compression level.
```

---

## 71/115 flow_id d08bdaa9d7 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow d08bdaa9d7
key        : <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>@L3028/result => <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>@L1730/1
source     : <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>[36@L3028] path = invokevirtual e1.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>[47@L1730] invokespecial file.<init>(dir, filename)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 3000 |   }
 3001 | 
 3002 |   private static boolean archiveEqualsInternal(File f1, File f2) throws IOException {
 3003 |     ZipFile zf1 = null;
 3004 |     ZipFile zf2 = null;
 3005 |     try {
 3006 |       zf1 = new ZipFile(f1);
 3007 |       zf2 = new ZipFile(f2);
 3008 | 
 3009 |       // Check the number of entries
 3010 |       if (zf1.size() != zf2.size()) {
 3011 |         log.debug("Number of entries changed (" + zf1.size() + " vs " + zf2.size() + ").");
 3012 |         return false;
 3013 |       }
 3014 |       /*
 3015 |        * As there are same number of entries in both archives we can traverse
 3016 |        * all entries of one of the archives and get the corresponding entries
 3017 |        * from the other archive.
 3018 |        *
 3019 |        * If a corresponding entry is missing from the second archive the
 3020 |        * archives are different and we finish the comparison.
 3021 |        *
 3022 |        * We guarantee that no entry of the second archive is skipped as there
 3023 |        * are same number of unique entries in both archives.
 3024 |        */
 3025 |       Enumeration<? extends ZipEntry> en = zf1.entries();
 3026 |       while (en.hasMoreElements()) {
 3027 |         ZipEntry e1 = (ZipEntry) en.nextElement();
 3028 |         String path = e1.getName();
 3029 |         ZipEntry e2 = zf2.getEntry(path);
      | ... (lines omitted) ...
 3035 | 
 3036 |         // Check the content
 3037 |         InputStream is1 = null;
 3038 |         InputStream is2 = null;
 3039 |         try {
 3040 |           is1 = zf1.getInputStream(e1);
 3041 |           is2 = zf2.getInputStream(e2);
 3042 | 
 3043 |           if (!IOUtils.contentEquals(is1, is2)) {
 3044 |             log.debug("Entry '{}' content changed.", path);
 3045 |             return false;
 3046 |           }
 3047 |         }
 3048 |         finally {
 3049 |           IOUtils.closeQuietly(is1);
 3050 |           IOUtils.closeQuietly(is2);
 3051 |         }
 3052 |       }
 3053 |     }
 3054 |     finally {
 3055 |       closeQuietly(zf1);
 3056 |       closeQuietly(zf2);
 3057 |     }
 3058 | 
 3059 |     log.debug("Archives are the same.");
 3060 | 
 3061 |     return true;
 3062 |   }
 3063 | 
 3064 |   /**

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>
file: org/zeroturnaround/zip/ZipUtil.java
 1713 |    *          if true, but directory to pack doesn't have any files, throw an exception.
 1714 |    */
 1715 |   private static void pack(File dir, ZipOutputStream out, NameMapper mapper, String pathPrefix, boolean mustHaveChildren) throws IOException {
 1716 |     String[] filenames = dir.list();
 1717 |     if (filenames == null) {
 1718 |       if (!dir.exists()) {
 1719 |         throw new ZipException("Given file '" + dir + "' doesn't exist!");
 1720 |       }
 1721 |       throw new IOException("Given file is not a directory '" + dir + "'");
 1722 |     }
 1723 | 
 1724 |     if (mustHaveChildren && filenames.length == 0) {
 1725 |       throw new ZipException("Given directory '" + dir + "' doesn't contain any files!");
 1726 |     }
 1727 | 
 1728 |     for (int i = 0; i < filenames.length; i++) {
 1729 |       String filename = filenames[i];
 1730 |       File file = new File(dir, filename);
 1731 |       boolean isDir = file.isDirectory();
 1732 |       String path = pathPrefix + file.getName(); // NOSONAR
 1733 |       if (isDir) {
 1734 |         path += PATH_SEPARATOR; // NOSONAR
 1735 |       }
 1736 | 
 1737 |       // Create a ZIP entry
 1738 |       String name = mapper.map(path);
 1739 |       if (name != null) {
 1740 |         ZipEntry zipEntry = ZipEntryUtil.fromFile(name, file);
 1741 | 
 1742 |         out.putNextEntry(zipEntry);
 1743 | 
 1744 |         // Copy the file content
 1745 |         if (!isDir) {
 1746 |           FileUtils.copy(file, out);
 1747 |         }
 1748 | 
 1749 |         out.closeEntry();
 1750 |       }
 1751 | 
 1752 |       // Traverse the directory
 1753 |       if (isDir) {
 1754 |         pack(file, out, mapper, path, false);
 1755 |       }
 1756 |     }
 1757 |   }
 1758 | 
 1759 |   /**
 1760 |    * Repacks a provided ZIP file into a new ZIP with a given compression level.
```

---

## 72/115 flow_id d083d79e6b (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow d083d79e6b
key        : <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>@L2408/result => <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>@L1730/1
source     : <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>[25@L2408] %v21 = invokevirtual entry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>[47@L1730] invokespecial file.<init>(dir, filename)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>
file: org/zeroturnaround/zip/ZipUtil.java
 2390 |    *
 2391 |    */
 2392 |   static Set<String> filterDirEntries(File zip, Collection<String> names) {
 2393 |     Set<String> dirs = new HashSet<String>();
 2394 |     if (zip == null) {
 2395 |       return dirs;
 2396 |     }
 2397 |     ZipFile zf = null;
 2398 |     try {
 2399 |       zf = new ZipFile(zip);
 2400 |       for (String entryName : names) {
 2401 |         ZipEntry entry = zf.getEntry(entryName);
 2402 |         if (entry != null) {
 2403 |           if (entry.isDirectory()) {
 2404 |             dirs.add(entry.getName());
 2405 |           }
 2406 |           else if (zf.getInputStream(entry) == null) {
 2407 |             // no input stream means that this is a dir.
 2408 |             dirs.add(entry.getName() + PATH_SEPARATOR);
 2409 |           }
 2410 |         }
 2411 |       }
 2412 | 
 2413 |     }
 2414 |     catch (IOException e) {
 2415 |       ZipExceptionUtil.rethrow(e);
 2416 |     }
 2417 |     finally {
 2418 |       closeQuietly(zf);
 2419 |     }
 2420 |     return dirs;
 2421 |   }
 2422 | 
 2423 |   /**

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>
file: org/zeroturnaround/zip/ZipUtil.java
 1713 |    *          if true, but directory to pack doesn't have any files, throw an exception.
 1714 |    */
 1715 |   private static void pack(File dir, ZipOutputStream out, NameMapper mapper, String pathPrefix, boolean mustHaveChildren) throws IOException {
 1716 |     String[] filenames = dir.list();
 1717 |     if (filenames == null) {
 1718 |       if (!dir.exists()) {
 1719 |         throw new ZipException("Given file '" + dir + "' doesn't exist!");
 1720 |       }
 1721 |       throw new IOException("Given file is not a directory '" + dir + "'");
 1722 |     }
 1723 | 
 1724 |     if (mustHaveChildren && filenames.length == 0) {
 1725 |       throw new ZipException("Given directory '" + dir + "' doesn't contain any files!");
 1726 |     }
 1727 | 
 1728 |     for (int i = 0; i < filenames.length; i++) {
 1729 |       String filename = filenames[i];
 1730 |       File file = new File(dir, filename);
 1731 |       boolean isDir = file.isDirectory();
 1732 |       String path = pathPrefix + file.getName(); // NOSONAR
 1733 |       if (isDir) {
 1734 |         path += PATH_SEPARATOR; // NOSONAR
 1735 |       }
 1736 | 
 1737 |       // Create a ZIP entry
 1738 |       String name = mapper.map(path);
 1739 |       if (name != null) {
 1740 |         ZipEntry zipEntry = ZipEntryUtil.fromFile(name, file);
 1741 | 
 1742 |         out.putNextEntry(zipEntry);
 1743 | 
 1744 |         // Copy the file content
 1745 |         if (!isDir) {
 1746 |           FileUtils.copy(file, out);
 1747 |         }
 1748 | 
 1749 |         out.closeEntry();
 1750 |       }
 1751 | 
 1752 |       // Traverse the directory
 1753 |       if (isDir) {
 1754 |         pack(file, out, mapper, path, false);
 1755 |       }
 1756 |     }
 1757 |   }
 1758 | 
 1759 |   /**
 1760 |    * Repacks a provided ZIP file into a new ZIP with a given compression level.
```

---

## 73/115 flow_id fdcb4523b1 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow fdcb4523b1
key        : <org.zeroturnaround.zip.ZipUtil$10: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2312/result => <org.zeroturnaround.zip.ZipUtil: void removeEntries(java.io.File,java.lang.String[],java.io.File)>@L2270/0
source     : <org.zeroturnaround.zip.ZipUtil$10: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L2312] entryName = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void removeEntries(java.io.File,java.lang.String[],java.io.File)>[25@L2270] invokespecial %v26.<init>(destZip)/0
fixed methods on this flow (GT): -
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$10: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void removeEntries(java.io.File,java.lang.String[],java.io.File)>, <org.zeroturnaround.zip.ZipUtil: void removeEntry(java.io.File,java.lang.String,java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$10: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2309 |     final Set<String> names = new HashSet<String>();
 2310 |     iterate(zip, new ZipEntryCallback() {
 2311 |       public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2312 |         String entryName = zipEntry.getName();
 2313 |         if (names.add(entryName)) {
 2314 |           ZipEntryUtil.copyEntry(zipEntry, in, out);
 2315 |         }
 2316 |         else if (log.isDebugEnabled()) {
 2317 |           log.debug("Duplicate entry: {}", entryName);
 2318 |         }
 2319 |       }
 2320 |     });
 2321 |   }
 2322 | 

### <org.zeroturnaround.zip.ZipUtil: void removeEntries(java.io.File,java.lang.String[],java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 2261 |    * @since 1.7
 2262 |    */
 2263 |   public static void removeEntries(File zip, String[] paths, File destZip) {
 2264 |     if (log.isDebugEnabled()) {
 2265 |       log.debug("Copying '" + zip + "' to '" + destZip + "' and removing paths " + Arrays.asList(paths) + ".");
 2266 |     }
 2267 | 
 2268 |     ZipOutputStream out = null;
 2269 |     try {
 2270 |       out = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(destZip)));
 2271 |       copyEntries(zip, out, new HashSet<String>(Arrays.asList(paths)));
 2272 |     }
 2273 |     catch (IOException e) {
 2274 |       throw ZipExceptionUtil.rethrow(e);
 2275 |     }
 2276 |     finally {
 2277 |       IOUtils.closeQuietly(out);
 2278 |     }
 2279 |   }
 2280 | 
 2281 |   /**
 2282 |    * Changes an existing ZIP file: removes entries with given paths.

### <org.zeroturnaround.zip.ZipUtil: void removeEntry(java.io.File,java.lang.String,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 2228 |    * @since 1.7
 2229 |    */
 2230 |   public static void removeEntry(File zip, String path, File destZip) {
 2231 |     removeEntries(zip, new String[] { path }, destZip);
 2232 |   }
 2233 | 
 2234 |   /**
 2235 |    * Changes an existing ZIP file: removes entry with a given path.
```

---

## 74/115 flow_id b908b106a4 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow b908b106a4
key        : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>@L313/result => <org.zeroturnaround.zip.ZipUtil: void repack(java.io.File,int)>@L1826/0
source     : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>[9@L313] o = invokeinterface elems.nextElement()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void repack(java.io.File,int)>[12@L1826] invokespecial %v6.<init>(%v11)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1
N3 (iris-like run1): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: void repack(java.io.File,int)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void repack(java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1817 |    */
 1818 |   public static void repack(File zip, int compressionLevel) {
 1819 |     try {
 1820 |       File tmpZip = FileUtils.getTempFileFor(zip);
 1821 | 
 1822 |       repack(zip, tmpZip, compressionLevel);
 1823 | 
 1824 |       // Delete original zip
 1825 |       if (!zip.delete()) {
 1826 |         throw new IOException("Unable to delete the file: " + zip);
 1827 |       }
 1828 | 
 1829 |       // Rename the archive
 1830 |       FileUtils.moveFile(tmpZip, zip);
 1831 |     }
 1832 |     catch (IOException e) {
 1833 |       throw ZipExceptionUtil.rethrow(e);
 1834 |     }
 1835 |   }
 1836 | 
 1837 |   /**
 1838 |    * RepackZipEntryCallback used in repacking methods.
```

---

## 75/115 flow_id e96fb1c68a (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow e96fb1c68a
key        : <org.apache.log4j.Category: void removeAllAppenders()>@L889/result => <org.zeroturnaround.zip.commons.FileExistsException: void <init>(java.lang.String)>@L48/0
source     : <org.apache.log4j.Category: void removeAllAppenders()>[10@L889] %v10 = invokeinterface iter.nextElement()/result
sink       : <org.zeroturnaround.zip.commons.FileExistsException: void <init>(java.lang.String)>[0@L48] invokespecial this.<init>(message)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.commons.FileExistsException: void <init>(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.commons.FileExistsException: void <init>(java.lang.String)>
file: org/zeroturnaround/zip/commons/FileExistsException.java
   45 |      * @param message The error message
   46 |      */
   47 |     public FileExistsException(String message) {
   48 |         super(message);
   49 |     }
   50 | 
   51 |     /**
   52 |      * Construct an instance with the specified file.
```

---

## 76/115 flow_id c47dceb68d (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow c47dceb68d
key        : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>@L77/result => <org.zeroturnaround.zip.commons.FileExistsException: void <init>(java.lang.String)>@L48/0
source     : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>[4@L77] %v5 = invokevirtual original.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileExistsException: void <init>(java.lang.String)>[0@L48] invokespecial this.<init>(message)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>, <org.zeroturnaround.zip.commons.FileExistsException: void <init>(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>
file: org/zeroturnaround/zip/ZipEntryUtil.java
   58 |    * @return copy of the original entry, but with the given name
   59 |    */
   60 |   static ZipEntry copy(ZipEntry original, String newName) {
   61 |     ZipEntry copy = new ZipEntry(newName == null ? original.getName() : newName);
   62 |     if (original.getCrc() != -1) {
   63 |       copy.setCrc(original.getCrc());
   64 |     }
   65 |     if (original.getMethod() != -1) {
   66 |       copy.setMethod(original.getMethod());
   67 |     }
   68 |     if (original.getSize() >= 0) {
   69 |       copy.setSize(original.getSize());
   70 |     }
   71 |     if (original.getExtra() != null) {
   72 |       copy.setExtra(original.getExtra());
   73 |     }
   74 | 
   75 |     copy.setComment(original.getComment());
   76 |     copy.setTime(original.getTime());
   77 |     return copy;
   78 |   }
   79 | 
   80 |   /**

### <org.zeroturnaround.zip.commons.FileExistsException: void <init>(java.lang.String)>
file: org/zeroturnaround/zip/commons/FileExistsException.java
   45 |      * @param message The error message
   46 |      */
   47 |     public FileExistsException(String message) {
   48 |         super(message);
   49 |     }
   50 | 
   51 |     /**
   52 |      * Construct an instance with the specified file.
```

---

## 77/115 flow_id dacfa30b19 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow dacfa30b19
key        : DRIVER => <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>@L75/1
source     : <nesy.NesyDriver: void main(java.lang.String[])>[4@L6] %v4 = invokestatic nesy.Taint.src()/result
sink       : <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>[15@L75] invokespecial result.<init>(parent, %v16)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtils.java
   67 |    * @return a non-existing file in the same directory using the same name as prefix.
   68 |    */
   69 |   public static File getTempFileFor(File file) {
   70 |     File parent = file.getParentFile();
   71 |     String name = file.getName();
   72 |     File result;
   73 |     int index = 0;
   74 |     do {
   75 |       result = new File(parent, name + "_" + index++);
   76 |     }
   77 |     while (result.exists());
   78 |     return result;
   79 |   }
   80 | }
```

---

## 78/115 flow_id 3d4c7875a7 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 3d4c7875a7
key        : DRIVER => <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean deleteQuietly(java.io.File)>@L689/base
source     : <nesy.NesyDriver: void main(java.lang.String[])>[172@L72] %v107 = invokestatic nesy.Taint.srcFile()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean deleteQuietly(java.io.File)>[8@L689] %v6 = invokevirtual file.delete()/base
fixed methods on this flow (GT): -
reported by: iris-like run0, v1 run0, v2 run0, v3 run0, v3-noV2 run0, v3-noV3 run0, v3-noval run0, v4 run0
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[172@L72] %v107 = invokestatic nesy.Taint.srcFile()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v107}
3. VarNode{<org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File)>/dir}
4. VarNode{<org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File,int)>/dir}
5. VarNode{<org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>/destFile}
6. VarNode{<org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean deleteQuietly(java.io.File)>/file}
7. <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean deleteQuietly(java.io.File)>[8@L689] %v6 = invokevirtual file.delete()/base

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 1875 |    * @see #pack(File, File)
 1876 |    */
 1877 |   public static void unexplode(File dir) {
 1878 |     unexplode(dir, DEFAULT_COMPRESSION_LEVEL);
 1879 |   }
 1880 | 
 1881 |   /**
 1882 |    * Compresses a given directory in its own location.

### <org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1895 |   public static void unexplode(File dir, int compressionLevel) {
 1896 |     try {
 1897 |       // Find a new unique name is the same directory
 1898 |       File zip = FileUtils.getTempFileFor(dir);
 1899 | 
 1900 |       // Pack it
 1901 |       pack(dir, zip, compressionLevel);
 1902 | 
 1903 |       // Delete the directory
 1904 |       FileUtils.deleteDirectory(dir);
 1905 | 
 1906 |       // Rename the archive
 1907 |       FileUtils.moveFile(zip, dir);
 1908 |     }
 1909 |     catch (IOException e) {
 1910 |       throw ZipExceptionUtil.rethrow(e);
 1911 |     }
 1912 |   }
 1913 | 
 1914 |   /**
 1915 |    * Compresses the given entries into an output stream.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
 1023 |    * @since 1.4
 1024 |    */
 1025 |   public static void moveFile(File srcFile, File destFile) throws IOException {
 1026 |     if (srcFile == null) {
 1027 |       throw new NullPointerException("Source must not be null");
 1028 |     }
 1029 |     if (destFile == null) {
 1030 |       throw new NullPointerException("Destination must not be null");
 1031 |     }
 1032 |     if (!srcFile.exists()) {
 1033 |       throw new FileNotFoundException("Source '" + srcFile + "' does not exist");
 1034 |     }
 1035 |     if (srcFile.isDirectory()) {
 1036 |       throw new IOException("Source '" + srcFile + "' is a directory");
 1037 |     }
 1038 |     if (destFile.exists()) {
 1039 |       throw new FileExistsException("Destination '" + destFile + "' already exists");
 1040 |     }
 1041 |     if (destFile.isDirectory()) {
 1042 |       throw new IOException("Destination '" + destFile + "' is a directory");
 1043 |     }
 1044 |     boolean rename = srcFile.renameTo(destFile);
 1045 |     if (!rename) {
 1046 |       copyFile( srcFile, destFile );
 1047 |       if (!srcFile.delete()) {
 1048 |         FileUtils.deleteQuietly(destFile);
 1049 |         throw new IOException("Failed to delete original file '" + srcFile +
 1050 |             "' after copy to '" + destFile + "'");
 1051 |       }
 1052 |     }
 1053 |   }
 1054 | 
 1055 |   /**
 1056 |    * Determines whether the specified file is a Symbolic Link rather than an actual file.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean deleteQuietly(java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  675 |    * @since 1.4
  676 |    */
  677 |   public static boolean deleteQuietly(File file) {
  678 |     if (file == null) {
  679 |       return false;
  680 |     }
  681 |     try {
  682 |       if (file.isDirectory()) {
  683 |         cleanDirectory(file);
  684 |       }
  685 |     } catch (Exception ignored) {
  686 |     }
  687 | 
  688 |     try {
  689 |       return file.delete();
  690 |     } catch (Exception ignored) {
  691 |       return false;
  692 |     }
  693 |   }
  694 | 
```

---

## 79/115 flow_id f1f5a76d36 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow f1f5a76d36
key        : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>@L77/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>@L1081/1
source     : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>[4@L77] %v5 = invokevirtual original.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>[18@L1081] invokespecial %v11.<init>(canonicalDir, %v12)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File)>, <org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File,int)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void deleteDirectory(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>
file: org/zeroturnaround/zip/ZipEntryUtil.java
   58 |    * @return copy of the original entry, but with the given name
   59 |    */
   60 |   static ZipEntry copy(ZipEntry original, String newName) {
   61 |     ZipEntry copy = new ZipEntry(newName == null ? original.getName() : newName);
   62 |     if (original.getCrc() != -1) {
   63 |       copy.setCrc(original.getCrc());
   64 |     }
   65 |     if (original.getMethod() != -1) {
   66 |       copy.setMethod(original.getMethod());
   67 |     }
   68 |     if (original.getSize() >= 0) {
   69 |       copy.setSize(original.getSize());
   70 |     }
   71 |     if (original.getExtra() != null) {
   72 |       copy.setExtra(original.getExtra());
   73 |     }
   74 | 
   75 |     copy.setComment(original.getComment());
   76 |     copy.setTime(original.getTime());
   77 |     return copy;
   78 |   }
   79 | 
   80 |   /**

### <org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 1875 |    * @see #pack(File, File)
 1876 |    */
 1877 |   public static void unexplode(File dir) {
 1878 |     unexplode(dir, DEFAULT_COMPRESSION_LEVEL);
 1879 |   }
 1880 | 
 1881 |   /**
 1882 |    * Compresses a given directory in its own location.

### <org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1895 |   public static void unexplode(File dir, int compressionLevel) {
 1896 |     try {
 1897 |       // Find a new unique name is the same directory
 1898 |       File zip = FileUtils.getTempFileFor(dir);
 1899 | 
 1900 |       // Pack it
 1901 |       pack(dir, zip, compressionLevel);
 1902 | 
 1903 |       // Delete the directory
 1904 |       FileUtils.deleteDirectory(dir);
 1905 | 
 1906 |       // Rename the archive
 1907 |       FileUtils.moveFile(zip, dir);
 1908 |     }
 1909 |     catch (IOException e) {
 1910 |       throw ZipExceptionUtil.rethrow(e);
 1911 |     }
 1912 |   }
 1913 | 
 1914 |   /**
 1915 |    * Compresses the given entries into an output stream.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
 1067 |    * @since 2.0
 1068 |    */
 1069 |   public static boolean isSymlink(File file) throws IOException {
 1070 |     if (file == null) {
 1071 |       throw new NullPointerException("File must not be null");
 1072 |     }
 1073 |     if (FilenameUtils.isSystemWindows()) {
 1074 |       return false;
 1075 |     }
 1076 |     File fileInCanonicalDir = null;
 1077 |     if (file.getParent() == null) {
 1078 |       fileInCanonicalDir = file;
 1079 |     } else {
 1080 |       File canonicalDir = file.getParentFile().getCanonicalFile();
 1081 |       fileInCanonicalDir = new File(canonicalDir, file.getName());
 1082 |     }
 1083 | 
 1084 |     if (fileInCanonicalDir.getCanonicalFile().equals(fileInCanonicalDir.getAbsoluteFile())) {
 1085 |       return false;
 1086 |     } else {
 1087 |       return true;
 1088 |     }
 1089 |   }
 1090 | }

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void deleteDirectory(java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  644 |    * @throws IOException in case deletion is unsuccessful
  645 |    */
  646 |   public static void deleteDirectory(File directory) throws IOException {
  647 |     if (!directory.exists()) {
  648 |       return;
  649 |     }
  650 | 
  651 |     if (!isSymlink(directory)) {
  652 |       cleanDirectory(directory);
  653 |     }
  654 | 
  655 |     if (!directory.delete()) {
  656 |       String message =
  657 |           "Unable to delete directory " + directory + ".";
  658 |       throw new IOException(message);
  659 |     }
  660 |   }
  661 | 
  662 |   /**
  663 |    * Deletes a file, never throwing an exception. If file is a directory, delete it and all sub-directories.
```

---

## 80/115 flow_id f699021396 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow f699021396
key        : <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2336/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: java.io.FileOutputStream openOutputStream(java.io.File,boolean)>@L207/0
source     : <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L2336] entryName = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: java.io.FileOutputStream openOutputStream(java.io.File,boolean)>[44@L207] invokespecial %v27.<init>(%v34)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: java.io.FileOutputStream openOutputStream(java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2333 |     final Set<String> names = new HashSet<String>();
 2334 |     iterate(is, new ZipEntryCallback() {
 2335 |       public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2336 |         String entryName = zipEntry.getName();
 2337 |         if (names.add(entryName)) {
 2338 |           ZipEntryUtil.copyEntry(zipEntry, in, out);
 2339 |         }
 2340 |         else if (log.isDebugEnabled()) {
 2341 |           log.debug("Duplicate entry: {}", entryName);
 2342 |         }
 2343 |       }
 2344 |     });
 2345 |   }
 2346 | 

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: java.io.FileOutputStream openOutputStream(java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  193 |    * @since 2.1
  194 |    */
  195 |   public static FileOutputStream openOutputStream(File file, boolean append) throws IOException {
  196 |     if (file.exists()) {
  197 |       if (file.isDirectory()) {
  198 |         throw new IOException("File '" + file + "' exists but is a directory");
  199 |       }
  200 |       if (file.canWrite() == false) {
  201 |         throw new IOException("File '" + file + "' cannot be written to");
  202 |       }
  203 |     } else {
  204 |       File parent = file.getParentFile();
  205 |       if (parent != null) {
  206 |         if (!parent.mkdirs() && !parent.isDirectory()) {
  207 |           throw new IOException("Directory '" + parent + "' could not be created");
  208 |         }
  209 |       }
  210 |     }
  211 |     return new FileOutputStream(file, append);
  212 |   }
  213 | 
  214 |   //-----------------------------------------------------------------------
```

---

## 81/115 flow_id 6080122b6a (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 6080122b6a
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipInfoCallback)>@L629/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: java.io.FileOutputStream openOutputStream(java.io.File,boolean)>@L207/0
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipInfoCallback)>[18@L629] %v18 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: java.io.FileOutputStream openOutputStream(java.io.File,boolean)>[44@L207] invokespecial %v27.<init>(%v34)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipInfoCallback)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: java.io.FileOutputStream openOutputStream(java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipInfoCallback)>
file: org/zeroturnaround/zip/ZipUtil.java
  615 |    * @see #iterate(File, ZipEntryCallback)
  616 |    */
  617 |   public static void iterate(File zip, ZipInfoCallback action) {
  618 |     ZipFile zf = null;
  619 |     try {
  620 |       zf = new ZipFile(zip);
  621 | 
  622 |       Enumeration<? extends ZipEntry> en = zf.entries();
  623 |       while (en.hasMoreElements()) {
  624 |         ZipEntry e = (ZipEntry) en.nextElement();
  625 |         try {
  626 |           action.process(e);
  627 |         }
  628 |         catch (IOException ze) {
  629 |           throw new ZipException("Failed to process zip entry '" + e.getName() + " with action " + action, ze);
  630 |         }
  631 |         catch (ZipBreakException ex) {
  632 |           break;
  633 |         }
  634 |       }
  635 |     }
  636 |     catch (IOException e) {
  637 |       throw ZipExceptionUtil.rethrow(e);
  638 |     }
  639 |     finally {
  640 |       closeQuietly(zf);
  641 |     }
  642 |   }
  643 | 
  644 |   /**
  645 |    * Scans the given ZIP file and executes the given action for each given entry.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: java.io.FileOutputStream openOutputStream(java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  193 |    * @since 2.1
  194 |    */
  195 |   public static FileOutputStream openOutputStream(File file, boolean append) throws IOException {
  196 |     if (file.exists()) {
  197 |       if (file.isDirectory()) {
  198 |         throw new IOException("File '" + file + "' exists but is a directory");
  199 |       }
  200 |       if (file.canWrite() == false) {
  201 |         throw new IOException("File '" + file + "' cannot be written to");
  202 |       }
  203 |     } else {
  204 |       File parent = file.getParentFile();
  205 |       if (parent != null) {
  206 |         if (!parent.mkdirs() && !parent.isDirectory()) {
  207 |           throw new IOException("Directory '" + parent + "' could not be created");
  208 |         }
  209 |       }
  210 |     }
  211 |     return new FileOutputStream(file, append);
  212 |   }
  213 | 
  214 |   //-----------------------------------------------------------------------
```

---

## 82/115 flow_id b7babde100 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow b7babde100
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipInfoCallback)>@L629/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void cleanDirectory(java.io.File)>@L714/0
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipInfoCallback)>[18@L629] %v18 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void cleanDirectory(java.io.File)>[33@L714] invokespecial %v25.<init>(%v30)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipInfoCallback)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void cleanDirectory(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipInfoCallback)>
file: org/zeroturnaround/zip/ZipUtil.java
  615 |    * @see #iterate(File, ZipEntryCallback)
  616 |    */
  617 |   public static void iterate(File zip, ZipInfoCallback action) {
  618 |     ZipFile zf = null;
  619 |     try {
  620 |       zf = new ZipFile(zip);
  621 | 
  622 |       Enumeration<? extends ZipEntry> en = zf.entries();
  623 |       while (en.hasMoreElements()) {
  624 |         ZipEntry e = (ZipEntry) en.nextElement();
  625 |         try {
  626 |           action.process(e);
  627 |         }
  628 |         catch (IOException ze) {
  629 |           throw new ZipException("Failed to process zip entry '" + e.getName() + " with action " + action, ze);
  630 |         }
  631 |         catch (ZipBreakException ex) {
  632 |           break;
  633 |         }
  634 |       }
  635 |     }
  636 |     catch (IOException e) {
  637 |       throw ZipExceptionUtil.rethrow(e);
  638 |     }
  639 |     finally {
  640 |       closeQuietly(zf);
  641 |     }
  642 |   }
  643 | 
  644 |   /**
  645 |    * Scans the given ZIP file and executes the given action for each given entry.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void cleanDirectory(java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  699 |    * @throws IOException in case cleaning is unsuccessful
  700 |    */
  701 |   public static void cleanDirectory(File directory) throws IOException {
  702 |     if (!directory.exists()) {
  703 |       String message = directory + " does not exist";
  704 |       throw new IllegalArgumentException(message);
  705 |     }
  706 | 
  707 |     if (!directory.isDirectory()) {
  708 |       String message = directory + " is not a directory";
  709 |       throw new IllegalArgumentException(message);
  710 |     }
  711 | 
  712 |     File[] files = directory.listFiles();
  713 |     if (files == null) {  // null if security restricted
  714 |       throw new IOException("Failed to list contents of " + directory);
  715 |     }
  716 | 
  717 |     IOException exception = null;
  718 |     for (File file : files) {
  719 |       try {
  720 |         forceDelete(file);
  721 |       } catch (IOException ioe) {
  722 |         exception = ioe;
  723 |       }
  724 |     }
  725 | 
  726 |     if (null != exception) {
  727 |       throw exception;
  728 |     }
  729 |   }
  730 | 
  731 |   //-----------------------------------------------------------------------
  732 |   /**
```

---

## 83/115 flow_id 02213da1f6 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 02213da1f6
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipInfoCallback)>@L629/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>@L571/0
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipInfoCallback)>[18@L629] %v18 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>[36@L571] invokespecial %v27.<init>(%v34)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipInfoCallback)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipInfoCallback)>
file: org/zeroturnaround/zip/ZipUtil.java
  615 |    * @see #iterate(File, ZipEntryCallback)
  616 |    */
  617 |   public static void iterate(File zip, ZipInfoCallback action) {
  618 |     ZipFile zf = null;
  619 |     try {
  620 |       zf = new ZipFile(zip);
  621 | 
  622 |       Enumeration<? extends ZipEntry> en = zf.entries();
  623 |       while (en.hasMoreElements()) {
  624 |         ZipEntry e = (ZipEntry) en.nextElement();
  625 |         try {
  626 |           action.process(e);
  627 |         }
  628 |         catch (IOException ze) {
  629 |           throw new ZipException("Failed to process zip entry '" + e.getName() + " with action " + action, ze);
  630 |         }
  631 |         catch (ZipBreakException ex) {
  632 |           break;
  633 |         }
  634 |       }
  635 |     }
  636 |     catch (IOException e) {
  637 |       throw ZipExceptionUtil.rethrow(e);
  638 |     }
  639 |     finally {
  640 |       closeQuietly(zf);
  641 |     }
  642 |   }
  643 | 
  644 |   /**
  645 |    * Scans the given ZIP file and executes the given action for each given entry.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  558 |    */
  559 |   public static void copyDirectory(File srcDir, File destDir,
  560 |       FileFilter filter, boolean preserveFileDate) throws IOException {
  561 |     if (srcDir == null) {
  562 |       throw new NullPointerException("Source must not be null");
  563 |     }
  564 |     if (destDir == null) {
  565 |       throw new NullPointerException("Destination must not be null");
  566 |     }
  567 |     if (srcDir.exists() == false) {
  568 |       throw new FileNotFoundException("Source '" + srcDir + "' does not exist");
  569 |     }
  570 |     if (srcDir.isDirectory() == false) {
  571 |       throw new IOException("Source '" + srcDir + "' exists but is not a directory");
  572 |     }
  573 |     if (srcDir.getCanonicalPath().equals(destDir.getCanonicalPath())) {
  574 |       throw new IOException("Source '" + srcDir + "' and destination '" + destDir + "' are the same");
  575 |     }
  576 | 
  577 |     // Cater for destination being directory within the source directory (see IO-141)
  578 |     List<String> exclusionList = null;
  579 |     if (destDir.getCanonicalPath().startsWith(srcDir.getCanonicalPath())) {
  580 |       File[] srcFiles = filter == null ? srcDir.listFiles() : srcDir.listFiles(filter);
  581 |       if (srcFiles != null && srcFiles.length > 0) {
  582 |         exclusionList = new ArrayList<String>(srcFiles.length);
  583 |         for (File srcFile : srcFiles) {
  584 |           File copiedFile = new File(destDir, srcFile.getName());
  585 |           exclusionList.add(copiedFile.getCanonicalPath());
  586 |         }
  587 |       }
  588 |     }
  589 |     doCopyDirectory(srcDir, destDir, filter, preserveFileDate, exclusionList);
  590 |   }
  591 | 
  592 |   /**
  593 |    * Internal copy directory method.
```

---

## 84/115 flow_id ed238c5914 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow ed238c5914
key        : DRIVER => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>@L584/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[619@L119] %v389 = invokestatic nesy.Taint.srcFile()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>[78@L584] invokespecial copiedFile.<init>(destDir, %v59)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[619@L119] %v389 = invokestatic nesy.Taint.srcFile()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v389}
3. VarNode{<org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File)>/destDir}
4. VarNode{<org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,boolean)>/destDir}
5. VarNode{<org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>/destDir}
6. <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>[78@L584] invokespecial copiedFile.<init>(destDir, %v59)/0

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  476 |    * @since 1.1
  477 |    */
  478 |   public static void copyDirectory(File srcDir, File destDir) throws IOException {
  479 |     copyDirectory(srcDir, destDir, true);
  480 |   }
  481 | 
  482 |   /**
  483 |    * Copies a whole directory to a new location.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  507 |    */
  508 |   public static void copyDirectory(File srcDir, File destDir,
  509 |       boolean preserveFileDate) throws IOException {
  510 |     copyDirectory(srcDir, destDir, null, preserveFileDate);
  511 |   }
  512 | 
  513 |   /**
  514 |    * Copies a filtered directory to a new location.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  558 |    */
  559 |   public static void copyDirectory(File srcDir, File destDir,
  560 |       FileFilter filter, boolean preserveFileDate) throws IOException {
  561 |     if (srcDir == null) {
  562 |       throw new NullPointerException("Source must not be null");
  563 |     }
  564 |     if (destDir == null) {
  565 |       throw new NullPointerException("Destination must not be null");
  566 |     }
  567 |     if (srcDir.exists() == false) {
  568 |       throw new FileNotFoundException("Source '" + srcDir + "' does not exist");
  569 |     }
  570 |     if (srcDir.isDirectory() == false) {
  571 |       throw new IOException("Source '" + srcDir + "' exists but is not a directory");
  572 |     }
  573 |     if (srcDir.getCanonicalPath().equals(destDir.getCanonicalPath())) {
  574 |       throw new IOException("Source '" + srcDir + "' and destination '" + destDir + "' are the same");
  575 |     }
  576 | 
  577 |     // Cater for destination being directory within the source directory (see IO-141)
  578 |     List<String> exclusionList = null;
  579 |     if (destDir.getCanonicalPath().startsWith(srcDir.getCanonicalPath())) {
  580 |       File[] srcFiles = filter == null ? srcDir.listFiles() : srcDir.listFiles(filter);
  581 |       if (srcFiles != null && srcFiles.length > 0) {
  582 |         exclusionList = new ArrayList<String>(srcFiles.length);
  583 |         for (File srcFile : srcFiles) {
  584 |           File copiedFile = new File(destDir, srcFile.getName());
  585 |           exclusionList.add(copiedFile.getCanonicalPath());
  586 |         }
  587 |       }
  588 |     }
  589 |     doCopyDirectory(srcDir, destDir, filter, preserveFileDate, exclusionList);
  590 |   }
  591 | 
  592 |   /**
  593 |    * Internal copy directory method.
```

---

## 85/115 flow_id d20a1dec0f (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow d20a1dec0f
key        : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>@L313/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>@L584/1
source     : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>[9@L313] o = invokeinterface elems.nextElement()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>[78@L584] invokespecial copiedFile.<init>(destDir, %v59)/1
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2
N3 (iris-like run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  558 |    */
  559 |   public static void copyDirectory(File srcDir, File destDir,
  560 |       FileFilter filter, boolean preserveFileDate) throws IOException {
  561 |     if (srcDir == null) {
  562 |       throw new NullPointerException("Source must not be null");
  563 |     }
  564 |     if (destDir == null) {
  565 |       throw new NullPointerException("Destination must not be null");
  566 |     }
  567 |     if (srcDir.exists() == false) {
  568 |       throw new FileNotFoundException("Source '" + srcDir + "' does not exist");
  569 |     }
  570 |     if (srcDir.isDirectory() == false) {
  571 |       throw new IOException("Source '" + srcDir + "' exists but is not a directory");
  572 |     }
  573 |     if (srcDir.getCanonicalPath().equals(destDir.getCanonicalPath())) {
  574 |       throw new IOException("Source '" + srcDir + "' and destination '" + destDir + "' are the same");
  575 |     }
  576 | 
  577 |     // Cater for destination being directory within the source directory (see IO-141)
  578 |     List<String> exclusionList = null;
  579 |     if (destDir.getCanonicalPath().startsWith(srcDir.getCanonicalPath())) {
  580 |       File[] srcFiles = filter == null ? srcDir.listFiles() : srcDir.listFiles(filter);
  581 |       if (srcFiles != null && srcFiles.length > 0) {
  582 |         exclusionList = new ArrayList<String>(srcFiles.length);
  583 |         for (File srcFile : srcFiles) {
  584 |           File copiedFile = new File(destDir, srcFile.getName());
  585 |           exclusionList.add(copiedFile.getCanonicalPath());
  586 |         }
  587 |       }
  588 |     }
  589 |     doCopyDirectory(srcDir, destDir, filter, preserveFileDate, exclusionList);
  590 |   }
  591 | 
  592 |   /**
  593 |    * Internal copy directory method.
```

---

## 86/115 flow_id 12c06dc687 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 12c06dc687
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>@L511/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>@L392/0
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>[25@L511] %v24 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>[35@L392] invokespecial %v20.<init>(%v27)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>
file: org/zeroturnaround/zip/ZipUtil.java
  490 |    * @see #iterate(File, ZipInfoCallback)
  491 |    */
  492 |   public static void iterate(File zip, ZipEntryCallback action, Charset charset) {
  493 |     ZipFile zf = null;
  494 |     try {
  495 |       if (charset == null) {
  496 |         zf = new ZipFile(zip);
  497 |       }
  498 |       else {
  499 |         zf = new ZipFile(zip, charset);
  500 |       }
  501 | 
  502 |       Enumeration<? extends ZipEntry> en = zf.entries();
  503 |       while (en.hasMoreElements()) {
  504 |         ZipEntry e = (ZipEntry) en.nextElement();
  505 | 
  506 |         InputStream is = zf.getInputStream(e);
  507 |         try {
  508 |           action.process(is, e);
  509 |         }
  510 |         catch (IOException ze) {
  511 |           throw new ZipException("Failed to process zip entry '" + e.getName() + "' with action " + action, ze);
  512 |         }
  513 |         catch (ZipBreakException ex) {
  514 |           break;
  515 |         }
  516 |         finally {
  517 |           IOUtils.closeQuietly(is);
  518 |         }
  519 |       }
  520 |     }
  521 |     catch (IOException e) {
  522 |       throw ZipExceptionUtil.rethrow(e);
  523 |     }
  524 |     finally {
  525 |       closeQuietly(zf);
  526 |     }
  527 |   }
  528 | 
  529 |   /**
  530 |    * Reads the given ZIP file and executes the given action for each given entry.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  379 |    */
  380 |   public static void copyFile(File srcFile, File destFile,
  381 |       boolean preserveFileDate) throws IOException {
  382 |     if (srcFile == null) {
  383 |       throw new NullPointerException("Source must not be null");
  384 |     }
  385 |     if (destFile == null) {
  386 |       throw new NullPointerException("Destination must not be null");
  387 |     }
  388 |     if (srcFile.exists() == false) {
  389 |       throw new FileNotFoundException("Source '" + srcFile + "' does not exist");
  390 |     }
  391 |     if (srcFile.isDirectory()) {
  392 |       throw new IOException("Source '" + srcFile + "' exists but is a directory");
  393 |     }
  394 |     if (srcFile.getCanonicalPath().equals(destFile.getCanonicalPath())) {
  395 |       throw new IOException("Source '" + srcFile + "' and destination '" + destFile + "' are the same");
  396 |     }
  397 |     File parentFile = destFile.getParentFile();
  398 |     if (parentFile != null) {
  399 |       if (!parentFile.mkdirs() && !parentFile.isDirectory()) {
  400 |         throw new IOException("Destination '" + parentFile + "' directory cannot be created");
  401 |       }
  402 |     }
  403 |     if (destFile.exists() && destFile.canWrite() == false) {
  404 |       throw new IOException("Destination '" + destFile + "' exists but is read-only");
  405 |     }
  406 |     doCopyFile(srcFile, destFile, preserveFileDate);
  407 |   }
  408 | 
  409 |   /**
  410 |    * Internal copy file method.
```

---

## 87/115 flow_id 6db049dc40 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 6db049dc40
key        : DRIVER => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>@L399/base
source     : <nesy.NesyDriver: void main(java.lang.String[])>[172@L72] %v107 = invokestatic nesy.Taint.srcFile()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>[57@L399] %v43 = invokevirtual parentFile.mkdirs()/base
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2, v2 run2, v3 run2, v3-noV2 run2, v3-noV3 run2, v3-noval run2, v4 run2
N3 (v3 run2): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[172@L72] %v107 = invokestatic nesy.Taint.srcFile()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v107}
3. VarNode{<org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File)>/dir}
4. VarNode{<org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File,int)>/dir}
5. VarNode{<org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>/destFile}
6. VarNode{<org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File)>/destFile}
7. VarNode{<org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>/destFile}
8. VarNode{<org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>/parentFile}
9. <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>[57@L399] %v43 = invokevirtual parentFile.mkdirs()/base

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 1875 |    * @see #pack(File, File)
 1876 |    */
 1877 |   public static void unexplode(File dir) {
 1878 |     unexplode(dir, DEFAULT_COMPRESSION_LEVEL);
 1879 |   }
 1880 | 
 1881 |   /**
 1882 |    * Compresses a given directory in its own location.

### <org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1895 |   public static void unexplode(File dir, int compressionLevel) {
 1896 |     try {
 1897 |       // Find a new unique name is the same directory
 1898 |       File zip = FileUtils.getTempFileFor(dir);
 1899 | 
 1900 |       // Pack it
 1901 |       pack(dir, zip, compressionLevel);
 1902 | 
 1903 |       // Delete the directory
 1904 |       FileUtils.deleteDirectory(dir);
 1905 | 
 1906 |       // Rename the archive
 1907 |       FileUtils.moveFile(zip, dir);
 1908 |     }
 1909 |     catch (IOException e) {
 1910 |       throw ZipExceptionUtil.rethrow(e);
 1911 |     }
 1912 |   }
 1913 | 
 1914 |   /**
 1915 |    * Compresses the given entries into an output stream.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
 1023 |    * @since 1.4
 1024 |    */
 1025 |   public static void moveFile(File srcFile, File destFile) throws IOException {
 1026 |     if (srcFile == null) {
 1027 |       throw new NullPointerException("Source must not be null");
 1028 |     }
 1029 |     if (destFile == null) {
 1030 |       throw new NullPointerException("Destination must not be null");
 1031 |     }
 1032 |     if (!srcFile.exists()) {
 1033 |       throw new FileNotFoundException("Source '" + srcFile + "' does not exist");
 1034 |     }
 1035 |     if (srcFile.isDirectory()) {
 1036 |       throw new IOException("Source '" + srcFile + "' is a directory");
 1037 |     }
 1038 |     if (destFile.exists()) {
 1039 |       throw new FileExistsException("Destination '" + destFile + "' already exists");
 1040 |     }
 1041 |     if (destFile.isDirectory()) {
 1042 |       throw new IOException("Destination '" + destFile + "' is a directory");
 1043 |     }
 1044 |     boolean rename = srcFile.renameTo(destFile);
 1045 |     if (!rename) {
 1046 |       copyFile( srcFile, destFile );
 1047 |       if (!srcFile.delete()) {
 1048 |         FileUtils.deleteQuietly(destFile);
 1049 |         throw new IOException("Failed to delete original file '" + srcFile +
 1050 |             "' after copy to '" + destFile + "'");
 1051 |       }
 1052 |     }
 1053 |   }
 1054 | 
 1055 |   /**
 1056 |    * Determines whether the specified file is a Symbolic Link rather than an actual file.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  350 |    * @see #copyFileToDirectory(File, File)
  351 |    */
  352 |   public static void copyFile(File srcFile, File destFile) throws IOException {
  353 |     copyFile(srcFile, destFile, true);
  354 |   }
  355 | 
  356 |   /**
  357 |    * Copies a file to a new location.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  379 |    */
  380 |   public static void copyFile(File srcFile, File destFile,
  381 |       boolean preserveFileDate) throws IOException {
  382 |     if (srcFile == null) {
  383 |       throw new NullPointerException("Source must not be null");
  384 |     }
  385 |     if (destFile == null) {
  386 |       throw new NullPointerException("Destination must not be null");
  387 |     }
  388 |     if (srcFile.exists() == false) {
  389 |       throw new FileNotFoundException("Source '" + srcFile + "' does not exist");
  390 |     }
  391 |     if (srcFile.isDirectory()) {
  392 |       throw new IOException("Source '" + srcFile + "' exists but is a directory");
  393 |     }
  394 |     if (srcFile.getCanonicalPath().equals(destFile.getCanonicalPath())) {
  395 |       throw new IOException("Source '" + srcFile + "' and destination '" + destFile + "' are the same");
  396 |     }
  397 |     File parentFile = destFile.getParentFile();
  398 |     if (parentFile != null) {
  399 |       if (!parentFile.mkdirs() && !parentFile.isDirectory()) {
  400 |         throw new IOException("Destination '" + parentFile + "' directory cannot be created");
  401 |       }
  402 |     }
  403 |     if (destFile.exists() && destFile.canWrite() == false) {
  404 |       throw new IOException("Destination '" + destFile + "' exists but is read-only");
  405 |     }
  406 |     doCopyFile(srcFile, destFile, preserveFileDate);
  407 |   }
  408 | 
  409 |   /**
  410 |    * Internal copy file method.
```

---

## 88/115 flow_id 53835931ea (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 53835931ea
key        : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>@L313/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>@L400/0
source     : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>[9@L313] o = invokeinterface elems.nextElement()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>[70@L400] invokespecial %v45.<init>(%v52)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  379 |    */
  380 |   public static void copyFile(File srcFile, File destFile,
  381 |       boolean preserveFileDate) throws IOException {
  382 |     if (srcFile == null) {
  383 |       throw new NullPointerException("Source must not be null");
  384 |     }
  385 |     if (destFile == null) {
  386 |       throw new NullPointerException("Destination must not be null");
  387 |     }
  388 |     if (srcFile.exists() == false) {
  389 |       throw new FileNotFoundException("Source '" + srcFile + "' does not exist");
  390 |     }
  391 |     if (srcFile.isDirectory()) {
  392 |       throw new IOException("Source '" + srcFile + "' exists but is a directory");
  393 |     }
  394 |     if (srcFile.getCanonicalPath().equals(destFile.getCanonicalPath())) {
  395 |       throw new IOException("Source '" + srcFile + "' and destination '" + destFile + "' are the same");
  396 |     }
  397 |     File parentFile = destFile.getParentFile();
  398 |     if (parentFile != null) {
  399 |       if (!parentFile.mkdirs() && !parentFile.isDirectory()) {
  400 |         throw new IOException("Destination '" + parentFile + "' directory cannot be created");
  401 |       }
  402 |     }
  403 |     if (destFile.exists() && destFile.canWrite() == false) {
  404 |       throw new IOException("Destination '" + destFile + "' exists but is read-only");
  405 |     }
  406 |     doCopyFile(srcFile, destFile, preserveFileDate);
  407 |   }
  408 | 
  409 |   /**
  410 |    * Internal copy file method.
```

---

## 89/115 flow_id 23ae6b2b73 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 23ae6b2b73
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>@L511/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>@L400/0
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>[25@L511] %v24 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>[70@L400] invokespecial %v45.<init>(%v52)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>
file: org/zeroturnaround/zip/ZipUtil.java
  490 |    * @see #iterate(File, ZipInfoCallback)
  491 |    */
  492 |   public static void iterate(File zip, ZipEntryCallback action, Charset charset) {
  493 |     ZipFile zf = null;
  494 |     try {
  495 |       if (charset == null) {
  496 |         zf = new ZipFile(zip);
  497 |       }
  498 |       else {
  499 |         zf = new ZipFile(zip, charset);
  500 |       }
  501 | 
  502 |       Enumeration<? extends ZipEntry> en = zf.entries();
  503 |       while (en.hasMoreElements()) {
  504 |         ZipEntry e = (ZipEntry) en.nextElement();
  505 | 
  506 |         InputStream is = zf.getInputStream(e);
  507 |         try {
  508 |           action.process(is, e);
  509 |         }
  510 |         catch (IOException ze) {
  511 |           throw new ZipException("Failed to process zip entry '" + e.getName() + "' with action " + action, ze);
  512 |         }
  513 |         catch (ZipBreakException ex) {
  514 |           break;
  515 |         }
  516 |         finally {
  517 |           IOUtils.closeQuietly(is);
  518 |         }
  519 |       }
  520 |     }
  521 |     catch (IOException e) {
  522 |       throw ZipExceptionUtil.rethrow(e);
  523 |     }
  524 |     finally {
  525 |       closeQuietly(zf);
  526 |     }
  527 |   }
  528 | 
  529 |   /**
  530 |    * Reads the given ZIP file and executes the given action for each given entry.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  379 |    */
  380 |   public static void copyFile(File srcFile, File destFile,
  381 |       boolean preserveFileDate) throws IOException {
  382 |     if (srcFile == null) {
  383 |       throw new NullPointerException("Source must not be null");
  384 |     }
  385 |     if (destFile == null) {
  386 |       throw new NullPointerException("Destination must not be null");
  387 |     }
  388 |     if (srcFile.exists() == false) {
  389 |       throw new FileNotFoundException("Source '" + srcFile + "' does not exist");
  390 |     }
  391 |     if (srcFile.isDirectory()) {
  392 |       throw new IOException("Source '" + srcFile + "' exists but is a directory");
  393 |     }
  394 |     if (srcFile.getCanonicalPath().equals(destFile.getCanonicalPath())) {
  395 |       throw new IOException("Source '" + srcFile + "' and destination '" + destFile + "' are the same");
  396 |     }
  397 |     File parentFile = destFile.getParentFile();
  398 |     if (parentFile != null) {
  399 |       if (!parentFile.mkdirs() && !parentFile.isDirectory()) {
  400 |         throw new IOException("Destination '" + parentFile + "' directory cannot be created");
  401 |       }
  402 |     }
  403 |     if (destFile.exists() && destFile.canWrite() == false) {
  404 |       throw new IOException("Destination '" + destFile + "' exists but is read-only");
  405 |     }
  406 |     doCopyFile(srcFile, destFile, preserveFileDate);
  407 |   }
  408 | 
  409 |   /**
  410 |    * Internal copy file method.
```

---

## 90/115 flow_id 02814d3b37 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 02814d3b37
key        : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>@L313/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>@L404/0
source     : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>[9@L313] o = invokeinterface elems.nextElement()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>[85@L404] invokespecial %v55.<init>(%v62)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  379 |    */
  380 |   public static void copyFile(File srcFile, File destFile,
  381 |       boolean preserveFileDate) throws IOException {
  382 |     if (srcFile == null) {
  383 |       throw new NullPointerException("Source must not be null");
  384 |     }
  385 |     if (destFile == null) {
  386 |       throw new NullPointerException("Destination must not be null");
  387 |     }
  388 |     if (srcFile.exists() == false) {
  389 |       throw new FileNotFoundException("Source '" + srcFile + "' does not exist");
  390 |     }
  391 |     if (srcFile.isDirectory()) {
  392 |       throw new IOException("Source '" + srcFile + "' exists but is a directory");
  393 |     }
  394 |     if (srcFile.getCanonicalPath().equals(destFile.getCanonicalPath())) {
  395 |       throw new IOException("Source '" + srcFile + "' and destination '" + destFile + "' are the same");
  396 |     }
  397 |     File parentFile = destFile.getParentFile();
  398 |     if (parentFile != null) {
  399 |       if (!parentFile.mkdirs() && !parentFile.isDirectory()) {
  400 |         throw new IOException("Destination '" + parentFile + "' directory cannot be created");
  401 |       }
  402 |     }
  403 |     if (destFile.exists() && destFile.canWrite() == false) {
  404 |       throw new IOException("Destination '" + destFile + "' exists but is read-only");
  405 |     }
  406 |     doCopyFile(srcFile, destFile, preserveFileDate);
  407 |   }
  408 | 
  409 |   /**
  410 |    * Internal copy file method.
```

---

## 91/115 flow_id b08825c27d (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow b08825c27d
key        : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>@L77/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>@L404/0
source     : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>[4@L77] %v5 = invokevirtual original.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>[85@L404] invokespecial %v55.<init>(%v62)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>
file: org/zeroturnaround/zip/ZipEntryUtil.java
   58 |    * @return copy of the original entry, but with the given name
   59 |    */
   60 |   static ZipEntry copy(ZipEntry original, String newName) {
   61 |     ZipEntry copy = new ZipEntry(newName == null ? original.getName() : newName);
   62 |     if (original.getCrc() != -1) {
   63 |       copy.setCrc(original.getCrc());
   64 |     }
   65 |     if (original.getMethod() != -1) {
   66 |       copy.setMethod(original.getMethod());
   67 |     }
   68 |     if (original.getSize() >= 0) {
   69 |       copy.setSize(original.getSize());
   70 |     }
   71 |     if (original.getExtra() != null) {
   72 |       copy.setExtra(original.getExtra());
   73 |     }
   74 | 
   75 |     copy.setComment(original.getComment());
   76 |     copy.setTime(original.getTime());
   77 |     return copy;
   78 |   }
   79 | 
   80 |   /**

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  379 |    */
  380 |   public static void copyFile(File srcFile, File destFile,
  381 |       boolean preserveFileDate) throws IOException {
  382 |     if (srcFile == null) {
  383 |       throw new NullPointerException("Source must not be null");
  384 |     }
  385 |     if (destFile == null) {
  386 |       throw new NullPointerException("Destination must not be null");
  387 |     }
  388 |     if (srcFile.exists() == false) {
  389 |       throw new FileNotFoundException("Source '" + srcFile + "' does not exist");
  390 |     }
  391 |     if (srcFile.isDirectory()) {
  392 |       throw new IOException("Source '" + srcFile + "' exists but is a directory");
  393 |     }
  394 |     if (srcFile.getCanonicalPath().equals(destFile.getCanonicalPath())) {
  395 |       throw new IOException("Source '" + srcFile + "' and destination '" + destFile + "' are the same");
  396 |     }
  397 |     File parentFile = destFile.getParentFile();
  398 |     if (parentFile != null) {
  399 |       if (!parentFile.mkdirs() && !parentFile.isDirectory()) {
  400 |         throw new IOException("Destination '" + parentFile + "' directory cannot be created");
  401 |       }
  402 |     }
  403 |     if (destFile.exists() && destFile.canWrite() == false) {
  404 |       throw new IOException("Destination '" + destFile + "' exists but is read-only");
  405 |     }
  406 |     doCopyFile(srcFile, destFile, preserveFileDate);
  407 |   }
  408 | 
  409 |   /**
  410 |    * Internal copy file method.
```

---

## 92/115 flow_id d7ce7558cb (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow d7ce7558cb
key        : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2639/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>@L404/0
source     : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2639] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>[85@L404] invokespecial %v55.<init>(%v62)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2636 |         final Set<String> names = new HashSet<String>();
 2637 |         iterate(zip, new ZipEntryCallback() {
 2638 |           public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2639 |             if (names.add(zipEntry.getName())) {
 2640 |               ZipEntrySource entry = (ZipEntrySource) entryByPath.remove(zipEntry.getName());
 2641 |               if (entry != null) {
 2642 |                 addEntry(entry, out);
 2643 |               }
 2644 |               else {
 2645 |                 ZipEntryUtil.copyEntry(zipEntry, in, out);
 2646 |               }
 2647 |             }
 2648 |             else if (log.isDebugEnabled()) {
 2649 |               log.debug("Duplicate entry: {}", zipEntry.getName());
 2650 |             }
 2651 |           }
 2652 |         });
 2653 | 
 2654 |         // Add new entries

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  379 |    */
  380 |   public static void copyFile(File srcFile, File destFile,
  381 |       boolean preserveFileDate) throws IOException {
  382 |     if (srcFile == null) {
  383 |       throw new NullPointerException("Source must not be null");
  384 |     }
  385 |     if (destFile == null) {
  386 |       throw new NullPointerException("Destination must not be null");
  387 |     }
  388 |     if (srcFile.exists() == false) {
  389 |       throw new FileNotFoundException("Source '" + srcFile + "' does not exist");
  390 |     }
  391 |     if (srcFile.isDirectory()) {
  392 |       throw new IOException("Source '" + srcFile + "' exists but is a directory");
  393 |     }
  394 |     if (srcFile.getCanonicalPath().equals(destFile.getCanonicalPath())) {
  395 |       throw new IOException("Source '" + srcFile + "' and destination '" + destFile + "' are the same");
  396 |     }
  397 |     File parentFile = destFile.getParentFile();
  398 |     if (parentFile != null) {
  399 |       if (!parentFile.mkdirs() && !parentFile.isDirectory()) {
  400 |         throw new IOException("Destination '" + parentFile + "' directory cannot be created");
  401 |       }
  402 |     }
  403 |     if (destFile.exists() && destFile.canWrite() == false) {
  404 |       throw new IOException("Destination '" + destFile + "' exists but is read-only");
  405 |     }
  406 |     doCopyFile(srcFile, destFile, preserveFileDate);
  407 |   }
  408 | 
  409 |   /**
  410 |    * Internal copy file method.
```

---

## 93/115 flow_id e7c1d100ba (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow e7c1d100ba
key        : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1196/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>@L404/0
source     : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[4@L1196] %v9 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>[85@L404] invokespecial %v55.<init>(%v62)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFile(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  379 |    */
  380 |   public static void copyFile(File srcFile, File destFile,
  381 |       boolean preserveFileDate) throws IOException {
  382 |     if (srcFile == null) {
  383 |       throw new NullPointerException("Source must not be null");
  384 |     }
  385 |     if (destFile == null) {
  386 |       throw new NullPointerException("Destination must not be null");
  387 |     }
  388 |     if (srcFile.exists() == false) {
  389 |       throw new FileNotFoundException("Source '" + srcFile + "' does not exist");
  390 |     }
  391 |     if (srcFile.isDirectory()) {
  392 |       throw new IOException("Source '" + srcFile + "' exists but is a directory");
  393 |     }
  394 |     if (srcFile.getCanonicalPath().equals(destFile.getCanonicalPath())) {
  395 |       throw new IOException("Source '" + srcFile + "' and destination '" + destFile + "' are the same");
  396 |     }
  397 |     File parentFile = destFile.getParentFile();
  398 |     if (parentFile != null) {
  399 |       if (!parentFile.mkdirs() && !parentFile.isDirectory()) {
  400 |         throw new IOException("Destination '" + parentFile + "' directory cannot be created");
  401 |       }
  402 |     }
  403 |     if (destFile.exists() && destFile.canWrite() == false) {
  404 |       throw new IOException("Destination '" + destFile + "' exists but is read-only");
  405 |     }
  406 |     doCopyFile(srcFile, destFile, preserveFileDate);
  407 |   }
  408 | 
  409 |   /**
  410 |    * Internal copy file method.
```

---

## 94/115 flow_id 5ac0fa8b04 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 5ac0fa8b04
key        : DRIVER => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFileToDirectory(java.io.File,java.io.File,boolean)>@L327/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[250@L56] %v155 = invokestatic nesy.Taint.srcFile()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFileToDirectory(java.io.File,java.io.File,boolean)>[23@L327] invokespecial destFile.<init>(destDir, %v19)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[250@L56] %v155 = invokestatic nesy.Taint.srcFile()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v155}
3. VarNode{<org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFileToDirectory(java.io.File,java.io.File)>/destDir}
4. VarNode{<org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFileToDirectory(java.io.File,java.io.File,boolean)>/destDir}
5. <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFileToDirectory(java.io.File,java.io.File,boolean)>[23@L327] invokespecial destFile.<init>(destDir, %v19)/0

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFileToDirectory(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  289 |    * @see #copyFile(File, File, boolean)
  290 |    */
  291 |   public static void copyFileToDirectory(File srcFile, File destDir) throws IOException {
  292 |     copyFileToDirectory(srcFile, destDir, true);
  293 |   }
  294 | 
  295 |   /**
  296 |    * Copies a file to a directory optionally preserving the file date.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFileToDirectory(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  318 |    * @since 1.3
  319 |    */
  320 |   public static void copyFileToDirectory(File srcFile, File destDir, boolean preserveFileDate) throws IOException {
  321 |     if (destDir == null) {
  322 |       throw new NullPointerException("Destination must not be null");
  323 |     }
  324 |     if (destDir.exists() && destDir.isDirectory() == false) {
  325 |       throw new IllegalArgumentException("Destination '" + destDir + "' is not a directory");
  326 |     }
  327 |     File destFile = new File(destDir, srcFile.getName());
  328 |     copyFile(srcFile, destFile, preserveFileDate);
  329 |   }
  330 | 
  331 |   /**
  332 |    * Copies a file to a new location preserving the file date.
```

---

## 95/115 flow_id bb473da35e (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow bb473da35e
key        : <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>@L3028/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFileToDirectory(java.io.File,java.io.File,boolean)>@L327/1
source     : <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>[36@L3028] path = invokevirtual e1.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFileToDirectory(java.io.File,java.io.File,boolean)>[23@L327] invokespecial destFile.<init>(destDir, %v19)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFileToDirectory(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 3000 |   }
 3001 | 
 3002 |   private static boolean archiveEqualsInternal(File f1, File f2) throws IOException {
 3003 |     ZipFile zf1 = null;
 3004 |     ZipFile zf2 = null;
 3005 |     try {
 3006 |       zf1 = new ZipFile(f1);
 3007 |       zf2 = new ZipFile(f2);
 3008 | 
 3009 |       // Check the number of entries
 3010 |       if (zf1.size() != zf2.size()) {
 3011 |         log.debug("Number of entries changed (" + zf1.size() + " vs " + zf2.size() + ").");
 3012 |         return false;
 3013 |       }
 3014 |       /*
 3015 |        * As there are same number of entries in both archives we can traverse
 3016 |        * all entries of one of the archives and get the corresponding entries
 3017 |        * from the other archive.
 3018 |        *
 3019 |        * If a corresponding entry is missing from the second archive the
 3020 |        * archives are different and we finish the comparison.
 3021 |        *
 3022 |        * We guarantee that no entry of the second archive is skipped as there
 3023 |        * are same number of unique entries in both archives.
 3024 |        */
 3025 |       Enumeration<? extends ZipEntry> en = zf1.entries();
 3026 |       while (en.hasMoreElements()) {
 3027 |         ZipEntry e1 = (ZipEntry) en.nextElement();
 3028 |         String path = e1.getName();
 3029 |         ZipEntry e2 = zf2.getEntry(path);
      | ... (lines omitted) ...
 3035 | 
 3036 |         // Check the content
 3037 |         InputStream is1 = null;
 3038 |         InputStream is2 = null;
 3039 |         try {
 3040 |           is1 = zf1.getInputStream(e1);
 3041 |           is2 = zf2.getInputStream(e2);
 3042 | 
 3043 |           if (!IOUtils.contentEquals(is1, is2)) {
 3044 |             log.debug("Entry '{}' content changed.", path);
 3045 |             return false;
 3046 |           }
 3047 |         }
 3048 |         finally {
 3049 |           IOUtils.closeQuietly(is1);
 3050 |           IOUtils.closeQuietly(is2);
 3051 |         }
 3052 |       }
 3053 |     }
 3054 |     finally {
 3055 |       closeQuietly(zf1);
 3056 |       closeQuietly(zf2);
 3057 |     }
 3058 | 
 3059 |     log.debug("Archives are the same.");
 3060 | 
 3061 |     return true;
 3062 |   }
 3063 | 
 3064 |   /**

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFileToDirectory(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  318 |    * @since 1.3
  319 |    */
  320 |   public static void copyFileToDirectory(File srcFile, File destDir, boolean preserveFileDate) throws IOException {
  321 |     if (destDir == null) {
  322 |       throw new NullPointerException("Destination must not be null");
  323 |     }
  324 |     if (destDir.exists() && destDir.isDirectory() == false) {
  325 |       throw new IllegalArgumentException("Destination '" + destDir + "' is not a directory");
  326 |     }
  327 |     File destFile = new File(destDir, srcFile.getName());
  328 |     copyFile(srcFile, destFile, preserveFileDate);
  329 |   }
  330 | 
  331 |   /**
  332 |    * Copies a file to a new location preserving the file date.
```

---

## 96/115 flow_id 11b7850b18 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 11b7850b18
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.InputStream,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>@L785/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFileToDirectory(java.io.File,java.io.File,boolean)>@L327/1
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.InputStream,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>[27@L785] %v24 = invokevirtual entry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFileToDirectory(java.io.File,java.io.File,boolean)>[23@L327] invokespecial destFile.<init>(destDir, %v19)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.InputStream,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFileToDirectory(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.InputStream,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>
file: org/zeroturnaround/zip/ZipUtil.java
  764 |    * @see #iterate(File, String[], ZipEntryCallback)
  765 |    */
  766 |   public static void iterate(InputStream is, String[] entryNames, ZipEntryCallback action, Charset charset) {
  767 |     Set<String> namesSet = new HashSet<String>();
  768 |     for (int i = 0; i < entryNames.length; i++) {
  769 |       namesSet.add(entryNames[i]);
  770 |     }
  771 |     try {
  772 |       ZipInputStream in = null;
  773 |       try {
  774 |         in = newCloseShieldZipInputStream(is, charset);
  775 |         ZipEntry entry;
  776 |         while ((entry = in.getNextEntry()) != null) {
  777 |           if (!namesSet.contains(entry.getName())) {
  778 |             // skip the unnecessary entry
  779 |             continue;
  780 |           }
  781 |           try {
  782 |             action.process(in, entry);
  783 |           }
  784 |           catch (IOException ze) {
  785 |             throw new ZipException("Failed to process zip entry '" + entry.getName() + " with action " + action, ze);
  786 |           }
  787 |           catch (ZipBreakException ex) {
  788 |             break;
  789 |           }
  790 |         }
  791 |       }
  792 |       finally {
  793 |         if (in != null) {
  794 |           in.close();
  795 |         }
  796 |       }
  797 |     }
  798 |     catch (IOException e) {
  799 |       throw ZipExceptionUtil.rethrow(e);
  800 |     }
  801 |   }
  802 | 
  803 |   /**
  804 |    * See @link{ {@link #iterate(InputStream, ZipEntryCallback, Charset)}. It is a

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFileToDirectory(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  318 |    * @since 1.3
  319 |    */
  320 |   public static void copyFileToDirectory(File srcFile, File destDir, boolean preserveFileDate) throws IOException {
  321 |     if (destDir == null) {
  322 |       throw new NullPointerException("Destination must not be null");
  323 |     }
  324 |     if (destDir.exists() && destDir.isDirectory() == false) {
  325 |       throw new IllegalArgumentException("Destination '" + destDir + "' is not a directory");
  326 |     }
  327 |     File destFile = new File(destDir, srcFile.getName());
  328 |     copyFile(srcFile, destFile, preserveFileDate);
  329 |   }
  330 | 
  331 |   /**
  332 |    * Copies a file to a new location preserving the file date.
```

---

## 97/115 flow_id f4a5a3688c (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow f4a5a3688c
key        : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2639/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void deleteDirectory(java.io.File)>@L658/0
source     : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2639] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void deleteDirectory(java.io.File)>[18@L658] invokespecial %v13.<init>(message)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void deleteDirectory(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2636 |         final Set<String> names = new HashSet<String>();
 2637 |         iterate(zip, new ZipEntryCallback() {
 2638 |           public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2639 |             if (names.add(zipEntry.getName())) {
 2640 |               ZipEntrySource entry = (ZipEntrySource) entryByPath.remove(zipEntry.getName());
 2641 |               if (entry != null) {
 2642 |                 addEntry(entry, out);
 2643 |               }
 2644 |               else {
 2645 |                 ZipEntryUtil.copyEntry(zipEntry, in, out);
 2646 |               }
 2647 |             }
 2648 |             else if (log.isDebugEnabled()) {
 2649 |               log.debug("Duplicate entry: {}", zipEntry.getName());
 2650 |             }
 2651 |           }
 2652 |         });
 2653 | 
 2654 |         // Add new entries

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void deleteDirectory(java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  644 |    * @throws IOException in case deletion is unsuccessful
  645 |    */
  646 |   public static void deleteDirectory(File directory) throws IOException {
  647 |     if (!directory.exists()) {
  648 |       return;
  649 |     }
  650 | 
  651 |     if (!isSymlink(directory)) {
  652 |       cleanDirectory(directory);
  653 |     }
  654 | 
  655 |     if (!directory.delete()) {
  656 |       String message =
  657 |           "Unable to delete directory " + directory + ".";
  658 |       throw new IOException(message);
  659 |     }
  660 |   }
  661 | 
  662 |   /**
  663 |    * Deletes a file, never throwing an exception. If file is a directory, delete it and all sub-directories.
```

---

## 98/115 flow_id 5e46bf2d9c (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 5e46bf2d9c
key        : <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2888/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void deleteDirectory(java.io.File)>@L658/0
source     : <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2888] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void deleteDirectory(java.io.File)>[18@L658] invokespecial %v13.<init>(message)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void deleteDirectory(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2885 |     }
 2886 | 
 2887 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2888 |       if (names.add(zipEntry.getName())) {
 2889 |         ZipEntryTransformer entry = (ZipEntryTransformer) entryByPath.remove(zipEntry.getName());
 2890 |         if (entry != null) {
 2891 |           entry.transform(in, zipEntry, out);
 2892 |         }
 2893 |         else {
 2894 |           ZipEntryUtil.copyEntry(zipEntry, in, out);
 2895 |         }
 2896 |       }
 2897 |       else if (log.isDebugEnabled()) {
 2898 |         log.debug("Duplicate entry: {}", zipEntry.getName());
 2899 |       }
 2900 |     }
 2901 | 
 2902 |     /**
 2903 |      * @return <code>true</code> if at least one entry was replaced.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void deleteDirectory(java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  644 |    * @throws IOException in case deletion is unsuccessful
  645 |    */
  646 |   public static void deleteDirectory(File directory) throws IOException {
  647 |     if (!directory.exists()) {
  648 |       return;
  649 |     }
  650 | 
  651 |     if (!isSymlink(directory)) {
  652 |       cleanDirectory(directory);
  653 |     }
  654 | 
  655 |     if (!directory.delete()) {
  656 |       String message =
  657 |           "Unable to delete directory " + directory + ".";
  658 |       throw new IOException(message);
  659 |     }
  660 |   }
  661 | 
  662 |   /**
  663 |    * Deletes a file, never throwing an exception. If file is a directory, delete it and all sub-directories.
```

---

## 99/115 flow_id 58baec4f32 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 58baec4f32
key        : <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2336/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>@L608/0
source     : <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L2336] entryName = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>[14@L608] invokespecial %v13.<init>(%v18)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2333 |     final Set<String> names = new HashSet<String>();
 2334 |     iterate(is, new ZipEntryCallback() {
 2335 |       public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2336 |         String entryName = zipEntry.getName();
 2337 |         if (names.add(entryName)) {
 2338 |           ZipEntryUtil.copyEntry(zipEntry, in, out);
 2339 |         }
 2340 |         else if (log.isDebugEnabled()) {
 2341 |           log.debug("Duplicate entry: {}", entryName);
 2342 |         }
 2343 |       }
 2344 |     });
 2345 |   }
 2346 | 

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  603 |   private static void doCopyDirectory(File srcDir, File destDir, FileFilter filter,
  604 |       boolean preserveFileDate, List<String> exclusionList) throws IOException {
  605 |     // recurse
  606 |     File[] srcFiles = filter == null ? srcDir.listFiles() : srcDir.listFiles(filter);
  607 |     if (srcFiles == null) {  // null if abstract pathname does not denote a directory, or if an I/O error occurs
  608 |       throw new IOException("Failed to list contents of " + srcDir);
  609 |     }
  610 |     if (destDir.exists()) {
  611 |       if (destDir.isDirectory() == false) {
  612 |         throw new IOException("Destination '" + destDir + "' exists but is not a directory");
  613 |       }
  614 |     } else {
  615 |       if (!destDir.mkdirs() && !destDir.isDirectory()) {
  616 |         throw new IOException("Destination '" + destDir + "' directory cannot be created");
  617 |       }
  618 |     }
  619 |     if (destDir.canWrite() == false) {
  620 |       throw new IOException("Destination '" + destDir + "' cannot be written to");
  621 |     }
  622 |     for (File srcFile : srcFiles) {
  623 |       File dstFile = new File(destDir, srcFile.getName());
  624 |       if (exclusionList == null || !exclusionList.contains(srcFile.getCanonicalPath())) {
  625 |         if (srcFile.isDirectory()) {
  626 |           doCopyDirectory(srcFile, dstFile, filter, preserveFileDate, exclusionList);
  627 |         } else {
  628 |           doCopyFile(srcFile, dstFile, preserveFileDate);
  629 |         }
  630 |       }
  631 |     }
  632 | 
  633 |     // Do this last, as the above has probably affected directory metadata
  634 |     if (preserveFileDate) {
  635 |       destDir.setLastModified(srcDir.lastModified());
  636 |     }
  637 |   }
  638 | 
  639 |   //-----------------------------------------------------------------------
  640 |   /**
```

---

## 100/115 flow_id 143fd7172b (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 143fd7172b
key        : <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>@L2404/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>@L612/0
source     : <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>[18@L2404] %v18 = invokevirtual entry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>[29@L612] invokespecial %v22.<init>(%v29)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>
file: org/zeroturnaround/zip/ZipUtil.java
 2390 |    *
 2391 |    */
 2392 |   static Set<String> filterDirEntries(File zip, Collection<String> names) {
 2393 |     Set<String> dirs = new HashSet<String>();
 2394 |     if (zip == null) {
 2395 |       return dirs;
 2396 |     }
 2397 |     ZipFile zf = null;
 2398 |     try {
 2399 |       zf = new ZipFile(zip);
 2400 |       for (String entryName : names) {
 2401 |         ZipEntry entry = zf.getEntry(entryName);
 2402 |         if (entry != null) {
 2403 |           if (entry.isDirectory()) {
 2404 |             dirs.add(entry.getName());
 2405 |           }
 2406 |           else if (zf.getInputStream(entry) == null) {
 2407 |             // no input stream means that this is a dir.
 2408 |             dirs.add(entry.getName() + PATH_SEPARATOR);
 2409 |           }
 2410 |         }
 2411 |       }
 2412 | 
 2413 |     }
 2414 |     catch (IOException e) {
 2415 |       ZipExceptionUtil.rethrow(e);
 2416 |     }
 2417 |     finally {
 2418 |       closeQuietly(zf);
 2419 |     }
 2420 |     return dirs;
 2421 |   }
 2422 | 
 2423 |   /**

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  603 |   private static void doCopyDirectory(File srcDir, File destDir, FileFilter filter,
  604 |       boolean preserveFileDate, List<String> exclusionList) throws IOException {
  605 |     // recurse
  606 |     File[] srcFiles = filter == null ? srcDir.listFiles() : srcDir.listFiles(filter);
  607 |     if (srcFiles == null) {  // null if abstract pathname does not denote a directory, or if an I/O error occurs
  608 |       throw new IOException("Failed to list contents of " + srcDir);
  609 |     }
  610 |     if (destDir.exists()) {
  611 |       if (destDir.isDirectory() == false) {
  612 |         throw new IOException("Destination '" + destDir + "' exists but is not a directory");
  613 |       }
  614 |     } else {
  615 |       if (!destDir.mkdirs() && !destDir.isDirectory()) {
  616 |         throw new IOException("Destination '" + destDir + "' directory cannot be created");
  617 |       }
  618 |     }
  619 |     if (destDir.canWrite() == false) {
  620 |       throw new IOException("Destination '" + destDir + "' cannot be written to");
  621 |     }
  622 |     for (File srcFile : srcFiles) {
  623 |       File dstFile = new File(destDir, srcFile.getName());
  624 |       if (exclusionList == null || !exclusionList.contains(srcFile.getCanonicalPath())) {
  625 |         if (srcFile.isDirectory()) {
  626 |           doCopyDirectory(srcFile, dstFile, filter, preserveFileDate, exclusionList);
  627 |         } else {
  628 |           doCopyFile(srcFile, dstFile, preserveFileDate);
  629 |         }
  630 |       }
  631 |     }
  632 | 
  633 |     // Do this last, as the above has probably affected directory metadata
  634 |     if (preserveFileDate) {
  635 |       destDir.setLastModified(srcDir.lastModified());
  636 |     }
  637 |   }
  638 | 
  639 |   //-----------------------------------------------------------------------
  640 |   /**
```

---

## 101/115 flow_id 996cfc6f55 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 996cfc6f55
key        : DRIVER => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>@L623/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[619@L119] %v389 = invokestatic nesy.Taint.srcFile()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>[65@L623] invokespecial dstFile.<init>(destDir, %v52)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[619@L119] %v389 = invokestatic nesy.Taint.srcFile()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v389}
3. VarNode{<org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File)>/destDir}
4. VarNode{<org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,boolean)>/destDir}
5. VarNode{<org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>/destDir}
6. VarNode{<org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>/destDir}
7. <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>[65@L623] invokespecial dstFile.<init>(destDir, %v52)/0

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  476 |    * @since 1.1
  477 |    */
  478 |   public static void copyDirectory(File srcDir, File destDir) throws IOException {
  479 |     copyDirectory(srcDir, destDir, true);
  480 |   }
  481 | 
  482 |   /**
  483 |    * Copies a whole directory to a new location.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  507 |    */
  508 |   public static void copyDirectory(File srcDir, File destDir,
  509 |       boolean preserveFileDate) throws IOException {
  510 |     copyDirectory(srcDir, destDir, null, preserveFileDate);
  511 |   }
  512 | 
  513 |   /**
  514 |    * Copies a filtered directory to a new location.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  558 |    */
  559 |   public static void copyDirectory(File srcDir, File destDir,
  560 |       FileFilter filter, boolean preserveFileDate) throws IOException {
  561 |     if (srcDir == null) {
  562 |       throw new NullPointerException("Source must not be null");
  563 |     }
  564 |     if (destDir == null) {
  565 |       throw new NullPointerException("Destination must not be null");
  566 |     }
  567 |     if (srcDir.exists() == false) {
  568 |       throw new FileNotFoundException("Source '" + srcDir + "' does not exist");
  569 |     }
  570 |     if (srcDir.isDirectory() == false) {
  571 |       throw new IOException("Source '" + srcDir + "' exists but is not a directory");
  572 |     }
  573 |     if (srcDir.getCanonicalPath().equals(destDir.getCanonicalPath())) {
  574 |       throw new IOException("Source '" + srcDir + "' and destination '" + destDir + "' are the same");
  575 |     }
  576 | 
  577 |     // Cater for destination being directory within the source directory (see IO-141)
  578 |     List<String> exclusionList = null;
  579 |     if (destDir.getCanonicalPath().startsWith(srcDir.getCanonicalPath())) {
  580 |       File[] srcFiles = filter == null ? srcDir.listFiles() : srcDir.listFiles(filter);
  581 |       if (srcFiles != null && srcFiles.length > 0) {
  582 |         exclusionList = new ArrayList<String>(srcFiles.length);
  583 |         for (File srcFile : srcFiles) {
  584 |           File copiedFile = new File(destDir, srcFile.getName());
  585 |           exclusionList.add(copiedFile.getCanonicalPath());
  586 |         }
  587 |       }
  588 |     }
  589 |     doCopyDirectory(srcDir, destDir, filter, preserveFileDate, exclusionList);
  590 |   }
  591 | 
  592 |   /**
  593 |    * Internal copy directory method.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  603 |   private static void doCopyDirectory(File srcDir, File destDir, FileFilter filter,
  604 |       boolean preserveFileDate, List<String> exclusionList) throws IOException {
  605 |     // recurse
  606 |     File[] srcFiles = filter == null ? srcDir.listFiles() : srcDir.listFiles(filter);
  607 |     if (srcFiles == null) {  // null if abstract pathname does not denote a directory, or if an I/O error occurs
  608 |       throw new IOException("Failed to list contents of " + srcDir);
  609 |     }
  610 |     if (destDir.exists()) {
  611 |       if (destDir.isDirectory() == false) {
  612 |         throw new IOException("Destination '" + destDir + "' exists but is not a directory");
  613 |       }
  614 |     } else {
  615 |       if (!destDir.mkdirs() && !destDir.isDirectory()) {
  616 |         throw new IOException("Destination '" + destDir + "' directory cannot be created");
  617 |       }
  618 |     }
  619 |     if (destDir.canWrite() == false) {
  620 |       throw new IOException("Destination '" + destDir + "' cannot be written to");
  621 |     }
  622 |     for (File srcFile : srcFiles) {
  623 |       File dstFile = new File(destDir, srcFile.getName());
  624 |       if (exclusionList == null || !exclusionList.contains(srcFile.getCanonicalPath())) {
  625 |         if (srcFile.isDirectory()) {
  626 |           doCopyDirectory(srcFile, dstFile, filter, preserveFileDate, exclusionList);
  627 |         } else {
  628 |           doCopyFile(srcFile, dstFile, preserveFileDate);
  629 |         }
  630 |       }
  631 |     }
  632 | 
  633 |     // Do this last, as the above has probably affected directory metadata
  634 |     if (preserveFileDate) {
  635 |       destDir.setLastModified(srcDir.lastModified());
  636 |     }
  637 |   }
  638 | 
  639 |   //-----------------------------------------------------------------------
  640 |   /**
```

---

## 102/115 flow_id c46eaa760d (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow c46eaa760d
key        : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2639/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>@L623/1
source     : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2639] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>[65@L623] invokespecial dstFile.<init>(destDir, %v52)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2636 |         final Set<String> names = new HashSet<String>();
 2637 |         iterate(zip, new ZipEntryCallback() {
 2638 |           public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2639 |             if (names.add(zipEntry.getName())) {
 2640 |               ZipEntrySource entry = (ZipEntrySource) entryByPath.remove(zipEntry.getName());
 2641 |               if (entry != null) {
 2642 |                 addEntry(entry, out);
 2643 |               }
 2644 |               else {
 2645 |                 ZipEntryUtil.copyEntry(zipEntry, in, out);
 2646 |               }
 2647 |             }
 2648 |             else if (log.isDebugEnabled()) {
 2649 |               log.debug("Duplicate entry: {}", zipEntry.getName());
 2650 |             }
 2651 |           }
 2652 |         });
 2653 | 
 2654 |         // Add new entries

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  603 |   private static void doCopyDirectory(File srcDir, File destDir, FileFilter filter,
  604 |       boolean preserveFileDate, List<String> exclusionList) throws IOException {
  605 |     // recurse
  606 |     File[] srcFiles = filter == null ? srcDir.listFiles() : srcDir.listFiles(filter);
  607 |     if (srcFiles == null) {  // null if abstract pathname does not denote a directory, or if an I/O error occurs
  608 |       throw new IOException("Failed to list contents of " + srcDir);
  609 |     }
  610 |     if (destDir.exists()) {
  611 |       if (destDir.isDirectory() == false) {
  612 |         throw new IOException("Destination '" + destDir + "' exists but is not a directory");
  613 |       }
  614 |     } else {
  615 |       if (!destDir.mkdirs() && !destDir.isDirectory()) {
  616 |         throw new IOException("Destination '" + destDir + "' directory cannot be created");
  617 |       }
  618 |     }
  619 |     if (destDir.canWrite() == false) {
  620 |       throw new IOException("Destination '" + destDir + "' cannot be written to");
  621 |     }
  622 |     for (File srcFile : srcFiles) {
  623 |       File dstFile = new File(destDir, srcFile.getName());
  624 |       if (exclusionList == null || !exclusionList.contains(srcFile.getCanonicalPath())) {
  625 |         if (srcFile.isDirectory()) {
  626 |           doCopyDirectory(srcFile, dstFile, filter, preserveFileDate, exclusionList);
  627 |         } else {
  628 |           doCopyFile(srcFile, dstFile, preserveFileDate);
  629 |         }
  630 |       }
  631 |     }
  632 | 
  633 |     // Do this last, as the above has probably affected directory metadata
  634 |     if (preserveFileDate) {
  635 |       destDir.setLastModified(srcDir.lastModified());
  636 |     }
  637 |   }
  638 | 
  639 |   //-----------------------------------------------------------------------
  640 |   /**
```

---

## 103/115 flow_id 9d3ea03f69 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 9d3ea03f69
key        : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1196/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>@L623/1
source     : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[4@L1196] %v9 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>[65@L623] invokespecial dstFile.<init>(destDir, %v52)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtils: void copy(java.io.InputStream,java.io.File)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtils: void copy(java.io.InputStream,java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtils.java
   51 |    * @throws java.io.IOException if file is not found or copying fails
   52 |    */
   53 |   public static void copy(InputStream in, File file) throws IOException {
   54 |     OutputStream out = new BufferedOutputStream(new FileOutputStream(file));
   55 |     try {
   56 |       IOUtils.copy(in, out);
   57 |     }
   58 |     finally {
   59 |       IOUtils.closeQuietly(out);
   60 |     }
   61 |   }
   62 | 
   63 |   /**
   64 |    * Find a non-existing file in the same directory using the same name as prefix.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  603 |   private static void doCopyDirectory(File srcDir, File destDir, FileFilter filter,
  604 |       boolean preserveFileDate, List<String> exclusionList) throws IOException {
  605 |     // recurse
  606 |     File[] srcFiles = filter == null ? srcDir.listFiles() : srcDir.listFiles(filter);
  607 |     if (srcFiles == null) {  // null if abstract pathname does not denote a directory, or if an I/O error occurs
  608 |       throw new IOException("Failed to list contents of " + srcDir);
  609 |     }
  610 |     if (destDir.exists()) {
  611 |       if (destDir.isDirectory() == false) {
  612 |         throw new IOException("Destination '" + destDir + "' exists but is not a directory");
  613 |       }
  614 |     } else {
  615 |       if (!destDir.mkdirs() && !destDir.isDirectory()) {
  616 |         throw new IOException("Destination '" + destDir + "' directory cannot be created");
  617 |       }
  618 |     }
  619 |     if (destDir.canWrite() == false) {
  620 |       throw new IOException("Destination '" + destDir + "' cannot be written to");
  621 |     }
  622 |     for (File srcFile : srcFiles) {
  623 |       File dstFile = new File(destDir, srcFile.getName());
  624 |       if (exclusionList == null || !exclusionList.contains(srcFile.getCanonicalPath())) {
  625 |         if (srcFile.isDirectory()) {
  626 |           doCopyDirectory(srcFile, dstFile, filter, preserveFileDate, exclusionList);
  627 |         } else {
  628 |           doCopyFile(srcFile, dstFile, preserveFileDate);
  629 |         }
  630 |       }
  631 |     }
  632 | 
  633 |     // Do this last, as the above has probably affected directory metadata
  634 |     if (preserveFileDate) {
  635 |       destDir.setLastModified(srcDir.lastModified());
  636 |     }
  637 |   }
  638 | 
  639 |   //-----------------------------------------------------------------------
  640 |   /**
```

---

## 104/115 flow_id cf408d75bf (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow cf408d75bf
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>@L585/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>@L623/1
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>[28@L585] %v25 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>[65@L623] invokespecial dstFile.<init>(destDir, %v52)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>
file: org/zeroturnaround/zip/ZipUtil.java
  563 |    * @see #iterate(File, String[], ZipInfoCallback)
  564 |    */
  565 |   public static void iterate(File zip, String[] entryNames, ZipEntryCallback action, Charset charset) {
  566 |     ZipFile zf = null;
  567 |     try {
  568 |       if (charset == null) {
  569 |         zf = new ZipFile(zip);
  570 |       }
  571 |       else {
  572 |         zf = new ZipFile(zip, charset);
  573 |       }
  574 | 
  575 |       for (int i = 0; i < entryNames.length; i++) {
  576 |         ZipEntry e = zf.getEntry(entryNames[i]);
  577 |         if (e == null) {
  578 |           continue;
  579 |         }
  580 |         InputStream is = zf.getInputStream(e);
  581 |         try {
  582 |           action.process(is, e);
  583 |         }
  584 |         catch (IOException ze) {
  585 |           throw new ZipException("Failed to process zip entry '" + e.getName() + " with action " + action, ze);
  586 |         }
  587 |         catch (ZipBreakException ex) {
  588 |           break;
  589 |         }
  590 |         finally {
  591 |           IOUtils.closeQuietly(is);
  592 |         }
  593 |       }
  594 |     }
  595 |     catch (IOException e) {
  596 |       throw ZipExceptionUtil.rethrow(e);
  597 |     }
  598 |     finally {
  599 |       closeQuietly(zf);
  600 |     }
  601 |   }
  602 | 
  603 |   /**
  604 |    * Scans the given ZIP file and executes the given action for each entry.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  603 |   private static void doCopyDirectory(File srcDir, File destDir, FileFilter filter,
  604 |       boolean preserveFileDate, List<String> exclusionList) throws IOException {
  605 |     // recurse
  606 |     File[] srcFiles = filter == null ? srcDir.listFiles() : srcDir.listFiles(filter);
  607 |     if (srcFiles == null) {  // null if abstract pathname does not denote a directory, or if an I/O error occurs
  608 |       throw new IOException("Failed to list contents of " + srcDir);
  609 |     }
  610 |     if (destDir.exists()) {
  611 |       if (destDir.isDirectory() == false) {
  612 |         throw new IOException("Destination '" + destDir + "' exists but is not a directory");
  613 |       }
  614 |     } else {
  615 |       if (!destDir.mkdirs() && !destDir.isDirectory()) {
  616 |         throw new IOException("Destination '" + destDir + "' directory cannot be created");
  617 |       }
  618 |     }
  619 |     if (destDir.canWrite() == false) {
  620 |       throw new IOException("Destination '" + destDir + "' cannot be written to");
  621 |     }
  622 |     for (File srcFile : srcFiles) {
  623 |       File dstFile = new File(destDir, srcFile.getName());
  624 |       if (exclusionList == null || !exclusionList.contains(srcFile.getCanonicalPath())) {
  625 |         if (srcFile.isDirectory()) {
  626 |           doCopyDirectory(srcFile, dstFile, filter, preserveFileDate, exclusionList);
  627 |         } else {
  628 |           doCopyFile(srcFile, dstFile, preserveFileDate);
  629 |         }
  630 |       }
  631 |     }
  632 | 
  633 |     // Do this last, as the above has probably affected directory metadata
  634 |     if (preserveFileDate) {
  635 |       destDir.setLastModified(srcDir.lastModified());
  636 |     }
  637 |   }
  638 | 
  639 |   //-----------------------------------------------------------------------
  640 |   /**
```

---

## 105/115 flow_id 71104e03d0 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 71104e03d0
key        : <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2573/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>@L419/0
source     : <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2573] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>[14@L419] invokespecial %v17.<init>(%v24)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2570 |         final Set<String> names = new HashSet<String>();
 2571 |         iterate(zip, new ZipEntryCallback() {
 2572 |           public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2573 |             if (names.add(zipEntry.getName())) {
 2574 |               ZipEntrySource entry = (ZipEntrySource) entryByPath.remove(zipEntry.getName());
 2575 |               if (entry != null) {
 2576 |                 addEntry(entry, out);
 2577 |               }
 2578 |               else {
 2579 |                 ZipEntryUtil.copyEntry(zipEntry, in, out);
 2580 |               }
 2581 |             }
 2582 |             else if (log.isDebugEnabled()) {
 2583 |               log.debug("Duplicate entry: {}", zipEntry.getName());
 2584 |             }
 2585 |           }
 2586 |         });
 2587 |       }
 2588 |       finally {

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  415 |    * @throws IOException if an error occurs
  416 |    */
  417 |   private static void doCopyFile(File srcFile, File destFile, boolean preserveFileDate) throws IOException {
  418 |     if (destFile.exists() && destFile.isDirectory()) {
  419 |       throw new IOException("Destination '" + destFile + "' exists but is a directory");
  420 |     }
  421 | 
  422 |     FileInputStream fis = null;
  423 |     FileOutputStream fos = null;
  424 |     FileChannel input = null;
  425 |     FileChannel output = null;
  426 |     try {
  427 |       fis = new FileInputStream(srcFile);
  428 |       fos = new FileOutputStream(destFile);
  429 |       input  = fis.getChannel();
  430 |       output = fos.getChannel();
  431 |       long size = input.size();
  432 |       long pos = 0;
  433 |       long count = 0;
  434 |       while (pos < size) {
  435 |         count = size - pos > FILE_COPY_BUFFER_SIZE ? FILE_COPY_BUFFER_SIZE : size - pos;
  436 |         pos += output.transferFrom(input, pos, count);
  437 |       }
  438 |     } finally {
  439 |       IOUtils.closeQuietly(output);
  440 |       IOUtils.closeQuietly(fos);
  441 |       IOUtils.closeQuietly(input);
  442 |       IOUtils.closeQuietly(fis);
  443 |     }
  444 | 
  445 |     if (srcFile.length() != destFile.length()) {
  446 |       throw new IOException("Failed to copy full contents from '" +
  447 |           srcFile + "' to '" + destFile + "'");
  448 |     }
  449 |     if (preserveFileDate) {
  450 |       destFile.setLastModified(srcFile.lastModified());
  451 |     }
  452 |   }
  453 | 
  454 |   /**
  455 |    * Copies a whole directory to a new location preserving the file dates.
```

---

## 106/115 flow_id fd8ca79437 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow fd8ca79437
key        : <org.apache.log4j.Category: void removeAllAppenders()>@L889/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>@L446/0
source     : <org.apache.log4j.Category: void removeAllAppenders()>[10@L889] %v10 = invokeinterface iter.nextElement()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>[69@L446] invokespecial %v37.<init>(%v47)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  415 |    * @throws IOException if an error occurs
  416 |    */
  417 |   private static void doCopyFile(File srcFile, File destFile, boolean preserveFileDate) throws IOException {
  418 |     if (destFile.exists() && destFile.isDirectory()) {
  419 |       throw new IOException("Destination '" + destFile + "' exists but is a directory");
  420 |     }
  421 | 
  422 |     FileInputStream fis = null;
  423 |     FileOutputStream fos = null;
  424 |     FileChannel input = null;
  425 |     FileChannel output = null;
  426 |     try {
  427 |       fis = new FileInputStream(srcFile);
  428 |       fos = new FileOutputStream(destFile);
  429 |       input  = fis.getChannel();
  430 |       output = fos.getChannel();
  431 |       long size = input.size();
  432 |       long pos = 0;
  433 |       long count = 0;
  434 |       while (pos < size) {
  435 |         count = size - pos > FILE_COPY_BUFFER_SIZE ? FILE_COPY_BUFFER_SIZE : size - pos;
  436 |         pos += output.transferFrom(input, pos, count);
  437 |       }
  438 |     } finally {
  439 |       IOUtils.closeQuietly(output);
  440 |       IOUtils.closeQuietly(fos);
  441 |       IOUtils.closeQuietly(input);
  442 |       IOUtils.closeQuietly(fis);
  443 |     }
  444 | 
  445 |     if (srcFile.length() != destFile.length()) {
  446 |       throw new IOException("Failed to copy full contents from '" +
  447 |           srcFile + "' to '" + destFile + "'");
  448 |     }
  449 |     if (preserveFileDate) {
  450 |       destFile.setLastModified(srcFile.lastModified());
  451 |     }
  452 |   }
  453 | 
  454 |   /**
  455 |    * Copies a whole directory to a new location preserving the file dates.
```

---

## 107/115 flow_id 8f0b88d6c8 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 8f0b88d6c8
key        : <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2888/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceDelete(java.io.File)>@L793/0
source     : <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2888] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceDelete(java.io.File)>[25@L793] invokespecial %v18.<init>(message)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceDelete(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2885 |     }
 2886 | 
 2887 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2888 |       if (names.add(zipEntry.getName())) {
 2889 |         ZipEntryTransformer entry = (ZipEntryTransformer) entryByPath.remove(zipEntry.getName());
 2890 |         if (entry != null) {
 2891 |           entry.transform(in, zipEntry, out);
 2892 |         }
 2893 |         else {
 2894 |           ZipEntryUtil.copyEntry(zipEntry, in, out);
 2895 |         }
 2896 |       }
 2897 |       else if (log.isDebugEnabled()) {
 2898 |         log.debug("Duplicate entry: {}", zipEntry.getName());
 2899 |       }
 2900 |     }
 2901 | 
 2902 |     /**
 2903 |      * @return <code>true</code> if at least one entry was replaced.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceDelete(java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  780 |    * @throws IOException in case deletion is unsuccessful
  781 |    */
  782 |   public static void forceDelete(File file) throws IOException {
  783 |     if (file.isDirectory()) {
  784 |       deleteDirectory(file);
  785 |     } else {
  786 |       boolean filePresent = file.exists();
  787 |       if (!file.delete()) {
  788 |         if (!filePresent){
  789 |           throw new FileNotFoundException("File does not exist: " + file);
  790 |         }
  791 |         String message =
  792 |             "Unable to delete file: " + file;
  793 |         throw new IOException(message);
  794 |       }
  795 |     }
  796 |   }
  797 | 
  798 |   /**
  799 |    * Schedules a file to be deleted when JVM exits.
```

---

## 108/115 flow_id c4ac5ec6de (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow c4ac5ec6de
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>@L511/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceDelete(java.io.File)>@L793/0
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>[25@L511] %v24 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceDelete(java.io.File)>[25@L793] invokespecial %v18.<init>(message)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceDelete(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>
file: org/zeroturnaround/zip/ZipUtil.java
  490 |    * @see #iterate(File, ZipInfoCallback)
  491 |    */
  492 |   public static void iterate(File zip, ZipEntryCallback action, Charset charset) {
  493 |     ZipFile zf = null;
  494 |     try {
  495 |       if (charset == null) {
  496 |         zf = new ZipFile(zip);
  497 |       }
  498 |       else {
  499 |         zf = new ZipFile(zip, charset);
  500 |       }
  501 | 
  502 |       Enumeration<? extends ZipEntry> en = zf.entries();
  503 |       while (en.hasMoreElements()) {
  504 |         ZipEntry e = (ZipEntry) en.nextElement();
  505 | 
  506 |         InputStream is = zf.getInputStream(e);
  507 |         try {
  508 |           action.process(is, e);
  509 |         }
  510 |         catch (IOException ze) {
  511 |           throw new ZipException("Failed to process zip entry '" + e.getName() + "' with action " + action, ze);
  512 |         }
  513 |         catch (ZipBreakException ex) {
  514 |           break;
  515 |         }
  516 |         finally {
  517 |           IOUtils.closeQuietly(is);
  518 |         }
  519 |       }
  520 |     }
  521 |     catch (IOException e) {
  522 |       throw ZipExceptionUtil.rethrow(e);
  523 |     }
  524 |     finally {
  525 |       closeQuietly(zf);
  526 |     }
  527 |   }
  528 | 
  529 |   /**
  530 |    * Reads the given ZIP file and executes the given action for each given entry.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceDelete(java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  780 |    * @throws IOException in case deletion is unsuccessful
  781 |    */
  782 |   public static void forceDelete(File file) throws IOException {
  783 |     if (file.isDirectory()) {
  784 |       deleteDirectory(file);
  785 |     } else {
  786 |       boolean filePresent = file.exists();
  787 |       if (!file.delete()) {
  788 |         if (!filePresent){
  789 |           throw new FileNotFoundException("File does not exist: " + file);
  790 |         }
  791 |         String message =
  792 |             "Unable to delete file: " + file;
  793 |         throw new IOException(message);
  794 |       }
  795 |     }
  796 |   }
  797 | 
  798 |   /**
  799 |    * Schedules a file to be deleted when JVM exits.
```

---

## 109/115 flow_id a9e98b5727 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow a9e98b5727
key        : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>@L313/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceMkdir(java.io.File)>@L888/0
source     : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>[9@L313] o = invokeinterface elems.nextElement()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceMkdir(java.io.File)>[14@L888] invokespecial %v12.<init>(message)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceMkdir(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceMkdir(java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  878 |    * @throws IOException if the directory cannot be created or the file already exists but is not a directory
  879 |    */
  880 |   public static void forceMkdir(File directory) throws IOException {
  881 |     if (directory.exists()) {
  882 |       if (!directory.isDirectory()) {
  883 |         String message =
  884 |             "File "
  885 |                 + directory
  886 |                 + " exists and is "
  887 |                 + "not a directory. Unable to create directory.";
  888 |         throw new IOException(message);
  889 |       }
  890 |     } else {
  891 |       if (!directory.mkdirs()) {
  892 |         // Double-check that some other thread or process hasn't made
  893 |         // the directory in the background
  894 |         if (!directory.isDirectory())
  895 |         {
  896 |           String message =
  897 |               "Unable to create directory " + directory;
  898 |           throw new IOException(message);
  899 |         }
  900 |       }
  901 |     }
  902 |   }
  903 | 
  904 |   //-----------------------------------------------------------------------
  905 |   /**
```

---

## 110/115 flow_id 89877111a3 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 89877111a3
key        : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>@L77/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceMkdir(java.io.File)>@L888/0
source     : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>[4@L77] %v5 = invokevirtual original.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceMkdir(java.io.File)>[14@L888] invokespecial %v12.<init>(message)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceMkdir(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>
file: org/zeroturnaround/zip/ZipEntryUtil.java
   58 |    * @return copy of the original entry, but with the given name
   59 |    */
   60 |   static ZipEntry copy(ZipEntry original, String newName) {
   61 |     ZipEntry copy = new ZipEntry(newName == null ? original.getName() : newName);
   62 |     if (original.getCrc() != -1) {
   63 |       copy.setCrc(original.getCrc());
   64 |     }
   65 |     if (original.getMethod() != -1) {
   66 |       copy.setMethod(original.getMethod());
   67 |     }
   68 |     if (original.getSize() >= 0) {
   69 |       copy.setSize(original.getSize());
   70 |     }
   71 |     if (original.getExtra() != null) {
   72 |       copy.setExtra(original.getExtra());
   73 |     }
   74 | 
   75 |     copy.setComment(original.getComment());
   76 |     copy.setTime(original.getTime());
   77 |     return copy;
   78 |   }
   79 | 
   80 |   /**

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceMkdir(java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  878 |    * @throws IOException if the directory cannot be created or the file already exists but is not a directory
  879 |    */
  880 |   public static void forceMkdir(File directory) throws IOException {
  881 |     if (directory.exists()) {
  882 |       if (!directory.isDirectory()) {
  883 |         String message =
  884 |             "File "
  885 |                 + directory
  886 |                 + " exists and is "
  887 |                 + "not a directory. Unable to create directory.";
  888 |         throw new IOException(message);
  889 |       }
  890 |     } else {
  891 |       if (!directory.mkdirs()) {
  892 |         // Double-check that some other thread or process hasn't made
  893 |         // the directory in the background
  894 |         if (!directory.isDirectory())
  895 |         {
  896 |           String message =
  897 |               "Unable to create directory " + directory;
  898 |           throw new IOException(message);
  899 |         }
  900 |       }
  901 |     }
  902 |   }
  903 | 
  904 |   //-----------------------------------------------------------------------
  905 |   /**
```

---

## 111/115 flow_id 345c470c79 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 345c470c79
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>@L511/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceMkdir(java.io.File)>@L898/0
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>[25@L511] %v24 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceMkdir(java.io.File)>[27@L898] invokespecial %v20.<init>(message#1)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceMkdir(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>
file: org/zeroturnaround/zip/ZipUtil.java
  490 |    * @see #iterate(File, ZipInfoCallback)
  491 |    */
  492 |   public static void iterate(File zip, ZipEntryCallback action, Charset charset) {
  493 |     ZipFile zf = null;
  494 |     try {
  495 |       if (charset == null) {
  496 |         zf = new ZipFile(zip);
  497 |       }
  498 |       else {
  499 |         zf = new ZipFile(zip, charset);
  500 |       }
  501 | 
  502 |       Enumeration<? extends ZipEntry> en = zf.entries();
  503 |       while (en.hasMoreElements()) {
  504 |         ZipEntry e = (ZipEntry) en.nextElement();
  505 | 
  506 |         InputStream is = zf.getInputStream(e);
  507 |         try {
  508 |           action.process(is, e);
  509 |         }
  510 |         catch (IOException ze) {
  511 |           throw new ZipException("Failed to process zip entry '" + e.getName() + "' with action " + action, ze);
  512 |         }
  513 |         catch (ZipBreakException ex) {
  514 |           break;
  515 |         }
  516 |         finally {
  517 |           IOUtils.closeQuietly(is);
  518 |         }
  519 |       }
  520 |     }
  521 |     catch (IOException e) {
  522 |       throw ZipExceptionUtil.rethrow(e);
  523 |     }
  524 |     finally {
  525 |       closeQuietly(zf);
  526 |     }
  527 |   }
  528 | 
  529 |   /**
  530 |    * Reads the given ZIP file and executes the given action for each given entry.

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceMkdir(java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
  878 |    * @throws IOException if the directory cannot be created or the file already exists but is not a directory
  879 |    */
  880 |   public static void forceMkdir(File directory) throws IOException {
  881 |     if (directory.exists()) {
  882 |       if (!directory.isDirectory()) {
  883 |         String message =
  884 |             "File "
  885 |                 + directory
  886 |                 + " exists and is "
  887 |                 + "not a directory. Unable to create directory.";
  888 |         throw new IOException(message);
  889 |       }
  890 |     } else {
  891 |       if (!directory.mkdirs()) {
  892 |         // Double-check that some other thread or process hasn't made
  893 |         // the directory in the background
  894 |         if (!directory.isDirectory())
  895 |         {
  896 |           String message =
  897 |               "Unable to create directory " + directory;
  898 |           throw new IOException(message);
  899 |         }
  900 |       }
  901 |     }
  902 |   }
  903 | 
  904 |   //-----------------------------------------------------------------------
  905 |   /**
```

---

## 112/115 flow_id 626481ad27 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 626481ad27
key        : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>@L77/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>@L1042/0
source     : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>[4@L77] %v5 = invokevirtual original.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>[61@L1042] invokespecial %v37.<init>(%v44)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>
file: org/zeroturnaround/zip/ZipEntryUtil.java
   58 |    * @return copy of the original entry, but with the given name
   59 |    */
   60 |   static ZipEntry copy(ZipEntry original, String newName) {
   61 |     ZipEntry copy = new ZipEntry(newName == null ? original.getName() : newName);
   62 |     if (original.getCrc() != -1) {
   63 |       copy.setCrc(original.getCrc());
   64 |     }
   65 |     if (original.getMethod() != -1) {
   66 |       copy.setMethod(original.getMethod());
   67 |     }
   68 |     if (original.getSize() >= 0) {
   69 |       copy.setSize(original.getSize());
   70 |     }
   71 |     if (original.getExtra() != null) {
   72 |       copy.setExtra(original.getExtra());
   73 |     }
   74 | 
   75 |     copy.setComment(original.getComment());
   76 |     copy.setTime(original.getTime());
   77 |     return copy;
   78 |   }
   79 | 
   80 |   /**

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
 1023 |    * @since 1.4
 1024 |    */
 1025 |   public static void moveFile(File srcFile, File destFile) throws IOException {
 1026 |     if (srcFile == null) {
 1027 |       throw new NullPointerException("Source must not be null");
 1028 |     }
 1029 |     if (destFile == null) {
 1030 |       throw new NullPointerException("Destination must not be null");
 1031 |     }
 1032 |     if (!srcFile.exists()) {
 1033 |       throw new FileNotFoundException("Source '" + srcFile + "' does not exist");
 1034 |     }
 1035 |     if (srcFile.isDirectory()) {
 1036 |       throw new IOException("Source '" + srcFile + "' is a directory");
 1037 |     }
 1038 |     if (destFile.exists()) {
 1039 |       throw new FileExistsException("Destination '" + destFile + "' already exists");
 1040 |     }
 1041 |     if (destFile.isDirectory()) {
 1042 |       throw new IOException("Destination '" + destFile + "' is a directory");
 1043 |     }
 1044 |     boolean rename = srcFile.renameTo(destFile);
 1045 |     if (!rename) {
 1046 |       copyFile( srcFile, destFile );
 1047 |       if (!srcFile.delete()) {
 1048 |         FileUtils.deleteQuietly(destFile);
 1049 |         throw new IOException("Failed to delete original file '" + srcFile +
 1050 |             "' after copy to '" + destFile + "'");
 1051 |       }
 1052 |     }
 1053 |   }
 1054 | 
 1055 |   /**
 1056 |    * Determines whether the specified file is a Symbolic Link rather than an actual file.
```

---

## 113/115 flow_id 18a414bd63 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 18a414bd63
key        : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2639/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>@L1042/0
source     : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2639] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>[61@L1042] invokespecial %v37.<init>(%v44)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2636 |         final Set<String> names = new HashSet<String>();
 2637 |         iterate(zip, new ZipEntryCallback() {
 2638 |           public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2639 |             if (names.add(zipEntry.getName())) {
 2640 |               ZipEntrySource entry = (ZipEntrySource) entryByPath.remove(zipEntry.getName());
 2641 |               if (entry != null) {
 2642 |                 addEntry(entry, out);
 2643 |               }
 2644 |               else {
 2645 |                 ZipEntryUtil.copyEntry(zipEntry, in, out);
 2646 |               }
 2647 |             }
 2648 |             else if (log.isDebugEnabled()) {
 2649 |               log.debug("Duplicate entry: {}", zipEntry.getName());
 2650 |             }
 2651 |           }
 2652 |         });
 2653 | 
 2654 |         // Add new entries

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
 1023 |    * @since 1.4
 1024 |    */
 1025 |   public static void moveFile(File srcFile, File destFile) throws IOException {
 1026 |     if (srcFile == null) {
 1027 |       throw new NullPointerException("Source must not be null");
 1028 |     }
 1029 |     if (destFile == null) {
 1030 |       throw new NullPointerException("Destination must not be null");
 1031 |     }
 1032 |     if (!srcFile.exists()) {
 1033 |       throw new FileNotFoundException("Source '" + srcFile + "' does not exist");
 1034 |     }
 1035 |     if (srcFile.isDirectory()) {
 1036 |       throw new IOException("Source '" + srcFile + "' is a directory");
 1037 |     }
 1038 |     if (destFile.exists()) {
 1039 |       throw new FileExistsException("Destination '" + destFile + "' already exists");
 1040 |     }
 1041 |     if (destFile.isDirectory()) {
 1042 |       throw new IOException("Destination '" + destFile + "' is a directory");
 1043 |     }
 1044 |     boolean rename = srcFile.renameTo(destFile);
 1045 |     if (!rename) {
 1046 |       copyFile( srcFile, destFile );
 1047 |       if (!srcFile.delete()) {
 1048 |         FileUtils.deleteQuietly(destFile);
 1049 |         throw new IOException("Failed to delete original file '" + srcFile +
 1050 |             "' after copy to '" + destFile + "'");
 1051 |       }
 1052 |     }
 1053 |   }
 1054 | 
 1055 |   /**
 1056 |    * Determines whether the specified file is a Symbolic Link rather than an actual file.
```

---

## 114/115 flow_id 57a9cd86b1 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 57a9cd86b1
key        : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>@L77/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>@L1049/0
source     : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>[4@L77] %v5 = invokevirtual original.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>[81@L1049] invokespecial %v47.<init>(%v57)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>
file: org/zeroturnaround/zip/ZipEntryUtil.java
   58 |    * @return copy of the original entry, but with the given name
   59 |    */
   60 |   static ZipEntry copy(ZipEntry original, String newName) {
   61 |     ZipEntry copy = new ZipEntry(newName == null ? original.getName() : newName);
   62 |     if (original.getCrc() != -1) {
   63 |       copy.setCrc(original.getCrc());
   64 |     }
   65 |     if (original.getMethod() != -1) {
   66 |       copy.setMethod(original.getMethod());
   67 |     }
   68 |     if (original.getSize() >= 0) {
   69 |       copy.setSize(original.getSize());
   70 |     }
   71 |     if (original.getExtra() != null) {
   72 |       copy.setExtra(original.getExtra());
   73 |     }
   74 | 
   75 |     copy.setComment(original.getComment());
   76 |     copy.setTime(original.getTime());
   77 |     return copy;
   78 |   }
   79 | 
   80 |   /**

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
 1023 |    * @since 1.4
 1024 |    */
 1025 |   public static void moveFile(File srcFile, File destFile) throws IOException {
 1026 |     if (srcFile == null) {
 1027 |       throw new NullPointerException("Source must not be null");
 1028 |     }
 1029 |     if (destFile == null) {
 1030 |       throw new NullPointerException("Destination must not be null");
 1031 |     }
 1032 |     if (!srcFile.exists()) {
 1033 |       throw new FileNotFoundException("Source '" + srcFile + "' does not exist");
 1034 |     }
 1035 |     if (srcFile.isDirectory()) {
 1036 |       throw new IOException("Source '" + srcFile + "' is a directory");
 1037 |     }
 1038 |     if (destFile.exists()) {
 1039 |       throw new FileExistsException("Destination '" + destFile + "' already exists");
 1040 |     }
 1041 |     if (destFile.isDirectory()) {
 1042 |       throw new IOException("Destination '" + destFile + "' is a directory");
 1043 |     }
 1044 |     boolean rename = srcFile.renameTo(destFile);
 1045 |     if (!rename) {
 1046 |       copyFile( srcFile, destFile );
 1047 |       if (!srcFile.delete()) {
 1048 |         FileUtils.deleteQuietly(destFile);
 1049 |         throw new IOException("Failed to delete original file '" + srcFile +
 1050 |             "' after copy to '" + destFile + "'");
 1051 |       }
 1052 |     }
 1053 |   }
 1054 | 
 1055 |   /**
 1056 |    * Determines whether the specified file is a Symbolic Link rather than an actual file.
```

---

## 115/115 flow_id 44f9b6a0b4 (priority 2)

```text
# zt-zip/buggy (CVE-2018-1002201, CWE-022) flow 44f9b6a0b4
key        : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1196/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>@L1049/0
source     : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[4@L1196] %v9 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>[81@L1049] invokespecial %v47.<init>(%v57)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1193 |     }
 1194 | 
 1195 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1196 |       String name = mapper.map(zipEntry.getName());
 1197 |       if (name != null) {
 1198 |         /**
 1199 |          * We assume that EVERY backslash will denote a directory
 1200 |          * separator. Also such broken archives don't have entries that
 1201 |          * are just directories. Everything is a file. See the example
 1202 |          *
 1203 |          * Archive: backSlashTest.zip
 1204 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1205 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1206 |          * No errors detected in compressed data of backSlashTest.zip.
 1207 |          */
 1208 |         if (name.indexOf('\\') != -1) {
 1209 |           File parentDirectory = outputDir;
 1210 |           String[] dirs = name.split("\\\\");
 1211 | 
 1212 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1213 |           for (int i = 0; i < dirs.length - 1; i++) {
 1214 |             File file = new File(parentDirectory, dirs[i]);
 1215 |             if (!file.exists()) {
 1216 |               FileUtils.forceMkdir(file);
 1217 |             }
 1218 |             parentDirectory = file;
 1219 |           }
 1220 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1221 |           FileUtils.copy(in, destFile);
 1222 |         }
 1223 |         // it could be that there are just top level files that the unpacker is used for
 1224 |         else {
 1225 |           File destFile = new File(outputDir, name);
 1226 |           FileUtils.copy(in, destFile);
 1227 |         }
 1228 |       }
 1229 |     }
 1230 |   }
 1231 | 
 1232 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 |         if (zipEntry.isDirectory()) {
 1154 |           FileUtils.forceMkdir(file);
 1155 |         }
 1156 |         else {
 1157 |           FileUtils.forceMkdir(file.getParentFile());
 1158 | 
 1159 |           if (log.isDebugEnabled() && file.exists()) {
 1160 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1161 |           }
 1162 | 
 1163 |           FileUtils.copy(in, file);
 1164 |         }
 1165 | 
 1166 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1167 |         if (permissions != null) {
 1168 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1169 |         }
 1170 |       }
 1171 |     }
 1172 |   }
 1173 | 
 1174 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1247 |     }
 1248 | 
 1249 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1250 |       String root = getRootName(zipEntry.getName());
 1251 |       if (rootDir == null) {
 1252 |         rootDir = root;
 1253 |       }
 1254 |       else if (!rootDir.equals(root)) {
 1255 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1256 |       }
 1257 | 
 1258 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1259 |       if (name != null) {
 1260 |         File file = new File(outputDir, name);
 1261 |         if (zipEntry.isDirectory()) {
 1262 |           FileUtils.forceMkdir(file);
 1263 |         }
 1264 |         else {
 1265 |           FileUtils.forceMkdir(file.getParentFile());
 1266 | 
 1267 |           if (log.isDebugEnabled() && file.exists()) {
 1268 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1269 |           }
 1270 | 
 1271 |           FileUtils.copy(in, file);
 1272 |         }
 1273 |       }
 1274 |     }
 1275 | 
 1276 |     private String getUnrootedName(String root, String name) {
 1277 |       return name.substring(root.length());

### <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/commons/FileUtilsV2_2.java
 1023 |    * @since 1.4
 1024 |    */
 1025 |   public static void moveFile(File srcFile, File destFile) throws IOException {
 1026 |     if (srcFile == null) {
 1027 |       throw new NullPointerException("Source must not be null");
 1028 |     }
 1029 |     if (destFile == null) {
 1030 |       throw new NullPointerException("Destination must not be null");
 1031 |     }
 1032 |     if (!srcFile.exists()) {
 1033 |       throw new FileNotFoundException("Source '" + srcFile + "' does not exist");
 1034 |     }
 1035 |     if (srcFile.isDirectory()) {
 1036 |       throw new IOException("Source '" + srcFile + "' is a directory");
 1037 |     }
 1038 |     if (destFile.exists()) {
 1039 |       throw new FileExistsException("Destination '" + destFile + "' already exists");
 1040 |     }
 1041 |     if (destFile.isDirectory()) {
 1042 |       throw new IOException("Destination '" + destFile + "' is a directory");
 1043 |     }
 1044 |     boolean rename = srcFile.renameTo(destFile);
 1045 |     if (!rename) {
 1046 |       copyFile( srcFile, destFile );
 1047 |       if (!srcFile.delete()) {
 1048 |         FileUtils.deleteQuietly(destFile);
 1049 |         throw new IOException("Failed to delete original file '" + srcFile +
 1050 |             "' after copy to '" + destFile + "'");
 1051 |       }
 1052 |     }
 1053 |   }
 1054 | 
 1055 |   /**
 1056 |    * Determines whether the specified file is a Symbolic Link rather than an actual file.
```
