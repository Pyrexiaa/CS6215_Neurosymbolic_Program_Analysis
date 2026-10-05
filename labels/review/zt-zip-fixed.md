# Labelling pack: zt-zip / fixed

97 frozen sampled rows. Evidence uses the exact raw source and sink in the chosen run record. Existing labels remain unverified and are unchanged. A canonical key may still group different drivers or routes; inspect the attacker model before reusing a label. Original packets are retained in results/history/pre-evidence-refresh.tar.gz.

---

## 1/97 flow_id ff270a482d (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow ff270a482d
key        : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1150/result => <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1223/1
source     : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[3@L1150] %v7 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[19@L1223] invokespecial file.<init>(parentDirectory, %v22)/1
fixed methods on this flow (GT): Unpacker.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1

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
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

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

## 2/97 flow_id 4e0f931a96 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 4e0f931a96
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1285/result => <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1229/1
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[25@L1285] %v24 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[30@L1229] invokespecial destFile.<init>(parentDirectory, %v27)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtils: void copy(java.io.InputStream,java.io.File)>

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
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

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

## 3/97 flow_id 4922d58124 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 4922d58124
key        : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1150/result => <org.zeroturnaround.zip.ZipUtil$RepackZipEntryCallback: void <init>(java.io.File,int)>@L1884/0
source     : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[3@L1150] %v7 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$RepackZipEntryCallback: void <init>(java.io.File,int)>[4@L1884] invokespecial %v6.<init>(dstZip)/0
fixed methods on this flow (GT): Unpacker.process
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$RepackZipEntryCallback: void <init>(java.io.File,int,org.zeroturnaround.zip.ZipUtil$1)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$RepackZipEntryCallback: void <init>(java.io.File,int)>

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
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$RepackZipEntryCallback: void <init>(java.io.File,int,org.zeroturnaround.zip.ZipUtil$1)>
file: org/zeroturnaround/zip/ZipUtil.java
 1875 |    *
 1876 |    * @author Pavel Grigorenko
 1877 |    */
 1878 |   private static final class RepackZipEntryCallback implements ZipEntryCallback {
 1879 | 
 1880 |     private ZipOutputStream out;
 1881 | 

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil$RepackZipEntryCallback: void <init>(java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1879 | 
 1880 |     private ZipOutputStream out;
 1881 | 
 1882 |     private RepackZipEntryCallback(File dstZip, int compressionLevel) {
 1883 |       try {
 1884 |         this.out = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(dstZip)));
 1885 |         this.out.setLevel(compressionLevel);
 1886 |       }
 1887 |       catch (IOException e) {
 1888 |         ZipExceptionUtil.rethrow(e);
 1889 |       }
 1890 |     }
 1891 | 
 1892 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1893 |       ZipEntryUtil.copyEntry(zipEntry, in, out);
```

---

## 4/97 flow_id 739dd783a9 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 739dd783a9
key        : DRIVER => <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1152/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[165@L41] %v100 = invokestatic nesy.Taint.srcFile()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[8@L1152] invokespecial file.<init>(%v11, name)/0
fixed methods on this flow (GT): Unpacker.process
reported by: B1 run0, B2 run0, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[165@L41] %v100 = invokestatic nesy.Taint.srcFile()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v100}
3. VarNode{<org.zeroturnaround.zip.ZipUtil: void unpack(java.io.File,java.io.File)>/outputDir}
4. VarNode{<org.zeroturnaround.zip.ZipUtil: void unpack(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper)>/outputDir}
5. VarNode{<org.zeroturnaround.zip.ZipUtil$Unpacker: void <init>(java.io.File,org.zeroturnaround.zip.NameMapper)>/outputDir}
6. InstanceFieldNode{NewObj{<org.zeroturnaround.zip.ZipUtil: void unpack(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper)>[3@L996] new org.zeroturnaround.zip.ZipUtil$Unpacker}.<org.zeroturnaround.zip.ZipUtil$Unpacker: java.io.File outputDir>}
7. VarNode{<org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>/%v11}
8. <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[8@L1152] invokespecial file.<init>(%v11, name)/0

## Application-code evidence (route or reachable-method fallback)
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
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**
```

---

## 5/97 flow_id af7381f997 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow af7381f997
key        : <org.apache.log4j.Category: void removeAllAppenders()>@L889/result => <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1152/1
source     : <org.apache.log4j.Category: void removeAllAppenders()>[10@L889] %v10 = invokeinterface iter.nextElement()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[8@L1152] invokespecial file.<init>(%v11, name)/1
fixed methods on this flow (GT): Unpacker.process
reported by: v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2

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
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
```

---

## 6/97 flow_id dc87503908 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow dc87503908
key        : <org.apache.log4j.helpers.Loader: java.lang.Class loadClass(java.lang.String)>@L198/0 => <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1152/1
source     : <org.apache.log4j.helpers.Loader: java.lang.Class loadClass(java.lang.String)>[21@L198] %v14 = invokestatic java.lang.Class.forName(clazz)/0
sink       : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[8@L1152] invokespecial file.<init>(%v11, name)/1
fixed methods on this flow (GT): Unpacker.process
reported by: v1 run1, v2 run1

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void packEntries(java.io.File[],java.io.File,org.zeroturnaround.zip.NameMapper,int)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>

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
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil: void packEntries(java.io.File[],java.io.File,org.zeroturnaround.zip.NameMapper,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1559 |    *          <code>Deflater.BEST_COMPRESSION</code>
 1560 |    */
 1561 |   public static void packEntries(File[] filesToPack, File destZipFile, NameMapper mapper, int compressionLevel) {
 1562 |     log.debug("Compressing '{}' into '{}'.", filesToPack, destZipFile);
 1563 | 
 1564 |     ZipOutputStream out = null;
 1565 |     FileOutputStream fos = null;
 1566 |     try {
 1567 |       fos = new FileOutputStream(destZipFile);
 1568 |       out = new ZipOutputStream(new BufferedOutputStream(fos));
 1569 |       out.setLevel(compressionLevel);
 1570 | 
 1571 |       for (int i = 0; i < filesToPack.length; i++) {
 1572 |         File fileToPack = filesToPack[i];
 1573 | 
 1574 |         ZipEntry zipEntry = ZipEntryUtil.fromFile(mapper.map(fileToPack.getName()), fileToPack);
 1575 |         out.putNextEntry(zipEntry);
 1576 |         FileUtils.copy(fileToPack, out);
 1577 |         out.closeEntry();
 1578 |       }
 1579 |     }
 1580 |     catch (IOException e) {
 1581 |       throw ZipExceptionUtil.rethrow(e);
 1582 |     }
 1583 |     finally {
 1584 |       IOUtils.closeQuietly(out);
 1585 |       IOUtils.closeQuietly(fos);
 1586 |     }
 1587 |   }
 1588 | 
 1589 |   /**
 1590 |    * Compresses the given directory and all its sub-directories into a ZIP file.

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**
```

---

## 7/97 flow_id d1baeffd89 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow d1baeffd89
key        : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>@L77/result => <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1152/1
source     : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>[4@L77] %v5 = invokevirtual original.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[8@L1152] invokespecial file.<init>(%v11, name)/1
fixed methods on this flow (GT): Unpacker.process
reported by: B2 run0, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>

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

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
```

---

## 8/97 flow_id ccd324687a (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow ccd324687a
key        : <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2372/result => <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1152/1
source     : <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L2372] entryName = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[8@L1152] invokespecial file.<init>(%v11, name)/1
fixed methods on this flow (GT): Unpacker.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>

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

### <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2369 |     final Set<String> names = new HashSet<String>();
 2370 |     iterate(is, new ZipEntryCallback() {
 2371 |       public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2372 |         String entryName = zipEntry.getName();
 2373 |         if (names.add(entryName)) {
 2374 |           ZipEntryUtil.copyEntry(zipEntry, in, out);
 2375 |         }
 2376 |         else if (log.isDebugEnabled()) {
 2377 |           log.debug("Duplicate entry: {}", entryName);
 2378 |         }
 2379 |       }
 2380 |     });
 2381 |   }
 2382 | 

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
```

---

## 9/97 flow_id 70ad36d893 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 70ad36d893
key        : <org.zeroturnaround.zip.ZipUtil$12: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2398/result => <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1152/1
source     : <org.zeroturnaround.zip.ZipUtil$12: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L2398] entryName = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[8@L1152] invokespecial file.<init>(%v11, name)/1
fixed methods on this flow (GT): Unpacker.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$12: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>

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

### <org.zeroturnaround.zip.ZipUtil$12: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2395 |     final Set<String> dirNames = filterDirEntries(zip, ignoredEntries);
 2396 |     iterate(zip, new ZipEntryCallback() {
 2397 |       public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2398 |         String entryName = zipEntry.getName();
 2399 |         if (ignoredEntries.contains(entryName)) {
 2400 |           return;
 2401 |         }
 2402 | 
 2403 |         for (String dirName : dirNames) {
 2404 |           if (entryName.startsWith(dirName)) {
 2405 |             return;
 2406 |           }
 2407 |         }
 2408 | 
 2409 |         if (names.add(entryName)) {
 2410 |           ZipEntryUtil.copyEntry(zipEntry, in, out);
 2411 |         }
 2412 |         else if (log.isDebugEnabled()) {
 2413 |           log.debug("Duplicate entry: {}", entryName);
 2414 |         }
 2415 |       }
 2416 |     });
 2417 |   }
 2418 | 

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
```

---

## 10/97 flow_id 566455258c (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 566455258c
key        : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2675/result => <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1152/1
source     : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2675] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[8@L1152] invokespecial file.<init>(%v11, name)/1
fixed methods on this flow (GT): Unpacker.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>

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

### <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2672 |         final Set<String> names = new HashSet<String>();
 2673 |         iterate(zip, new ZipEntryCallback() {
 2674 |           public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2675 |             if (names.add(zipEntry.getName())) {
 2676 |               ZipEntrySource entry = (ZipEntrySource) entryByPath.remove(zipEntry.getName());
 2677 |               if (entry != null) {
 2678 |                 addEntry(entry, out);
 2679 |               }
 2680 |               else {
 2681 |                 ZipEntryUtil.copyEntry(zipEntry, in, out);
 2682 |               }
 2683 |             }
 2684 |             else if (log.isDebugEnabled()) {
 2685 |               log.debug("Duplicate entry: {}", zipEntry.getName());
 2686 |             }
 2687 |           }
 2688 |         });
 2689 | 
 2690 |         // Add new entries

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
```

---

## 11/97 flow_id f0304d5532 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow f0304d5532
key        : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1205/result => <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1152/1
source     : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[4@L1205] %v9 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[8@L1152] invokespecial file.<init>(%v11, name)/1
fixed methods on this flow (GT): Unpacker.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1

## Route (taint flow graph)
1. <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[4@L1205] %v9 = invokevirtual zipEntry.getName()/result
2. VarNode{<org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>/%v9}
3. VarNode{<org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>/name}
4. VarNode{<org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>/name}
5. <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[8@L1152] invokespecial file.<init>(%v11, name)/1

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

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
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**
```

---

## 12/97 flow_id 217b8cd94d (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 217b8cd94d
key        : <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2927/result => <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1152/1
source     : <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2927] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[8@L1152] invokespecial file.<init>(%v11, name)/1
fixed methods on this flow (GT): Unpacker.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run2, v3-noV2 run2, v3-noV3 run2, v3-noval run2, v4 run2
N3 (v3 run2): uncertain / unparseable (kept=True, v3_ok=None)

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
 2924 |     }
 2925 | 
 2926 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2927 |       if (names.add(zipEntry.getName())) {
 2928 |         ZipEntryTransformer entry = (ZipEntryTransformer) entryByPath.remove(zipEntry.getName());
 2929 |         if (entry != null) {
 2930 |           entry.transform(in, zipEntry, out);
 2931 |         }
 2932 |         else {
 2933 |           ZipEntryUtil.copyEntry(zipEntry, in, out);
 2934 |         }
 2935 |       }
 2936 |       else if (log.isDebugEnabled()) {
 2937 |         log.debug("Duplicate entry: {}", zipEntry.getName());
 2938 |       }
 2939 |     }
 2940 | 
 2941 |     /**
 2942 |      * @return <code>true</code> if at least one entry was replaced.

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
```

---

## 13/97 flow_id c5af9c7fc9 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow c5af9c7fc9
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1277/result => <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1152/1
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1277] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[8@L1152] invokespecial file.<init>(%v11, name)/1
fixed methods on this flow (GT): Unwraper.process, Unpacker.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2

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
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
```

---

## 14/97 flow_id 683ab5a3d6 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 683ab5a3d6
key        : <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>@L2444/result => <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1152/1
source     : <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>[25@L2444] %v21 = invokevirtual entry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[8@L1152] invokespecial file.<init>(%v11, name)/1
fixed methods on this flow (GT): Unpacker.process
reported by: B2 run0, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>

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
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>
file: org/zeroturnaround/zip/ZipUtil.java
 2426 |    *
 2427 |    */
 2428 |   static Set<String> filterDirEntries(File zip, Collection<String> names) {
 2429 |     Set<String> dirs = new HashSet<String>();
 2430 |     if (zip == null) {
 2431 |       return dirs;
 2432 |     }
 2433 |     ZipFile zf = null;
 2434 |     try {
 2435 |       zf = new ZipFile(zip);
 2436 |       for (String entryName : names) {
 2437 |         ZipEntry entry = zf.getEntry(entryName);
 2438 |         if (entry != null) {
 2439 |           if (entry.isDirectory()) {
 2440 |             dirs.add(entry.getName());
 2441 |           }
 2442 |           else if (zf.getInputStream(entry) == null) {
 2443 |             // no input stream means that this is a dir.
 2444 |             dirs.add(entry.getName() + PATH_SEPARATOR);
 2445 |           }
 2446 |         }
 2447 |       }
 2448 | 
 2449 |     }
 2450 |     catch (IOException e) {
 2451 |       ZipExceptionUtil.rethrow(e);
 2452 |     }
 2453 |     finally {
 2454 |       closeQuietly(zf);
 2455 |     }
 2456 |     return dirs;
 2457 |   }
 2458 | 
 2459 |   /**
```

---

## 15/97 flow_id 49dc8939fe (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 49dc8939fe
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>@L585/result => <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1152/1
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>[28@L585] %v25 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[8@L1152] invokespecial file.<init>(%v11, name)/1
fixed methods on this flow (GT): Unpacker.process
reported by: B2 run0, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>

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
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

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

## 16/97 flow_id 2917a7373e (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 2917a7373e
key        : DRIVER => <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1152/1
source     : <nesy.NesyDriver: void main(java.lang.String[])>[86@L28] %v49 = invokestatic nesy.Taint.srcFile()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[8@L1152] invokespecial file.<init>(%v11, name)/1
fixed methods on this flow (GT): Unpacker.process
reported by: B2 run0, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2

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
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
```

---

## 17/97 flow_id 870f4b46fc (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 870f4b46fc
key        : DRIVER => <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1287/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[213@L49] %v132 = invokestatic nesy.Taint.srcFile()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[31@L1287] invokespecial file.<init>(%v28, name)/0
fixed methods on this flow (GT): Unwraper.process
reported by: B1 run0, B2 run0, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[213@L49] %v132 = invokestatic nesy.Taint.srcFile()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v132}
3. VarNode{<org.zeroturnaround.zip.ZipUtil: void unwrap(java.io.File,java.io.File)>/outputDir}
4. VarNode{<org.zeroturnaround.zip.ZipUtil: void unwrap(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper)>/outputDir}
5. VarNode{<org.zeroturnaround.zip.ZipUtil$Unwraper: void <init>(java.io.File,org.zeroturnaround.zip.NameMapper)>/outputDir}
6. InstanceFieldNode{NewObj{<org.zeroturnaround.zip.ZipUtil: void unwrap(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper)>[3@L1031] new org.zeroturnaround.zip.ZipUtil$Unwraper}.<org.zeroturnaround.zip.ZipUtil$Unwraper: java.io.File outputDir>}
7. VarNode{<org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>/%v28}
8. <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[31@L1287] invokespecial file.<init>(%v28, name)/0

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
 1268 |     private final NameMapper mapper;
 1269 |     private String rootDir;
 1270 | 
 1271 |     public Unwraper(File outputDir, NameMapper mapper) {
 1272 |       this.outputDir = outputDir;
 1273 |       this.mapper = mapper;
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
```

---

## 18/97 flow_id 504c7cc38d (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 504c7cc38d
key        : <org.apache.log4j.helpers.Loader: java.lang.Class loadClass(java.lang.String)>@L198/0 => <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1287/1
source     : <org.apache.log4j.helpers.Loader: java.lang.Class loadClass(java.lang.String)>[21@L198] %v14 = invokestatic java.lang.Class.forName(clazz)/0
sink       : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[31@L1287] invokespecial file.<init>(%v28, name)/1
fixed methods on this flow (GT): Unwraper.process
reported by: v1 run1, v2 run1

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil: void packEntries(java.io.File[],java.io.File,org.zeroturnaround.zip.NameMapper,int)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>

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
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil: void packEntries(java.io.File[],java.io.File,org.zeroturnaround.zip.NameMapper,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1559 |    *          <code>Deflater.BEST_COMPRESSION</code>
 1560 |    */
 1561 |   public static void packEntries(File[] filesToPack, File destZipFile, NameMapper mapper, int compressionLevel) {
 1562 |     log.debug("Compressing '{}' into '{}'.", filesToPack, destZipFile);
 1563 | 
 1564 |     ZipOutputStream out = null;
 1565 |     FileOutputStream fos = null;
 1566 |     try {
 1567 |       fos = new FileOutputStream(destZipFile);
 1568 |       out = new ZipOutputStream(new BufferedOutputStream(fos));
 1569 |       out.setLevel(compressionLevel);
 1570 | 
 1571 |       for (int i = 0; i < filesToPack.length; i++) {
 1572 |         File fileToPack = filesToPack[i];
 1573 | 
 1574 |         ZipEntry zipEntry = ZipEntryUtil.fromFile(mapper.map(fileToPack.getName()), fileToPack);
 1575 |         out.putNextEntry(zipEntry);
 1576 |         FileUtils.copy(fileToPack, out);
 1577 |         out.closeEntry();
 1578 |       }
 1579 |     }
 1580 |     catch (IOException e) {
 1581 |       throw ZipExceptionUtil.rethrow(e);
 1582 |     }
 1583 |     finally {
 1584 |       IOUtils.closeQuietly(out);
 1585 |       IOUtils.closeQuietly(fos);
 1586 |     }
 1587 |   }
 1588 | 
 1589 |   /**
 1590 |    * Compresses the given directory and all its sub-directories into a ZIP file.

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
```

---

## 19/97 flow_id e78c6f72dd (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow e78c6f72dd
key        : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>@L77/result => <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1287/1
source     : <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>[4@L77] %v5 = invokevirtual original.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[31@L1287] invokespecial file.<init>(%v28, name)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipEntryUtil: java.util.zip.ZipEntry copy(java.util.zip.ZipEntry,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>

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

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
```

---

## 20/97 flow_id e78a9092b1 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow e78a9092b1
key        : <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2372/result => <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1287/1
source     : <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L2372] entryName = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[31@L1287] invokespecial file.<init>(%v28, name)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>

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

### <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2369 |     final Set<String> names = new HashSet<String>();
 2370 |     iterate(is, new ZipEntryCallback() {
 2371 |       public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2372 |         String entryName = zipEntry.getName();
 2373 |         if (names.add(entryName)) {
 2374 |           ZipEntryUtil.copyEntry(zipEntry, in, out);
 2375 |         }
 2376 |         else if (log.isDebugEnabled()) {
 2377 |           log.debug("Duplicate entry: {}", entryName);
 2378 |         }
 2379 |       }
 2380 |     });
 2381 |   }
 2382 | 

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
```

---

## 21/97 flow_id c1d15798c8 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow c1d15798c8
key        : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2675/result => <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1287/1
source     : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2675] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[31@L1287] invokespecial file.<init>(%v28, name)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>

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

### <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2672 |         final Set<String> names = new HashSet<String>();
 2673 |         iterate(zip, new ZipEntryCallback() {
 2674 |           public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2675 |             if (names.add(zipEntry.getName())) {
 2676 |               ZipEntrySource entry = (ZipEntrySource) entryByPath.remove(zipEntry.getName());
 2677 |               if (entry != null) {
 2678 |                 addEntry(entry, out);
 2679 |               }
 2680 |               else {
 2681 |                 ZipEntryUtil.copyEntry(zipEntry, in, out);
 2682 |               }
 2683 |             }
 2684 |             else if (log.isDebugEnabled()) {
 2685 |               log.debug("Duplicate entry: {}", zipEntry.getName());
 2686 |             }
 2687 |           }
 2688 |         });
 2689 | 
 2690 |         // Add new entries

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
```

---

## 22/97 flow_id 331bcff3cb (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 331bcff3cb
key        : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1205/result => <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1287/1
source     : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[4@L1205] %v9 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[31@L1287] invokespecial file.<init>(%v28, name)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1

## Route (taint flow graph)
1. <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[4@L1205] %v9 = invokevirtual zipEntry.getName()/result
2. VarNode{<org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>/%v9}
3. VarNode{<org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>/name}
4. VarNode{<org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>/name}
5. <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[31@L1287] invokespecial file.<init>(%v28, name)/1

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
```

---

## 23/97 flow_id 43bfa32676 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 43bfa32676
key        : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1150/result => <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1287/1
source     : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[3@L1150] %v7 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[31@L1287] invokespecial file.<init>(%v28, name)/1
fixed methods on this flow (GT): Unpacker.process, Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2

## Route (taint flow graph)
1. <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[3@L1150] %v7 = invokevirtual zipEntry.getName()/result
2. VarNode{<org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>/%v7}
3. VarNode{<org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>/name}
4. VarNode{<org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>/name}
5. <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[31@L1287] invokespecial file.<init>(%v28, name)/1

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>
file: org/zeroturnaround/zip/IdentityNameMapper.java
   29 |   private IdentityNameMapper() {}
   30 |   
   31 |   public String map(String name) {
   32 |     return name;
   33 |   }
   34 | 
   35 | }

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
```

---

## 24/97 flow_id 5655351387 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 5655351387
key        : <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>@L3067/result => <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1287/1
source     : <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>[36@L3067] path = invokevirtual e1.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[31@L1287] invokespecial file.<init>(%v28, name)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>

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
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 3039 |   }
 3040 | 
 3041 |   private static boolean archiveEqualsInternal(File f1, File f2) throws IOException {
 3042 |     ZipFile zf1 = null;
 3043 |     ZipFile zf2 = null;
 3044 |     try {
 3045 |       zf1 = new ZipFile(f1);
 3046 |       zf2 = new ZipFile(f2);
 3047 | 
 3048 |       // Check the number of entries
 3049 |       if (zf1.size() != zf2.size()) {
 3050 |         log.debug("Number of entries changed (" + zf1.size() + " vs " + zf2.size() + ").");
 3051 |         return false;
 3052 |       }
 3053 |       /*
 3054 |        * As there are same number of entries in both archives we can traverse
 3055 |        * all entries of one of the archives and get the corresponding entries
 3056 |        * from the other archive.
 3057 |        *
 3058 |        * If a corresponding entry is missing from the second archive the
 3059 |        * archives are different and we finish the comparison.
 3060 |        *
 3061 |        * We guarantee that no entry of the second archive is skipped as there
 3062 |        * are same number of unique entries in both archives.
 3063 |        */
 3064 |       Enumeration<? extends ZipEntry> en = zf1.entries();
 3065 |       while (en.hasMoreElements()) {
 3066 |         ZipEntry e1 = (ZipEntry) en.nextElement();
 3067 |         String path = e1.getName();
 3068 |         ZipEntry e2 = zf2.getEntry(path);
      | ... (lines omitted) ...
 3074 | 
 3075 |         // Check the content
 3076 |         InputStream is1 = null;
 3077 |         InputStream is2 = null;
 3078 |         try {
 3079 |           is1 = zf1.getInputStream(e1);
 3080 |           is2 = zf2.getInputStream(e2);
 3081 | 
 3082 |           if (!IOUtils.contentEquals(is1, is2)) {
 3083 |             log.debug("Entry '{}' content changed.", path);
 3084 |             return false;
 3085 |           }
 3086 |         }
 3087 |         finally {
 3088 |           IOUtils.closeQuietly(is1);
 3089 |           IOUtils.closeQuietly(is2);
 3090 |         }
 3091 |       }
 3092 |     }
 3093 |     finally {
 3094 |       closeQuietly(zf1);
 3095 |       closeQuietly(zf2);
 3096 |     }
 3097 | 
 3098 |     log.debug("Archives are the same.");
 3099 | 
 3100 |     return true;
 3101 |   }
 3102 | 
 3103 |   /**
```

---

## 25/97 flow_id 843db8c056 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 843db8c056
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.InputStream,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>@L715/result => <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1287/1
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.InputStream,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>[12@L715] %v14 = invokevirtual entry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[31@L1287] invokespecial file.<init>(%v28, name)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.InputStream,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>

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
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

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

## 26/97 flow_id f57a670481 (priority 1)

Historical evidence: this sampled key is absent from the corrected run records; the original label is retained without re-adjudication.

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow f57a670481
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1285/result => <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>@L3080/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[25@L1285] %v24 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>[46@L3080] is2 = invokevirtual zf2.getInputStream(e2)/0
fixed methods on this flow (GT): Unwraper.process
reported by: iris-like run2, v1 run2
N3 (iris-like run2): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>

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
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 3039 |   }
 3040 | 
 3041 |   private static boolean archiveEqualsInternal(File f1, File f2) throws IOException {
 3042 |     ZipFile zf1 = null;
 3043 |     ZipFile zf2 = null;
 3044 |     try {
 3045 |       zf1 = new ZipFile(f1);
 3046 |       zf2 = new ZipFile(f2);
 3047 | 
 3048 |       // Check the number of entries
 3049 |       if (zf1.size() != zf2.size()) {
 3050 |         log.debug("Number of entries changed (" + zf1.size() + " vs " + zf2.size() + ").");
 3051 |         return false;
 3052 |       }
 3053 |       /*
 3054 |        * As there are same number of entries in both archives we can traverse
 3055 |        * all entries of one of the archives and get the corresponding entries
 3056 |        * from the other archive.
 3057 |        *
 3058 |        * If a corresponding entry is missing from the second archive the
 3059 |        * archives are different and we finish the comparison.
 3060 |        *
 3061 |        * We guarantee that no entry of the second archive is skipped as there
 3062 |        * are same number of unique entries in both archives.
 3063 |        */
 3064 |       Enumeration<? extends ZipEntry> en = zf1.entries();
 3065 |       while (en.hasMoreElements()) {
 3066 |         ZipEntry e1 = (ZipEntry) en.nextElement();
 3067 |         String path = e1.getName();
 3068 |         ZipEntry e2 = zf2.getEntry(path);
      | ... (lines omitted) ...
 3074 | 
 3075 |         // Check the content
 3076 |         InputStream is1 = null;
 3077 |         InputStream is2 = null;
 3078 |         try {
 3079 |           is1 = zf1.getInputStream(e1);
 3080 |           is2 = zf2.getInputStream(e2);
 3081 | 
 3082 |           if (!IOUtils.contentEquals(is1, is2)) {
 3083 |             log.debug("Entry '{}' content changed.", path);
 3084 |             return false;
 3085 |           }
 3086 |         }
 3087 |         finally {
 3088 |           IOUtils.closeQuietly(is1);
 3089 |           IOUtils.closeQuietly(is2);
 3090 |         }
 3091 |       }
 3092 |     }
 3093 |     finally {
 3094 |       closeQuietly(zf1);
 3095 |       closeQuietly(zf2);
 3096 |     }
 3097 | 
 3098 |     log.debug("Archives are the same.");
 3099 | 
 3100 |     return true;
 3101 |   }
 3102 | 
 3103 |   /**
```

---

## 27/97 flow_id 2c59f0ced7 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 2c59f0ced7
key        : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1150/result => <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>@L2437/0
source     : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[3@L1150] %v7 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>[14@L2437] entry = invokevirtual zf.getEntry(entryName)/0
fixed methods on this flow (GT): Unpacker.process
reported by: iris-like run2, v1 run2
N3 (iris-like run2): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>

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
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>
file: org/zeroturnaround/zip/ZipUtil.java
 2426 |    *
 2427 |    */
 2428 |   static Set<String> filterDirEntries(File zip, Collection<String> names) {
 2429 |     Set<String> dirs = new HashSet<String>();
 2430 |     if (zip == null) {
 2431 |       return dirs;
 2432 |     }
 2433 |     ZipFile zf = null;
 2434 |     try {
 2435 |       zf = new ZipFile(zip);
 2436 |       for (String entryName : names) {
 2437 |         ZipEntry entry = zf.getEntry(entryName);
 2438 |         if (entry != null) {
 2439 |           if (entry.isDirectory()) {
 2440 |             dirs.add(entry.getName());
 2441 |           }
 2442 |           else if (zf.getInputStream(entry) == null) {
 2443 |             // no input stream means that this is a dir.
 2444 |             dirs.add(entry.getName() + PATH_SEPARATOR);
 2445 |           }
 2446 |         }
 2447 |       }
 2448 | 
 2449 |     }
 2450 |     catch (IOException e) {
 2451 |       ZipExceptionUtil.rethrow(e);
 2452 |     }
 2453 |     finally {
 2454 |       closeQuietly(zf);
 2455 |     }
 2456 |     return dirs;
 2457 |   }
 2458 | 
 2459 |   /**
```

---

## 28/97 flow_id 95de446abb (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 95de446abb
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1277/result => <org.zeroturnaround.zip.ZipUtil: void addOrReplaceEntries(java.io.File,org.zeroturnaround.zip.ZipEntrySource[],java.io.File)>@L2669/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1277] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void addOrReplaceEntries(java.io.File,org.zeroturnaround.zip.ZipEntrySource[],java.io.File)>[25@L2669] invokespecial %v30.<init>(destZip)/0
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void addOrReplaceEntries(java.io.File,org.zeroturnaround.zip.ZipEntrySource[],java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil: void addOrReplaceEntries(java.io.File,org.zeroturnaround.zip.ZipEntrySource[],java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 2659 |    *          new ZIP file created.
 2660 |    */
 2661 |   public static void addOrReplaceEntries(File zip, ZipEntrySource[] entries, File destZip) {
 2662 |     if (log.isDebugEnabled()) {
 2663 |       log.debug("Copying '" + zip + "' to '" + destZip + "' and adding/replacing entries " + Arrays.asList(entries)
 2664 |           + ".");
 2665 |     }
 2666 | 
 2667 |     final Map<String, ZipEntrySource> entryByPath = entriesByPath(entries);
 2668 |     try {
 2669 |       final ZipOutputStream out = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(destZip)));
 2670 |       try {
 2671 |         // Copy and replace entries
 2672 |         final Set<String> names = new HashSet<String>();
 2673 |         iterate(zip, new ZipEntryCallback() {
 2674 |           public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2675 |             if (names.add(zipEntry.getName())) {
 2676 |               ZipEntrySource entry = (ZipEntrySource) entryByPath.remove(zipEntry.getName());
 2677 |               if (entry != null) {
 2678 |                 addEntry(entry, out);
 2679 |               }
 2680 |               else {
 2681 |                 ZipEntryUtil.copyEntry(zipEntry, in, out);
 2682 |               }
 2683 |             }
 2684 |             else if (log.isDebugEnabled()) {
 2685 |               log.debug("Duplicate entry: {}", zipEntry.getName());
 2686 |             }
 2687 |           }
 2688 |         });
 2689 | 
 2690 |         // Add new entries
 2691 |         for (ZipEntrySource zipEntrySource : entryByPath.values()) {
 2692 |           addEntry(zipEntrySource, out);
 2693 |         }
 2694 |       }
 2695 |       finally {
 2696 |         IOUtils.closeQuietly(out);
 2697 |       }
 2698 |     }
 2699 |     catch (IOException e) {
 2700 |       ZipExceptionUtil.rethrow(e);
 2701 |     }
 2702 |   }
 2703 | 
 2704 |   /**
 2705 |    * Changes a ZIP file: adds/replaces the given entries in it.
```

---

## 29/97 flow_id 9aa5f75442 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 9aa5f75442
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1277/result => <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper,int)>@L1626/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1277] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper,int)>[22@L1626] invokespecial %v21.<init>(targetZip)/0
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,boolean)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,int)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper,int)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 1399 |    *          ZIP file that will be created or overwritten.
 1400 |    */
 1401 |   public static void pack(File rootDir, File zip) {
 1402 |     pack(rootDir, zip, DEFAULT_COMPRESSION_LEVEL);
 1403 |   }
 1404 | 
 1405 |   /**
 1406 |    * Compresses the given directory and all its sub-directories into a ZIP file.

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/ZipUtil.java
 1433 |    *          true if the resulted archive should have the top directory entry
 1434 |    */
 1435 |   public static void pack(final File sourceDir, final File targetZipFile, final boolean preserveRoot) {
 1436 |     if (preserveRoot) {
 1437 |       final String parentName = sourceDir.getName();
 1438 |       pack(sourceDir, targetZipFile, new NameMapper() {
 1439 |         public String map(String name) {
 1440 |           return parentName + PATH_SEPARATOR + name;
 1441 |         }
 1442 |       });
 1443 |     }
 1444 |     else {
 1445 |       pack(sourceDir, targetZipFile);
 1446 |     }
 1447 |   }
 1448 | 
 1449 |   /**
 1450 |    * Compresses the given file into a ZIP file.

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1416 |    *          compression level
 1417 |    */
 1418 |   public static void pack(File rootDir, File zip, int compressionLevel) {
 1419 |     pack(rootDir, zip, IdentityNameMapper.INSTANCE, compressionLevel);
 1420 |   }
 1421 | 
 1422 |   /**
 1423 |    * Compresses the given directory and all its sub-directories into a ZIP file.

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper)>
file: org/zeroturnaround/zip/ZipUtil.java
 1599 |    *          call-back for renaming the entries.
 1600 |    */
 1601 |   public static void pack(File sourceDir, File targetZip, NameMapper mapper) {
 1602 |     pack(sourceDir, targetZip, mapper, DEFAULT_COMPRESSION_LEVEL);
 1603 |   }
 1604 | 
 1605 |   /**
 1606 |    * Compresses the given directory and all its sub-directories into a ZIP file.

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1617 |    *          compression level
 1618 |    */
 1619 |   public static void pack(File sourceDir, File targetZip, NameMapper mapper, int compressionLevel) {
 1620 |     log.debug("Compressing '{}' into '{}'.", sourceDir, targetZip);
 1621 |     if (!sourceDir.exists()) {
 1622 |       throw new ZipException("Given file '" + sourceDir + "' doesn't exist!");
 1623 |     }
 1624 |     ZipOutputStream out = null;
 1625 |     try {
 1626 |       out = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(targetZip)));
 1627 |       out.setLevel(compressionLevel);
 1628 |       pack(sourceDir, out, mapper, "", true);
 1629 |     }
 1630 |     catch (IOException e) {
 1631 |       throw ZipExceptionUtil.rethrow(e);
 1632 |     }
 1633 |     finally {
 1634 |       IOUtils.closeQuietly(out);
 1635 |     }
 1636 |   }
 1637 | 
 1638 |   /**
 1639 |    * Compresses the given directory and all of its sub-directories into the passed in
```

---

## 30/97 flow_id 48c4911853 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 48c4911853
key        : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1150/result => <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>@L75/1
source     : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[3@L1150] %v7 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>[15@L75] invokespecial result.<init>(parent, %v16)/1
fixed methods on this flow (GT): Unpacker.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>, <org.zeroturnaround.zip.commons.FileUtils: void copy(java.io.InputStream,java.io.File)>

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
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

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

## 31/97 flow_id 0f7748a144 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 0f7748a144
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1277/result => <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>@L75/1
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1277] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>[15@L75] invokespecial result.<init>(parent, %v16)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

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

## 32/97 flow_id 486017d526 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 486017d526
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1285/result => <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>@L75/1
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[25@L1285] %v24 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>[15@L75] invokespecial result.<init>(parent, %v16)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>

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
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

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

## 33/97 flow_id 225ad7f353 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 225ad7f353
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1285/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>@L1081/1
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[25@L1285] %v24 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>[18@L1081] invokespecial %v11.<init>(canonicalDir, %v12)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>

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
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

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
```

---

## 34/97 flow_id 589b4f080d (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 589b4f080d
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1277/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>@L584/1
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1277] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>[78@L584] invokespecial copiedFile.<init>(destDir, %v59)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

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

## 35/97 flow_id f5658328da (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow f5658328da
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1285/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>@L584/1
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[25@L1285] %v24 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>[78@L584] invokespecial copiedFile.<init>(destDir, %v59)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

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
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: java.lang.String getUnrootedName(java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());
 1314 |     }
 1315 | 
 1316 |     private String getRootName(final String name) {

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

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

## 36/97 flow_id 13f0585a90 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 13f0585a90
key        : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1150/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFileToDirectory(java.io.File,java.io.File,boolean)>@L327/1
source     : <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[3@L1150] %v7 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFileToDirectory(java.io.File,java.io.File,boolean)>[23@L327] invokespecial destFile.<init>(destDir, %v19)/1
fixed methods on this flow (GT): Unpacker.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtils: void copy(java.io.InputStream,java.io.File)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFileToDirectory(java.io.File,java.io.File,boolean)>

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
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

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

## 37/97 flow_id 971ab7d686 (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 971ab7d686
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1277/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>@L623/1
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1277] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>[65@L623] invokespecial dstFile.<init>(destDir, %v52)/1
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

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

## 38/97 flow_id 8f06d02e2f (priority 1)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 8f06d02e2f
key        : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1277/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>@L428/0
source     : <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L1277] %v6 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>[24@L428] invokespecial %v26.<init>(destFile)/0
fixed methods on this flow (GT): Unwraper.process
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: boolean operateInPlace(java.io.File,org.zeroturnaround.zip.ZipUtil$InPlaceAction)>, <org.zeroturnaround.zip.ZipUtil: boolean replaceEntries(java.io.File,org.zeroturnaround.zip.ZipEntrySource[])>, <org.zeroturnaround.zip.ZipUtil: boolean replaceEntry(java.io.File,java.lang.String,byte[])>, <org.zeroturnaround.zip.ZipUtil: boolean replaceEntry(java.io.File,java.lang.String,byte[],int)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

### <org.zeroturnaround.zip.ZipUtil: boolean operateInPlace(java.io.File,org.zeroturnaround.zip.ZipUtil$InPlaceAction)>
file: org/zeroturnaround/zip/ZipUtil.java
 3325 |    * @return result of the action
 3326 |    */
 3327 |   private static boolean operateInPlace(File src, InPlaceAction action) {
 3328 |     File tmp = null;
 3329 |     try {
 3330 |       tmp = File.createTempFile("zt-zip-tmp", ".zip");
 3331 |       boolean result = action.act(tmp);
 3332 |       if (result) { // else nothing changes
 3333 |         FileUtils.forceDelete(src);
 3334 |         FileUtils.moveFile(tmp, src);
 3335 |       }
 3336 |       return result;
 3337 |     }
 3338 |     catch (IOException e) {
 3339 |       throw ZipExceptionUtil.rethrow(e);
 3340 |     }
 3341 |     finally {
 3342 |       FileUtils.deleteQuietly(tmp);
 3343 |     }
 3344 |   }
 3345 | 
 3346 | }

### <org.zeroturnaround.zip.ZipUtil: boolean replaceEntries(java.io.File,org.zeroturnaround.zip.ZipEntrySource[])>
file: org/zeroturnaround/zip/ZipUtil.java
 2641 |    * @return <code>true</code> if at least one entry was replaced.
 2642 |    */
 2643 |   public static boolean replaceEntries(final File zip, final ZipEntrySource[] entries) {
 2644 |     return operateInPlace(zip, new InPlaceAction() {
 2645 |       public boolean act(File tmpFile) {
 2646 |         return replaceEntries(zip, entries, tmpFile);
 2647 |       }

### <org.zeroturnaround.zip.ZipUtil: boolean replaceEntry(java.io.File,java.lang.String,byte[])>
file: org/zeroturnaround/zip/ZipUtil.java
 2521 |    * @return <code>true</code> if the entry was replaced.
 2522 |    */
 2523 |   public static boolean replaceEntry(final File zip, final String path, final byte[] bytes) {
 2524 |     return operateInPlace(zip, new InPlaceAction() {
 2525 |       public boolean act(File tmpFile) {
 2526 |         return replaceEntry(zip, new ByteSource(path, bytes), tmpFile);
 2527 |       }

### <org.zeroturnaround.zip.ZipUtil: boolean replaceEntry(java.io.File,java.lang.String,byte[],int)>
file: org/zeroturnaround/zip/ZipUtil.java
 2543 |    */
 2544 |   public static boolean replaceEntry(final File zip, final String path, final byte[] bytes,
 2545 |       final int compressionMethod) {
 2546 |     return operateInPlace(zip, new InPlaceAction() {
 2547 |       public boolean act(File tmpFile) {
 2548 |         return replaceEntry(zip, new ByteSource(path, bytes, compressionMethod), tmpFile);
 2549 |       }

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

## 39/97 flow_id aec1d02d52 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow aec1d02d52
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.InputStream,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>@L715/result => <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>@L57/0
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.InputStream,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>[12@L715] %v14 = invokevirtual entry.getName()/result
sink       : <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>[9@L57] invokespecial file.<init>(dir, %v11)/0
fixed methods on this flow (GT): -
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZTFileUtil: java.util.Collection listFiles(java.io.File)>, <org.zeroturnaround.zip.ZTFileUtil: java.util.Collection listFiles(java.io.File,java.io.FileFilter)>, <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>, <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.InputStream,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>

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

## 40/97 flow_id 2036eec71b (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 2036eec71b
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

## 41/97 flow_id 89d5183538 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 89d5183538
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipInfoCallback)>@L629/result => <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>@L57/1
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipInfoCallback)>[18@L629] %v18 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>[9@L57] invokespecial file.<init>(dir, %v11)/1
fixed methods on this flow (GT): -
reported by: B2 run0, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>, <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipInfoCallback)>

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
```

---

## 42/97 flow_id cc5044c871 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow cc5044c871
key        : DRIVER => <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>@L57/1
source     : <nesy.NesyDriver: void main(java.lang.String[])>[86@L28] %v49 = invokestatic nesy.Taint.srcFile()/result
sink       : <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>[9@L57] invokespecial file.<init>(dir, %v11)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZTFileUtil: void innerListFiles(java.io.File,java.util.Collection,java.io.FileFilter)>

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
```

---

## 43/97 flow_id 1eec8baf4d (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 1eec8baf4d
key        : <org.apache.log4j.helpers.Loader: java.lang.Class loadClass(java.lang.String)>@L182/0 => <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1223/1
source     : <org.apache.log4j.helpers.Loader: java.lang.Class loadClass(java.lang.String)>[5@L182] %v15 = invokestatic java.lang.Class.forName(clazz)/0
sink       : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[19@L1223] invokespecial file.<init>(parentDirectory, %v22)/1
fixed methods on this flow (GT): -
reported by: v1 run1, v2 run1

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**
```

---

## 44/97 flow_id e2bf0cc685 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow e2bf0cc685
key        : <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2372/result => <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1223/1
source     : <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L2372] entryName = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[19@L1223] invokespecial file.<init>(parentDirectory, %v22)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2369 |     final Set<String> names = new HashSet<String>();
 2370 |     iterate(is, new ZipEntryCallback() {
 2371 |       public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2372 |         String entryName = zipEntry.getName();
 2373 |         if (names.add(entryName)) {
 2374 |           ZipEntryUtil.copyEntry(zipEntry, in, out);
 2375 |         }
 2376 |         else if (log.isDebugEnabled()) {
 2377 |           log.debug("Duplicate entry: {}", entryName);
 2378 |         }
 2379 |       }
 2380 |     });
 2381 |   }
 2382 | 

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**
```

---

## 45/97 flow_id 46c111998a (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 46c111998a
key        : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2675/result => <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1223/1
source     : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2675] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[19@L1223] invokespecial file.<init>(parentDirectory, %v22)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2672 |         final Set<String> names = new HashSet<String>();
 2673 |         iterate(zip, new ZipEntryCallback() {
 2674 |           public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2675 |             if (names.add(zipEntry.getName())) {
 2676 |               ZipEntrySource entry = (ZipEntrySource) entryByPath.remove(zipEntry.getName());
 2677 |               if (entry != null) {
 2678 |                 addEntry(entry, out);
 2679 |               }
 2680 |               else {
 2681 |                 ZipEntryUtil.copyEntry(zipEntry, in, out);
 2682 |               }
 2683 |             }
 2684 |             else if (log.isDebugEnabled()) {
 2685 |               log.debug("Duplicate entry: {}", zipEntry.getName());
 2686 |             }
 2687 |           }
 2688 |         });
 2689 | 
 2690 |         // Add new entries

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**
```

---

## 46/97 flow_id bdf21916fa (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow bdf21916fa
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>@L585/result => <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1223/1
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>[28@L585] %v25 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[19@L1223] invokespecial file.<init>(parentDirectory, %v22)/1
fixed methods on this flow (GT): -
reported by: B2 run0, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

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

## 47/97 flow_id a1a82c2378 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow a1a82c2378
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>@L511/result => <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1223/1
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>[25@L511] %v24 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[19@L1223] invokespecial file.<init>(parentDirectory, %v22)/1
fixed methods on this flow (GT): -
reported by: B2 run0, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

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

## 48/97 flow_id b8596bef63 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow b8596bef63
key        : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2675/result => <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1229/1
source     : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2675] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[30@L1229] invokespecial destFile.<init>(parentDirectory, %v27)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2672 |         final Set<String> names = new HashSet<String>();
 2673 |         iterate(zip, new ZipEntryCallback() {
 2674 |           public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2675 |             if (names.add(zipEntry.getName())) {
 2676 |               ZipEntrySource entry = (ZipEntrySource) entryByPath.remove(zipEntry.getName());
 2677 |               if (entry != null) {
 2678 |                 addEntry(entry, out);
 2679 |               }
 2680 |               else {
 2681 |                 ZipEntryUtil.copyEntry(zipEntry, in, out);
 2682 |               }
 2683 |             }
 2684 |             else if (log.isDebugEnabled()) {
 2685 |               log.debug("Duplicate entry: {}", zipEntry.getName());
 2686 |             }
 2687 |           }
 2688 |         });
 2689 | 
 2690 |         // Add new entries

### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**
```

---

## 49/97 flow_id a30bdeed5f (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow a30bdeed5f
key        : <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2927/result => <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1229/1
source     : <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2927] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[30@L1229] invokespecial destFile.<init>(parentDirectory, %v27)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2924 |     }
 2925 | 
 2926 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2927 |       if (names.add(zipEntry.getName())) {
 2928 |         ZipEntryTransformer entry = (ZipEntryTransformer) entryByPath.remove(zipEntry.getName());
 2929 |         if (entry != null) {
 2930 |           entry.transform(in, zipEntry, out);
 2931 |         }
 2932 |         else {
 2933 |           ZipEntryUtil.copyEntry(zipEntry, in, out);
 2934 |         }
 2935 |       }
 2936 |       else if (log.isDebugEnabled()) {
 2937 |         log.debug("Duplicate entry: {}", zipEntry.getName());
 2938 |       }
 2939 |     }
 2940 | 
 2941 |     /**
 2942 |      * @return <code>true</code> if at least one entry was replaced.
```

---

## 50/97 flow_id 3781e84698 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 3781e84698
key        : <org.zeroturnaround.zip.ZipUtil$10: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2348/result => <org.zeroturnaround.zip.ZipUtil$RepackZipEntryCallback: void <init>(java.io.File,int)>@L1884/0
source     : <org.zeroturnaround.zip.ZipUtil$10: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L2348] entryName = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil$RepackZipEntryCallback: void <init>(java.io.File,int)>[4@L1884] invokespecial %v6.<init>(dstZip)/0
fixed methods on this flow (GT): -
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$10: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$RepackZipEntryCallback: void <init>(java.io.File,int)>, <org.zeroturnaround.zip.ZipUtil$RepackZipEntryCallback: void <init>(java.io.File,int,org.zeroturnaround.zip.ZipUtil$1)>, <org.zeroturnaround.zip.ZipUtil: void repack(java.io.File,java.io.File,int)>, <org.zeroturnaround.zip.ZipUtil: void repack(java.io.InputStream,java.io.File,int)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$10: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2345 |     final Set<String> names = new HashSet<String>();
 2346 |     iterate(zip, new ZipEntryCallback() {
 2347 |       public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2348 |         String entryName = zipEntry.getName();
 2349 |         if (names.add(entryName)) {
 2350 |           ZipEntryUtil.copyEntry(zipEntry, in, out);
 2351 |         }
 2352 |         else if (log.isDebugEnabled()) {
 2353 |           log.debug("Duplicate entry: {}", entryName);
 2354 |         }
 2355 |       }
 2356 |     });
 2357 |   }
 2358 | 

### <org.zeroturnaround.zip.ZipUtil$RepackZipEntryCallback: void <init>(java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1879 | 
 1880 |     private ZipOutputStream out;
 1881 | 
 1882 |     private RepackZipEntryCallback(File dstZip, int compressionLevel) {
 1883 |       try {
 1884 |         this.out = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(dstZip)));
 1885 |         this.out.setLevel(compressionLevel);
 1886 |       }
 1887 |       catch (IOException e) {
 1888 |         ZipExceptionUtil.rethrow(e);
 1889 |       }
 1890 |     }
 1891 | 
 1892 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1893 |       ZipEntryUtil.copyEntry(zipEntry, in, out);

### <org.zeroturnaround.zip.ZipUtil$RepackZipEntryCallback: void <init>(java.io.File,int,org.zeroturnaround.zip.ZipUtil$1)>
file: org/zeroturnaround/zip/ZipUtil.java
 1875 |    *
 1876 |    * @author Pavel Grigorenko
 1877 |    */
 1878 |   private static final class RepackZipEntryCallback implements ZipEntryCallback {
 1879 | 
 1880 |     private ZipOutputStream out;
 1881 | 

### <org.zeroturnaround.zip.ZipUtil: void repack(java.io.File,java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1805 |    */
 1806 |   public static void repack(File srcZip, File dstZip, int compressionLevel) {
 1807 | 
 1808 |     log.debug("Repacking '{}' into '{}'.", srcZip, dstZip);
 1809 | 
 1810 |     RepackZipEntryCallback callback = new RepackZipEntryCallback(dstZip, compressionLevel);
 1811 | 
 1812 |     try {
 1813 |       iterate(srcZip, callback);
 1814 |     }
 1815 |     finally {
 1816 |       callback.closeStream();
 1817 |     }
 1818 |   }
 1819 | 
 1820 |   /**
 1821 |    * Repacks a provided ZIP input stream into a ZIP file with a given compression level.

### <org.zeroturnaround.zip.ZipUtil: void repack(java.io.InputStream,java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1830 |    */
 1831 |   public static void repack(InputStream is, File dstZip, int compressionLevel) {
 1832 | 
 1833 |     log.debug("Repacking from input stream into '{}'.", dstZip);
 1834 | 
 1835 |     RepackZipEntryCallback callback = new RepackZipEntryCallback(dstZip, compressionLevel);
 1836 | 
 1837 |     try {
 1838 |       iterate(is, callback);
 1839 |     }
 1840 |     finally {
 1841 |       callback.closeStream();
 1842 |     }
 1843 |   }
 1844 | 
 1845 |   /**
 1846 |    * Repacks a provided ZIP file and replaces old file with the new one.
```

---

## 51/97 flow_id ed4c6d6935 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow ed4c6d6935
key        : DRIVER => <org.zeroturnaround.zip.ZipUtil$RepackZipEntryCallback: void <init>(java.io.File,int)>@L1884/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[86@L28] %v49 = invokestatic nesy.Taint.srcFile()/result
sink       : <org.zeroturnaround.zip.ZipUtil$RepackZipEntryCallback: void <init>(java.io.File,int)>[4@L1884] invokespecial %v6.<init>(dstZip)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$RepackZipEntryCallback: void <init>(java.io.File,int)>, <org.zeroturnaround.zip.ZipUtil$RepackZipEntryCallback: void <init>(java.io.File,int,org.zeroturnaround.zip.ZipUtil$1)>, <org.zeroturnaround.zip.ZipUtil: void repack(java.io.File,java.io.File,int)>, <org.zeroturnaround.zip.ZipUtil: void repack(java.io.InputStream,java.io.File,int)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$RepackZipEntryCallback: void <init>(java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1879 | 
 1880 |     private ZipOutputStream out;
 1881 | 
 1882 |     private RepackZipEntryCallback(File dstZip, int compressionLevel) {
 1883 |       try {
 1884 |         this.out = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(dstZip)));
 1885 |         this.out.setLevel(compressionLevel);
 1886 |       }
 1887 |       catch (IOException e) {
 1888 |         ZipExceptionUtil.rethrow(e);
 1889 |       }
 1890 |     }
 1891 | 
 1892 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1893 |       ZipEntryUtil.copyEntry(zipEntry, in, out);

### <org.zeroturnaround.zip.ZipUtil$RepackZipEntryCallback: void <init>(java.io.File,int,org.zeroturnaround.zip.ZipUtil$1)>
file: org/zeroturnaround/zip/ZipUtil.java
 1875 |    *
 1876 |    * @author Pavel Grigorenko
 1877 |    */
 1878 |   private static final class RepackZipEntryCallback implements ZipEntryCallback {
 1879 | 
 1880 |     private ZipOutputStream out;
 1881 | 

### <org.zeroturnaround.zip.ZipUtil: void repack(java.io.File,java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1805 |    */
 1806 |   public static void repack(File srcZip, File dstZip, int compressionLevel) {
 1807 | 
 1808 |     log.debug("Repacking '{}' into '{}'.", srcZip, dstZip);
 1809 | 
 1810 |     RepackZipEntryCallback callback = new RepackZipEntryCallback(dstZip, compressionLevel);
 1811 | 
 1812 |     try {
 1813 |       iterate(srcZip, callback);
 1814 |     }
 1815 |     finally {
 1816 |       callback.closeStream();
 1817 |     }
 1818 |   }
 1819 | 
 1820 |   /**
 1821 |    * Repacks a provided ZIP input stream into a ZIP file with a given compression level.

### <org.zeroturnaround.zip.ZipUtil: void repack(java.io.InputStream,java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1830 |    */
 1831 |   public static void repack(InputStream is, File dstZip, int compressionLevel) {
 1832 | 
 1833 |     log.debug("Repacking from input stream into '{}'.", dstZip);
 1834 | 
 1835 |     RepackZipEntryCallback callback = new RepackZipEntryCallback(dstZip, compressionLevel);
 1836 | 
 1837 |     try {
 1838 |       iterate(is, callback);
 1839 |     }
 1840 |     finally {
 1841 |       callback.closeStream();
 1842 |     }
 1843 |   }
 1844 | 
 1845 |   /**
 1846 |    * Repacks a provided ZIP file and replaces old file with the new one.
```

---

## 52/97 flow_id 674ed49a39 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 674ed49a39
key        : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>@L313/result => <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>@L3068/0
source     : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>[9@L313] o = invokeinterface elems.nextElement()/result
sink       : <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>[37@L3068] e2 = invokevirtual zf2.getEntry(path)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2
N3 (iris-like run2): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 3039 |   }
 3040 | 
 3041 |   private static boolean archiveEqualsInternal(File f1, File f2) throws IOException {
 3042 |     ZipFile zf1 = null;
 3043 |     ZipFile zf2 = null;
 3044 |     try {
 3045 |       zf1 = new ZipFile(f1);
 3046 |       zf2 = new ZipFile(f2);
 3047 | 
 3048 |       // Check the number of entries
 3049 |       if (zf1.size() != zf2.size()) {
 3050 |         log.debug("Number of entries changed (" + zf1.size() + " vs " + zf2.size() + ").");
 3051 |         return false;
 3052 |       }
 3053 |       /*
 3054 |        * As there are same number of entries in both archives we can traverse
 3055 |        * all entries of one of the archives and get the corresponding entries
 3056 |        * from the other archive.
 3057 |        *
 3058 |        * If a corresponding entry is missing from the second archive the
 3059 |        * archives are different and we finish the comparison.
 3060 |        *
 3061 |        * We guarantee that no entry of the second archive is skipped as there
 3062 |        * are same number of unique entries in both archives.
 3063 |        */
 3064 |       Enumeration<? extends ZipEntry> en = zf1.entries();
 3065 |       while (en.hasMoreElements()) {
 3066 |         ZipEntry e1 = (ZipEntry) en.nextElement();
 3067 |         String path = e1.getName();
 3068 |         ZipEntry e2 = zf2.getEntry(path);
      | ... (lines omitted) ...
 3074 | 
 3075 |         // Check the content
 3076 |         InputStream is1 = null;
 3077 |         InputStream is2 = null;
 3078 |         try {
 3079 |           is1 = zf1.getInputStream(e1);
 3080 |           is2 = zf2.getInputStream(e2);
 3081 | 
 3082 |           if (!IOUtils.contentEquals(is1, is2)) {
 3083 |             log.debug("Entry '{}' content changed.", path);
 3084 |             return false;
 3085 |           }
 3086 |         }
 3087 |         finally {
 3088 |           IOUtils.closeQuietly(is1);
 3089 |           IOUtils.closeQuietly(is2);
 3090 |         }
 3091 |       }
 3092 |     }
 3093 |     finally {
 3094 |       closeQuietly(zf1);
 3095 |       closeQuietly(zf2);
 3096 |     }
 3097 | 
 3098 |     log.debug("Archives are the same.");
 3099 | 
 3100 |     return true;
 3101 |   }
 3102 | 
 3103 |   /**
```

---

## 53/97 flow_id 5381f82b34 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 5381f82b34
key        : <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>@L2440/result => <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>@L3068/0
source     : <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>[18@L2440] %v18 = invokevirtual entry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>[37@L3068] e2 = invokevirtual zf2.getEntry(path)/0
fixed methods on this flow (GT): -
reported by: v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>, <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 3039 |   }
 3040 | 
 3041 |   private static boolean archiveEqualsInternal(File f1, File f2) throws IOException {
 3042 |     ZipFile zf1 = null;
 3043 |     ZipFile zf2 = null;
 3044 |     try {
 3045 |       zf1 = new ZipFile(f1);
 3046 |       zf2 = new ZipFile(f2);
 3047 | 
 3048 |       // Check the number of entries
 3049 |       if (zf1.size() != zf2.size()) {
 3050 |         log.debug("Number of entries changed (" + zf1.size() + " vs " + zf2.size() + ").");
 3051 |         return false;
 3052 |       }
 3053 |       /*
 3054 |        * As there are same number of entries in both archives we can traverse
 3055 |        * all entries of one of the archives and get the corresponding entries
 3056 |        * from the other archive.
 3057 |        *
 3058 |        * If a corresponding entry is missing from the second archive the
 3059 |        * archives are different and we finish the comparison.
 3060 |        *
 3061 |        * We guarantee that no entry of the second archive is skipped as there
 3062 |        * are same number of unique entries in both archives.
 3063 |        */
 3064 |       Enumeration<? extends ZipEntry> en = zf1.entries();
 3065 |       while (en.hasMoreElements()) {
 3066 |         ZipEntry e1 = (ZipEntry) en.nextElement();
 3067 |         String path = e1.getName();
 3068 |         ZipEntry e2 = zf2.getEntry(path);
      | ... (lines omitted) ...
 3074 | 
 3075 |         // Check the content
 3076 |         InputStream is1 = null;
 3077 |         InputStream is2 = null;
 3078 |         try {
 3079 |           is1 = zf1.getInputStream(e1);
 3080 |           is2 = zf2.getInputStream(e2);
 3081 | 
 3082 |           if (!IOUtils.contentEquals(is1, is2)) {
 3083 |             log.debug("Entry '{}' content changed.", path);
 3084 |             return false;
 3085 |           }
 3086 |         }
 3087 |         finally {
 3088 |           IOUtils.closeQuietly(is1);
 3089 |           IOUtils.closeQuietly(is2);
 3090 |         }
 3091 |       }
 3092 |     }
 3093 |     finally {
 3094 |       closeQuietly(zf1);
 3095 |       closeQuietly(zf2);
 3096 |     }
 3097 | 
 3098 |     log.debug("Archives are the same.");
 3099 | 
 3100 |     return true;
 3101 |   }
 3102 | 
 3103 |   /**

### <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>
file: org/zeroturnaround/zip/ZipUtil.java
 2426 |    *
 2427 |    */
 2428 |   static Set<String> filterDirEntries(File zip, Collection<String> names) {
 2429 |     Set<String> dirs = new HashSet<String>();
 2430 |     if (zip == null) {
 2431 |       return dirs;
 2432 |     }
 2433 |     ZipFile zf = null;
 2434 |     try {
 2435 |       zf = new ZipFile(zip);
 2436 |       for (String entryName : names) {
 2437 |         ZipEntry entry = zf.getEntry(entryName);
 2438 |         if (entry != null) {
 2439 |           if (entry.isDirectory()) {
 2440 |             dirs.add(entry.getName());
 2441 |           }
 2442 |           else if (zf.getInputStream(entry) == null) {
 2443 |             // no input stream means that this is a dir.
 2444 |             dirs.add(entry.getName() + PATH_SEPARATOR);
 2445 |           }
 2446 |         }
 2447 |       }
 2448 | 
 2449 |     }
 2450 |     catch (IOException e) {
 2451 |       ZipExceptionUtil.rethrow(e);
 2452 |     }
 2453 |     finally {
 2454 |       closeQuietly(zf);
 2455 |     }
 2456 |     return dirs;
 2457 |   }
 2458 | 
 2459 |   /**
```

---

## 54/97 flow_id 816aa6cdd8 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 816aa6cdd8
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipInfoCallback)>@L629/result => <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>@L3068/0
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipInfoCallback)>[18@L629] %v18 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>[37@L3068] e2 = invokevirtual zf2.getEntry(path)/0
fixed methods on this flow (GT): -
reported by: v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>, <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipInfoCallback)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 3039 |   }
 3040 | 
 3041 |   private static boolean archiveEqualsInternal(File f1, File f2) throws IOException {
 3042 |     ZipFile zf1 = null;
 3043 |     ZipFile zf2 = null;
 3044 |     try {
 3045 |       zf1 = new ZipFile(f1);
 3046 |       zf2 = new ZipFile(f2);
 3047 | 
 3048 |       // Check the number of entries
 3049 |       if (zf1.size() != zf2.size()) {
 3050 |         log.debug("Number of entries changed (" + zf1.size() + " vs " + zf2.size() + ").");
 3051 |         return false;
 3052 |       }
 3053 |       /*
 3054 |        * As there are same number of entries in both archives we can traverse
 3055 |        * all entries of one of the archives and get the corresponding entries
 3056 |        * from the other archive.
 3057 |        *
 3058 |        * If a corresponding entry is missing from the second archive the
 3059 |        * archives are different and we finish the comparison.
 3060 |        *
 3061 |        * We guarantee that no entry of the second archive is skipped as there
 3062 |        * are same number of unique entries in both archives.
 3063 |        */
 3064 |       Enumeration<? extends ZipEntry> en = zf1.entries();
 3065 |       while (en.hasMoreElements()) {
 3066 |         ZipEntry e1 = (ZipEntry) en.nextElement();
 3067 |         String path = e1.getName();
 3068 |         ZipEntry e2 = zf2.getEntry(path);
      | ... (lines omitted) ...
 3074 | 
 3075 |         // Check the content
 3076 |         InputStream is1 = null;
 3077 |         InputStream is2 = null;
 3078 |         try {
 3079 |           is1 = zf1.getInputStream(e1);
 3080 |           is2 = zf2.getInputStream(e2);
 3081 | 
 3082 |           if (!IOUtils.contentEquals(is1, is2)) {
 3083 |             log.debug("Entry '{}' content changed.", path);
 3084 |             return false;
 3085 |           }
 3086 |         }
 3087 |         finally {
 3088 |           IOUtils.closeQuietly(is1);
 3089 |           IOUtils.closeQuietly(is2);
 3090 |         }
 3091 |       }
 3092 |     }
 3093 |     finally {
 3094 |       closeQuietly(zf1);
 3095 |       closeQuietly(zf2);
 3096 |     }
 3097 | 
 3098 |     log.debug("Archives are the same.");
 3099 | 
 3100 |     return true;
 3101 |   }
 3102 | 
 3103 |   /**

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
```

---

## 55/97 flow_id 64ea7b73e6 (priority 2)

Historical evidence: this sampled key is absent from the corrected run records; the original label is retained without re-adjudication.

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 64ea7b73e6
key        : DRIVER => <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>@L3080/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[86@L28] %v49 = invokestatic nesy.Taint.srcFile()/result
sink       : <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>[46@L3080] is2 = invokevirtual zf2.getInputStream(e2)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2
N3 (iris-like run2): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 3039 |   }
 3040 | 
 3041 |   private static boolean archiveEqualsInternal(File f1, File f2) throws IOException {
 3042 |     ZipFile zf1 = null;
 3043 |     ZipFile zf2 = null;
 3044 |     try {
 3045 |       zf1 = new ZipFile(f1);
 3046 |       zf2 = new ZipFile(f2);
 3047 | 
 3048 |       // Check the number of entries
 3049 |       if (zf1.size() != zf2.size()) {
 3050 |         log.debug("Number of entries changed (" + zf1.size() + " vs " + zf2.size() + ").");
 3051 |         return false;
 3052 |       }
 3053 |       /*
 3054 |        * As there are same number of entries in both archives we can traverse
 3055 |        * all entries of one of the archives and get the corresponding entries
 3056 |        * from the other archive.
 3057 |        *
 3058 |        * If a corresponding entry is missing from the second archive the
 3059 |        * archives are different and we finish the comparison.
 3060 |        *
 3061 |        * We guarantee that no entry of the second archive is skipped as there
 3062 |        * are same number of unique entries in both archives.
 3063 |        */
 3064 |       Enumeration<? extends ZipEntry> en = zf1.entries();
 3065 |       while (en.hasMoreElements()) {
 3066 |         ZipEntry e1 = (ZipEntry) en.nextElement();
 3067 |         String path = e1.getName();
 3068 |         ZipEntry e2 = zf2.getEntry(path);
      | ... (lines omitted) ...
 3074 | 
 3075 |         // Check the content
 3076 |         InputStream is1 = null;
 3077 |         InputStream is2 = null;
 3078 |         try {
 3079 |           is1 = zf1.getInputStream(e1);
 3080 |           is2 = zf2.getInputStream(e2);
 3081 | 
 3082 |           if (!IOUtils.contentEquals(is1, is2)) {
 3083 |             log.debug("Entry '{}' content changed.", path);
 3084 |             return false;
 3085 |           }
 3086 |         }
 3087 |         finally {
 3088 |           IOUtils.closeQuietly(is1);
 3089 |           IOUtils.closeQuietly(is2);
 3090 |         }
 3091 |       }
 3092 |     }
 3093 |     finally {
 3094 |       closeQuietly(zf1);
 3095 |       closeQuietly(zf2);
 3096 |     }
 3097 | 
 3098 |     log.debug("Archives are the same.");
 3099 | 
 3100 |     return true;
 3101 |   }
 3102 | 
 3103 |   /**
```

---

## 56/97 flow_id a0e82dbb88 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow a0e82dbb88
key        : DRIVER => <org.zeroturnaround.zip.ZipUtil: boolean containsAnyEntry(java.io.File,java.lang.String[])>@L160/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[442@L90] %v277 = invokestatic nesy.Taint.src()/result
sink       : <org.zeroturnaround.zip.ZipUtil: boolean containsAnyEntry(java.io.File,java.lang.String[])>[10@L160] %v10 = invokevirtual zf.getEntry(%v9)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2
N3 (iris-like run2): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[442@L90] %v277 = invokestatic nesy.Taint.src()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v277}
3. ArrayIndexNode{NewObj{<nesy.NesyDriver: void main(java.lang.String[])>[441@L90] newarray java.lang.String[%ci1]}}
4. VarNode{<org.zeroturnaround.zip.ZipUtil: boolean containsAnyEntry(java.io.File,java.lang.String[])>/%v9}
5. <org.zeroturnaround.zip.ZipUtil: boolean containsAnyEntry(java.io.File,java.lang.String[])>[10@L160] %v10 = invokevirtual zf.getEntry(%v9)/0

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: boolean containsAnyEntry(java.io.File,java.lang.String[])>
file: org/zeroturnaround/zip/ZipUtil.java
  153 |    *         entries.
  154 |    */
  155 |   public static boolean containsAnyEntry(File zip, String[] names) {
  156 |     ZipFile zf = null;
  157 |     try {
  158 |       zf = new ZipFile(zip);
  159 |       for (int i = 0; i < names.length; i++) {
  160 |         if (zf.getEntry(names[i]) != null) {
  161 |           return true;
  162 |         }
  163 |       }
  164 |       return false;
  165 |     }
  166 |     catch (IOException e) {
  167 |       throw ZipExceptionUtil.rethrow(e);
  168 |     }
  169 |     finally {
  170 |       closeQuietly(zf);
  171 |     }
  172 |   }
  173 | 
  174 |   /**
```

---

## 57/97 flow_id eaf27d2dab (priority 2)

Historical evidence: this sampled key is absent from the corrected run records; the original label is retained without re-adjudication.

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow eaf27d2dab
key        : DRIVER => <org.zeroturnaround.zip.ZipUtil: boolean doEntryEquals(java.util.zip.ZipFile,java.util.zip.ZipFile,java.lang.String,java.lang.String)>@L3270/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[264@L107] %v166 = invokestatic nesy.Taint.src()/result
sink       : <org.zeroturnaround.zip.ZipUtil: boolean doEntryEquals(java.util.zip.ZipFile,java.util.zip.ZipFile,java.lang.String,java.lang.String)>[16@L3270] is1 = invokevirtual zf1.getInputStream(e1)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2, v2 run2, v3 run2, v3-noV2 run2, v3-noV3 run2, v3-noval run2, v4 run2
N3 (v3 run2): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[264@L107] %v166 = invokestatic nesy.Taint.src()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v166}
3. VarNode{<org.zeroturnaround.zip.ZipUtil: boolean entryEquals(java.io.File,java.io.File,java.lang.String)>/path}
4. VarNode{<org.zeroturnaround.zip.ZipUtil: boolean entryEquals(java.io.File,java.io.File,java.lang.String,java.lang.String)>/path1}
5. VarNode{<org.zeroturnaround.zip.ZipUtil: boolean doEntryEquals(java.util.zip.ZipFile,java.util.zip.ZipFile,java.lang.String,java.lang.String)>/path1}
6. VarNode{<org.zeroturnaround.zip.ZipUtil: boolean doEntryEquals(java.util.zip.ZipFile,java.util.zip.ZipFile,java.lang.String,java.lang.String)>/e1}
7. <org.zeroturnaround.zip.ZipUtil: boolean doEntryEquals(java.util.zip.ZipFile,java.util.zip.ZipFile,java.lang.String,java.lang.String)>[16@L3270] is1 = invokevirtual zf1.getInputStream(e1)/0

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: boolean entryEquals(java.io.File,java.io.File,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 3182 |    *         files.
 3183 |    */
 3184 |   public static boolean entryEquals(File f1, File f2, String path) {
 3185 |     return entryEquals(f1, f2, path, path);
 3186 |   }
 3187 | 
 3188 |   /**

### <org.zeroturnaround.zip.ZipUtil: boolean entryEquals(java.io.File,java.io.File,java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 3199 |    * @return <code>true</code> if the contents of the entries were same.
 3200 |    */
 3201 |   public static boolean entryEquals(File f1, File f2, String path1, String path2) {
 3202 |     ZipFile zf1 = null;
 3203 |     ZipFile zf2 = null;
 3204 | 
 3205 |     try {
 3206 |       zf1 = new ZipFile(f1);
 3207 |       zf2 = new ZipFile(f2);
 3208 | 
 3209 |       return doEntryEquals(zf1, zf2, path1, path2);
 3210 |     }
 3211 |     catch (IOException e) {
 3212 |       throw ZipExceptionUtil.rethrow(e);
 3213 |     }
 3214 |     finally {
 3215 |       closeQuietly(zf1);
 3216 |       closeQuietly(zf2);
 3217 |     }
 3218 |   }
 3219 | 
 3220 |   /**

### <org.zeroturnaround.zip.ZipUtil: boolean doEntryEquals(java.util.zip.ZipFile,java.util.zip.ZipFile,java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 3253 |    * @return <code>true</code> if the contents of the entries were same.
 3254 |    */
 3255 |   private static boolean doEntryEquals(ZipFile zf1, ZipFile zf2, String path1, String path2) throws IOException {
 3256 |     InputStream is1 = null;
 3257 |     InputStream is2 = null;
 3258 |     try {
 3259 |       ZipEntry e1 = zf1.getEntry(path1);
 3260 |       ZipEntry e2 = zf2.getEntry(path2);
 3261 | 
 3262 |       if (e1 == null && e2 == null) {
 3263 |         return true;
 3264 |       }
 3265 | 
 3266 |       if (e1 == null || e2 == null) {
 3267 |         return false;
 3268 |       }
 3269 | 
 3270 |       is1 = zf1.getInputStream(e1);
 3271 |       is2 = zf2.getInputStream(e2);
 3272 |       if (is1 == null && is2 == null) {
 3273 |         return true;
 3274 |       }
 3275 |       if (is1 == null || is2 == null) {
 3276 |         return false;
 3277 |       }
 3278 | 
 3279 |       return IOUtils.contentEquals(is1, is2);
 3280 |     }
 3281 |     finally {
 3282 |       IOUtils.closeQuietly(is1);
 3283 |       IOUtils.closeQuietly(is2);
 3284 |     }
 3285 |   }
 3286 | 
 3287 |   /**
```

---

## 58/97 flow_id 855c323cc8 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 855c323cc8
key        : DRIVER => <org.zeroturnaround.zip.ZipUtil: boolean doEntryEquals(java.util.zip.ZipFile,java.util.zip.ZipFile,java.lang.String,java.lang.String)>@L3259/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[264@L107] %v166 = invokestatic nesy.Taint.src()/result
sink       : <org.zeroturnaround.zip.ZipUtil: boolean doEntryEquals(java.util.zip.ZipFile,java.util.zip.ZipFile,java.lang.String,java.lang.String)>[4@L3259] e1 = invokevirtual zf1.getEntry(path1)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2, v2 run2, v3 run2, v3-noV2 run2, v3-noV3 run2, v3-noval run2, v4 run2
N3 (v3 run2): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[264@L107] %v166 = invokestatic nesy.Taint.src()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v166}
3. VarNode{<org.zeroturnaround.zip.ZipUtil: boolean entryEquals(java.io.File,java.io.File,java.lang.String)>/path}
4. VarNode{<org.zeroturnaround.zip.ZipUtil: boolean entryEquals(java.io.File,java.io.File,java.lang.String,java.lang.String)>/path1}
5. VarNode{<org.zeroturnaround.zip.ZipUtil: boolean doEntryEquals(java.util.zip.ZipFile,java.util.zip.ZipFile,java.lang.String,java.lang.String)>/path1}
6. <org.zeroturnaround.zip.ZipUtil: boolean doEntryEquals(java.util.zip.ZipFile,java.util.zip.ZipFile,java.lang.String,java.lang.String)>[4@L3259] e1 = invokevirtual zf1.getEntry(path1)/0

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: boolean entryEquals(java.io.File,java.io.File,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 3182 |    *         files.
 3183 |    */
 3184 |   public static boolean entryEquals(File f1, File f2, String path) {
 3185 |     return entryEquals(f1, f2, path, path);
 3186 |   }
 3187 | 
 3188 |   /**

### <org.zeroturnaround.zip.ZipUtil: boolean entryEquals(java.io.File,java.io.File,java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 3199 |    * @return <code>true</code> if the contents of the entries were same.
 3200 |    */
 3201 |   public static boolean entryEquals(File f1, File f2, String path1, String path2) {
 3202 |     ZipFile zf1 = null;
 3203 |     ZipFile zf2 = null;
 3204 | 
 3205 |     try {
 3206 |       zf1 = new ZipFile(f1);
 3207 |       zf2 = new ZipFile(f2);
 3208 | 
 3209 |       return doEntryEquals(zf1, zf2, path1, path2);
 3210 |     }
 3211 |     catch (IOException e) {
 3212 |       throw ZipExceptionUtil.rethrow(e);
 3213 |     }
 3214 |     finally {
 3215 |       closeQuietly(zf1);
 3216 |       closeQuietly(zf2);
 3217 |     }
 3218 |   }
 3219 | 
 3220 |   /**

### <org.zeroturnaround.zip.ZipUtil: boolean doEntryEquals(java.util.zip.ZipFile,java.util.zip.ZipFile,java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 3253 |    * @return <code>true</code> if the contents of the entries were same.
 3254 |    */
 3255 |   private static boolean doEntryEquals(ZipFile zf1, ZipFile zf2, String path1, String path2) throws IOException {
 3256 |     InputStream is1 = null;
 3257 |     InputStream is2 = null;
 3258 |     try {
 3259 |       ZipEntry e1 = zf1.getEntry(path1);
 3260 |       ZipEntry e2 = zf2.getEntry(path2);
 3261 | 
 3262 |       if (e1 == null && e2 == null) {
 3263 |         return true;
 3264 |       }
 3265 | 
 3266 |       if (e1 == null || e2 == null) {
 3267 |         return false;
 3268 |       }
 3269 | 
 3270 |       is1 = zf1.getInputStream(e1);
 3271 |       is2 = zf2.getInputStream(e2);
 3272 |       if (is1 == null && is2 == null) {
 3273 |         return true;
 3274 |       }
 3275 |       if (is1 == null || is2 == null) {
 3276 |         return false;
 3277 |       }
 3278 | 
 3279 |       return IOUtils.contentEquals(is1, is2);
 3280 |     }
 3281 |     finally {
 3282 |       IOUtils.closeQuietly(is1);
 3283 |       IOUtils.closeQuietly(is2);
 3284 |     }
 3285 |   }
 3286 | 
 3287 |   /**
```

---

## 59/97 flow_id 6fea35b91f (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 6fea35b91f
key        : DRIVER => <org.zeroturnaround.zip.ZipUtil: boolean doEntryEquals(java.util.zip.ZipFile,java.util.zip.ZipFile,java.lang.String,java.lang.String)>@L3260/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[264@L107] %v166 = invokestatic nesy.Taint.src()/result
sink       : <org.zeroturnaround.zip.ZipUtil: boolean doEntryEquals(java.util.zip.ZipFile,java.util.zip.ZipFile,java.lang.String,java.lang.String)>[5@L3260] e2 = invokevirtual zf2.getEntry(path2)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2, v2 run2, v3 run2, v3-noV2 run2, v3-noV3 run2, v3-noval run2, v4 run2
N3 (v3 run2): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[264@L107] %v166 = invokestatic nesy.Taint.src()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v166}
3. VarNode{<org.zeroturnaround.zip.ZipUtil: boolean entryEquals(java.io.File,java.io.File,java.lang.String)>/path}
4. VarNode{<org.zeroturnaround.zip.ZipUtil: boolean entryEquals(java.io.File,java.io.File,java.lang.String,java.lang.String)>/path2}
5. VarNode{<org.zeroturnaround.zip.ZipUtil: boolean doEntryEquals(java.util.zip.ZipFile,java.util.zip.ZipFile,java.lang.String,java.lang.String)>/path2}
6. <org.zeroturnaround.zip.ZipUtil: boolean doEntryEquals(java.util.zip.ZipFile,java.util.zip.ZipFile,java.lang.String,java.lang.String)>[5@L3260] e2 = invokevirtual zf2.getEntry(path2)/0

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: boolean entryEquals(java.io.File,java.io.File,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 3182 |    *         files.
 3183 |    */
 3184 |   public static boolean entryEquals(File f1, File f2, String path) {
 3185 |     return entryEquals(f1, f2, path, path);
 3186 |   }
 3187 | 
 3188 |   /**

### <org.zeroturnaround.zip.ZipUtil: boolean entryEquals(java.io.File,java.io.File,java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 3199 |    * @return <code>true</code> if the contents of the entries were same.
 3200 |    */
 3201 |   public static boolean entryEquals(File f1, File f2, String path1, String path2) {
 3202 |     ZipFile zf1 = null;
 3203 |     ZipFile zf2 = null;
 3204 | 
 3205 |     try {
 3206 |       zf1 = new ZipFile(f1);
 3207 |       zf2 = new ZipFile(f2);
 3208 | 
 3209 |       return doEntryEquals(zf1, zf2, path1, path2);
 3210 |     }
 3211 |     catch (IOException e) {
 3212 |       throw ZipExceptionUtil.rethrow(e);
 3213 |     }
 3214 |     finally {
 3215 |       closeQuietly(zf1);
 3216 |       closeQuietly(zf2);
 3217 |     }
 3218 |   }
 3219 | 
 3220 |   /**

### <org.zeroturnaround.zip.ZipUtil: boolean doEntryEquals(java.util.zip.ZipFile,java.util.zip.ZipFile,java.lang.String,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
 3253 |    * @return <code>true</code> if the contents of the entries were same.
 3254 |    */
 3255 |   private static boolean doEntryEquals(ZipFile zf1, ZipFile zf2, String path1, String path2) throws IOException {
 3256 |     InputStream is1 = null;
 3257 |     InputStream is2 = null;
 3258 |     try {
 3259 |       ZipEntry e1 = zf1.getEntry(path1);
 3260 |       ZipEntry e2 = zf2.getEntry(path2);
 3261 | 
 3262 |       if (e1 == null && e2 == null) {
 3263 |         return true;
 3264 |       }
 3265 | 
 3266 |       if (e1 == null || e2 == null) {
 3267 |         return false;
 3268 |       }
 3269 | 
 3270 |       is1 = zf1.getInputStream(e1);
 3271 |       is2 = zf2.getInputStream(e2);
 3272 |       if (is1 == null && is2 == null) {
 3273 |         return true;
 3274 |       }
 3275 |       if (is1 == null || is2 == null) {
 3276 |         return false;
 3277 |       }
 3278 | 
 3279 |       return IOUtils.contentEquals(is1, is2);
 3280 |     }
 3281 |     finally {
 3282 |       IOUtils.closeQuietly(is1);
 3283 |       IOUtils.closeQuietly(is2);
 3284 |     }
 3285 |   }
 3286 | 
 3287 |   /**
```

---

## 60/97 flow_id 77810c9031 (priority 2)

Historical evidence: this sampled key is absent from the corrected run records; the original label is retained without re-adjudication.

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 77810c9031
key        : DRIVER => <org.zeroturnaround.zip.ZipUtil: boolean doUnpackEntry(java.util.zip.ZipFile,java.lang.String,java.io.File)>@L399/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[4@L11] %v4 = invokestatic nesy.Taint.src()/result
sink       : <org.zeroturnaround.zip.ZipUtil: boolean doUnpackEntry(java.util.zip.ZipFile,java.lang.String,java.io.File)>[27@L399] %v27 = invokevirtual zf.getInputStream(ze)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2, v2 run2, v3 run2, v3-noV2 run2, v3-noV3 run2, v3-noval run2, v4 run2
N3 (v3 run2): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: boolean doUnpackEntry(java.util.zip.ZipFile,java.lang.String,java.io.File)>, <org.zeroturnaround.zip.ZipUtil: boolean unpackEntry(java.io.File,java.lang.String,java.io.File)>, <org.zeroturnaround.zip.ZipUtil: boolean unpackEntry(java.io.File,java.lang.String,java.io.File,java.nio.charset.Charset)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: boolean doUnpackEntry(java.util.zip.ZipFile,java.lang.String,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
  387 |    *         <code>false</code> if the entry was not found.
  388 |    */
  389 |   private static boolean doUnpackEntry(ZipFile zf, String name, File file) throws IOException {
  390 |     if (log.isTraceEnabled()) {
  391 |       log.trace("Extracting '" + zf.getName() + "' entry '" + name + "' into '" + file + "'.");
  392 |     }
  393 | 
  394 |     ZipEntry ze = zf.getEntry(name);
  395 |     if (ze == null) {
  396 |       return false; // entry not found
  397 |     }
  398 | 
  399 |     if (ze.isDirectory() || zf.getInputStream(ze) == null) {
  400 |       if (file.isDirectory()) {
  401 |         return true;
  402 |       }
  403 |       if (file.exists()) {
  404 |         FileUtils.forceDelete(file);
  405 |       }
  406 |       return file.mkdirs();
  407 |     }
  408 | 
  409 |     InputStream in = new BufferedInputStream(zf.getInputStream(ze));
  410 |     try {
  411 |       FileUtils.copy(in, file);
  412 |     }
  413 |     finally {
  414 |       IOUtils.closeQuietly(in);
  415 |     }
  416 |     return true;
  417 |   }
  418 | 
  419 |   /**

### <org.zeroturnaround.zip.ZipUtil: boolean unpackEntry(java.io.File,java.lang.String,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
  316 |    *         <code>false</code> if the entry was not found.
  317 |    */
  318 |   public static boolean unpackEntry(File zip, String name, File file) {
  319 |     return unpackEntry(zip, name, file, null);
  320 |   }
  321 | 
  322 |   /**

### <org.zeroturnaround.zip.ZipUtil: boolean unpackEntry(java.io.File,java.lang.String,java.io.File,java.nio.charset.Charset)>
file: org/zeroturnaround/zip/ZipUtil.java
  335 |    *         <code>false</code> if the entry was not found.
  336 |    */
  337 |   public static boolean unpackEntry(File zip, String name, File file, Charset charset) {
  338 |     ZipFile zf = null;
  339 |     try {
  340 |       if (charset != null) {
  341 |         zf = new ZipFile(zip, charset);
  342 |       }
  343 |       else {
  344 |         zf = new ZipFile(zip);
  345 |       }
  346 |       return doUnpackEntry(zf, name, file);
  347 |     }
  348 |     catch (IOException e) {
  349 |       throw ZipExceptionUtil.rethrow(e);
  350 |     }
  351 |     finally {
  352 |       closeQuietly(zf);
  353 |     }
  354 |   }
  355 | 
  356 |   /**
```

---

## 61/97 flow_id 618bf36b9f (priority 2)

Historical evidence: this sampled key is absent from the corrected run records; the original label is retained without re-adjudication.

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 618bf36b9f
key        : DRIVER => <org.zeroturnaround.zip.ZipUtil: boolean doUnpackEntry(java.util.zip.ZipFile,java.lang.String,java.io.File)>@L409/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[4@L11] %v4 = invokestatic nesy.Taint.src()/result
sink       : <org.zeroturnaround.zip.ZipUtil: boolean doUnpackEntry(java.util.zip.ZipFile,java.lang.String,java.io.File)>[38@L409] %v29 = invokevirtual zf.getInputStream(ze)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2, v2 run2, v3 run2, v3-noV2 run2, v3-noV3 run2, v3-noval run2, v4 run2
N3 (v3 run2): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[4@L11] %v4 = invokestatic nesy.Taint.src()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v4}
3. VarNode{<org.zeroturnaround.zip.ZipUtil: boolean unpackEntry(java.io.File,java.lang.String,java.io.File)>/name}
4. VarNode{<org.zeroturnaround.zip.ZipUtil: boolean unpackEntry(java.io.File,java.lang.String,java.io.File,java.nio.charset.Charset)>/name}
5. VarNode{<org.zeroturnaround.zip.ZipUtil: boolean doUnpackEntry(java.util.zip.ZipFile,java.lang.String,java.io.File)>/name}
6. VarNode{<org.zeroturnaround.zip.ZipUtil: boolean doUnpackEntry(java.util.zip.ZipFile,java.lang.String,java.io.File)>/ze}
7. <org.zeroturnaround.zip.ZipUtil: boolean doUnpackEntry(java.util.zip.ZipFile,java.lang.String,java.io.File)>[38@L409] %v29 = invokevirtual zf.getInputStream(ze)/0

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: boolean unpackEntry(java.io.File,java.lang.String,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
  316 |    *         <code>false</code> if the entry was not found.
  317 |    */
  318 |   public static boolean unpackEntry(File zip, String name, File file) {
  319 |     return unpackEntry(zip, name, file, null);
  320 |   }
  321 | 
  322 |   /**

### <org.zeroturnaround.zip.ZipUtil: boolean unpackEntry(java.io.File,java.lang.String,java.io.File,java.nio.charset.Charset)>
file: org/zeroturnaround/zip/ZipUtil.java
  335 |    *         <code>false</code> if the entry was not found.
  336 |    */
  337 |   public static boolean unpackEntry(File zip, String name, File file, Charset charset) {
  338 |     ZipFile zf = null;
  339 |     try {
  340 |       if (charset != null) {
  341 |         zf = new ZipFile(zip, charset);
  342 |       }
  343 |       else {
  344 |         zf = new ZipFile(zip);
  345 |       }
  346 |       return doUnpackEntry(zf, name, file);
  347 |     }
  348 |     catch (IOException e) {
  349 |       throw ZipExceptionUtil.rethrow(e);
  350 |     }
  351 |     finally {
  352 |       closeQuietly(zf);
  353 |     }
  354 |   }
  355 | 
  356 |   /**

### <org.zeroturnaround.zip.ZipUtil: boolean doUnpackEntry(java.util.zip.ZipFile,java.lang.String,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
  387 |    *         <code>false</code> if the entry was not found.
  388 |    */
  389 |   private static boolean doUnpackEntry(ZipFile zf, String name, File file) throws IOException {
  390 |     if (log.isTraceEnabled()) {
  391 |       log.trace("Extracting '" + zf.getName() + "' entry '" + name + "' into '" + file + "'.");
  392 |     }
  393 | 
  394 |     ZipEntry ze = zf.getEntry(name);
  395 |     if (ze == null) {
  396 |       return false; // entry not found
  397 |     }
  398 | 
  399 |     if (ze.isDirectory() || zf.getInputStream(ze) == null) {
  400 |       if (file.isDirectory()) {
  401 |         return true;
  402 |       }
  403 |       if (file.exists()) {
  404 |         FileUtils.forceDelete(file);
  405 |       }
  406 |       return file.mkdirs();
  407 |     }
  408 | 
  409 |     InputStream in = new BufferedInputStream(zf.getInputStream(ze));
  410 |     try {
  411 |       FileUtils.copy(in, file);
  412 |     }
  413 |     finally {
  414 |       IOUtils.closeQuietly(in);
  415 |     }
  416 |     return true;
  417 |   }
  418 | 
  419 |   /**
```

---

## 62/97 flow_id 20bc5cac51 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 20bc5cac51
key        : DRIVER => <org.zeroturnaround.zip.ZipUtil: boolean unpackEntry(java.io.File,java.lang.String,java.io.File,java.nio.charset.Charset)>@L344/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[86@L28] %v49 = invokestatic nesy.Taint.srcFile()/result
sink       : <org.zeroturnaround.zip.ZipUtil: boolean unpackEntry(java.io.File,java.lang.String,java.io.File,java.nio.charset.Charset)>[7@L344] invokespecial %v9.<init>(zip)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, v1 run0
N3 (iris-like run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[86@L28] %v49 = invokestatic nesy.Taint.srcFile()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v49}
3. VarNode{<org.zeroturnaround.zip.ZipUtil: boolean unpackEntry(java.io.File,java.lang.String,java.io.File)>/zip}
4. VarNode{<org.zeroturnaround.zip.ZipUtil: boolean unpackEntry(java.io.File,java.lang.String,java.io.File,java.nio.charset.Charset)>/zip}
5. <org.zeroturnaround.zip.ZipUtil: boolean unpackEntry(java.io.File,java.lang.String,java.io.File,java.nio.charset.Charset)>[7@L344] invokespecial %v9.<init>(zip)/0

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: boolean unpackEntry(java.io.File,java.lang.String,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
  316 |    *         <code>false</code> if the entry was not found.
  317 |    */
  318 |   public static boolean unpackEntry(File zip, String name, File file) {
  319 |     return unpackEntry(zip, name, file, null);
  320 |   }
  321 | 
  322 |   /**

### <org.zeroturnaround.zip.ZipUtil: boolean unpackEntry(java.io.File,java.lang.String,java.io.File,java.nio.charset.Charset)>
file: org/zeroturnaround/zip/ZipUtil.java
  335 |    *         <code>false</code> if the entry was not found.
  336 |    */
  337 |   public static boolean unpackEntry(File zip, String name, File file, Charset charset) {
  338 |     ZipFile zf = null;
  339 |     try {
  340 |       if (charset != null) {
  341 |         zf = new ZipFile(zip, charset);
  342 |       }
  343 |       else {
  344 |         zf = new ZipFile(zip);
  345 |       }
  346 |       return doUnpackEntry(zf, name, file);
  347 |     }
  348 |     catch (IOException e) {
  349 |       throw ZipExceptionUtil.rethrow(e);
  350 |     }
  351 |     finally {
  352 |       closeQuietly(zf);
  353 |     }
  354 |   }
  355 | 
  356 |   /**
```

---

## 63/97 flow_id 14de090dce (priority 2)

Historical evidence: this sampled key is absent from the corrected run records; the original label is retained without re-adjudication.

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 14de090dce
key        : DRIVER => <org.zeroturnaround.zip.ZipUtil: byte[] doUnpackEntry(java.util.zip.ZipFile,java.lang.String)>@L262/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[44@L23] %v29 = invokestatic nesy.Taint.src()/result
sink       : <org.zeroturnaround.zip.ZipUtil: byte[] doUnpackEntry(java.util.zip.ZipFile,java.lang.String)>[3@L262] is = invokevirtual zf.getInputStream(ze)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2, v2 run2, v3 run2, v3-noV2 run2, v3-noV3 run2, v3-noval run2, v4 run2
N3 (v3 run2): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[44@L23] %v29 = invokestatic nesy.Taint.src()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v29}
3. VarNode{<org.zeroturnaround.zip.ZipUtil: byte[] unpackEntry(java.io.File,java.lang.String)>/name}
4. VarNode{<org.zeroturnaround.zip.ZipUtil: byte[] doUnpackEntry(java.util.zip.ZipFile,java.lang.String)>/name}
5. VarNode{<org.zeroturnaround.zip.ZipUtil: byte[] doUnpackEntry(java.util.zip.ZipFile,java.lang.String)>/ze}
6. <org.zeroturnaround.zip.ZipUtil: byte[] doUnpackEntry(java.util.zip.ZipFile,java.lang.String)>[3@L262] is = invokevirtual zf.getInputStream(ze)/0

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: byte[] unpackEntry(java.io.File,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
  181 |    * @return contents of the entry or <code>null</code> if it was not found.
  182 |    */
  183 |   public static byte[] unpackEntry(File zip, String name) {
  184 |     ZipFile zf = null;
  185 |     try {
  186 |       zf = new ZipFile(zip);
  187 |       return doUnpackEntry(zf, name);
  188 |     }
  189 |     catch (IOException e) {
  190 |       throw ZipExceptionUtil.rethrow(e);
  191 |     }
  192 |     finally {
  193 |       closeQuietly(zf);
  194 |     }
  195 |   }
  196 | 
  197 |   /**

### <org.zeroturnaround.zip.ZipUtil: byte[] doUnpackEntry(java.util.zip.ZipFile,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
  254 |    * @return contents of the entry or <code>null</code> if it was not found.
  255 |    */
  256 |   private static byte[] doUnpackEntry(ZipFile zf, String name) throws IOException {
  257 |     ZipEntry ze = zf.getEntry(name);
  258 |     if (ze == null) {
  259 |       return null; // entry not found
  260 |     }
  261 | 
  262 |     InputStream is = zf.getInputStream(ze);
  263 |     try {
  264 |       return IOUtils.toByteArray(is);
  265 |     }
  266 |     finally {
  267 |       IOUtils.closeQuietly(is);
  268 |     }
  269 |   }
  270 | 
  271 |   /**
```

---

## 64/97 flow_id fdd8b70bfb (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow fdd8b70bfb
key        : DRIVER => <org.zeroturnaround.zip.ZipUtil: int getCompressionMethodOfEntry(java.io.File,java.lang.String)>@L131/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[254@L104] %v160 = invokestatic nesy.Taint.src()/result
sink       : <org.zeroturnaround.zip.ZipUtil: int getCompressionMethodOfEntry(java.io.File,java.lang.String)>[5@L131] zipEntry = invokevirtual zf.getEntry(name)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2, v2 run2, v3 run2, v3-noV2 run2, v3-noV3 run2, v3-noval run2, v4 run2
N3 (v3 run2): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[254@L104] %v160 = invokestatic nesy.Taint.src()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v160}
3. VarNode{<org.zeroturnaround.zip.ZipUtil: int getCompressionMethodOfEntry(java.io.File,java.lang.String)>/name}
4. <org.zeroturnaround.zip.ZipUtil: int getCompressionMethodOfEntry(java.io.File,java.lang.String)>[5@L131] zipEntry = invokevirtual zf.getEntry(name)/0

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: int getCompressionMethodOfEntry(java.io.File,java.lang.String)>
file: org/zeroturnaround/zip/ZipUtil.java
  125 |    *         the ZIP file does not contain the given entry.
  126 |    */
  127 |   public static int getCompressionMethodOfEntry(File zip, String name) {
  128 |     ZipFile zf = null;
  129 |     try {
  130 |       zf = new ZipFile(zip);
  131 |       ZipEntry zipEntry = zf.getEntry(name);
  132 |       if (zipEntry == null) {
  133 |         return -1;
  134 |       }
  135 |       return zipEntry.getMethod();
  136 |     }
  137 |     catch (IOException e) {
  138 |       throw ZipExceptionUtil.rethrow(e);
  139 |     }
  140 |     finally {
  141 |       closeQuietly(zf);
  142 |     }
  143 |   }
  144 | 
  145 |   /**
```

---

## 65/97 flow_id d8aff3d6a3 (priority 2)

Historical evidence: this sampled key is absent from the corrected run records; the original label is retained without re-adjudication.

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow d8aff3d6a3
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>@L585/result => <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>@L2442/0
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>[28@L585] %v25 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>[21@L2442] %v19 = invokevirtual zf.getInputStream(entry)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2
N3 (iris-like run2): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>, <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: java.util.Set filterDirEntries(java.io.File,java.util.Collection)>
file: org/zeroturnaround/zip/ZipUtil.java
 2426 |    *
 2427 |    */
 2428 |   static Set<String> filterDirEntries(File zip, Collection<String> names) {
 2429 |     Set<String> dirs = new HashSet<String>();
 2430 |     if (zip == null) {
 2431 |       return dirs;
 2432 |     }
 2433 |     ZipFile zf = null;
 2434 |     try {
 2435 |       zf = new ZipFile(zip);
 2436 |       for (String entryName : names) {
 2437 |         ZipEntry entry = zf.getEntry(entryName);
 2438 |         if (entry != null) {
 2439 |           if (entry.isDirectory()) {
 2440 |             dirs.add(entry.getName());
 2441 |           }
 2442 |           else if (zf.getInputStream(entry) == null) {
 2443 |             // no input stream means that this is a dir.
 2444 |             dirs.add(entry.getName() + PATH_SEPARATOR);
 2445 |           }
 2446 |         }
 2447 |       }
 2448 | 
 2449 |     }
 2450 |     catch (IOException e) {
 2451 |       ZipExceptionUtil.rethrow(e);
 2452 |     }
 2453 |     finally {
 2454 |       closeQuietly(zf);
 2455 |     }
 2456 |     return dirs;
 2457 |   }
 2458 | 
 2459 |   /**

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

## 66/97 flow_id 87a5352189 (priority 2)

Historical evidence: this sampled key is absent from the corrected run records; the original label is retained without re-adjudication.

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 87a5352189
key        : DRIVER => <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>@L580/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[508@L101] %v320 = invokestatic nesy.Taint.src()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>[18@L580] is = invokevirtual zf.getInputStream(e)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2
N3 (iris-like run2): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[508@L101] %v320 = invokestatic nesy.Taint.src()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v320}
3. ArrayIndexNode{NewObj{<nesy.NesyDriver: void main(java.lang.String[])>[507@L101] newarray java.lang.String[%ci1]}}
4. VarNode{<org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>/%v16}
5. VarNode{<org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>/e}
6. <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>[18@L580] is = invokevirtual zf.getInputStream(e)/0

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
```

---

## 67/97 flow_id 8c6b47e909 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 8c6b47e909
key        : DRIVER => <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipInfoCallback)>@L662/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[523@L103] %v329 = invokestatic nesy.Taint.srcFile()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipInfoCallback)>[4@L662] invokespecial %v8.<init>(zip)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, v1 run0
N3 (iris-like run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[523@L103] %v329 = invokestatic nesy.Taint.srcFile()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v329}
3. VarNode{<org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipInfoCallback)>/zip}
4. <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipInfoCallback)>[4@L662] invokespecial %v8.<init>(zip)/0

## Application-code evidence (route or reachable-method fallback)
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

## 68/97 flow_id e7e05bf517 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow e7e05bf517
key        : <org.zeroturnaround.zip.ZipUtil$10: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2348/result => <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>@L1766/0
source     : <org.zeroturnaround.zip.ZipUtil$10: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L2348] entryName = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>[47@L1766] invokespecial file.<init>(dir, filename)/0
fixed methods on this flow (GT): -
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$10: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,boolean)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,int)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$10: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2345 |     final Set<String> names = new HashSet<String>();
 2346 |     iterate(zip, new ZipEntryCallback() {
 2347 |       public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2348 |         String entryName = zipEntry.getName();
 2349 |         if (names.add(entryName)) {
 2350 |           ZipEntryUtil.copyEntry(zipEntry, in, out);
 2351 |         }
 2352 |         else if (log.isDebugEnabled()) {
 2353 |           log.debug("Duplicate entry: {}", entryName);
 2354 |         }
 2355 |       }
 2356 |     });
 2357 |   }
 2358 | 

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 1399 |    *          ZIP file that will be created or overwritten.
 1400 |    */
 1401 |   public static void pack(File rootDir, File zip) {
 1402 |     pack(rootDir, zip, DEFAULT_COMPRESSION_LEVEL);
 1403 |   }
 1404 | 
 1405 |   /**
 1406 |    * Compresses the given directory and all its sub-directories into a ZIP file.

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/ZipUtil.java
 1433 |    *          true if the resulted archive should have the top directory entry
 1434 |    */
 1435 |   public static void pack(final File sourceDir, final File targetZipFile, final boolean preserveRoot) {
 1436 |     if (preserveRoot) {
 1437 |       final String parentName = sourceDir.getName();
 1438 |       pack(sourceDir, targetZipFile, new NameMapper() {
 1439 |         public String map(String name) {
 1440 |           return parentName + PATH_SEPARATOR + name;
 1441 |         }
 1442 |       });
 1443 |     }
 1444 |     else {
 1445 |       pack(sourceDir, targetZipFile);
 1446 |     }
 1447 |   }
 1448 | 
 1449 |   /**
 1450 |    * Compresses the given file into a ZIP file.

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1416 |    *          compression level
 1417 |    */
 1418 |   public static void pack(File rootDir, File zip, int compressionLevel) {
 1419 |     pack(rootDir, zip, IdentityNameMapper.INSTANCE, compressionLevel);
 1420 |   }
 1421 | 
 1422 |   /**
 1423 |    * Compresses the given directory and all its sub-directories into a ZIP file.

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper)>
file: org/zeroturnaround/zip/ZipUtil.java
 1599 |    *          call-back for renaming the entries.
 1600 |    */
 1601 |   public static void pack(File sourceDir, File targetZip, NameMapper mapper) {
 1602 |     pack(sourceDir, targetZip, mapper, DEFAULT_COMPRESSION_LEVEL);
 1603 |   }
 1604 | 
 1605 |   /**
 1606 |    * Compresses the given directory and all its sub-directories into a ZIP file.

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>
file: org/zeroturnaround/zip/ZipUtil.java
 1749 |    *          if true, but directory to pack doesn't have any files, throw an exception.
 1750 |    */
 1751 |   private static void pack(File dir, ZipOutputStream out, NameMapper mapper, String pathPrefix, boolean mustHaveChildren) throws IOException {
 1752 |     String[] filenames = dir.list();
 1753 |     if (filenames == null) {
 1754 |       if (!dir.exists()) {
 1755 |         throw new ZipException("Given file '" + dir + "' doesn't exist!");
 1756 |       }
 1757 |       throw new IOException("Given file is not a directory '" + dir + "'");
 1758 |     }
 1759 | 
 1760 |     if (mustHaveChildren && filenames.length == 0) {
 1761 |       throw new ZipException("Given directory '" + dir + "' doesn't contain any files!");
 1762 |     }
 1763 | 
 1764 |     for (int i = 0; i < filenames.length; i++) {
 1765 |       String filename = filenames[i];
 1766 |       File file = new File(dir, filename);
 1767 |       boolean isDir = file.isDirectory();
 1768 |       String path = pathPrefix + file.getName(); // NOSONAR
 1769 |       if (isDir) {
 1770 |         path += PATH_SEPARATOR; // NOSONAR
 1771 |       }
 1772 | 
 1773 |       // Create a ZIP entry
 1774 |       String name = mapper.map(path);
 1775 |       if (name != null) {
 1776 |         ZipEntry zipEntry = ZipEntryUtil.fromFile(name, file);
 1777 | 
 1778 |         out.putNextEntry(zipEntry);
 1779 | 
 1780 |         // Copy the file content
 1781 |         if (!isDir) {
 1782 |           FileUtils.copy(file, out);
 1783 |         }
 1784 | 
 1785 |         out.closeEntry();
 1786 |       }
 1787 | 
 1788 |       // Traverse the directory
 1789 |       if (isDir) {
 1790 |         pack(file, out, mapper, path, false);
 1791 |       }
 1792 |     }
 1793 |   }
 1794 | 
 1795 |   /**
 1796 |    * Repacks a provided ZIP file into a new ZIP with a given compression level.
```

---

## 69/97 flow_id f6c263e0fd (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow f6c263e0fd
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>@L585/result => <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>@L1766/0
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>[28@L585] %v25 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>[47@L1766] invokespecial file.<init>(dir, filename)/0
fixed methods on this flow (GT): -
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,java.lang.String[],org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,boolean)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,int)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>

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

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 1399 |    *          ZIP file that will be created or overwritten.
 1400 |    */
 1401 |   public static void pack(File rootDir, File zip) {
 1402 |     pack(rootDir, zip, DEFAULT_COMPRESSION_LEVEL);
 1403 |   }
 1404 | 
 1405 |   /**
 1406 |    * Compresses the given directory and all its sub-directories into a ZIP file.

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,boolean)>
file: org/zeroturnaround/zip/ZipUtil.java
 1433 |    *          true if the resulted archive should have the top directory entry
 1434 |    */
 1435 |   public static void pack(final File sourceDir, final File targetZipFile, final boolean preserveRoot) {
 1436 |     if (preserveRoot) {
 1437 |       final String parentName = sourceDir.getName();
 1438 |       pack(sourceDir, targetZipFile, new NameMapper() {
 1439 |         public String map(String name) {
 1440 |           return parentName + PATH_SEPARATOR + name;
 1441 |         }
 1442 |       });
 1443 |     }
 1444 |     else {
 1445 |       pack(sourceDir, targetZipFile);
 1446 |     }
 1447 |   }
 1448 | 
 1449 |   /**
 1450 |    * Compresses the given file into a ZIP file.

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1416 |    *          compression level
 1417 |    */
 1418 |   public static void pack(File rootDir, File zip, int compressionLevel) {
 1419 |     pack(rootDir, zip, IdentityNameMapper.INSTANCE, compressionLevel);
 1420 |   }
 1421 | 
 1422 |   /**
 1423 |    * Compresses the given directory and all its sub-directories into a ZIP file.

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper)>
file: org/zeroturnaround/zip/ZipUtil.java
 1599 |    *          call-back for renaming the entries.
 1600 |    */
 1601 |   public static void pack(File sourceDir, File targetZip, NameMapper mapper) {
 1602 |     pack(sourceDir, targetZip, mapper, DEFAULT_COMPRESSION_LEVEL);
 1603 |   }
 1604 | 
 1605 |   /**
 1606 |    * Compresses the given directory and all its sub-directories into a ZIP file.

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>
file: org/zeroturnaround/zip/ZipUtil.java
 1749 |    *          if true, but directory to pack doesn't have any files, throw an exception.
 1750 |    */
 1751 |   private static void pack(File dir, ZipOutputStream out, NameMapper mapper, String pathPrefix, boolean mustHaveChildren) throws IOException {
 1752 |     String[] filenames = dir.list();
 1753 |     if (filenames == null) {
 1754 |       if (!dir.exists()) {
 1755 |         throw new ZipException("Given file '" + dir + "' doesn't exist!");
 1756 |       }
 1757 |       throw new IOException("Given file is not a directory '" + dir + "'");
 1758 |     }
 1759 | 
 1760 |     if (mustHaveChildren && filenames.length == 0) {
 1761 |       throw new ZipException("Given directory '" + dir + "' doesn't contain any files!");
 1762 |     }
 1763 | 
 1764 |     for (int i = 0; i < filenames.length; i++) {
 1765 |       String filename = filenames[i];
 1766 |       File file = new File(dir, filename);
 1767 |       boolean isDir = file.isDirectory();
 1768 |       String path = pathPrefix + file.getName(); // NOSONAR
 1769 |       if (isDir) {
 1770 |         path += PATH_SEPARATOR; // NOSONAR
 1771 |       }
 1772 | 
 1773 |       // Create a ZIP entry
 1774 |       String name = mapper.map(path);
 1775 |       if (name != null) {
 1776 |         ZipEntry zipEntry = ZipEntryUtil.fromFile(name, file);
 1777 | 
 1778 |         out.putNextEntry(zipEntry);
 1779 | 
 1780 |         // Copy the file content
 1781 |         if (!isDir) {
 1782 |           FileUtils.copy(file, out);
 1783 |         }
 1784 | 
 1785 |         out.closeEntry();
 1786 |       }
 1787 | 
 1788 |       // Traverse the directory
 1789 |       if (isDir) {
 1790 |         pack(file, out, mapper, path, false);
 1791 |       }
 1792 |     }
 1793 |   }
 1794 | 
 1795 |   /**
 1796 |    * Repacks a provided ZIP file into a new ZIP with a given compression level.
```

---

## 70/97 flow_id 1da6f1afff (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 1da6f1afff
key        : DRIVER => <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>@L1766/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[282@L63] %v173 = invokestatic nesy.Taint.srcFile()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>[47@L1766] invokespecial file.<init>(dir, filename)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v4 run0, v4 run1, v4 run2

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[282@L63] %v173 = invokestatic nesy.Taint.srcFile()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v173}
3. VarNode{<org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File)>/dir}
4. VarNode{<org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File,int)>/dir}
5. VarNode{<org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,int)>/rootDir}
6. VarNode{<org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper,int)>/sourceDir}
7. VarNode{<org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>/dir}
8. <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>[47@L1766] invokespecial file.<init>(dir, filename)/0

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 1911 |    * @see #pack(File, File)
 1912 |    */
 1913 |   public static void unexplode(File dir) {
 1914 |     unexplode(dir, DEFAULT_COMPRESSION_LEVEL);
 1915 |   }
 1916 | 
 1917 |   /**
 1918 |    * Compresses a given directory in its own location.

### <org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1931 |   public static void unexplode(File dir, int compressionLevel) {
 1932 |     try {
 1933 |       // Find a new unique name is the same directory
 1934 |       File zip = FileUtils.getTempFileFor(dir);
 1935 | 
 1936 |       // Pack it
 1937 |       pack(dir, zip, compressionLevel);
 1938 | 
 1939 |       // Delete the directory
 1940 |       FileUtils.deleteDirectory(dir);
 1941 | 
 1942 |       // Rename the archive
 1943 |       FileUtils.moveFile(zip, dir);
 1944 |     }
 1945 |     catch (IOException e) {
 1946 |       throw ZipExceptionUtil.rethrow(e);
 1947 |     }
 1948 |   }
 1949 | 
 1950 |   /**
 1951 |    * Compresses the given entries into an output stream.

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1416 |    *          compression level
 1417 |    */
 1418 |   public static void pack(File rootDir, File zip, int compressionLevel) {
 1419 |     pack(rootDir, zip, IdentityNameMapper.INSTANCE, compressionLevel);
 1420 |   }
 1421 | 
 1422 |   /**
 1423 |    * Compresses the given directory and all its sub-directories into a ZIP file.

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.io.File,org.zeroturnaround.zip.NameMapper,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1617 |    *          compression level
 1618 |    */
 1619 |   public static void pack(File sourceDir, File targetZip, NameMapper mapper, int compressionLevel) {
 1620 |     log.debug("Compressing '{}' into '{}'.", sourceDir, targetZip);
 1621 |     if (!sourceDir.exists()) {
 1622 |       throw new ZipException("Given file '" + sourceDir + "' doesn't exist!");
 1623 |     }
 1624 |     ZipOutputStream out = null;
 1625 |     try {
 1626 |       out = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(targetZip)));
 1627 |       out.setLevel(compressionLevel);
 1628 |       pack(sourceDir, out, mapper, "", true);
 1629 |     }
 1630 |     catch (IOException e) {
 1631 |       throw ZipExceptionUtil.rethrow(e);
 1632 |     }
 1633 |     finally {
 1634 |       IOUtils.closeQuietly(out);
 1635 |     }
 1636 |   }
 1637 | 
 1638 |   /**
 1639 |    * Compresses the given directory and all of its sub-directories into the passed in

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>
file: org/zeroturnaround/zip/ZipUtil.java
 1749 |    *          if true, but directory to pack doesn't have any files, throw an exception.
 1750 |    */
 1751 |   private static void pack(File dir, ZipOutputStream out, NameMapper mapper, String pathPrefix, boolean mustHaveChildren) throws IOException {
 1752 |     String[] filenames = dir.list();
 1753 |     if (filenames == null) {
 1754 |       if (!dir.exists()) {
 1755 |         throw new ZipException("Given file '" + dir + "' doesn't exist!");
 1756 |       }
 1757 |       throw new IOException("Given file is not a directory '" + dir + "'");
 1758 |     }
 1759 | 
 1760 |     if (mustHaveChildren && filenames.length == 0) {
 1761 |       throw new ZipException("Given directory '" + dir + "' doesn't contain any files!");
 1762 |     }
 1763 | 
 1764 |     for (int i = 0; i < filenames.length; i++) {
 1765 |       String filename = filenames[i];
 1766 |       File file = new File(dir, filename);
 1767 |       boolean isDir = file.isDirectory();
 1768 |       String path = pathPrefix + file.getName(); // NOSONAR
 1769 |       if (isDir) {
 1770 |         path += PATH_SEPARATOR; // NOSONAR
 1771 |       }
 1772 | 
 1773 |       // Create a ZIP entry
 1774 |       String name = mapper.map(path);
 1775 |       if (name != null) {
 1776 |         ZipEntry zipEntry = ZipEntryUtil.fromFile(name, file);
 1777 | 
 1778 |         out.putNextEntry(zipEntry);
 1779 | 
 1780 |         // Copy the file content
 1781 |         if (!isDir) {
 1782 |           FileUtils.copy(file, out);
 1783 |         }
 1784 | 
 1785 |         out.closeEntry();
 1786 |       }
 1787 | 
 1788 |       // Traverse the directory
 1789 |       if (isDir) {
 1790 |         pack(file, out, mapper, path, false);
 1791 |       }
 1792 |     }
 1793 |   }
 1794 | 
 1795 |   /**
 1796 |    * Repacks a provided ZIP file into a new ZIP with a given compression level.
```

---

## 71/97 flow_id b38512e59c (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow b38512e59c
key        : <org.apache.log4j.Category: void removeAllAppenders()>@L889/result => <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>@L1766/1
source     : <org.apache.log4j.Category: void removeAllAppenders()>[10@L889] %v10 = invokeinterface iter.nextElement()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>[47@L1766] invokespecial file.<init>(dir, filename)/1
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>
file: org/zeroturnaround/zip/ZipUtil.java
 1749 |    *          if true, but directory to pack doesn't have any files, throw an exception.
 1750 |    */
 1751 |   private static void pack(File dir, ZipOutputStream out, NameMapper mapper, String pathPrefix, boolean mustHaveChildren) throws IOException {
 1752 |     String[] filenames = dir.list();
 1753 |     if (filenames == null) {
 1754 |       if (!dir.exists()) {
 1755 |         throw new ZipException("Given file '" + dir + "' doesn't exist!");
 1756 |       }
 1757 |       throw new IOException("Given file is not a directory '" + dir + "'");
 1758 |     }
 1759 | 
 1760 |     if (mustHaveChildren && filenames.length == 0) {
 1761 |       throw new ZipException("Given directory '" + dir + "' doesn't contain any files!");
 1762 |     }
 1763 | 
 1764 |     for (int i = 0; i < filenames.length; i++) {
 1765 |       String filename = filenames[i];
 1766 |       File file = new File(dir, filename);
 1767 |       boolean isDir = file.isDirectory();
 1768 |       String path = pathPrefix + file.getName(); // NOSONAR
 1769 |       if (isDir) {
 1770 |         path += PATH_SEPARATOR; // NOSONAR
 1771 |       }
 1772 | 
 1773 |       // Create a ZIP entry
 1774 |       String name = mapper.map(path);
 1775 |       if (name != null) {
 1776 |         ZipEntry zipEntry = ZipEntryUtil.fromFile(name, file);
 1777 | 
 1778 |         out.putNextEntry(zipEntry);
 1779 | 
 1780 |         // Copy the file content
 1781 |         if (!isDir) {
 1782 |           FileUtils.copy(file, out);
 1783 |         }
 1784 | 
 1785 |         out.closeEntry();
 1786 |       }
 1787 | 
 1788 |       // Traverse the directory
 1789 |       if (isDir) {
 1790 |         pack(file, out, mapper, path, false);
 1791 |       }
 1792 |     }
 1793 |   }
 1794 | 
 1795 |   /**
 1796 |    * Repacks a provided ZIP file into a new ZIP with a given compression level.
```

---

## 72/97 flow_id 476fe4a413 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 476fe4a413
key        : <org.apache.log4j.helpers.Loader: java.lang.Class loadClass(java.lang.String)>@L182/0 => <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>@L1766/1
source     : <org.apache.log4j.helpers.Loader: java.lang.Class loadClass(java.lang.String)>[5@L182] %v15 = invokestatic java.lang.Class.forName(clazz)/0
sink       : <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>[47@L1766] invokespecial file.<init>(dir, filename)/1
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>
file: org/zeroturnaround/zip/ZipUtil.java
 1749 |    *          if true, but directory to pack doesn't have any files, throw an exception.
 1750 |    */
 1751 |   private static void pack(File dir, ZipOutputStream out, NameMapper mapper, String pathPrefix, boolean mustHaveChildren) throws IOException {
 1752 |     String[] filenames = dir.list();
 1753 |     if (filenames == null) {
 1754 |       if (!dir.exists()) {
 1755 |         throw new ZipException("Given file '" + dir + "' doesn't exist!");
 1756 |       }
 1757 |       throw new IOException("Given file is not a directory '" + dir + "'");
 1758 |     }
 1759 | 
 1760 |     if (mustHaveChildren && filenames.length == 0) {
 1761 |       throw new ZipException("Given directory '" + dir + "' doesn't contain any files!");
 1762 |     }
 1763 | 
 1764 |     for (int i = 0; i < filenames.length; i++) {
 1765 |       String filename = filenames[i];
 1766 |       File file = new File(dir, filename);
 1767 |       boolean isDir = file.isDirectory();
 1768 |       String path = pathPrefix + file.getName(); // NOSONAR
 1769 |       if (isDir) {
 1770 |         path += PATH_SEPARATOR; // NOSONAR
 1771 |       }
 1772 | 
 1773 |       // Create a ZIP entry
 1774 |       String name = mapper.map(path);
 1775 |       if (name != null) {
 1776 |         ZipEntry zipEntry = ZipEntryUtil.fromFile(name, file);
 1777 | 
 1778 |         out.putNextEntry(zipEntry);
 1779 | 
 1780 |         // Copy the file content
 1781 |         if (!isDir) {
 1782 |           FileUtils.copy(file, out);
 1783 |         }
 1784 | 
 1785 |         out.closeEntry();
 1786 |       }
 1787 | 
 1788 |       // Traverse the directory
 1789 |       if (isDir) {
 1790 |         pack(file, out, mapper, path, false);
 1791 |       }
 1792 |     }
 1793 |   }
 1794 | 
 1795 |   /**
 1796 |    * Repacks a provided ZIP file into a new ZIP with a given compression level.
```

---

## 73/97 flow_id 1765a9535c (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 1765a9535c
key        : <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2609/result => <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>@L1766/1
source     : <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2609] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>[47@L1766] invokespecial file.<init>(dir, filename)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2606 |         final Set<String> names = new HashSet<String>();
 2607 |         iterate(zip, new ZipEntryCallback() {
 2608 |           public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2609 |             if (names.add(zipEntry.getName())) {
 2610 |               ZipEntrySource entry = (ZipEntrySource) entryByPath.remove(zipEntry.getName());
 2611 |               if (entry != null) {
 2612 |                 addEntry(entry, out);
 2613 |               }
 2614 |               else {
 2615 |                 ZipEntryUtil.copyEntry(zipEntry, in, out);
 2616 |               }
 2617 |             }
 2618 |             else if (log.isDebugEnabled()) {
 2619 |               log.debug("Duplicate entry: {}", zipEntry.getName());
 2620 |             }
 2621 |           }
 2622 |         });
 2623 |       }
 2624 |       finally {

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>
file: org/zeroturnaround/zip/ZipUtil.java
 1749 |    *          if true, but directory to pack doesn't have any files, throw an exception.
 1750 |    */
 1751 |   private static void pack(File dir, ZipOutputStream out, NameMapper mapper, String pathPrefix, boolean mustHaveChildren) throws IOException {
 1752 |     String[] filenames = dir.list();
 1753 |     if (filenames == null) {
 1754 |       if (!dir.exists()) {
 1755 |         throw new ZipException("Given file '" + dir + "' doesn't exist!");
 1756 |       }
 1757 |       throw new IOException("Given file is not a directory '" + dir + "'");
 1758 |     }
 1759 | 
 1760 |     if (mustHaveChildren && filenames.length == 0) {
 1761 |       throw new ZipException("Given directory '" + dir + "' doesn't contain any files!");
 1762 |     }
 1763 | 
 1764 |     for (int i = 0; i < filenames.length; i++) {
 1765 |       String filename = filenames[i];
 1766 |       File file = new File(dir, filename);
 1767 |       boolean isDir = file.isDirectory();
 1768 |       String path = pathPrefix + file.getName(); // NOSONAR
 1769 |       if (isDir) {
 1770 |         path += PATH_SEPARATOR; // NOSONAR
 1771 |       }
 1772 | 
 1773 |       // Create a ZIP entry
 1774 |       String name = mapper.map(path);
 1775 |       if (name != null) {
 1776 |         ZipEntry zipEntry = ZipEntryUtil.fromFile(name, file);
 1777 | 
 1778 |         out.putNextEntry(zipEntry);
 1779 | 
 1780 |         // Copy the file content
 1781 |         if (!isDir) {
 1782 |           FileUtils.copy(file, out);
 1783 |         }
 1784 | 
 1785 |         out.closeEntry();
 1786 |       }
 1787 | 
 1788 |       // Traverse the directory
 1789 |       if (isDir) {
 1790 |         pack(file, out, mapper, path, false);
 1791 |       }
 1792 |     }
 1793 |   }
 1794 | 
 1795 |   /**
 1796 |    * Repacks a provided ZIP file into a new ZIP with a given compression level.
```

---

## 74/97 flow_id 1ad9208e74 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 1ad9208e74
key        : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2675/result => <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>@L1766/1
source     : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2675] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>[47@L1766] invokespecial file.<init>(dir, filename)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v3 run0, v3 run1, v3-noV2 run0, v3-noV2 run1, v3-noV3 run0, v3-noV3 run1, v3-noval run0, v3-noval run1, v4 run0, v4 run1
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2672 |         final Set<String> names = new HashSet<String>();
 2673 |         iterate(zip, new ZipEntryCallback() {
 2674 |           public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2675 |             if (names.add(zipEntry.getName())) {
 2676 |               ZipEntrySource entry = (ZipEntrySource) entryByPath.remove(zipEntry.getName());
 2677 |               if (entry != null) {
 2678 |                 addEntry(entry, out);
 2679 |               }
 2680 |               else {
 2681 |                 ZipEntryUtil.copyEntry(zipEntry, in, out);
 2682 |               }
 2683 |             }
 2684 |             else if (log.isDebugEnabled()) {
 2685 |               log.debug("Duplicate entry: {}", zipEntry.getName());
 2686 |             }
 2687 |           }
 2688 |         });
 2689 | 
 2690 |         // Add new entries

### <org.zeroturnaround.zip.ZipUtil: void pack(java.io.File,java.util.zip.ZipOutputStream,org.zeroturnaround.zip.NameMapper,java.lang.String,boolean)>
file: org/zeroturnaround/zip/ZipUtil.java
 1749 |    *          if true, but directory to pack doesn't have any files, throw an exception.
 1750 |    */
 1751 |   private static void pack(File dir, ZipOutputStream out, NameMapper mapper, String pathPrefix, boolean mustHaveChildren) throws IOException {
 1752 |     String[] filenames = dir.list();
 1753 |     if (filenames == null) {
 1754 |       if (!dir.exists()) {
 1755 |         throw new ZipException("Given file '" + dir + "' doesn't exist!");
 1756 |       }
 1757 |       throw new IOException("Given file is not a directory '" + dir + "'");
 1758 |     }
 1759 | 
 1760 |     if (mustHaveChildren && filenames.length == 0) {
 1761 |       throw new ZipException("Given directory '" + dir + "' doesn't contain any files!");
 1762 |     }
 1763 | 
 1764 |     for (int i = 0; i < filenames.length; i++) {
 1765 |       String filename = filenames[i];
 1766 |       File file = new File(dir, filename);
 1767 |       boolean isDir = file.isDirectory();
 1768 |       String path = pathPrefix + file.getName(); // NOSONAR
 1769 |       if (isDir) {
 1770 |         path += PATH_SEPARATOR; // NOSONAR
 1771 |       }
 1772 | 
 1773 |       // Create a ZIP entry
 1774 |       String name = mapper.map(path);
 1775 |       if (name != null) {
 1776 |         ZipEntry zipEntry = ZipEntryUtil.fromFile(name, file);
 1777 | 
 1778 |         out.putNextEntry(zipEntry);
 1779 | 
 1780 |         // Copy the file content
 1781 |         if (!isDir) {
 1782 |           FileUtils.copy(file, out);
 1783 |         }
 1784 | 
 1785 |         out.closeEntry();
 1786 |       }
 1787 | 
 1788 |       // Traverse the directory
 1789 |       if (isDir) {
 1790 |         pack(file, out, mapper, path, false);
 1791 |       }
 1792 |     }
 1793 |   }
 1794 | 
 1795 |   /**
 1796 |    * Repacks a provided ZIP file into a new ZIP with a given compression level.
```

---

## 75/97 flow_id 69214feb10 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 69214feb10
key        : <org.apache.log4j.Category: void removeAllAppenders()>@L889/result => <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>@L75/1
source     : <org.apache.log4j.Category: void removeAllAppenders()>[10@L889] %v10 = invokeinterface iter.nextElement()/result
sink       : <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>[15@L75] invokespecial result.<init>(parent, %v16)/1
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
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

## 76/97 flow_id 678bff712c (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 678bff712c
key        : <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2609/result => <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>@L75/1
source     : <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2609] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>[15@L75] invokespecial result.<init>(parent, %v16)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$17: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2606 |         final Set<String> names = new HashSet<String>();
 2607 |         iterate(zip, new ZipEntryCallback() {
 2608 |           public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2609 |             if (names.add(zipEntry.getName())) {
 2610 |               ZipEntrySource entry = (ZipEntrySource) entryByPath.remove(zipEntry.getName());
 2611 |               if (entry != null) {
 2612 |                 addEntry(entry, out);
 2613 |               }
 2614 |               else {
 2615 |                 ZipEntryUtil.copyEntry(zipEntry, in, out);
 2616 |               }
 2617 |             }
 2618 |             else if (log.isDebugEnabled()) {
 2619 |               log.debug("Duplicate entry: {}", zipEntry.getName());
 2620 |             }
 2621 |           }
 2622 |         });
 2623 |       }
 2624 |       finally {

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

## 77/97 flow_id 74cc59b67f (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 74cc59b67f
key        : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2675/result => <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>@L75/1
source     : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2675] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>[15@L75] invokespecial result.<init>(parent, %v16)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v3 run0, v3 run1, v3-noV2 run0, v3-noV2 run1, v3-noV3 run0, v3-noV3 run1, v3-noval run0, v3-noval run1, v4 run0, v4 run1
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2672 |         final Set<String> names = new HashSet<String>();
 2673 |         iterate(zip, new ZipEntryCallback() {
 2674 |           public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2675 |             if (names.add(zipEntry.getName())) {
 2676 |               ZipEntrySource entry = (ZipEntrySource) entryByPath.remove(zipEntry.getName());
 2677 |               if (entry != null) {
 2678 |                 addEntry(entry, out);
 2679 |               }
 2680 |               else {
 2681 |                 ZipEntryUtil.copyEntry(zipEntry, in, out);
 2682 |               }
 2683 |             }
 2684 |             else if (log.isDebugEnabled()) {
 2685 |               log.debug("Duplicate entry: {}", zipEntry.getName());
 2686 |             }
 2687 |           }
 2688 |         });
 2689 | 
 2690 |         // Add new entries

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

## 78/97 flow_id 25f7806247 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 25f7806247
key        : <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2927/result => <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>@L75/1
source     : <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2927] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>[15@L75] invokespecial result.<init>(parent, %v16)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$TransformerZipEntryCallback: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2924 |     }
 2925 | 
 2926 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2927 |       if (names.add(zipEntry.getName())) {
 2928 |         ZipEntryTransformer entry = (ZipEntryTransformer) entryByPath.remove(zipEntry.getName());
 2929 |         if (entry != null) {
 2930 |           entry.transform(in, zipEntry, out);
 2931 |         }
 2932 |         else {
 2933 |           ZipEntryUtil.copyEntry(zipEntry, in, out);
 2934 |         }
 2935 |       }
 2936 |       else if (log.isDebugEnabled()) {
 2937 |         log.debug("Duplicate entry: {}", zipEntry.getName());
 2938 |       }
 2939 |     }
 2940 | 
 2941 |     /**
 2942 |      * @return <code>true</code> if at least one entry was replaced.

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

## 79/97 flow_id 73e4eb5189 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 73e4eb5189
key        : DRIVER => <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>@L70/base
source     : <nesy.NesyDriver: void main(java.lang.String[])>[168@L91] %v107 = invokestatic nesy.Taint.srcFile()/result
sink       : <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>[2@L70] parent = invokevirtual file.getParentFile()/base
fixed methods on this flow (GT): -
reported by: iris-like run0, v1 run0, v2 run0, v3 run0, v3-noV2 run0, v3-noV3 run0, v3-noval run0, v4 run0
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[168@L91] %v107 = invokestatic nesy.Taint.srcFile()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v107}
3. VarNode{<org.zeroturnaround.zip.ZipUtil: void explode(java.io.File)>/zip}
4. VarNode{<org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>/file}
5. <org.zeroturnaround.zip.commons.FileUtils: java.io.File getTempFileFor(java.io.File)>[2@L70] parent = invokevirtual file.getParentFile()/base

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void explode(java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 1337 |   public static void explode(File zip) {
 1338 |     try {
 1339 |       // Find a new unique name is the same directory
 1340 |       File tempFile = FileUtils.getTempFileFor(zip);
 1341 | 
 1342 |       // Rename the archive
 1343 |       FileUtils.moveFile(zip, tempFile);
 1344 | 
 1345 |       // Unpack it
 1346 |       unpack(tempFile, zip);
 1347 | 
 1348 |       // Delete the archive
 1349 |       if (!tempFile.delete()) {
 1350 |         throw new IOException("Unable to delete file: " + tempFile);
 1351 |       }
 1352 |     }
 1353 |     catch (IOException e) {
 1354 |       throw ZipExceptionUtil.rethrow(e);
 1355 |     }
 1356 |   }
 1357 | 
 1358 |   /* Compressing single entries to ZIP files. */
 1359 | 

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

## 80/97 flow_id 8657db68eb (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 8657db68eb
key        : DRIVER => <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>@L1081/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[88@L28] %v51 = invokestatic nesy.Taint.srcFile()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>[18@L1081] invokespecial %v11.<init>(canonicalDir, %v12)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, iris-like run2, v1 run1, v1 run2, v2 run1, v2 run2, v4 run1, v4 run2
N3 (iris-like run1): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[88@L28] %v51 = invokestatic nesy.Taint.srcFile()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v51}
3. VarNode{<org.zeroturnaround.zip.ZipUtil: boolean unpackEntry(java.io.File,java.lang.String,java.io.File)>/file}
4. VarNode{<org.zeroturnaround.zip.ZipUtil: boolean unpackEntry(java.io.File,java.lang.String,java.io.File,java.nio.charset.Charset)>/file}
5. VarNode{<org.zeroturnaround.zip.ZipUtil: boolean doUnpackEntry(java.util.zip.ZipFile,java.lang.String,java.io.File)>/file}
6. VarNode{<org.zeroturnaround.zip.commons.FileUtilsV2_2: void forceDelete(java.io.File)>/file}
7. VarNode{<org.zeroturnaround.zip.commons.FileUtilsV2_2: void deleteDirectory(java.io.File)>/directory}
8. VarNode{<org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>/file}
9. VarNode{<org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>/%v9}
10. VarNode{<org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>/canonicalDir}
11. <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>[18@L1081] invokespecial %v11.<init>(canonicalDir, %v12)/0

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: boolean unpackEntry(java.io.File,java.lang.String,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
  316 |    *         <code>false</code> if the entry was not found.
  317 |    */
  318 |   public static boolean unpackEntry(File zip, String name, File file) {
  319 |     return unpackEntry(zip, name, file, null);
  320 |   }
  321 | 
  322 |   /**

### <org.zeroturnaround.zip.ZipUtil: boolean unpackEntry(java.io.File,java.lang.String,java.io.File,java.nio.charset.Charset)>
file: org/zeroturnaround/zip/ZipUtil.java
  335 |    *         <code>false</code> if the entry was not found.
  336 |    */
  337 |   public static boolean unpackEntry(File zip, String name, File file, Charset charset) {
  338 |     ZipFile zf = null;
  339 |     try {
  340 |       if (charset != null) {
  341 |         zf = new ZipFile(zip, charset);
  342 |       }
  343 |       else {
  344 |         zf = new ZipFile(zip);
  345 |       }
  346 |       return doUnpackEntry(zf, name, file);
  347 |     }
  348 |     catch (IOException e) {
  349 |       throw ZipExceptionUtil.rethrow(e);
  350 |     }
  351 |     finally {
  352 |       closeQuietly(zf);
  353 |     }
  354 |   }
  355 | 
  356 |   /**

### <org.zeroturnaround.zip.ZipUtil: boolean doUnpackEntry(java.util.zip.ZipFile,java.lang.String,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
  387 |    *         <code>false</code> if the entry was not found.
  388 |    */
  389 |   private static boolean doUnpackEntry(ZipFile zf, String name, File file) throws IOException {
  390 |     if (log.isTraceEnabled()) {
  391 |       log.trace("Extracting '" + zf.getName() + "' entry '" + name + "' into '" + file + "'.");
  392 |     }
  393 | 
  394 |     ZipEntry ze = zf.getEntry(name);
  395 |     if (ze == null) {
  396 |       return false; // entry not found
  397 |     }
  398 | 
  399 |     if (ze.isDirectory() || zf.getInputStream(ze) == null) {
  400 |       if (file.isDirectory()) {
  401 |         return true;
  402 |       }
  403 |       if (file.exists()) {
  404 |         FileUtils.forceDelete(file);
  405 |       }
  406 |       return file.mkdirs();
  407 |     }
  408 | 
  409 |     InputStream in = new BufferedInputStream(zf.getInputStream(ze));
  410 |     try {
  411 |       FileUtils.copy(in, file);
  412 |     }
  413 |     finally {
  414 |       IOUtils.closeQuietly(in);
  415 |     }
  416 |     return true;
  417 |   }
  418 | 
  419 |   /**

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
```

---

## 81/97 flow_id d2c8e4e956 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow d2c8e4e956
key        : <org.apache.log4j.Category: void removeAllAppenders()>@L889/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>@L1081/1
source     : <org.apache.log4j.Category: void removeAllAppenders()>[10@L889] %v10 = invokeinterface iter.nextElement()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>[18@L1081] invokespecial %v11.<init>(canonicalDir, %v12)/1
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
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
```

---

## 82/97 flow_id f6eb672a29 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow f6eb672a29
key        : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>@L313/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>@L1081/1
source     : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>[9@L313] o = invokeinterface elems.nextElement()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>[18@L1081] invokespecial %v11.<init>(canonicalDir, %v12)/1
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
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
```

---

## 83/97 flow_id 558e5a4f96 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 558e5a4f96
key        : <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2372/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>@L1081/1
source     : <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L2372] entryName = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>[18@L1081] invokespecial %v11.<init>(canonicalDir, %v12)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2369 |     final Set<String> names = new HashSet<String>();
 2370 |     iterate(is, new ZipEntryCallback() {
 2371 |       public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2372 |         String entryName = zipEntry.getName();
 2373 |         if (names.add(entryName)) {
 2374 |           ZipEntryUtil.copyEntry(zipEntry, in, out);
 2375 |         }
 2376 |         else if (log.isDebugEnabled()) {
 2377 |           log.debug("Duplicate entry: {}", entryName);
 2378 |         }
 2379 |       }
 2380 |     });
 2381 |   }
 2382 | 

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
```

---

## 84/97 flow_id 1e09c56981 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 1e09c56981
key        : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2675/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>@L1081/1
source     : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2675] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>[18@L1081] invokespecial %v11.<init>(canonicalDir, %v12)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v4 run1

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2672 |         final Set<String> names = new HashSet<String>();
 2673 |         iterate(zip, new ZipEntryCallback() {
 2674 |           public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2675 |             if (names.add(zipEntry.getName())) {
 2676 |               ZipEntrySource entry = (ZipEntrySource) entryByPath.remove(zipEntry.getName());
 2677 |               if (entry != null) {
 2678 |                 addEntry(entry, out);
 2679 |               }
 2680 |               else {
 2681 |                 ZipEntryUtil.copyEntry(zipEntry, in, out);
 2682 |               }
 2683 |             }
 2684 |             else if (log.isDebugEnabled()) {
 2685 |               log.debug("Duplicate entry: {}", zipEntry.getName());
 2686 |             }
 2687 |           }
 2688 |         });
 2689 | 
 2690 |         // Add new entries

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
```

---

## 85/97 flow_id 064f3842ce (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 064f3842ce
key        : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L1205/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>@L1081/1
source     : <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>[4@L1205] %v9 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>[18@L1081] invokespecial %v11.<init>(canonicalDir, %v12)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.IdentityNameMapper: java.lang.String map(java.lang.String)>, <org.zeroturnaround.zip.ZipUtil$BackslashUnpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtils: void copy(java.io.InputStream,java.io.File)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>

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
 1202 |     }
 1203 | 
 1204 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1205 |       String name = mapper.map(zipEntry.getName());
 1206 |       if (name != null) {
 1207 |         /**
 1208 |          * We assume that EVERY backslash will denote a directory
 1209 |          * separator. Also such broken archives don't have entries that
 1210 |          * are just directories. Everything is a file. See the example
 1211 |          *
 1212 |          * Archive: backSlashTest.zip
 1213 |          * testing: testDirectory\testfileInTestDirectory.txt OK
 1214 |          * testing: testDirectory\testSubdirectory\testFileInTestSubdirectory.txt OK
 1215 |          * No errors detected in compressed data of backSlashTest.zip.
 1216 |          */
 1217 |         if (name.indexOf('\\') != -1) {
 1218 |           File parentDirectory = outputDir;
 1219 |           String[] dirs = name.split("\\\\");
 1220 | 
 1221 |           // lets create all the directories and the last entry is the file as EVERY entry is a file
 1222 |           for (int i = 0; i < dirs.length - 1; i++) {
 1223 |             File file = new File(parentDirectory, dirs[i]);
 1224 |             if (!file.exists()) {
 1225 |               FileUtils.forceMkdir(file);
 1226 |             }
 1227 |             parentDirectory = file;
 1228 |           }
 1229 |           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
 1230 | 
 1231 |           /* If we see the relative traversal string of ".." we need to make sure
 1232 |            * that the outputdir + name doesn't leave the outputdir. See
 1233 |            * DirectoryTraversalMaliciousTest for details.
 1234 |            */
 1235 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1236 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1237 |           }
 1238 | 
 1239 |           FileUtils.copy(in, destFile);
 1240 |         }
 1241 |         // it could be that there are just top level files that the unpacker is used for
 1242 |         else {
 1243 |           File destFile = new File(outputDir, name);
 1244 | 
 1245 |           /* If we see the relative traversal string of ".." we need to make sure
 1246 |            * that the outputdir + name doesn't leave the outputdir. See
 1247 |            * DirectoryTraversalMaliciousTest for details.
 1248 |            */
 1249 |           if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1250 |             throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1251 |           }
 1252 | 
 1253 |           FileUtils.copy(in, destFile);
 1254 |         }
 1255 |       }
 1256 |     }
 1257 |   }
 1258 | 
 1259 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1147 |     }
 1148 | 
 1149 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1150 |       String name = mapper.map(zipEntry.getName());
 1151 |       if (name != null) {
 1152 |         File file = new File(outputDir, name);
 1153 | 
 1154 |         /* If we see the relative traversal string of ".." we need to make sure
 1155 |          * that the outputdir + name doesn't leave the outputdir. See
 1156 |          * DirectoryTraversalMaliciousTest for details.
 1157 |          */
 1158 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1159 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1160 |         }
 1161 | 
 1162 |         if (zipEntry.isDirectory()) {
 1163 |           FileUtils.forceMkdir(file);
 1164 |         }
 1165 |         else {
 1166 |           FileUtils.forceMkdir(file.getParentFile());
 1167 | 
 1168 |           if (log.isDebugEnabled() && file.exists()) {
 1169 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1170 |           }
 1171 | 
 1172 |           FileUtils.copy(in, file);
 1173 |         }
 1174 | 
 1175 |         ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
 1176 |         if (permissions != null) {
 1177 |           ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
 1178 |         }
 1179 |       }
 1180 |     }
 1181 |   }
 1182 | 
 1183 |   /**

### <org.zeroturnaround.zip.ZipUtil$Unwraper: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 1274 |     }
 1275 | 
 1276 |     public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 1277 |       String root = getRootName(zipEntry.getName());
 1278 |       if (rootDir == null) {
 1279 |         rootDir = root;
 1280 |       }
 1281 |       else if (!rootDir.equals(root)) {
 1282 |         throw new ZipException("Unwrapping with multiple roots is not supported, roots: " + rootDir + ", " + root);
 1283 |       }
 1284 | 
 1285 |       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
 1286 |       if (name != null) {
 1287 |         File file = new File(outputDir, name);
 1288 | 
 1289 |         /* If we see the relative traversal string of ".." we need to make sure
 1290 |          * that the outputdir + name doesn't leave the outputdir. See
 1291 |          * DirectoryTraversalMaliciousTest for details.
 1292 |          */
 1293 |         if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
 1294 |           throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
 1295 |         }
 1296 | 
 1297 |         if (zipEntry.isDirectory()) {
 1298 |           FileUtils.forceMkdir(file);
 1299 |         }
 1300 |         else {
 1301 |           FileUtils.forceMkdir(file.getParentFile());
 1302 | 
 1303 |           if (log.isDebugEnabled() && file.exists()) {
 1304 |             log.debug("Overwriting file '{}'.", zipEntry.getName());
 1305 |           }
 1306 | 
 1307 |           FileUtils.copy(in, file);
 1308 |         }
 1309 |       }
 1310 |     }
 1311 | 
 1312 |     private String getUnrootedName(String root, String name) {
 1313 |       return name.substring(root.length());

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
```

---

## 86/97 flow_id 1f1b4f8346 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 1f1b4f8346
key        : DRIVER => <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>@L1081/1
source     : <nesy.NesyDriver: void main(java.lang.String[])>[5@L11] %v4 = invokestatic nesy.Taint.src()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>[18@L1081] invokespecial %v11.<init>(canonicalDir, %v12)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.commons.FileUtilsV2_2: boolean isSymlink(java.io.File)>

## Application-code evidence (route or reachable-method fallback)
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
```

---

## 87/97 flow_id ed238c5914 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow ed238c5914
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

## 88/97 flow_id 9dbcea191a (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 9dbcea191a
key        : <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>@L3067/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>@L584/1
source     : <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>[36@L3067] path = invokevirtual e1.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>[78@L584] invokespecial copiedFile.<init>(destDir, %v59)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: boolean archiveEqualsInternal(java.io.File,java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 3039 |   }
 3040 | 
 3041 |   private static boolean archiveEqualsInternal(File f1, File f2) throws IOException {
 3042 |     ZipFile zf1 = null;
 3043 |     ZipFile zf2 = null;
 3044 |     try {
 3045 |       zf1 = new ZipFile(f1);
 3046 |       zf2 = new ZipFile(f2);
 3047 | 
 3048 |       // Check the number of entries
 3049 |       if (zf1.size() != zf2.size()) {
 3050 |         log.debug("Number of entries changed (" + zf1.size() + " vs " + zf2.size() + ").");
 3051 |         return false;
 3052 |       }
 3053 |       /*
 3054 |        * As there are same number of entries in both archives we can traverse
 3055 |        * all entries of one of the archives and get the corresponding entries
 3056 |        * from the other archive.
 3057 |        *
 3058 |        * If a corresponding entry is missing from the second archive the
 3059 |        * archives are different and we finish the comparison.
 3060 |        *
 3061 |        * We guarantee that no entry of the second archive is skipped as there
 3062 |        * are same number of unique entries in both archives.
 3063 |        */
 3064 |       Enumeration<? extends ZipEntry> en = zf1.entries();
 3065 |       while (en.hasMoreElements()) {
 3066 |         ZipEntry e1 = (ZipEntry) en.nextElement();
 3067 |         String path = e1.getName();
 3068 |         ZipEntry e2 = zf2.getEntry(path);
      | ... (lines omitted) ...
 3074 | 
 3075 |         // Check the content
 3076 |         InputStream is1 = null;
 3077 |         InputStream is2 = null;
 3078 |         try {
 3079 |           is1 = zf1.getInputStream(e1);
 3080 |           is2 = zf2.getInputStream(e2);
 3081 | 
 3082 |           if (!IOUtils.contentEquals(is1, is2)) {
 3083 |             log.debug("Entry '{}' content changed.", path);
 3084 |             return false;
 3085 |           }
 3086 |         }
 3087 |         finally {
 3088 |           IOUtils.closeQuietly(is1);
 3089 |           IOUtils.closeQuietly(is2);
 3090 |         }
 3091 |       }
 3092 |     }
 3093 |     finally {
 3094 |       closeQuietly(zf1);
 3095 |       closeQuietly(zf2);
 3096 |     }
 3097 | 
 3098 |     log.debug("Archives are the same.");
 3099 | 
 3100 |     return true;
 3101 |   }
 3102 | 
 3103 |   /**

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

## 89/97 flow_id afd6aaef14 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow afd6aaef14
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipInfoCallback)>@L629/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>@L584/1
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipInfoCallback)>[18@L629] %v18 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean)>[78@L584] invokespecial copiedFile.<init>(destDir, %v59)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

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

## 90/97 flow_id 5ac0fa8b04 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 5ac0fa8b04
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

## 91/97 flow_id dd3499936f (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow dd3499936f
key        : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>@L313/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFileToDirectory(java.io.File,java.io.File,boolean)>@L327/1
source     : <org.apache.log4j.Hierarchy: java.util.Enumeration getCurrentLoggers()>[9@L313] o = invokeinterface elems.nextElement()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFileToDirectory(java.io.File,java.io.File,boolean)>[23@L327] invokespecial destFile.<init>(destDir, %v19)/1
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2
N3 (iris-like run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.commons.FileUtilsV2_2: void copyFileToDirectory(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
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

## 92/97 flow_id 996cfc6f55 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 996cfc6f55
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

## 93/97 flow_id 2d86dd1be2 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 2d86dd1be2
key        : <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2372/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>@L623/1
source     : <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L2372] entryName = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>[65@L623] invokespecial dstFile.<init>(destDir, %v52)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2369 |     final Set<String> names = new HashSet<String>();
 2370 |     iterate(is, new ZipEntryCallback() {
 2371 |       public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2372 |         String entryName = zipEntry.getName();
 2373 |         if (names.add(entryName)) {
 2374 |           ZipEntryUtil.copyEntry(zipEntry, in, out);
 2375 |         }
 2376 |         else if (log.isDebugEnabled()) {
 2377 |           log.debug("Duplicate entry: {}", entryName);
 2378 |         }
 2379 |       }
 2380 |     });
 2381 |   }
 2382 | 

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

## 94/97 flow_id c1cace0a04 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow c1cace0a04
key        : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>@L511/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>@L623/1
source     : <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>[25@L511] %v24 = invokevirtual e.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>[65@L623] invokespecial dstFile.<init>(destDir, %v52)/1
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil: void iterate(java.io.File,org.zeroturnaround.zip.ZipEntryCallback,java.nio.charset.Charset)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyDirectory(java.io.File,java.io.File,java.io.FileFilter,boolean,java.util.List)>

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

## 95/97 flow_id 024b5b4061 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 024b5b4061
key        : <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2372/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>@L428/0
source     : <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>[1@L2372] entryName = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>[24@L428] invokespecial %v26.<init>(destFile)/0
fixed methods on this flow (GT): -
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: boolean operateInPlace(java.io.File,org.zeroturnaround.zip.ZipUtil$InPlaceAction)>, <org.zeroturnaround.zip.ZipUtil: boolean replaceEntries(java.io.File,org.zeroturnaround.zip.ZipEntrySource[])>, <org.zeroturnaround.zip.ZipUtil: boolean replaceEntry(java.io.File,java.lang.String,byte[])>, <org.zeroturnaround.zip.ZipUtil: boolean replaceEntry(java.io.File,java.lang.String,byte[],int)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$11: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2369 |     final Set<String> names = new HashSet<String>();
 2370 |     iterate(is, new ZipEntryCallback() {
 2371 |       public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2372 |         String entryName = zipEntry.getName();
 2373 |         if (names.add(entryName)) {
 2374 |           ZipEntryUtil.copyEntry(zipEntry, in, out);
 2375 |         }
 2376 |         else if (log.isDebugEnabled()) {
 2377 |           log.debug("Duplicate entry: {}", entryName);
 2378 |         }
 2379 |       }
 2380 |     });
 2381 |   }
 2382 | 

### <org.zeroturnaround.zip.ZipUtil: boolean operateInPlace(java.io.File,org.zeroturnaround.zip.ZipUtil$InPlaceAction)>
file: org/zeroturnaround/zip/ZipUtil.java
 3325 |    * @return result of the action
 3326 |    */
 3327 |   private static boolean operateInPlace(File src, InPlaceAction action) {
 3328 |     File tmp = null;
 3329 |     try {
 3330 |       tmp = File.createTempFile("zt-zip-tmp", ".zip");
 3331 |       boolean result = action.act(tmp);
 3332 |       if (result) { // else nothing changes
 3333 |         FileUtils.forceDelete(src);
 3334 |         FileUtils.moveFile(tmp, src);
 3335 |       }
 3336 |       return result;
 3337 |     }
 3338 |     catch (IOException e) {
 3339 |       throw ZipExceptionUtil.rethrow(e);
 3340 |     }
 3341 |     finally {
 3342 |       FileUtils.deleteQuietly(tmp);
 3343 |     }
 3344 |   }
 3345 | 
 3346 | }

### <org.zeroturnaround.zip.ZipUtil: boolean replaceEntries(java.io.File,org.zeroturnaround.zip.ZipEntrySource[])>
file: org/zeroturnaround/zip/ZipUtil.java
 2641 |    * @return <code>true</code> if at least one entry was replaced.
 2642 |    */
 2643 |   public static boolean replaceEntries(final File zip, final ZipEntrySource[] entries) {
 2644 |     return operateInPlace(zip, new InPlaceAction() {
 2645 |       public boolean act(File tmpFile) {
 2646 |         return replaceEntries(zip, entries, tmpFile);
 2647 |       }

### <org.zeroturnaround.zip.ZipUtil: boolean replaceEntry(java.io.File,java.lang.String,byte[])>
file: org/zeroturnaround/zip/ZipUtil.java
 2521 |    * @return <code>true</code> if the entry was replaced.
 2522 |    */
 2523 |   public static boolean replaceEntry(final File zip, final String path, final byte[] bytes) {
 2524 |     return operateInPlace(zip, new InPlaceAction() {
 2525 |       public boolean act(File tmpFile) {
 2526 |         return replaceEntry(zip, new ByteSource(path, bytes), tmpFile);
 2527 |       }

### <org.zeroturnaround.zip.ZipUtil: boolean replaceEntry(java.io.File,java.lang.String,byte[],int)>
file: org/zeroturnaround/zip/ZipUtil.java
 2543 |    */
 2544 |   public static boolean replaceEntry(final File zip, final String path, final byte[] bytes,
 2545 |       final int compressionMethod) {
 2546 |     return operateInPlace(zip, new InPlaceAction() {
 2547 |       public boolean act(File tmpFile) {
 2548 |         return replaceEntry(zip, new ByteSource(path, bytes, compressionMethod), tmpFile);
 2549 |       }

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

## 96/97 flow_id 87e080b2b9 (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 87e080b2b9
key        : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>@L2675/result => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>@L428/0
source     : <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>[2@L2675] %v5 = invokevirtual zipEntry.getName()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>[24@L428] invokespecial %v26.<init>(destFile)/0
fixed methods on this flow (GT): -
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>, <org.zeroturnaround.zip.ZipUtil: boolean operateInPlace(java.io.File,org.zeroturnaround.zip.ZipUtil$InPlaceAction)>, <org.zeroturnaround.zip.ZipUtil: boolean replaceEntries(java.io.File,org.zeroturnaround.zip.ZipEntrySource[])>, <org.zeroturnaround.zip.ZipUtil: boolean replaceEntry(java.io.File,java.lang.String,byte[])>, <org.zeroturnaround.zip.ZipUtil: boolean replaceEntry(java.io.File,java.lang.String,byte[],int)>, <org.zeroturnaround.zip.commons.FileUtilsV2_2: void doCopyFile(java.io.File,java.io.File,boolean)>

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil$19: void process(java.io.InputStream,java.util.zip.ZipEntry)>
file: org/zeroturnaround/zip/ZipUtil.java
 2672 |         final Set<String> names = new HashSet<String>();
 2673 |         iterate(zip, new ZipEntryCallback() {
 2674 |           public void process(InputStream in, ZipEntry zipEntry) throws IOException {
 2675 |             if (names.add(zipEntry.getName())) {
 2676 |               ZipEntrySource entry = (ZipEntrySource) entryByPath.remove(zipEntry.getName());
 2677 |               if (entry != null) {
 2678 |                 addEntry(entry, out);
 2679 |               }
 2680 |               else {
 2681 |                 ZipEntryUtil.copyEntry(zipEntry, in, out);
 2682 |               }
 2683 |             }
 2684 |             else if (log.isDebugEnabled()) {
 2685 |               log.debug("Duplicate entry: {}", zipEntry.getName());
 2686 |             }
 2687 |           }
 2688 |         });
 2689 | 
 2690 |         // Add new entries

### <org.zeroturnaround.zip.ZipUtil: boolean operateInPlace(java.io.File,org.zeroturnaround.zip.ZipUtil$InPlaceAction)>
file: org/zeroturnaround/zip/ZipUtil.java
 3325 |    * @return result of the action
 3326 |    */
 3327 |   private static boolean operateInPlace(File src, InPlaceAction action) {
 3328 |     File tmp = null;
 3329 |     try {
 3330 |       tmp = File.createTempFile("zt-zip-tmp", ".zip");
 3331 |       boolean result = action.act(tmp);
 3332 |       if (result) { // else nothing changes
 3333 |         FileUtils.forceDelete(src);
 3334 |         FileUtils.moveFile(tmp, src);
 3335 |       }
 3336 |       return result;
 3337 |     }
 3338 |     catch (IOException e) {
 3339 |       throw ZipExceptionUtil.rethrow(e);
 3340 |     }
 3341 |     finally {
 3342 |       FileUtils.deleteQuietly(tmp);
 3343 |     }
 3344 |   }
 3345 | 
 3346 | }

### <org.zeroturnaround.zip.ZipUtil: boolean replaceEntries(java.io.File,org.zeroturnaround.zip.ZipEntrySource[])>
file: org/zeroturnaround/zip/ZipUtil.java
 2641 |    * @return <code>true</code> if at least one entry was replaced.
 2642 |    */
 2643 |   public static boolean replaceEntries(final File zip, final ZipEntrySource[] entries) {
 2644 |     return operateInPlace(zip, new InPlaceAction() {
 2645 |       public boolean act(File tmpFile) {
 2646 |         return replaceEntries(zip, entries, tmpFile);
 2647 |       }

### <org.zeroturnaround.zip.ZipUtil: boolean replaceEntry(java.io.File,java.lang.String,byte[])>
file: org/zeroturnaround/zip/ZipUtil.java
 2521 |    * @return <code>true</code> if the entry was replaced.
 2522 |    */
 2523 |   public static boolean replaceEntry(final File zip, final String path, final byte[] bytes) {
 2524 |     return operateInPlace(zip, new InPlaceAction() {
 2525 |       public boolean act(File tmpFile) {
 2526 |         return replaceEntry(zip, new ByteSource(path, bytes), tmpFile);
 2527 |       }

### <org.zeroturnaround.zip.ZipUtil: boolean replaceEntry(java.io.File,java.lang.String,byte[],int)>
file: org/zeroturnaround/zip/ZipUtil.java
 2543 |    */
 2544 |   public static boolean replaceEntry(final File zip, final String path, final byte[] bytes,
 2545 |       final int compressionMethod) {
 2546 |     return operateInPlace(zip, new InPlaceAction() {
 2547 |       public boolean act(File tmpFile) {
 2548 |         return replaceEntry(zip, new ByteSource(path, bytes, compressionMethod), tmpFile);
 2549 |       }

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

## 97/97 flow_id 08beb1afcb (priority 2)

```text
# zt-zip/fixed (CVE-2018-1002201, CWE-022) flow 08beb1afcb
key        : DRIVER => <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>@L1044/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[172@L95] %v109 = invokestatic nesy.Taint.srcFile()/result
sink       : <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>[63@L1044] rename = invokevirtual srcFile.renameTo(destFile)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[172@L95] %v109 = invokestatic nesy.Taint.srcFile()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v109}
3. VarNode{<org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File)>/dir}
4. VarNode{<org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File,int)>/dir}
5. VarNode{<org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>/destFile}
6. <org.zeroturnaround.zip.commons.FileUtilsV2_2: void moveFile(java.io.File,java.io.File)>[63@L1044] rename = invokevirtual srcFile.renameTo(destFile)/0

## Application-code evidence (route or reachable-method fallback)
### <org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File)>
file: org/zeroturnaround/zip/ZipUtil.java
 1911 |    * @see #pack(File, File)
 1912 |    */
 1913 |   public static void unexplode(File dir) {
 1914 |     unexplode(dir, DEFAULT_COMPRESSION_LEVEL);
 1915 |   }
 1916 | 
 1917 |   /**
 1918 |    * Compresses a given directory in its own location.

### <org.zeroturnaround.zip.ZipUtil: void unexplode(java.io.File,int)>
file: org/zeroturnaround/zip/ZipUtil.java
 1931 |   public static void unexplode(File dir, int compressionLevel) {
 1932 |     try {
 1933 |       // Find a new unique name is the same directory
 1934 |       File zip = FileUtils.getTempFileFor(dir);
 1935 | 
 1936 |       // Pack it
 1937 |       pack(dir, zip, compressionLevel);
 1938 | 
 1939 |       // Delete the directory
 1940 |       FileUtils.deleteDirectory(dir);
 1941 | 
 1942 |       // Rename the archive
 1943 |       FileUtils.moveFile(zip, dir);
 1944 |     }
 1945 |     catch (IOException e) {
 1946 |       throw ZipExceptionUtil.rethrow(e);
 1947 |     }
 1948 |   }
 1949 | 
 1950 |   /**
 1951 |    * Compresses the given entries into an output stream.

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
