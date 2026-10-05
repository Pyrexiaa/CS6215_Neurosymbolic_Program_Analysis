# Labelling pack: spark / fixed

100 frozen sampled rows. Evidence uses the exact raw source and sink in the chosen run record. Existing labels remain unverified and are unchanged. A canonical key may still group different drivers or routes; inspect the attacker model before reusing a label. Original packets are retained in results/history/pre-evidence-refresh.tar.gz.

---

## 1/100 flow_id 87dd014ebd (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 87dd014ebd
key        : <org.eclipse.jetty.http.HttpParser: boolean parseHeaders(java.nio.ByteBuffer)>@L1002/result => <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L63/0
source     : <org.eclipse.jetty.http.HttpParser: boolean parseHeaders(java.nio.ByteBuffer)>[192@L1002] v = invokevirtual field.getValue()/result
sink       : <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L63] invokespecial %v36.<init>(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource
reported by: iris-like run0, iris-like run1, v1 run0, v1 run1
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>, <spark.Service: spark.Service staticFileLocation(java.lang.String)>, <spark.Spark: void externalStaticFileLocation(java.lang.String)>, <spark.Spark: void staticFileLocation(java.lang.String)>, <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>
file: spark/Service.java
  247 |      * @return the object with external folder set
  248 |      */
  249 |     public synchronized Service externalStaticFileLocation(String externalFolder) {
  250 |         if (initialized && !isRunningFromServlet()) {
  251 |             throwBeforeRouteMappingException();
  252 |         }
  253 | 
  254 |         externalStaticFileFolder = externalFolder;
  255 | 
  256 |         if (!servletExternalStaticLocationSet) {
  257 |             staticFilesConfiguration.configureExternal(externalStaticFileFolder);
  258 |             servletExternalStaticLocationSet = true;
  259 |         } else {
  260 |             LOG.warn("External static file location has already been set");
  261 |         }
  262 |         return this;
  263 |     }
  264 | 
  265 |     /**

### <spark.Service: spark.Service staticFileLocation(java.lang.String)>
file: spark/Service.java
  224 |      * @return the object with folder set
  225 |      */
  226 |     public synchronized Service staticFileLocation(String folder) {
  227 |         if (initialized && !isRunningFromServlet()) {
  228 |             throwBeforeRouteMappingException();
  229 |         }
  230 | 
  231 |         staticFileFolder = folder;
  232 | 
  233 |         if (!servletStaticLocationSet) {
  234 |             staticFilesConfiguration.configure(staticFileFolder);
  235 |             servletStaticLocationSet = true;
  236 |         } else {
  237 |             LOG.warn("Static file location has already been set");
  238 |         }
  239 |         return this;
  240 |     }
  241 | 
  242 |     /**

### <spark.Spark: void externalStaticFileLocation(java.lang.String)>
file: spark/Spark.java
 1031 |      * @param externalFolder the external folder serving static files.
 1032 |      */
 1033 |     public static void externalStaticFileLocation(String externalFolder) {
 1034 |         getInstance().externalStaticFileLocation(externalFolder);
 1035 |     }
 1036 | 
 1037 |     /**
 1038 |      * Waits for the spark server to be initialized.

### <spark.Spark: void staticFileLocation(java.lang.String)>
file: spark/Spark.java
 1019 |      * @param folder the folder in classpath.
 1020 |      */
 1021 |     public static void staticFileLocation(String folder) {
 1022 |         getInstance().staticFileLocation(folder);
 1023 |     }
 1024 | 
 1025 |     /**
 1026 |      * Sets the external folder serving static files. <b>Observe: this method

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ClassPathResourceHandler.java
   59 | 
   60 |     @Override
   61 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   62 |         if (path == null || !path.startsWith("/")) {
   63 |             throw new MalformedURLException(path);
   64 |         }
   65 | 
   66 |         try {
   67 |             path = UriPath.canonical(path);
   68 | 
   69 |             final String addedPath = addPaths(baseResource, path);
   70 | 
   71 |             ClassPathResource resource = new ClassPathResource(addedPath);
   72 | 
   73 |             if (resource.exists() && resource.getFile().isDirectory()) {
   74 |                 if (welcomeFile != null) {
   75 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   76 |                 } else {
   77 |                     //  No welcome file configured, serve nothing since it's a directory
   78 |                     resource = null;
   79 |                 }
   80 |             }
   81 | 
   82 |             if (resource != null && resource.exists()) {
   83 |                 DirectoryTraversal.protectAgainstInClassPath(resource.getPath());
   84 |                 return resource;
   85 |             } else {
   86 |                 return null;
   87 |             }
   88 | 
   89 |         } catch (DirectoryTraversal.DirectoryTraversalDetection directoryTraversalDetection) {
   90 |             throw directoryTraversalDetection;
   91 |         } catch (Exception e) {
   92 |             if (LOG.isDebugEnabled()) {
   93 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   94 |             }
   95 |         }
   96 |         return null;
   97 |     }
   98 | 
   99 | }
```

---

## 2/100 flow_id 78eb31e710 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 78eb31e710
key        : <org.eclipse.jetty.server.Request: java.lang.String findServerName()>@L1386/result => <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L63/0
source     : <org.eclipse.jetty.server.Request: java.lang.String findServerName()>[11@L1386] %v12 = invokevirtual host.getValue()/result
sink       : <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L63] invokespecial %v36.<init>(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource
reported by: iris-like run0, iris-like run1, v1 run0, v1 run1
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>, <spark.Service: spark.Service staticFileLocation(java.lang.String)>, <spark.Spark: void externalStaticFileLocation(java.lang.String)>, <spark.Spark: void staticFileLocation(java.lang.String)>, <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>
file: spark/Service.java
  247 |      * @return the object with external folder set
  248 |      */
  249 |     public synchronized Service externalStaticFileLocation(String externalFolder) {
  250 |         if (initialized && !isRunningFromServlet()) {
  251 |             throwBeforeRouteMappingException();
  252 |         }
  253 | 
  254 |         externalStaticFileFolder = externalFolder;
  255 | 
  256 |         if (!servletExternalStaticLocationSet) {
  257 |             staticFilesConfiguration.configureExternal(externalStaticFileFolder);
  258 |             servletExternalStaticLocationSet = true;
  259 |         } else {
  260 |             LOG.warn("External static file location has already been set");
  261 |         }
  262 |         return this;
  263 |     }
  264 | 
  265 |     /**

### <spark.Service: spark.Service staticFileLocation(java.lang.String)>
file: spark/Service.java
  224 |      * @return the object with folder set
  225 |      */
  226 |     public synchronized Service staticFileLocation(String folder) {
  227 |         if (initialized && !isRunningFromServlet()) {
  228 |             throwBeforeRouteMappingException();
  229 |         }
  230 | 
  231 |         staticFileFolder = folder;
  232 | 
  233 |         if (!servletStaticLocationSet) {
  234 |             staticFilesConfiguration.configure(staticFileFolder);
  235 |             servletStaticLocationSet = true;
  236 |         } else {
  237 |             LOG.warn("Static file location has already been set");
  238 |         }
  239 |         return this;
  240 |     }
  241 | 
  242 |     /**

### <spark.Spark: void externalStaticFileLocation(java.lang.String)>
file: spark/Spark.java
 1031 |      * @param externalFolder the external folder serving static files.
 1032 |      */
 1033 |     public static void externalStaticFileLocation(String externalFolder) {
 1034 |         getInstance().externalStaticFileLocation(externalFolder);
 1035 |     }
 1036 | 
 1037 |     /**
 1038 |      * Waits for the spark server to be initialized.

### <spark.Spark: void staticFileLocation(java.lang.String)>
file: spark/Spark.java
 1019 |      * @param folder the folder in classpath.
 1020 |      */
 1021 |     public static void staticFileLocation(String folder) {
 1022 |         getInstance().staticFileLocation(folder);
 1023 |     }
 1024 | 
 1025 |     /**
 1026 |      * Sets the external folder serving static files. <b>Observe: this method

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ClassPathResourceHandler.java
   59 | 
   60 |     @Override
   61 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   62 |         if (path == null || !path.startsWith("/")) {
   63 |             throw new MalformedURLException(path);
   64 |         }
   65 | 
   66 |         try {
   67 |             path = UriPath.canonical(path);
   68 | 
   69 |             final String addedPath = addPaths(baseResource, path);
   70 | 
   71 |             ClassPathResource resource = new ClassPathResource(addedPath);
   72 | 
   73 |             if (resource.exists() && resource.getFile().isDirectory()) {
   74 |                 if (welcomeFile != null) {
   75 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   76 |                 } else {
   77 |                     //  No welcome file configured, serve nothing since it's a directory
   78 |                     resource = null;
   79 |                 }
   80 |             }
   81 | 
   82 |             if (resource != null && resource.exists()) {
   83 |                 DirectoryTraversal.protectAgainstInClassPath(resource.getPath());
   84 |                 return resource;
   85 |             } else {
   86 |                 return null;
   87 |             }
   88 | 
   89 |         } catch (DirectoryTraversal.DirectoryTraversalDetection directoryTraversalDetection) {
   90 |             throw directoryTraversalDetection;
   91 |         } catch (Exception e) {
   92 |             if (LOG.isDebugEnabled()) {
   93 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   94 |             }
   95 |         }
   96 |         return null;
   97 |     }
   98 | 
   99 | }
```

---

## 3/100 flow_id 96e24ca037 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 96e24ca037
key        : <org.eclipse.jetty.websocket.server.WebSocketUpgradeFilter: void init(javax.servlet.FilterConfig)>@L282/result => <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L63/0
source     : <org.eclipse.jetty.websocket.server.WebSocketUpgradeFilter: void init(javax.servlet.FilterConfig)>[23@L282] max#3 = invokeinterface config.getInitParameter(%c21)/result
sink       : <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L63] invokespecial %v36.<init>(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource
reported by: iris-like run0, iris-like run1, v1 run0, v1 run1
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>, <spark.Service: spark.Service staticFileLocation(java.lang.String)>, <spark.Spark: void externalStaticFileLocation(java.lang.String)>, <spark.Spark: void staticFileLocation(java.lang.String)>, <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>
file: spark/Service.java
  247 |      * @return the object with external folder set
  248 |      */
  249 |     public synchronized Service externalStaticFileLocation(String externalFolder) {
  250 |         if (initialized && !isRunningFromServlet()) {
  251 |             throwBeforeRouteMappingException();
  252 |         }
  253 | 
  254 |         externalStaticFileFolder = externalFolder;
  255 | 
  256 |         if (!servletExternalStaticLocationSet) {
  257 |             staticFilesConfiguration.configureExternal(externalStaticFileFolder);
  258 |             servletExternalStaticLocationSet = true;
  259 |         } else {
  260 |             LOG.warn("External static file location has already been set");
  261 |         }
  262 |         return this;
  263 |     }
  264 | 
  265 |     /**

### <spark.Service: spark.Service staticFileLocation(java.lang.String)>
file: spark/Service.java
  224 |      * @return the object with folder set
  225 |      */
  226 |     public synchronized Service staticFileLocation(String folder) {
  227 |         if (initialized && !isRunningFromServlet()) {
  228 |             throwBeforeRouteMappingException();
  229 |         }
  230 | 
  231 |         staticFileFolder = folder;
  232 | 
  233 |         if (!servletStaticLocationSet) {
  234 |             staticFilesConfiguration.configure(staticFileFolder);
  235 |             servletStaticLocationSet = true;
  236 |         } else {
  237 |             LOG.warn("Static file location has already been set");
  238 |         }
  239 |         return this;
  240 |     }
  241 | 
  242 |     /**

### <spark.Spark: void externalStaticFileLocation(java.lang.String)>
file: spark/Spark.java
 1031 |      * @param externalFolder the external folder serving static files.
 1032 |      */
 1033 |     public static void externalStaticFileLocation(String externalFolder) {
 1034 |         getInstance().externalStaticFileLocation(externalFolder);
 1035 |     }
 1036 | 
 1037 |     /**
 1038 |      * Waits for the spark server to be initialized.

### <spark.Spark: void staticFileLocation(java.lang.String)>
file: spark/Spark.java
 1019 |      * @param folder the folder in classpath.
 1020 |      */
 1021 |     public static void staticFileLocation(String folder) {
 1022 |         getInstance().staticFileLocation(folder);
 1023 |     }
 1024 | 
 1025 |     /**
 1026 |      * Sets the external folder serving static files. <b>Observe: this method

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ClassPathResourceHandler.java
   59 | 
   60 |     @Override
   61 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   62 |         if (path == null || !path.startsWith("/")) {
   63 |             throw new MalformedURLException(path);
   64 |         }
   65 | 
   66 |         try {
   67 |             path = UriPath.canonical(path);
   68 | 
   69 |             final String addedPath = addPaths(baseResource, path);
   70 | 
   71 |             ClassPathResource resource = new ClassPathResource(addedPath);
   72 | 
   73 |             if (resource.exists() && resource.getFile().isDirectory()) {
   74 |                 if (welcomeFile != null) {
   75 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   76 |                 } else {
   77 |                     //  No welcome file configured, serve nothing since it's a directory
   78 |                     resource = null;
   79 |                 }
   80 |             }
   81 | 
   82 |             if (resource != null && resource.exists()) {
   83 |                 DirectoryTraversal.protectAgainstInClassPath(resource.getPath());
   84 |                 return resource;
   85 |             } else {
   86 |                 return null;
   87 |             }
   88 | 
   89 |         } catch (DirectoryTraversal.DirectoryTraversalDetection directoryTraversalDetection) {
   90 |             throw directoryTraversalDetection;
   91 |         } catch (Exception e) {
   92 |             if (LOG.isDebugEnabled()) {
   93 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   94 |             }
   95 |         }
   96 |         return null;
   97 |     }
   98 | 
   99 | }
```

---

## 4/100 flow_id 0c39547c78 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 0c39547c78
key        : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>@L72/result => <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L63/0
source     : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[21@L72] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L63] invokespecial %v36.<init>(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource, ExternalResourceHandler.getResource
reported by: iris-like run0, iris-like run1, v1 run0, v1 run1
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[21@L72] pathInfo = invokeinterface request.getPathInfo()/result
2. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>/pathInfo}
3. VarNode{<spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>/segment2}
4. VarNode{<spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>/pathInContext}
5. VarNode{<spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>/path}
6. <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L63] invokespecial %v36.<init>(path)/0

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/JarResourceHandler.java
   57 |         String servletPath;
   58 |         String pathInfo;
   59 | 
   60 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   61 | 
   62 |         if (included) {
   63 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   64 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   65 | 
   66 |             if (servletPath == null && pathInfo == null) {
   67 |                 servletPath = request.getServletPath();
   68 |                 pathInfo = request.getPathInfo();
   69 |             }
   70 |         } else {
   71 |             servletPath = request.getServletPath();
   72 |             pathInfo = request.getPathInfo();
   73 |         }
   74 | 
   75 |         String pathInContext = addPaths(servletPath, pathInfo);
   76 |         return getResourceStream(pathInContext);
   77 |     }
   78 | 
   79 |     private InputStream getResourceStream(String path) throws MalformedURLException {

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/AbstractResourceHandler.java
   40 |     public AbstractFileResolvingResource getResource(HttpServletRequest request) throws MalformedURLException {
   41 |         String servletPath;
   42 |         String pathInfo;
   43 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   44 | 
   45 |         if (included) {
   46 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   47 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   48 | 
   49 |             if (servletPath == null && pathInfo == null) {
   50 |                 servletPath = request.getServletPath();
   51 |                 pathInfo = request.getPathInfo();
   52 |             }
   53 |         } else {
   54 |             servletPath = request.getServletPath();
   55 |             pathInfo = request.getPathInfo();
   56 |         }
   57 | 
   58 |         String pathInContext = addPaths(servletPath, pathInfo);
   59 |         return getResource(pathInContext);
   60 |     }
   61 | 
   62 |     /**

### <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ClassPathResourceHandler.java
   59 | 
   60 |     @Override
   61 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   62 |         if (path == null || !path.startsWith("/")) {
   63 |             throw new MalformedURLException(path);
   64 |         }
   65 | 
   66 |         try {
   67 |             path = UriPath.canonical(path);
   68 | 
   69 |             final String addedPath = addPaths(baseResource, path);
   70 | 
   71 |             ClassPathResource resource = new ClassPathResource(addedPath);
   72 | 
   73 |             if (resource.exists() && resource.getFile().isDirectory()) {
   74 |                 if (welcomeFile != null) {
   75 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   76 |                 } else {
   77 |                     //  No welcome file configured, serve nothing since it's a directory
   78 |                     resource = null;
   79 |                 }
   80 |             }
   81 | 
   82 |             if (resource != null && resource.exists()) {
   83 |                 DirectoryTraversal.protectAgainstInClassPath(resource.getPath());
   84 |                 return resource;
   85 |             } else {
   86 |                 return null;
   87 |             }
   88 | 
   89 |         } catch (DirectoryTraversal.DirectoryTraversalDetection directoryTraversalDetection) {
   90 |             throw directoryTraversalDetection;
   91 |         } catch (Exception e) {
   92 |             if (LOG.isDebugEnabled()) {
   93 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   94 |             }
   95 |         }
   96 |         return null;
   97 |     }
   98 | 
   99 | }
```

---

## 5/100 flow_id d0416daf15 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow d0416daf15
key        : <org.eclipse.jetty.http.HttpFields: java.lang.String toString()>@L660/result => <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L62/0
source     : <org.eclipse.jetty.http.HttpFields: java.lang.String toString()>[14@L660] tmp#1 = invokevirtual field.getValue()/result
sink       : <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0
fixed methods on this flow (GT): ExternalResourceHandler.getResource
reported by: iris-like run0, iris-like run1, v1 run0, v1 run1
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>, <spark.Service: spark.Service staticFileLocation(java.lang.String)>, <spark.Spark: void externalStaticFileLocation(java.lang.String)>, <spark.Spark: void staticFileLocation(java.lang.String)>, <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>
file: spark/Service.java
  247 |      * @return the object with external folder set
  248 |      */
  249 |     public synchronized Service externalStaticFileLocation(String externalFolder) {
  250 |         if (initialized && !isRunningFromServlet()) {
  251 |             throwBeforeRouteMappingException();
  252 |         }
  253 | 
  254 |         externalStaticFileFolder = externalFolder;
  255 | 
  256 |         if (!servletExternalStaticLocationSet) {
  257 |             staticFilesConfiguration.configureExternal(externalStaticFileFolder);
  258 |             servletExternalStaticLocationSet = true;
  259 |         } else {
  260 |             LOG.warn("External static file location has already been set");
  261 |         }
  262 |         return this;
  263 |     }
  264 | 
  265 |     /**

### <spark.Service: spark.Service staticFileLocation(java.lang.String)>
file: spark/Service.java
  224 |      * @return the object with folder set
  225 |      */
  226 |     public synchronized Service staticFileLocation(String folder) {
  227 |         if (initialized && !isRunningFromServlet()) {
  228 |             throwBeforeRouteMappingException();
  229 |         }
  230 | 
  231 |         staticFileFolder = folder;
  232 | 
  233 |         if (!servletStaticLocationSet) {
  234 |             staticFilesConfiguration.configure(staticFileFolder);
  235 |             servletStaticLocationSet = true;
  236 |         } else {
  237 |             LOG.warn("Static file location has already been set");
  238 |         }
  239 |         return this;
  240 |     }
  241 | 
  242 |     /**

### <spark.Spark: void externalStaticFileLocation(java.lang.String)>
file: spark/Spark.java
 1031 |      * @param externalFolder the external folder serving static files.
 1032 |      */
 1033 |     public static void externalStaticFileLocation(String externalFolder) {
 1034 |         getInstance().externalStaticFileLocation(externalFolder);
 1035 |     }
 1036 | 
 1037 |     /**
 1038 |      * Waits for the spark server to be initialized.

### <spark.Spark: void staticFileLocation(java.lang.String)>
file: spark/Spark.java
 1019 |      * @param folder the folder in classpath.
 1020 |      */
 1021 |     public static void staticFileLocation(String folder) {
 1022 |         getInstance().staticFileLocation(folder);
 1023 |     }
 1024 | 
 1025 |     /**
 1026 |      * Sets the external folder serving static files. <b>Observe: this method

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   58 | 
   59 |     @Override
   60 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   61 |         if (path == null || !path.startsWith("/")) {
   62 |             throw new MalformedURLException(path);
   63 |         }
   64 | 
   65 |         try {
   66 |             path = UriPath.canonical(path);
   67 | 
   68 |             final String addedPath = addPaths(baseResource, path);
   69 | 
   70 |             ExternalResource resource = new ExternalResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             if (resource != null && resource.exists()) {
   82 |                 DirectoryTraversal.protectAgainstForExternal(resource.getPath());
   83 |                 return resource;
   84 |             } else {
   85 |                 return null;
   86 |             }
   87 | 
   88 |         } catch (DirectoryTraversal.DirectoryTraversalDetection directoryTraversalDetection) {
   89 |             throw directoryTraversalDetection;
   90 |         } catch (Exception e) {
   91 |             if (LOG.isDebugEnabled()) {
   92 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   93 |             }
   94 |         }
   95 |         return null;
   96 |     }
   97 | 
   98 | }
```

---

## 6/100 flow_id 9c84ecd37f (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 9c84ecd37f
key        : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>@L267/result => <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L62/0
source     : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>[30@L267] username = invokeinterface request.getParameter(%c37)/result
sink       : <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0
fixed methods on this flow (GT): ExternalResourceHandler.getResource
reported by: iris-like run0, iris-like run1, v1 run0, v1 run1
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>, <spark.Service: spark.Service staticFileLocation(java.lang.String)>, <spark.Spark: void externalStaticFileLocation(java.lang.String)>, <spark.Spark: void staticFileLocation(java.lang.String)>, <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>
file: spark/Service.java
  247 |      * @return the object with external folder set
  248 |      */
  249 |     public synchronized Service externalStaticFileLocation(String externalFolder) {
  250 |         if (initialized && !isRunningFromServlet()) {
  251 |             throwBeforeRouteMappingException();
  252 |         }
  253 | 
  254 |         externalStaticFileFolder = externalFolder;
  255 | 
  256 |         if (!servletExternalStaticLocationSet) {
  257 |             staticFilesConfiguration.configureExternal(externalStaticFileFolder);
  258 |             servletExternalStaticLocationSet = true;
  259 |         } else {
  260 |             LOG.warn("External static file location has already been set");
  261 |         }
  262 |         return this;
  263 |     }
  264 | 
  265 |     /**

### <spark.Service: spark.Service staticFileLocation(java.lang.String)>
file: spark/Service.java
  224 |      * @return the object with folder set
  225 |      */
  226 |     public synchronized Service staticFileLocation(String folder) {
  227 |         if (initialized && !isRunningFromServlet()) {
  228 |             throwBeforeRouteMappingException();
  229 |         }
  230 | 
  231 |         staticFileFolder = folder;
  232 | 
  233 |         if (!servletStaticLocationSet) {
  234 |             staticFilesConfiguration.configure(staticFileFolder);
  235 |             servletStaticLocationSet = true;
  236 |         } else {
  237 |             LOG.warn("Static file location has already been set");
  238 |         }
  239 |         return this;
  240 |     }
  241 | 
  242 |     /**

### <spark.Spark: void externalStaticFileLocation(java.lang.String)>
file: spark/Spark.java
 1031 |      * @param externalFolder the external folder serving static files.
 1032 |      */
 1033 |     public static void externalStaticFileLocation(String externalFolder) {
 1034 |         getInstance().externalStaticFileLocation(externalFolder);
 1035 |     }
 1036 | 
 1037 |     /**
 1038 |      * Waits for the spark server to be initialized.

### <spark.Spark: void staticFileLocation(java.lang.String)>
file: spark/Spark.java
 1019 |      * @param folder the folder in classpath.
 1020 |      */
 1021 |     public static void staticFileLocation(String folder) {
 1022 |         getInstance().staticFileLocation(folder);
 1023 |     }
 1024 | 
 1025 |     /**
 1026 |      * Sets the external folder serving static files. <b>Observe: this method

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   58 | 
   59 |     @Override
   60 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   61 |         if (path == null || !path.startsWith("/")) {
   62 |             throw new MalformedURLException(path);
   63 |         }
   64 | 
   65 |         try {
   66 |             path = UriPath.canonical(path);
   67 | 
   68 |             final String addedPath = addPaths(baseResource, path);
   69 | 
   70 |             ExternalResource resource = new ExternalResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             if (resource != null && resource.exists()) {
   82 |                 DirectoryTraversal.protectAgainstForExternal(resource.getPath());
   83 |                 return resource;
   84 |             } else {
   85 |                 return null;
   86 |             }
   87 | 
   88 |         } catch (DirectoryTraversal.DirectoryTraversalDetection directoryTraversalDetection) {
   89 |             throw directoryTraversalDetection;
   90 |         } catch (Exception e) {
   91 |             if (LOG.isDebugEnabled()) {
   92 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   93 |             }
   94 |         }
   95 |         return null;
   96 |     }
   97 | 
   98 | }
```

---

## 7/100 flow_id c796964b46 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow c796964b46
key        : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>@L187/result => <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L62/0
source     : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[75@L187] %v67 = invokevirtual %v66.getQuery()/result
sink       : <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0
fixed methods on this flow (GT): ExternalResourceHandler.getResource, ClassPathResourceHandler.getResource
reported by: iris-like run0, iris-like run1, v1 run0, v1 run1
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[75@L187] %v67 = invokevirtual %v66.getQuery()/result
2. VarNode{<org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>/%v67}
3. VarNode{<org.eclipse.jetty.http.HttpURI: void <init>(java.lang.String,java.lang.String,int,java.lang.String,java.lang.String,java.lang.String,java.lang.String)>/query}
4. InstanceFieldNode{NewObj{<org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[66@L186] new org.eclipse.jetty.http.HttpURI}.<org.eclipse.jetty.http.HttpURI: java.lang.String _query>}
5. VarNode{<org.eclipse.jetty.http.HttpURI: java.lang.String getQuery()>/%v1}
6. VarNode{<org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>/%v56}
7. InstanceFieldNode{NewObj{<org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[33@L163] new org.eclipse.jetty.server.Dispatcher$ForwardAttributes}.<org.eclipse.jetty.server.Dispatcher$ForwardAttributes: java.lang.
8. VarNode{<org.eclipse.jetty.server.Dispatcher$ForwardAttributes: java.lang.Object getAttribute(java.lang.String)>/%v20}
9. VarNode{<org.eclipse.jetty.server.Request: java.lang.Object getAttribute(java.lang.String)>/%v25}
10. VarNode{<javax.servlet.ServletRequestWrapper: java.lang.Object getAttribute(java.lang.String)>/%v3}
11. VarNode{<spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>/%v15}
12. VarNode{<spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>/pathInfo}
13. VarNode{<spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>/segment2}
14. VarNode{<spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>/pathInContext}
15. VarNode{<spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>/path}
16. <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/AbstractResourceHandler.java
   40 |     public AbstractFileResolvingResource getResource(HttpServletRequest request) throws MalformedURLException {
   41 |         String servletPath;
   42 |         String pathInfo;
   43 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   44 | 
   45 |         if (included) {
   46 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   47 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   48 | 
   49 |             if (servletPath == null && pathInfo == null) {
   50 |                 servletPath = request.getServletPath();
   51 |                 pathInfo = request.getPathInfo();
   52 |             }
   53 |         } else {
   54 |             servletPath = request.getServletPath();
   55 |             pathInfo = request.getPathInfo();
   56 |         }
   57 | 
   58 |         String pathInContext = addPaths(servletPath, pathInfo);
   59 |         return getResource(pathInContext);
   60 |     }
   61 | 
   62 |     /**

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   58 | 
   59 |     @Override
   60 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   61 |         if (path == null || !path.startsWith("/")) {
   62 |             throw new MalformedURLException(path);
   63 |         }
   64 | 
   65 |         try {
   66 |             path = UriPath.canonical(path);
   67 | 
   68 |             final String addedPath = addPaths(baseResource, path);
   69 | 
   70 |             ExternalResource resource = new ExternalResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             if (resource != null && resource.exists()) {
   82 |                 DirectoryTraversal.protectAgainstForExternal(resource.getPath());
   83 |                 return resource;
   84 |             } else {
   85 |                 return null;
   86 |             }
   87 | 
   88 |         } catch (DirectoryTraversal.DirectoryTraversalDetection directoryTraversalDetection) {
   89 |             throw directoryTraversalDetection;
   90 |         } catch (Exception e) {
   91 |             if (LOG.isDebugEnabled()) {
   92 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   93 |             }
   94 |         }
   95 |         return null;
   96 |     }
   97 | 
   98 | }
```

---

## 8/100 flow_id 58d33c3205 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 58d33c3205
key        : <org.eclipse.jetty.server.Request: java.lang.String getContentType()>@L658/result => <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L62/0
source     : <org.eclipse.jetty.server.Request: java.lang.String getContentType()>[3@L658] content_type = invokevirtual %v5.get(%v6)/result
sink       : <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0
fixed methods on this flow (GT): ExternalResourceHandler.getResource
reported by: iris-like run0, iris-like run1, v1 run0, v1 run1
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>, <spark.Service: spark.Service staticFileLocation(java.lang.String)>, <spark.Spark: void externalStaticFileLocation(java.lang.String)>, <spark.Spark: void staticFileLocation(java.lang.String)>, <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>
file: spark/Service.java
  247 |      * @return the object with external folder set
  248 |      */
  249 |     public synchronized Service externalStaticFileLocation(String externalFolder) {
  250 |         if (initialized && !isRunningFromServlet()) {
  251 |             throwBeforeRouteMappingException();
  252 |         }
  253 | 
  254 |         externalStaticFileFolder = externalFolder;
  255 | 
  256 |         if (!servletExternalStaticLocationSet) {
  257 |             staticFilesConfiguration.configureExternal(externalStaticFileFolder);
  258 |             servletExternalStaticLocationSet = true;
  259 |         } else {
  260 |             LOG.warn("External static file location has already been set");
  261 |         }
  262 |         return this;
  263 |     }
  264 | 
  265 |     /**

### <spark.Service: spark.Service staticFileLocation(java.lang.String)>
file: spark/Service.java
  224 |      * @return the object with folder set
  225 |      */
  226 |     public synchronized Service staticFileLocation(String folder) {
  227 |         if (initialized && !isRunningFromServlet()) {
  228 |             throwBeforeRouteMappingException();
  229 |         }
  230 | 
  231 |         staticFileFolder = folder;
  232 | 
  233 |         if (!servletStaticLocationSet) {
  234 |             staticFilesConfiguration.configure(staticFileFolder);
  235 |             servletStaticLocationSet = true;
  236 |         } else {
  237 |             LOG.warn("Static file location has already been set");
  238 |         }
  239 |         return this;
  240 |     }
  241 | 
  242 |     /**

### <spark.Spark: void externalStaticFileLocation(java.lang.String)>
file: spark/Spark.java
 1031 |      * @param externalFolder the external folder serving static files.
 1032 |      */
 1033 |     public static void externalStaticFileLocation(String externalFolder) {
 1034 |         getInstance().externalStaticFileLocation(externalFolder);
 1035 |     }
 1036 | 
 1037 |     /**
 1038 |      * Waits for the spark server to be initialized.

### <spark.Spark: void staticFileLocation(java.lang.String)>
file: spark/Spark.java
 1019 |      * @param folder the folder in classpath.
 1020 |      */
 1021 |     public static void staticFileLocation(String folder) {
 1022 |         getInstance().staticFileLocation(folder);
 1023 |     }
 1024 | 
 1025 |     /**
 1026 |      * Sets the external folder serving static files. <b>Observe: this method

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   58 | 
   59 |     @Override
   60 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   61 |         if (path == null || !path.startsWith("/")) {
   62 |             throw new MalformedURLException(path);
   63 |         }
   64 | 
   65 |         try {
   66 |             path = UriPath.canonical(path);
   67 | 
   68 |             final String addedPath = addPaths(baseResource, path);
   69 | 
   70 |             ExternalResource resource = new ExternalResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             if (resource != null && resource.exists()) {
   82 |                 DirectoryTraversal.protectAgainstForExternal(resource.getPath());
   83 |                 return resource;
   84 |             } else {
   85 |                 return null;
   86 |             }
   87 | 
   88 |         } catch (DirectoryTraversal.DirectoryTraversalDetection directoryTraversalDetection) {
   89 |             throw directoryTraversalDetection;
   90 |         } catch (Exception e) {
   91 |             if (LOG.isDebugEnabled()) {
   92 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   93 |             }
   94 |         }
   95 |         return null;
   96 |     }
   97 | 
   98 | }
```

---

## 9/100 flow_id 42c1100513 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 42c1100513
key        : <org.eclipse.jetty.server.Request: java.lang.String getServerName()>@L1367/result => <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L62/0
source     : <org.eclipse.jetty.server.Request: java.lang.String getServerName()>[2@L1367] name = invokevirtual %v3.getHost()/result
sink       : <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0
fixed methods on this flow (GT): ExternalResourceHandler.getResource
reported by: iris-like run0, iris-like run1, v1 run0, v1 run1
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>, <spark.Service: spark.Service staticFileLocation(java.lang.String)>, <spark.Spark: void externalStaticFileLocation(java.lang.String)>, <spark.Spark: void staticFileLocation(java.lang.String)>, <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>
file: spark/Service.java
  247 |      * @return the object with external folder set
  248 |      */
  249 |     public synchronized Service externalStaticFileLocation(String externalFolder) {
  250 |         if (initialized && !isRunningFromServlet()) {
  251 |             throwBeforeRouteMappingException();
  252 |         }
  253 | 
  254 |         externalStaticFileFolder = externalFolder;
  255 | 
  256 |         if (!servletExternalStaticLocationSet) {
  257 |             staticFilesConfiguration.configureExternal(externalStaticFileFolder);
  258 |             servletExternalStaticLocationSet = true;
  259 |         } else {
  260 |             LOG.warn("External static file location has already been set");
  261 |         }
  262 |         return this;
  263 |     }
  264 | 
  265 |     /**

### <spark.Service: spark.Service staticFileLocation(java.lang.String)>
file: spark/Service.java
  224 |      * @return the object with folder set
  225 |      */
  226 |     public synchronized Service staticFileLocation(String folder) {
  227 |         if (initialized && !isRunningFromServlet()) {
  228 |             throwBeforeRouteMappingException();
  229 |         }
  230 | 
  231 |         staticFileFolder = folder;
  232 | 
  233 |         if (!servletStaticLocationSet) {
  234 |             staticFilesConfiguration.configure(staticFileFolder);
  235 |             servletStaticLocationSet = true;
  236 |         } else {
  237 |             LOG.warn("Static file location has already been set");
  238 |         }
  239 |         return this;
  240 |     }
  241 | 
  242 |     /**

### <spark.Spark: void externalStaticFileLocation(java.lang.String)>
file: spark/Spark.java
 1031 |      * @param externalFolder the external folder serving static files.
 1032 |      */
 1033 |     public static void externalStaticFileLocation(String externalFolder) {
 1034 |         getInstance().externalStaticFileLocation(externalFolder);
 1035 |     }
 1036 | 
 1037 |     /**
 1038 |      * Waits for the spark server to be initialized.

### <spark.Spark: void staticFileLocation(java.lang.String)>
file: spark/Spark.java
 1019 |      * @param folder the folder in classpath.
 1020 |      */
 1021 |     public static void staticFileLocation(String folder) {
 1022 |         getInstance().staticFileLocation(folder);
 1023 |     }
 1024 | 
 1025 |     /**
 1026 |      * Sets the external folder serving static files. <b>Observe: this method

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   58 | 
   59 |     @Override
   60 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   61 |         if (path == null || !path.startsWith("/")) {
   62 |             throw new MalformedURLException(path);
   63 |         }
   64 | 
   65 |         try {
   66 |             path = UriPath.canonical(path);
   67 | 
   68 |             final String addedPath = addPaths(baseResource, path);
   69 | 
   70 |             ExternalResource resource = new ExternalResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             if (resource != null && resource.exists()) {
   82 |                 DirectoryTraversal.protectAgainstForExternal(resource.getPath());
   83 |                 return resource;
   84 |             } else {
   85 |                 return null;
   86 |             }
   87 | 
   88 |         } catch (DirectoryTraversal.DirectoryTraversalDetection directoryTraversalDetection) {
   89 |             throw directoryTraversalDetection;
   90 |         } catch (Exception e) {
   91 |             if (LOG.isDebugEnabled()) {
   92 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   93 |             }
   94 |         }
   95 |         return null;
   96 |     }
   97 | 
   98 | }
```

---

## 10/100 flow_id 4b50fb6cb6 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 4b50fb6cb6
key        : <org.eclipse.jetty.server.handler.gzip.GzipHttpOutputInterceptor: void commit(java.nio.ByteBuffer,boolean,org.eclipse.jetty.util.Callback)>@L212/result => <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L62/0
source     : <org.eclipse.jetty.server.handler.gzip.GzipHttpOutputInterceptor: void commit(java.nio.ByteBuffer,boolean,org.eclipse.jetty.util.Callback)>[116@L212] etag = invokevirtual fields.get(%v84)/result
sink       : <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0
fixed methods on this flow (GT): ExternalResourceHandler.getResource
reported by: iris-like run0, iris-like run1, v1 run0, v1 run1
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>, <spark.Service: spark.Service staticFileLocation(java.lang.String)>, <spark.Spark: void externalStaticFileLocation(java.lang.String)>, <spark.Spark: void staticFileLocation(java.lang.String)>, <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>
file: spark/Service.java
  247 |      * @return the object with external folder set
  248 |      */
  249 |     public synchronized Service externalStaticFileLocation(String externalFolder) {
  250 |         if (initialized && !isRunningFromServlet()) {
  251 |             throwBeforeRouteMappingException();
  252 |         }
  253 | 
  254 |         externalStaticFileFolder = externalFolder;
  255 | 
  256 |         if (!servletExternalStaticLocationSet) {
  257 |             staticFilesConfiguration.configureExternal(externalStaticFileFolder);
  258 |             servletExternalStaticLocationSet = true;
  259 |         } else {
  260 |             LOG.warn("External static file location has already been set");
  261 |         }
  262 |         return this;
  263 |     }
  264 | 
  265 |     /**

### <spark.Service: spark.Service staticFileLocation(java.lang.String)>
file: spark/Service.java
  224 |      * @return the object with folder set
  225 |      */
  226 |     public synchronized Service staticFileLocation(String folder) {
  227 |         if (initialized && !isRunningFromServlet()) {
  228 |             throwBeforeRouteMappingException();
  229 |         }
  230 | 
  231 |         staticFileFolder = folder;
  232 | 
  233 |         if (!servletStaticLocationSet) {
  234 |             staticFilesConfiguration.configure(staticFileFolder);
  235 |             servletStaticLocationSet = true;
  236 |         } else {
  237 |             LOG.warn("Static file location has already been set");
  238 |         }
  239 |         return this;
  240 |     }
  241 | 
  242 |     /**

### <spark.Spark: void externalStaticFileLocation(java.lang.String)>
file: spark/Spark.java
 1031 |      * @param externalFolder the external folder serving static files.
 1032 |      */
 1033 |     public static void externalStaticFileLocation(String externalFolder) {
 1034 |         getInstance().externalStaticFileLocation(externalFolder);
 1035 |     }
 1036 | 
 1037 |     /**
 1038 |      * Waits for the spark server to be initialized.

### <spark.Spark: void staticFileLocation(java.lang.String)>
file: spark/Spark.java
 1019 |      * @param folder the folder in classpath.
 1020 |      */
 1021 |     public static void staticFileLocation(String folder) {
 1022 |         getInstance().staticFileLocation(folder);
 1023 |     }
 1024 | 
 1025 |     /**
 1026 |      * Sets the external folder serving static files. <b>Observe: this method

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   58 | 
   59 |     @Override
   60 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   61 |         if (path == null || !path.startsWith("/")) {
   62 |             throw new MalformedURLException(path);
   63 |         }
   64 | 
   65 |         try {
   66 |             path = UriPath.canonical(path);
   67 | 
   68 |             final String addedPath = addPaths(baseResource, path);
   69 | 
   70 |             ExternalResource resource = new ExternalResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             if (resource != null && resource.exists()) {
   82 |                 DirectoryTraversal.protectAgainstForExternal(resource.getPath());
   83 |                 return resource;
   84 |             } else {
   85 |                 return null;
   86 |             }
   87 | 
   88 |         } catch (DirectoryTraversal.DirectoryTraversalDetection directoryTraversalDetection) {
   89 |             throw directoryTraversalDetection;
   90 |         } catch (Exception e) {
   91 |             if (LOG.isDebugEnabled()) {
   92 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   93 |             }
   94 |         }
   95 |         return null;
   96 |     }
   97 | 
   98 | }
```

---

## 11/100 flow_id c08e88ed45 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow c08e88ed45
key        : <org.eclipse.jetty.server.session.SessionHandler: void checkRequestedSessionId(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest)>@L267/result => <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L62/0
source     : <org.eclipse.jetty.server.session.SessionHandler: void checkRequestedSessionId(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest)>[36@L267] requested_session_id = invokevirtual %v30.getValue()/result
sink       : <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0
fixed methods on this flow (GT): ExternalResourceHandler.getResource
reported by: iris-like run0, iris-like run1, v1 run0, v1 run1
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>, <spark.Service: spark.Service staticFileLocation(java.lang.String)>, <spark.Spark: void externalStaticFileLocation(java.lang.String)>, <spark.Spark: void staticFileLocation(java.lang.String)>, <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>
file: spark/Service.java
  247 |      * @return the object with external folder set
  248 |      */
  249 |     public synchronized Service externalStaticFileLocation(String externalFolder) {
  250 |         if (initialized && !isRunningFromServlet()) {
  251 |             throwBeforeRouteMappingException();
  252 |         }
  253 | 
  254 |         externalStaticFileFolder = externalFolder;
  255 | 
  256 |         if (!servletExternalStaticLocationSet) {
  257 |             staticFilesConfiguration.configureExternal(externalStaticFileFolder);
  258 |             servletExternalStaticLocationSet = true;
  259 |         } else {
  260 |             LOG.warn("External static file location has already been set");
  261 |         }
  262 |         return this;
  263 |     }
  264 | 
  265 |     /**

### <spark.Service: spark.Service staticFileLocation(java.lang.String)>
file: spark/Service.java
  224 |      * @return the object with folder set
  225 |      */
  226 |     public synchronized Service staticFileLocation(String folder) {
  227 |         if (initialized && !isRunningFromServlet()) {
  228 |             throwBeforeRouteMappingException();
  229 |         }
  230 | 
  231 |         staticFileFolder = folder;
  232 | 
  233 |         if (!servletStaticLocationSet) {
  234 |             staticFilesConfiguration.configure(staticFileFolder);
  235 |             servletStaticLocationSet = true;
  236 |         } else {
  237 |             LOG.warn("Static file location has already been set");
  238 |         }
  239 |         return this;
  240 |     }
  241 | 
  242 |     /**

### <spark.Spark: void externalStaticFileLocation(java.lang.String)>
file: spark/Spark.java
 1031 |      * @param externalFolder the external folder serving static files.
 1032 |      */
 1033 |     public static void externalStaticFileLocation(String externalFolder) {
 1034 |         getInstance().externalStaticFileLocation(externalFolder);
 1035 |     }
 1036 | 
 1037 |     /**
 1038 |      * Waits for the spark server to be initialized.

### <spark.Spark: void staticFileLocation(java.lang.String)>
file: spark/Spark.java
 1019 |      * @param folder the folder in classpath.
 1020 |      */
 1021 |     public static void staticFileLocation(String folder) {
 1022 |         getInstance().staticFileLocation(folder);
 1023 |     }
 1024 | 
 1025 |     /**
 1026 |      * Sets the external folder serving static files. <b>Observe: this method

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   58 | 
   59 |     @Override
   60 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   61 |         if (path == null || !path.startsWith("/")) {
   62 |             throw new MalformedURLException(path);
   63 |         }
   64 | 
   65 |         try {
   66 |             path = UriPath.canonical(path);
   67 | 
   68 |             final String addedPath = addPaths(baseResource, path);
   69 | 
   70 |             ExternalResource resource = new ExternalResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             if (resource != null && resource.exists()) {
   82 |                 DirectoryTraversal.protectAgainstForExternal(resource.getPath());
   83 |                 return resource;
   84 |             } else {
   85 |                 return null;
   86 |             }
   87 | 
   88 |         } catch (DirectoryTraversal.DirectoryTraversalDetection directoryTraversalDetection) {
   89 |             throw directoryTraversalDetection;
   90 |         } catch (Exception e) {
   91 |             if (LOG.isDebugEnabled()) {
   92 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   93 |             }
   94 |         }
   95 |         return null;
   96 |     }
   97 | 
   98 | }
```

---

## 12/100 flow_id 53288576f7 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 53288576f7
key        : <org.eclipse.jetty.server.session.SessionHandler: void checkRequestedSessionId(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest)>@L293/result => <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L62/0
source     : <org.eclipse.jetty.server.session.SessionHandler: void checkRequestedSessionId(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest)>[60@L293] uri = invokeinterface request.getRequestURI()/result
sink       : <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0
fixed methods on this flow (GT): ExternalResourceHandler.getResource
reported by: iris-like run0, iris-like run1, v1 run0, v1 run1
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>, <spark.Service: spark.Service staticFileLocation(java.lang.String)>, <spark.Spark: void externalStaticFileLocation(java.lang.String)>, <spark.Spark: void staticFileLocation(java.lang.String)>, <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>
file: spark/Service.java
  247 |      * @return the object with external folder set
  248 |      */
  249 |     public synchronized Service externalStaticFileLocation(String externalFolder) {
  250 |         if (initialized && !isRunningFromServlet()) {
  251 |             throwBeforeRouteMappingException();
  252 |         }
  253 | 
  254 |         externalStaticFileFolder = externalFolder;
  255 | 
  256 |         if (!servletExternalStaticLocationSet) {
  257 |             staticFilesConfiguration.configureExternal(externalStaticFileFolder);
  258 |             servletExternalStaticLocationSet = true;
  259 |         } else {
  260 |             LOG.warn("External static file location has already been set");
  261 |         }
  262 |         return this;
  263 |     }
  264 | 
  265 |     /**

### <spark.Service: spark.Service staticFileLocation(java.lang.String)>
file: spark/Service.java
  224 |      * @return the object with folder set
  225 |      */
  226 |     public synchronized Service staticFileLocation(String folder) {
  227 |         if (initialized && !isRunningFromServlet()) {
  228 |             throwBeforeRouteMappingException();
  229 |         }
  230 | 
  231 |         staticFileFolder = folder;
  232 | 
  233 |         if (!servletStaticLocationSet) {
  234 |             staticFilesConfiguration.configure(staticFileFolder);
  235 |             servletStaticLocationSet = true;
  236 |         } else {
  237 |             LOG.warn("Static file location has already been set");
  238 |         }
  239 |         return this;
  240 |     }
  241 | 
  242 |     /**

### <spark.Spark: void externalStaticFileLocation(java.lang.String)>
file: spark/Spark.java
 1031 |      * @param externalFolder the external folder serving static files.
 1032 |      */
 1033 |     public static void externalStaticFileLocation(String externalFolder) {
 1034 |         getInstance().externalStaticFileLocation(externalFolder);
 1035 |     }
 1036 | 
 1037 |     /**
 1038 |      * Waits for the spark server to be initialized.

### <spark.Spark: void staticFileLocation(java.lang.String)>
file: spark/Spark.java
 1019 |      * @param folder the folder in classpath.
 1020 |      */
 1021 |     public static void staticFileLocation(String folder) {
 1022 |         getInstance().staticFileLocation(folder);
 1023 |     }
 1024 | 
 1025 |     /**
 1026 |      * Sets the external folder serving static files. <b>Observe: this method

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   58 | 
   59 |     @Override
   60 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   61 |         if (path == null || !path.startsWith("/")) {
   62 |             throw new MalformedURLException(path);
   63 |         }
   64 | 
   65 |         try {
   66 |             path = UriPath.canonical(path);
   67 | 
   68 |             final String addedPath = addPaths(baseResource, path);
   69 | 
   70 |             ExternalResource resource = new ExternalResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             if (resource != null && resource.exists()) {
   82 |                 DirectoryTraversal.protectAgainstForExternal(resource.getPath());
   83 |                 return resource;
   84 |             } else {
   85 |                 return null;
   86 |             }
   87 | 
   88 |         } catch (DirectoryTraversal.DirectoryTraversalDetection directoryTraversalDetection) {
   89 |             throw directoryTraversalDetection;
   90 |         } catch (Exception e) {
   91 |             if (LOG.isDebugEnabled()) {
   92 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   93 |             }
   94 |         }
   95 |         return null;
   96 |     }
   97 | 
   98 | }
```

---

## 13/100 flow_id b6c52c1af6 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow b6c52c1af6
key        : <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>@L102/result => <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L62/0
source     : <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>[14@L102] acceptType = invokeinterface httpRequest.getHeader(%c26)/result
sink       : <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0
fixed methods on this flow (GT): ExternalResourceHandler.getResource
reported by: iris-like run0, iris-like run1, v1 run0, v1 run1
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>, <spark.Service: spark.Service staticFileLocation(java.lang.String)>, <spark.Spark: void externalStaticFileLocation(java.lang.String)>, <spark.Spark: void staticFileLocation(java.lang.String)>, <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>, <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>
file: spark/Service.java
  247 |      * @return the object with external folder set
  248 |      */
  249 |     public synchronized Service externalStaticFileLocation(String externalFolder) {
  250 |         if (initialized && !isRunningFromServlet()) {
  251 |             throwBeforeRouteMappingException();
  252 |         }
  253 | 
  254 |         externalStaticFileFolder = externalFolder;
  255 | 
  256 |         if (!servletExternalStaticLocationSet) {
  257 |             staticFilesConfiguration.configureExternal(externalStaticFileFolder);
  258 |             servletExternalStaticLocationSet = true;
  259 |         } else {
  260 |             LOG.warn("External static file location has already been set");
  261 |         }
  262 |         return this;
  263 |     }
  264 | 
  265 |     /**

### <spark.Service: spark.Service staticFileLocation(java.lang.String)>
file: spark/Service.java
  224 |      * @return the object with folder set
  225 |      */
  226 |     public synchronized Service staticFileLocation(String folder) {
  227 |         if (initialized && !isRunningFromServlet()) {
  228 |             throwBeforeRouteMappingException();
  229 |         }
  230 | 
  231 |         staticFileFolder = folder;
  232 | 
  233 |         if (!servletStaticLocationSet) {
  234 |             staticFilesConfiguration.configure(staticFileFolder);
  235 |             servletStaticLocationSet = true;
  236 |         } else {
  237 |             LOG.warn("Static file location has already been set");
  238 |         }
  239 |         return this;
  240 |     }
  241 | 
  242 |     /**

### <spark.Spark: void externalStaticFileLocation(java.lang.String)>
file: spark/Spark.java
 1031 |      * @param externalFolder the external folder serving static files.
 1032 |      */
 1033 |     public static void externalStaticFileLocation(String externalFolder) {
 1034 |         getInstance().externalStaticFileLocation(externalFolder);
 1035 |     }
 1036 | 
 1037 |     /**
 1038 |      * Waits for the spark server to be initialized.

### <spark.Spark: void staticFileLocation(java.lang.String)>
file: spark/Spark.java
 1019 |      * @param folder the folder in classpath.
 1020 |      */
 1021 |     public static void staticFileLocation(String folder) {
 1022 |         getInstance().staticFileLocation(folder);
 1023 |     }
 1024 | 
 1025 |     /**
 1026 |      * Sets the external folder serving static files. <b>Observe: this method

### <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>
file: spark/http/matching/MatcherFilter.java
   85 |                          ServletResponse servletResponse,
   86 |                          FilterChain chain) throws IOException, ServletException {
   87 | 
   88 |         HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
   89 |         HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;
   90 | 
   91 |         // handle static resources
   92 |         boolean consumedByStaticFile = staticFiles.consume(httpRequest, httpResponse);
   93 | 
   94 |         if (consumedByStaticFile) {
   95 |             return;
   96 |         }
   97 | 
   98 |         String method = getHttpMethodFrom(httpRequest);
   99 | 
  100 |         String httpMethodStr = method.toLowerCase();
  101 |         String uri = httpRequest.getRequestURI();
  102 |         String acceptType = httpRequest.getHeader(ACCEPT_TYPE_REQUEST_MIME_HEADER);
  103 | 
  104 |         Body body = Body.create();
  105 | 
  106 |         RequestWrapper requestWrapper = RequestWrapper.create();
  107 |         ResponseWrapper responseWrapper = ResponseWrapper.create();
  108 | 
  109 |         Response response = RequestResponseFactory.create(httpResponse);
  110 | 
  111 |         HttpMethod httpMethod = HttpMethod.get(httpMethodStr);
  112 | 
  113 |         RouteContext context = RouteContext.create()
  114 |                 .withMatcher(routeMatcher)
      | ... (lines omitted) ...
  139 | 
  140 |         // If redirected and content is null set to empty string to not throw NotConsumedException
  141 |         if (body.notSet() && responseWrapper.isRedirected()) {
  142 |             body.set("");
  143 |         }
  144 | 
  145 |         if (body.notSet() && hasOtherHandlers) {
  146 |             if (servletRequest instanceof HttpRequestWrapper) {
  147 |                 ((HttpRequestWrapper) servletRequest).notConsumed(true);
  148 |                 return;
  149 |             }
  150 |         }
  151 | 
  152 |         if (body.notSet() && !externalContainer) {
  153 |             LOG.info("The requested route [{}] has not been mapped in Spark for {}: [{}]",
  154 |                 uri, ACCEPT_TYPE_REQUEST_MIME_HEADER, acceptType);
  155 |             httpResponse.setStatus(HttpServletResponse.SC_NOT_FOUND);
  156 |             body.set(String.format(NOT_FOUND));
  157 |         }
  158 | 
  159 |         if (body.isSet()) {
  160 |             body.serializeTo(httpResponse, serializerChain, httpRequest);
  161 | 
  162 |         } else if (chain != null) {
  163 |             chain.doFilter(httpRequest, httpResponse);
  164 |         }
  165 |     }
  166 | 
  167 |     private String getHttpMethodFrom(HttpServletRequest httpRequest) {
  168 |         String method = httpRequest.getHeader(HTTP_METHOD_OVERRIDE_HEADER);

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   58 | 
   59 |     @Override
   60 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   61 |         if (path == null || !path.startsWith("/")) {
   62 |             throw new MalformedURLException(path);
   63 |         }
   64 | 
   65 |         try {
   66 |             path = UriPath.canonical(path);
   67 | 
   68 |             final String addedPath = addPaths(baseResource, path);
   69 | 
   70 |             ExternalResource resource = new ExternalResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             if (resource != null && resource.exists()) {
   82 |                 DirectoryTraversal.protectAgainstForExternal(resource.getPath());
   83 |                 return resource;
   84 |             } else {
   85 |                 return null;
   86 |             }
   87 | 
   88 |         } catch (DirectoryTraversal.DirectoryTraversalDetection directoryTraversalDetection) {
   89 |             throw directoryTraversalDetection;
   90 |         } catch (Exception e) {
   91 |             if (LOG.isDebugEnabled()) {
   92 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   93 |             }
   94 |         }
   95 |         return null;
   96 |     }
   97 | 
   98 | }
```

---

## 14/100 flow_id 3e82d40508 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 3e82d40508
key        : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>@L68/result => <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L62/0
source     : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[18@L68] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0
fixed methods on this flow (GT): ExternalResourceHandler.getResource
reported by: iris-like run0, iris-like run1, v1 run0, v1 run1
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>, <spark.Service: spark.Service staticFileLocation(java.lang.String)>, <spark.Spark: void externalStaticFileLocation(java.lang.String)>, <spark.Spark: void staticFileLocation(java.lang.String)>, <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>
file: spark/Service.java
  247 |      * @return the object with external folder set
  248 |      */
  249 |     public synchronized Service externalStaticFileLocation(String externalFolder) {
  250 |         if (initialized && !isRunningFromServlet()) {
  251 |             throwBeforeRouteMappingException();
  252 |         }
  253 | 
  254 |         externalStaticFileFolder = externalFolder;
  255 | 
  256 |         if (!servletExternalStaticLocationSet) {
  257 |             staticFilesConfiguration.configureExternal(externalStaticFileFolder);
  258 |             servletExternalStaticLocationSet = true;
  259 |         } else {
  260 |             LOG.warn("External static file location has already been set");
  261 |         }
  262 |         return this;
  263 |     }
  264 | 
  265 |     /**

### <spark.Service: spark.Service staticFileLocation(java.lang.String)>
file: spark/Service.java
  224 |      * @return the object with folder set
  225 |      */
  226 |     public synchronized Service staticFileLocation(String folder) {
  227 |         if (initialized && !isRunningFromServlet()) {
  228 |             throwBeforeRouteMappingException();
  229 |         }
  230 | 
  231 |         staticFileFolder = folder;
  232 | 
  233 |         if (!servletStaticLocationSet) {
  234 |             staticFilesConfiguration.configure(staticFileFolder);
  235 |             servletStaticLocationSet = true;
  236 |         } else {
  237 |             LOG.warn("Static file location has already been set");
  238 |         }
  239 |         return this;
  240 |     }
  241 | 
  242 |     /**

### <spark.Spark: void externalStaticFileLocation(java.lang.String)>
file: spark/Spark.java
 1031 |      * @param externalFolder the external folder serving static files.
 1032 |      */
 1033 |     public static void externalStaticFileLocation(String externalFolder) {
 1034 |         getInstance().externalStaticFileLocation(externalFolder);
 1035 |     }
 1036 | 
 1037 |     /**
 1038 |      * Waits for the spark server to be initialized.

### <spark.Spark: void staticFileLocation(java.lang.String)>
file: spark/Spark.java
 1019 |      * @param folder the folder in classpath.
 1020 |      */
 1021 |     public static void staticFileLocation(String folder) {
 1022 |         getInstance().staticFileLocation(folder);
 1023 |     }
 1024 | 
 1025 |     /**
 1026 |      * Sets the external folder serving static files. <b>Observe: this method

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   58 | 
   59 |     @Override
   60 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   61 |         if (path == null || !path.startsWith("/")) {
   62 |             throw new MalformedURLException(path);
   63 |         }
   64 | 
   65 |         try {
   66 |             path = UriPath.canonical(path);
   67 | 
   68 |             final String addedPath = addPaths(baseResource, path);
   69 | 
   70 |             ExternalResource resource = new ExternalResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             if (resource != null && resource.exists()) {
   82 |                 DirectoryTraversal.protectAgainstForExternal(resource.getPath());
   83 |                 return resource;
   84 |             } else {
   85 |                 return null;
   86 |             }
   87 | 
   88 |         } catch (DirectoryTraversal.DirectoryTraversalDetection directoryTraversalDetection) {
   89 |             throw directoryTraversalDetection;
   90 |         } catch (Exception e) {
   91 |             if (LOG.isDebugEnabled()) {
   92 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   93 |             }
   94 |         }
   95 |         return null;
   96 |     }
   97 | 
   98 | }
```

---

## 15/100 flow_id dfbac02001 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow dfbac02001
key        : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>@L180/result => <spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>@L81/0
source     : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[60@L180] %v56 = invokevirtual old_uri.getQuery()/result
sink       : <spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>[6@L81] invokespecial %v28.<init>(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource, ExternalResourceHandler.getResource
reported by: iris-like run0, iris-like run1, v1 run0, v1 run1
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[60@L180] %v56 = invokevirtual old_uri.getQuery()/result
2. VarNode{<org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>/%v56}
3. InstanceFieldNode{NewObj{<org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[33@L163] new org.eclipse.jetty.server.Dispatcher$ForwardAttributes}.<org.eclipse.jetty.server.Dispatcher$ForwardAttributes: java.lang.
4. VarNode{<org.eclipse.jetty.server.Dispatcher$ForwardAttributes: java.lang.Object getAttribute(java.lang.String)>/%v20}
5. VarNode{<org.eclipse.jetty.server.Request: java.lang.Object getAttribute(java.lang.String)>/%v25}
6. VarNode{<javax.servlet.ServletRequestWrapper: java.lang.Object getAttribute(java.lang.String)>/%v3}
7. VarNode{<spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>/%v15}
8. VarNode{<spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>/pathInfo}
9. VarNode{<spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>/segment2}
10. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>/pathInContext}
11. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>/path}
12. <spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>[6@L81] invokespecial %v28.<init>(path)/0

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/AbstractResourceHandler.java
   40 |     public AbstractFileResolvingResource getResource(HttpServletRequest request) throws MalformedURLException {
   41 |         String servletPath;
   42 |         String pathInfo;
   43 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   44 | 
   45 |         if (included) {
   46 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   47 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   48 | 
   49 |             if (servletPath == null && pathInfo == null) {
   50 |                 servletPath = request.getServletPath();
   51 |                 pathInfo = request.getPathInfo();
   52 |             }
   53 |         } else {
   54 |             servletPath = request.getServletPath();
   55 |             pathInfo = request.getPathInfo();
   56 |         }
   57 | 
   58 |         String pathInContext = addPaths(servletPath, pathInfo);
   59 |         return getResource(pathInContext);
   60 |     }
   61 | 
   62 |     /**

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/JarResourceHandler.java
   57 |         String servletPath;
   58 |         String pathInfo;
   59 | 
   60 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   61 | 
   62 |         if (included) {
   63 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   64 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   65 | 
   66 |             if (servletPath == null && pathInfo == null) {
   67 |                 servletPath = request.getServletPath();
   68 |                 pathInfo = request.getPathInfo();
   69 |             }
   70 |         } else {
   71 |             servletPath = request.getServletPath();
   72 |             pathInfo = request.getPathInfo();
   73 |         }
   74 | 
   75 |         String pathInContext = addPaths(servletPath, pathInfo);
   76 |         return getResourceStream(pathInContext);
   77 |     }
   78 | 
   79 |     private InputStream getResourceStream(String path) throws MalformedURLException {

### <spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>
file: spark/resource/JarResourceHandler.java
   77 |     }
   78 | 
   79 |     private InputStream getResourceStream(String path) throws MalformedURLException {
   80 |         if (path == null || !path.startsWith("/")) {
   81 |             throw new MalformedURLException(path);
   82 |         }
   83 | 
   84 |         InputStream resourceStream = null;
   85 | 
   86 |         try {
   87 |             path = UriPath.canonical(path);
   88 |             path = addPaths(baseResource, path);
   89 | 
   90 |             if (isDirectory(path)) {
   91 |                 if (welcomeFileConfigured()) {
   92 |                     path = addPaths(path, welcomeFile);
   93 |                     resourceStream = loadStream(path);
   94 |                 }
   95 |             } else {
   96 |                 resourceStream = loadStream(path);
   97 |             }
   98 | 
   99 |         } catch (Exception e) {
  100 |             if (LOG.isDebugEnabled()) {
  101 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
  102 |             }
  103 |         }
  104 | 
  105 |         return resourceStream;
  106 |     }
  107 | 
  108 |     private InputStream loadStream(String path) {
```

---

## 16/100 flow_id aceb96f032 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow aceb96f032
key        : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>@L411/result => <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>@L109/0
source     : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>[311@L411] %v200 = invokeinterface request.getContextPath()/result
sink       : <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>[1@L109] %v3 = invokevirtual %c2.getResourceAsStream(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource, ExternalResourceHandler.getResource
reported by: iris-like run2, v1 run2, v4 run2
N3 (iris-like run2): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>[311@L411] %v200 = invokeinterface request.getContextPath()/result
2. VarNode{<org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>/%v200}
3. VarNode{<org.eclipse.jetty.util.URIUtil: java.lang.String addPaths(java.lang.String,java.lang.String)>/p1}
4. VarNode{<org.eclipse.jetty.server.Response: void sendRedirect(int,java.lang.String)>/%v25}
5. VarNode{<org.eclipse.jetty.util.URIUtil: java.lang.String canonicalPath(java.lang.String)>/path}
6. VarNode{<org.eclipse.jetty.server.Request: void setMetaData(org.eclipse.jetty.http.MetaData$Request)>/info}
7. VarNode{<org.eclipse.jetty.server.Request: void setPathInfo(java.lang.String)>/pathInfo}
8. InstanceFieldNode{NewObj{<org.eclipse.jetty.server.HttpChannel: void <init>(org.eclipse.jetty.server.Connector,org.eclipse.jetty.server.HttpConfiguration,org.eclipse.jetty.io.EndPoint,org.eclipse.jetty.server.HttpTransport)>[19@L94] new org.eclipse.jetty.server.Request}.<org.eclipse.jetty.server.Req
9. VarNode{<org.eclipse.jetty.server.Request: java.lang.String getPathInfo()>/%v1}
10. VarNode{<javax.servlet.http.HttpServletRequestWrapper: java.lang.String getPathInfo()>/%v2}
11. VarNode{<spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>/pathInfo}
12. VarNode{<spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>/segment2}
13. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>/path#3}
14. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>/path}
15. <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>[1@L109] %v3 = invokevirtual %c2.getResourceAsStream(path)/0

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/AbstractResourceHandler.java
   40 |     public AbstractFileResolvingResource getResource(HttpServletRequest request) throws MalformedURLException {
   41 |         String servletPath;
   42 |         String pathInfo;
   43 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   44 | 
   45 |         if (included) {
   46 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   47 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   48 | 
   49 |             if (servletPath == null && pathInfo == null) {
   50 |                 servletPath = request.getServletPath();
   51 |                 pathInfo = request.getPathInfo();
   52 |             }
   53 |         } else {
   54 |             servletPath = request.getServletPath();
   55 |             pathInfo = request.getPathInfo();
   56 |         }
   57 | 
   58 |         String pathInContext = addPaths(servletPath, pathInfo);
   59 |         return getResource(pathInContext);
   60 |     }
   61 | 
   62 |     /**

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>
file: spark/resource/JarResourceHandler.java
   77 |     }
   78 | 
   79 |     private InputStream getResourceStream(String path) throws MalformedURLException {
   80 |         if (path == null || !path.startsWith("/")) {
   81 |             throw new MalformedURLException(path);
   82 |         }
   83 | 
   84 |         InputStream resourceStream = null;
   85 | 
   86 |         try {
   87 |             path = UriPath.canonical(path);
   88 |             path = addPaths(baseResource, path);
   89 | 
   90 |             if (isDirectory(path)) {
   91 |                 if (welcomeFileConfigured()) {
   92 |                     path = addPaths(path, welcomeFile);
   93 |                     resourceStream = loadStream(path);
   94 |                 }
   95 |             } else {
   96 |                 resourceStream = loadStream(path);
   97 |             }
   98 | 
   99 |         } catch (Exception e) {
  100 |             if (LOG.isDebugEnabled()) {
  101 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
  102 |             }
  103 |         }
  104 | 
  105 |         return resourceStream;
  106 |     }
  107 | 
  108 |     private InputStream loadStream(String path) {

### <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>
file: spark/resource/JarResourceHandler.java
  106 |     }
  107 | 
  108 |     private InputStream loadStream(String path) {
  109 |         return JarResourceHandler.class.getResourceAsStream(path);
  110 |     }
  111 | 
  112 |     private boolean welcomeFileConfigured() {
```

---

## 17/100 flow_id efc543cd91 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow efc543cd91
key        : <org.eclipse.jetty.server.Request: java.lang.String getQueryString()>@L1141/result => <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>@L109/0
source     : <org.eclipse.jetty.server.Request: java.lang.String getQueryString()>[2@L1141] %v3 = invokevirtual %v2.getQuery()/result
sink       : <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>[1@L109] %v3 = invokevirtual %c2.getResourceAsStream(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource, ExternalResourceHandler.getResource
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <org.eclipse.jetty.server.Request: java.lang.String getQueryString()>[2@L1141] %v3 = invokevirtual %v2.getQuery()/result
2. VarNode{<org.eclipse.jetty.server.Request: java.lang.String getQueryString()>/%v3}
3. VarNode{<org.eclipse.jetty.server.Server: void handleAsync(org.eclipse.jetty.server.HttpChannel)>/query}
4. VarNode{<org.eclipse.jetty.server.Request: void mergeQueryParameters(java.lang.String,java.lang.String,boolean)>/oldQuery}
5. VarNode{<org.eclipse.jetty.server.Request: void setQueryString(java.lang.String)>/queryString}
6. VarNode{<org.eclipse.jetty.http.HttpURI: void setQuery(java.lang.String)>/query}
7. InstanceFieldNode{NewObj{<org.eclipse.jetty.server.HttpChannelOverHttp: void <init>(org.eclipse.jetty.server.HttpConnection,org.eclipse.jetty.server.Connector,org.eclipse.jetty.server.HttpConfiguration,org.eclipse.jetty.io.EndPoint,org.eclipse.jetty.server.HttpTransport)>[15@L66] new org.eclipse.jet
8. VarNode{<org.eclipse.jetty.http.HttpURI: java.lang.String getQuery()>/%v1}
9. VarNode{<org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>/%v56}
10. InstanceFieldNode{NewObj{<org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[33@L163] new org.eclipse.jetty.server.Dispatcher$ForwardAttributes}.<org.eclipse.jetty.server.Dispatcher$ForwardAttributes: java.lang.
11. VarNode{<org.eclipse.jetty.server.Dispatcher$ForwardAttributes: java.lang.Object getAttribute(java.lang.String)>/%v20}
12. VarNode{<org.eclipse.jetty.server.Request: java.lang.Object getAttribute(java.lang.String)>/%v25}
13. VarNode{<javax.servlet.ServletRequestWrapper: java.lang.Object getAttribute(java.lang.String)>/%v3}
14. VarNode{<spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>/%v15}
15. VarNode{<spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>/pathInfo}
16. VarNode{<spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>/segment2}
17. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>/path#2}
18. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>/path}
19. <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>[1@L109] %v3 = invokevirtual %c2.getResourceAsStream(path)/0

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/AbstractResourceHandler.java
   40 |     public AbstractFileResolvingResource getResource(HttpServletRequest request) throws MalformedURLException {
   41 |         String servletPath;
   42 |         String pathInfo;
   43 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   44 | 
   45 |         if (included) {
   46 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   47 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   48 | 
   49 |             if (servletPath == null && pathInfo == null) {
   50 |                 servletPath = request.getServletPath();
   51 |                 pathInfo = request.getPathInfo();
   52 |             }
   53 |         } else {
   54 |             servletPath = request.getServletPath();
   55 |             pathInfo = request.getPathInfo();
   56 |         }
   57 | 
   58 |         String pathInContext = addPaths(servletPath, pathInfo);
   59 |         return getResource(pathInContext);
   60 |     }
   61 | 
   62 |     /**

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>
file: spark/resource/JarResourceHandler.java
   77 |     }
   78 | 
   79 |     private InputStream getResourceStream(String path) throws MalformedURLException {
   80 |         if (path == null || !path.startsWith("/")) {
   81 |             throw new MalformedURLException(path);
   82 |         }
   83 | 
   84 |         InputStream resourceStream = null;
   85 | 
   86 |         try {
   87 |             path = UriPath.canonical(path);
   88 |             path = addPaths(baseResource, path);
   89 | 
   90 |             if (isDirectory(path)) {
   91 |                 if (welcomeFileConfigured()) {
   92 |                     path = addPaths(path, welcomeFile);
   93 |                     resourceStream = loadStream(path);
   94 |                 }
   95 |             } else {
   96 |                 resourceStream = loadStream(path);
   97 |             }
   98 | 
   99 |         } catch (Exception e) {
  100 |             if (LOG.isDebugEnabled()) {
  101 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
  102 |             }
  103 |         }
  104 | 
  105 |         return resourceStream;
  106 |     }
  107 | 
  108 |     private InputStream loadStream(String path) {

### <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>
file: spark/resource/JarResourceHandler.java
  106 |     }
  107 | 
  108 |     private InputStream loadStream(String path) {
  109 |         return JarResourceHandler.class.getResourceAsStream(path);
  110 |     }
  111 | 
  112 |     private boolean welcomeFileConfigured() {
```

---

## 18/100 flow_id ef653de66f (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow ef653de66f
key        : <org.eclipse.jetty.server.Server: void handleAsync(org.eclipse.jetty.server.HttpChannel)>@L553/result => <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>@L109/0
source     : <org.eclipse.jetty.server.Server: void handleAsync(org.eclipse.jetty.server.HttpChannel)>[21@L553] %v23 = invokevirtual uri.getQuery()/result
sink       : <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>[1@L109] %v3 = invokevirtual %c2.getResourceAsStream(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource, ExternalResourceHandler.getResource
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <org.eclipse.jetty.server.Server: void handleAsync(org.eclipse.jetty.server.HttpChannel)>[21@L553] %v23 = invokevirtual uri.getQuery()/result
2. VarNode{<org.eclipse.jetty.server.Server: void handleAsync(org.eclipse.jetty.server.HttpChannel)>/%v23}
3. VarNode{<org.eclipse.jetty.server.Request: void mergeQueryParameters(java.lang.String,java.lang.String,boolean)>/newQuery}
4. VarNode{<org.eclipse.jetty.server.Request: void setQueryString(java.lang.String)>/queryString}
5. VarNode{<org.eclipse.jetty.http.HttpURI: void setQuery(java.lang.String)>/query}
6. InstanceFieldNode{NewObj{<org.eclipse.jetty.server.HttpChannelOverHttp: void <init>(org.eclipse.jetty.server.HttpConnection,org.eclipse.jetty.server.Connector,org.eclipse.jetty.server.HttpConfiguration,org.eclipse.jetty.io.EndPoint,org.eclipse.jetty.server.HttpTransport)>[15@L66] new org.eclipse.jet
7. VarNode{<org.eclipse.jetty.http.HttpURI: java.lang.String getQuery()>/%v1}
8. VarNode{<org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>/%v56}
9. InstanceFieldNode{NewObj{<org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[33@L163] new org.eclipse.jetty.server.Dispatcher$ForwardAttributes}.<org.eclipse.jetty.server.Dispatcher$ForwardAttributes: java.lang.
10. VarNode{<org.eclipse.jetty.server.Dispatcher$ForwardAttributes: java.lang.Object getAttribute(java.lang.String)>/%v20}
11. VarNode{<org.eclipse.jetty.server.Request: java.lang.Object getAttribute(java.lang.String)>/%v25}
12. VarNode{<javax.servlet.ServletRequestWrapper: java.lang.Object getAttribute(java.lang.String)>/%v3}
13. VarNode{<spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>/%v15}
14. VarNode{<spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>/pathInfo}
15. VarNode{<spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>/segment2}
16. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>/path#2}
17. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>/path}
18. <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>[1@L109] %v3 = invokevirtual %c2.getResourceAsStream(path)/0

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/AbstractResourceHandler.java
   40 |     public AbstractFileResolvingResource getResource(HttpServletRequest request) throws MalformedURLException {
   41 |         String servletPath;
   42 |         String pathInfo;
   43 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   44 | 
   45 |         if (included) {
   46 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   47 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   48 | 
   49 |             if (servletPath == null && pathInfo == null) {
   50 |                 servletPath = request.getServletPath();
   51 |                 pathInfo = request.getPathInfo();
   52 |             }
   53 |         } else {
   54 |             servletPath = request.getServletPath();
   55 |             pathInfo = request.getPathInfo();
   56 |         }
   57 | 
   58 |         String pathInContext = addPaths(servletPath, pathInfo);
   59 |         return getResource(pathInContext);
   60 |     }
   61 | 
   62 |     /**

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>
file: spark/resource/JarResourceHandler.java
   77 |     }
   78 | 
   79 |     private InputStream getResourceStream(String path) throws MalformedURLException {
   80 |         if (path == null || !path.startsWith("/")) {
   81 |             throw new MalformedURLException(path);
   82 |         }
   83 | 
   84 |         InputStream resourceStream = null;
   85 | 
   86 |         try {
   87 |             path = UriPath.canonical(path);
   88 |             path = addPaths(baseResource, path);
   89 | 
   90 |             if (isDirectory(path)) {
   91 |                 if (welcomeFileConfigured()) {
   92 |                     path = addPaths(path, welcomeFile);
   93 |                     resourceStream = loadStream(path);
   94 |                 }
   95 |             } else {
   96 |                 resourceStream = loadStream(path);
   97 |             }
   98 | 
   99 |         } catch (Exception e) {
  100 |             if (LOG.isDebugEnabled()) {
  101 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
  102 |             }
  103 |         }
  104 | 
  105 |         return resourceStream;
  106 |     }
  107 | 
  108 |     private InputStream loadStream(String path) {

### <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>
file: spark/resource/JarResourceHandler.java
  106 |     }
  107 | 
  108 |     private InputStream loadStream(String path) {
  109 |         return JarResourceHandler.class.getResourceAsStream(path);
  110 |     }
  111 | 
  112 |     private boolean welcomeFileConfigured() {
```

---

## 19/100 flow_id 356125cd13 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 356125cd13
key        : <org.eclipse.jetty.servlet.ServletHandler: void notFound(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>@L1556/result => <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>@L109/0
source     : <org.eclipse.jetty.servlet.ServletHandler: void notFound(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>[13@L1556] %v14 = invokeinterface request.getServletPath()/result
sink       : <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>[1@L109] %v3 = invokevirtual %c2.getResourceAsStream(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource, ExternalResourceHandler.getResource
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <org.eclipse.jetty.servlet.ServletHandler: void notFound(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>[13@L1556] %v14 = invokeinterface request.getServletPath()/result
2. VarNode{<org.eclipse.jetty.servlet.ServletHandler: void notFound(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>/%v14}
3. VarNode{<org.eclipse.jetty.util.URIUtil: java.lang.String addPaths(java.lang.String,java.lang.String)>/p1}
4. VarNode{<org.eclipse.jetty.server.Response: void sendRedirect(int,java.lang.String)>/%v25}
5. VarNode{<org.eclipse.jetty.util.URIUtil: java.lang.String canonicalPath(java.lang.String)>/path}
6. VarNode{<org.eclipse.jetty.server.Request: void setMetaData(org.eclipse.jetty.http.MetaData$Request)>/info}
7. VarNode{<org.eclipse.jetty.server.Request: void setPathInfo(java.lang.String)>/pathInfo}
8. InstanceFieldNode{NewObj{<org.eclipse.jetty.server.HttpChannel: void <init>(org.eclipse.jetty.server.Connector,org.eclipse.jetty.server.HttpConfiguration,org.eclipse.jetty.io.EndPoint,org.eclipse.jetty.server.HttpTransport)>[19@L94] new org.eclipse.jetty.server.Request}.<org.eclipse.jetty.server.Req
9. VarNode{<org.eclipse.jetty.server.Request: java.lang.String getPathInfo()>/%v1}
10. VarNode{<javax.servlet.http.HttpServletRequestWrapper: java.lang.String getPathInfo()>/%v2}
11. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>/pathInfo}
12. VarNode{<spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>/segment2}
13. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>/path#2}
14. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>/path}
15. <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>[1@L109] %v3 = invokevirtual %c2.getResourceAsStream(path)/0

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/JarResourceHandler.java
   57 |         String servletPath;
   58 |         String pathInfo;
   59 | 
   60 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   61 | 
   62 |         if (included) {
   63 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   64 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   65 | 
   66 |             if (servletPath == null && pathInfo == null) {
   67 |                 servletPath = request.getServletPath();
   68 |                 pathInfo = request.getPathInfo();
   69 |             }
   70 |         } else {
   71 |             servletPath = request.getServletPath();
   72 |             pathInfo = request.getPathInfo();
   73 |         }
   74 | 
   75 |         String pathInContext = addPaths(servletPath, pathInfo);
   76 |         return getResourceStream(pathInContext);
   77 |     }
   78 | 
   79 |     private InputStream getResourceStream(String path) throws MalformedURLException {

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>
file: spark/resource/JarResourceHandler.java
   77 |     }
   78 | 
   79 |     private InputStream getResourceStream(String path) throws MalformedURLException {
   80 |         if (path == null || !path.startsWith("/")) {
   81 |             throw new MalformedURLException(path);
   82 |         }
   83 | 
   84 |         InputStream resourceStream = null;
   85 | 
   86 |         try {
   87 |             path = UriPath.canonical(path);
   88 |             path = addPaths(baseResource, path);
   89 | 
   90 |             if (isDirectory(path)) {
   91 |                 if (welcomeFileConfigured()) {
   92 |                     path = addPaths(path, welcomeFile);
   93 |                     resourceStream = loadStream(path);
   94 |                 }
   95 |             } else {
   96 |                 resourceStream = loadStream(path);
   97 |             }
   98 | 
   99 |         } catch (Exception e) {
  100 |             if (LOG.isDebugEnabled()) {
  101 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
  102 |             }
  103 |         }
  104 | 
  105 |         return resourceStream;
  106 |     }
  107 | 
  108 |     private InputStream loadStream(String path) {

### <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>
file: spark/resource/JarResourceHandler.java
  106 |     }
  107 | 
  108 |     private InputStream loadStream(String path) {
  109 |         return JarResourceHandler.class.getResourceAsStream(path);
  110 |     }
  111 | 
  112 |     private boolean welcomeFileConfigured() {
```

---

## 20/100 flow_id dccb4dad3e (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow dccb4dad3e
key        : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>@L67/result => <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>@L109/0
source     : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[17@L67] servletPath = invokeinterface request.getServletPath()/result
sink       : <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>[1@L109] %v3 = invokevirtual %c2.getResourceAsStream(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource, ExternalResourceHandler.getResource
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[17@L67] servletPath = invokeinterface request.getServletPath()/result
2. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>/servletPath}
3. VarNode{<spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>/segment1}
4. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>/path#3}
5. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>/path}
6. <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>[1@L109] %v3 = invokevirtual %c2.getResourceAsStream(path)/0

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/JarResourceHandler.java
   57 |         String servletPath;
   58 |         String pathInfo;
   59 | 
   60 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   61 | 
   62 |         if (included) {
   63 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   64 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   65 | 
   66 |             if (servletPath == null && pathInfo == null) {
   67 |                 servletPath = request.getServletPath();
   68 |                 pathInfo = request.getPathInfo();
   69 |             }
   70 |         } else {
   71 |             servletPath = request.getServletPath();
   72 |             pathInfo = request.getPathInfo();
   73 |         }
   74 | 
   75 |         String pathInContext = addPaths(servletPath, pathInfo);
   76 |         return getResourceStream(pathInContext);
   77 |     }
   78 | 
   79 |     private InputStream getResourceStream(String path) throws MalformedURLException {

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>
file: spark/resource/JarResourceHandler.java
   77 |     }
   78 | 
   79 |     private InputStream getResourceStream(String path) throws MalformedURLException {
   80 |         if (path == null || !path.startsWith("/")) {
   81 |             throw new MalformedURLException(path);
   82 |         }
   83 | 
   84 |         InputStream resourceStream = null;
   85 | 
   86 |         try {
   87 |             path = UriPath.canonical(path);
   88 |             path = addPaths(baseResource, path);
   89 | 
   90 |             if (isDirectory(path)) {
   91 |                 if (welcomeFileConfigured()) {
   92 |                     path = addPaths(path, welcomeFile);
   93 |                     resourceStream = loadStream(path);
   94 |                 }
   95 |             } else {
   96 |                 resourceStream = loadStream(path);
   97 |             }
   98 | 
   99 |         } catch (Exception e) {
  100 |             if (LOG.isDebugEnabled()) {
  101 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
  102 |             }
  103 |         }
  104 | 
  105 |         return resourceStream;
  106 |     }
  107 | 
  108 |     private InputStream loadStream(String path) {

### <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>
file: spark/resource/JarResourceHandler.java
  106 |     }
  107 | 
  108 |     private InputStream loadStream(String path) {
  109 |         return JarResourceHandler.class.getResourceAsStream(path);
  110 |     }
  111 | 
  112 |     private boolean welcomeFileConfigured() {
```

---

## 21/100 flow_id 4ea1f3e7a4 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 4ea1f3e7a4
key        : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>@L257/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/base
source     : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>[16@L257] %v28 = invokeinterface request.getServletPath()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[19@L219] %v17 = invokevirtual %v16.getSchemeSpecificPart()/base
fixed methods on this flow (GT): ClassPathResourceHandler.getResource, ExternalResourceHandler.getResource
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>[16@L257] %v28 = invokeinterface request.getServletPath()/result
2. VarNode{<org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>/%v28}
3. VarNode{<org.eclipse.jetty.util.URIUtil: java.lang.String addPaths(java.lang.String,java.lang.String)>/p1}
4. VarNode{<org.eclipse.jetty.server.Response: void sendRedirect(int,java.lang.String)>/%v25}
5. VarNode{<org.eclipse.jetty.util.URIUtil: java.lang.String canonicalPath(java.lang.String)>/path}
6. VarNode{<org.eclipse.jetty.server.Request: void setMetaData(org.eclipse.jetty.http.MetaData$Request)>/info}
7. VarNode{<org.eclipse.jetty.server.Request: void setPathInfo(java.lang.String)>/pathInfo}
8. InstanceFieldNode{NewObj{<org.eclipse.jetty.server.HttpChannel: void <init>(org.eclipse.jetty.server.Connector,org.eclipse.jetty.server.HttpConfiguration,org.eclipse.jetty.io.EndPoint,org.eclipse.jetty.server.HttpTransport)>[19@L94] new org.eclipse.jetty.server.Request}.<org.eclipse.jetty.server.Req
9. VarNode{<org.eclipse.jetty.server.Request: java.lang.String getPathInfo()>/%v1}
10. VarNode{<javax.servlet.http.HttpServletRequestWrapper: java.lang.String getPathInfo()>/%v2}
11. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>/pathInfo}
12. VarNode{<spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>/segment2}
13. VarNode{<spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>/addedPath}
14. VarNode{<spark.resource.ExternalResource: void <init>(java.lang.String)>/path}
15. VarNode{<spark.utils.StringUtils: java.lang.String cleanPath(java.lang.String)>/path}
16. VarNode{<spark.utils.StringUtils: java.lang.String replace(java.lang.String,java.lang.String,java.lang.String)>/inString}
17. VarNode{<spark.utils.ResourceUtils: java.net.URI toURI(java.lang.String)>/%v4}
18. VarNode{<spark.utils.ResourceUtils: java.net.URI toURI(java.lang.String)>/%v1}
19. VarNode{<spark.utils.ResourceUtils: java.net.URI toURI(java.net.URL)>/%v2}
20. VarNode{<spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>/%v16}
21. <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[19@L219] %v17 = invokevirtual %v16.getSchemeSpecificPart()/base

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/JarResourceHandler.java
   57 |         String servletPath;
   58 |         String pathInfo;
   59 | 
   60 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   61 | 
   62 |         if (included) {
   63 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   64 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   65 | 
   66 |             if (servletPath == null && pathInfo == null) {
   67 |                 servletPath = request.getServletPath();
   68 |                 pathInfo = request.getPathInfo();
   69 |             }
   70 |         } else {
   71 |             servletPath = request.getServletPath();
   72 |             pathInfo = request.getPathInfo();
   73 |         }
   74 | 
   75 |         String pathInContext = addPaths(servletPath, pathInfo);
   76 |         return getResourceStream(pathInContext);
   77 |     }
   78 | 
   79 |     private InputStream getResourceStream(String path) throws MalformedURLException {

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   58 | 
   59 |     @Override
   60 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   61 |         if (path == null || !path.startsWith("/")) {
   62 |             throw new MalformedURLException(path);
   63 |         }
   64 | 
   65 |         try {
   66 |             path = UriPath.canonical(path);
   67 | 
   68 |             final String addedPath = addPaths(baseResource, path);
   69 | 
   70 |             ExternalResource resource = new ExternalResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             if (resource != null && resource.exists()) {
   82 |                 DirectoryTraversal.protectAgainstForExternal(resource.getPath());
   83 |                 return resource;
   84 |             } else {
   85 |                 return null;
   86 |             }
   87 | 
   88 |         } catch (DirectoryTraversal.DirectoryTraversalDetection directoryTraversalDetection) {
   89 |             throw directoryTraversalDetection;
   90 |         } catch (Exception e) {
   91 |             if (LOG.isDebugEnabled()) {
   92 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   93 |             }
   94 |         }
   95 |         return null;
   96 |     }
   97 | 
   98 | }

### <spark.resource.ExternalResource: void <init>(java.lang.String)>
file: spark/resource/ExternalResource.java
   36 |      *
   37 |      * @param path the path to the external resource
   38 |      */
   39 |     public ExternalResource(String path) {
   40 |         file = new File(StringUtils.cleanPath(path));
   41 |     }
   42 | 
   43 |     /**
   44 |      * Tests whether the file denoted by this abstract pathname is a

### <spark.utils.StringUtils: java.lang.String cleanPath(java.lang.String)>
file: spark/utils/StringUtils.java
  216 |      * @return the normalized path
  217 |      */
  218 |     public static String cleanPath(String path) {
  219 |         if (path == null) {
  220 |             return null;
  221 |         }
  222 |         String pathToUse = replace(path, WINDOWS_FOLDER_SEPARATOR, FOLDER_SEPARATOR);
  223 | 
  224 |         // Strip prefix from path to analyze, to not treat it as part of the
  225 |         // first path element. This is necessary to correctly parse paths like
  226 |         // "file:core/../core/io/Resource.class", where the ".." should just
  227 |         // strip the first "core" directory while keeping the "file:" prefix.
  228 |         int prefixIndex = pathToUse.indexOf(":");
  229 |         String prefix = "";
  230 |         if (prefixIndex != -1) {
  231 |             prefix = pathToUse.substring(0, prefixIndex + 1);
  232 |             pathToUse = pathToUse.substring(prefixIndex + 1);
  233 |         }
  234 |         if (pathToUse.startsWith(FOLDER_SEPARATOR)) {
  235 |             prefix = prefix + FOLDER_SEPARATOR;
  236 |             pathToUse = pathToUse.substring(1);
  237 |         }
  238 | 
  239 |         String[] pathArray = delimitedListToStringArray(pathToUse, FOLDER_SEPARATOR);
  240 |         List<String> pathElements = new LinkedList<>();
  241 |         int tops = 0;
  242 | 
  243 |         for (int i = pathArray.length - 1; i >= 0; i--) {
  244 |             String element = pathArray[i];
  245 |             if (CURRENT_PATH.equals(element)) {
  246 |                 // Points to current directory - drop it.
  247 |             } else if (TOP_PATH.equals(element)) {
  248 |                 // Registering top path found.
  249 |                 tops++;
  250 |             } else {
  251 |                 if (tops > 0) {
  252 |                     // Merging path element with element corresponding to top path.
  253 |                     tops--;
  254 |                 } else {
  255 |                     // Normal path element found.
  256 |                     pathElements.add(0, element);
  257 |                 }
  258 |             }
  259 |         }
  260 | 
  261 |         // Remaining top paths need to be retained.
  262 |         for (int i = 0; i < tops; i++) {
  263 |             pathElements.add(0, TOP_PATH);
  264 |         }
  265 | 
  266 |         return prefix + collectionToDelimitedString(pathElements, FOLDER_SEPARATOR);
  267 |     }
  268 | 
  269 |     /**

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 22/100 flow_id abbccf04f6 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow abbccf04f6
key        : <org.eclipse.jetty.servlet.ServletHandler: void notFound(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>@L1556/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/base
source     : <org.eclipse.jetty.servlet.ServletHandler: void notFound(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>[13@L1556] %v14 = invokeinterface request.getServletPath()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[19@L219] %v17 = invokevirtual %v16.getSchemeSpecificPart()/base
fixed methods on this flow (GT): ClassPathResourceHandler.getResource, ExternalResourceHandler.getResource
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <org.eclipse.jetty.servlet.ServletHandler: void notFound(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>[13@L1556] %v14 = invokeinterface request.getServletPath()/result
2. VarNode{<org.eclipse.jetty.servlet.ServletHandler: void notFound(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>/%v14}
3. VarNode{<org.eclipse.jetty.util.URIUtil: java.lang.String addPaths(java.lang.String,java.lang.String)>/p1}
4. VarNode{<org.eclipse.jetty.server.Response: void sendRedirect(int,java.lang.String)>/%v25}
5. VarNode{<org.eclipse.jetty.util.URIUtil: java.lang.String canonicalPath(java.lang.String)>/path}
6. VarNode{<org.eclipse.jetty.server.Request: void setMetaData(org.eclipse.jetty.http.MetaData$Request)>/info}
7. VarNode{<org.eclipse.jetty.server.Request: void setPathInfo(java.lang.String)>/pathInfo}
8. InstanceFieldNode{NewObj{<org.eclipse.jetty.server.HttpChannel: void <init>(org.eclipse.jetty.server.Connector,org.eclipse.jetty.server.HttpConfiguration,org.eclipse.jetty.io.EndPoint,org.eclipse.jetty.server.HttpTransport)>[19@L94] new org.eclipse.jetty.server.Request}.<org.eclipse.jetty.server.Req
9. VarNode{<org.eclipse.jetty.server.Request: java.lang.String getPathInfo()>/%v1}
10. VarNode{<javax.servlet.http.HttpServletRequestWrapper: java.lang.String getPathInfo()>/%v2}
11. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>/pathInfo}
12. VarNode{<spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>/segment2}
13. VarNode{<spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>/addedPath}
14. VarNode{<spark.resource.ExternalResource: void <init>(java.lang.String)>/path}
15. VarNode{<spark.utils.StringUtils: java.lang.String cleanPath(java.lang.String)>/path}
16. VarNode{<spark.utils.StringUtils: java.lang.String replace(java.lang.String,java.lang.String,java.lang.String)>/inString}
17. VarNode{<spark.utils.ResourceUtils: java.net.URI toURI(java.lang.String)>/%v4}
18. VarNode{<spark.utils.ResourceUtils: java.net.URI toURI(java.lang.String)>/%v1}
19. VarNode{<spark.utils.ResourceUtils: java.net.URI toURI(java.net.URL)>/%v2}
20. VarNode{<spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>/%v16}
21. <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[19@L219] %v17 = invokevirtual %v16.getSchemeSpecificPart()/base

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/JarResourceHandler.java
   57 |         String servletPath;
   58 |         String pathInfo;
   59 | 
   60 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   61 | 
   62 |         if (included) {
   63 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   64 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   65 | 
   66 |             if (servletPath == null && pathInfo == null) {
   67 |                 servletPath = request.getServletPath();
   68 |                 pathInfo = request.getPathInfo();
   69 |             }
   70 |         } else {
   71 |             servletPath = request.getServletPath();
   72 |             pathInfo = request.getPathInfo();
   73 |         }
   74 | 
   75 |         String pathInContext = addPaths(servletPath, pathInfo);
   76 |         return getResourceStream(pathInContext);
   77 |     }
   78 | 
   79 |     private InputStream getResourceStream(String path) throws MalformedURLException {

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   58 | 
   59 |     @Override
   60 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   61 |         if (path == null || !path.startsWith("/")) {
   62 |             throw new MalformedURLException(path);
   63 |         }
   64 | 
   65 |         try {
   66 |             path = UriPath.canonical(path);
   67 | 
   68 |             final String addedPath = addPaths(baseResource, path);
   69 | 
   70 |             ExternalResource resource = new ExternalResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             if (resource != null && resource.exists()) {
   82 |                 DirectoryTraversal.protectAgainstForExternal(resource.getPath());
   83 |                 return resource;
   84 |             } else {
   85 |                 return null;
   86 |             }
   87 | 
   88 |         } catch (DirectoryTraversal.DirectoryTraversalDetection directoryTraversalDetection) {
   89 |             throw directoryTraversalDetection;
   90 |         } catch (Exception e) {
   91 |             if (LOG.isDebugEnabled()) {
   92 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   93 |             }
   94 |         }
   95 |         return null;
   96 |     }
   97 | 
   98 | }

### <spark.resource.ExternalResource: void <init>(java.lang.String)>
file: spark/resource/ExternalResource.java
   36 |      *
   37 |      * @param path the path to the external resource
   38 |      */
   39 |     public ExternalResource(String path) {
   40 |         file = new File(StringUtils.cleanPath(path));
   41 |     }
   42 | 
   43 |     /**
   44 |      * Tests whether the file denoted by this abstract pathname is a

### <spark.utils.StringUtils: java.lang.String cleanPath(java.lang.String)>
file: spark/utils/StringUtils.java
  216 |      * @return the normalized path
  217 |      */
  218 |     public static String cleanPath(String path) {
  219 |         if (path == null) {
  220 |             return null;
  221 |         }
  222 |         String pathToUse = replace(path, WINDOWS_FOLDER_SEPARATOR, FOLDER_SEPARATOR);
  223 | 
  224 |         // Strip prefix from path to analyze, to not treat it as part of the
  225 |         // first path element. This is necessary to correctly parse paths like
  226 |         // "file:core/../core/io/Resource.class", where the ".." should just
  227 |         // strip the first "core" directory while keeping the "file:" prefix.
  228 |         int prefixIndex = pathToUse.indexOf(":");
  229 |         String prefix = "";
  230 |         if (prefixIndex != -1) {
  231 |             prefix = pathToUse.substring(0, prefixIndex + 1);
  232 |             pathToUse = pathToUse.substring(prefixIndex + 1);
  233 |         }
  234 |         if (pathToUse.startsWith(FOLDER_SEPARATOR)) {
  235 |             prefix = prefix + FOLDER_SEPARATOR;
  236 |             pathToUse = pathToUse.substring(1);
  237 |         }
  238 | 
  239 |         String[] pathArray = delimitedListToStringArray(pathToUse, FOLDER_SEPARATOR);
  240 |         List<String> pathElements = new LinkedList<>();
  241 |         int tops = 0;
  242 | 
  243 |         for (int i = pathArray.length - 1; i >= 0; i--) {
  244 |             String element = pathArray[i];
  245 |             if (CURRENT_PATH.equals(element)) {
  246 |                 // Points to current directory - drop it.
  247 |             } else if (TOP_PATH.equals(element)) {
  248 |                 // Registering top path found.
  249 |                 tops++;
  250 |             } else {
  251 |                 if (tops > 0) {
  252 |                     // Merging path element with element corresponding to top path.
  253 |                     tops--;
  254 |                 } else {
  255 |                     // Normal path element found.
  256 |                     pathElements.add(0, element);
  257 |                 }
  258 |             }
  259 |         }
  260 | 
  261 |         // Remaining top paths need to be retained.
  262 |         for (int i = 0; i < tops; i++) {
  263 |             pathElements.add(0, TOP_PATH);
  264 |         }
  265 | 
  266 |         return prefix + collectionToDelimitedString(pathElements, FOLDER_SEPARATOR);
  267 |     }
  268 | 
  269 |     /**

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 23/100 flow_id 3bd3353e36 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 3bd3353e36
key        : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>@L257/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>[16@L257] %v28 = invokeinterface request.getServletPath()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 24/100 flow_id aa6d384cc3 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow aa6d384cc3
key        : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>@L319/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>[144@L319] %v103 = invokeinterface request.getContextPath()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource, ExternalResourceHandler.getResource
reported by: iris-like run2, v1 run2, v4 run2
N3 (iris-like run2): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>[144@L319] %v103 = invokeinterface request.getContextPath()/result
2. VarNode{<org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>/%v103}
3. VarNode{<org.eclipse.jetty.util.URIUtil: java.lang.String addPaths(java.lang.String,java.lang.String)>/p1}
4. VarNode{<org.eclipse.jetty.server.Response: void sendRedirect(int,java.lang.String)>/%v25}
5. VarNode{<org.eclipse.jetty.util.URIUtil: java.lang.String canonicalPath(java.lang.String)>/path}
6. VarNode{<org.eclipse.jetty.server.Request: void setMetaData(org.eclipse.jetty.http.MetaData$Request)>/info}
7. VarNode{<org.eclipse.jetty.server.Request: void setPathInfo(java.lang.String)>/pathInfo}
8. InstanceFieldNode{NewObj{<org.eclipse.jetty.server.HttpChannel: void <init>(org.eclipse.jetty.server.Connector,org.eclipse.jetty.server.HttpConfiguration,org.eclipse.jetty.io.EndPoint,org.eclipse.jetty.server.HttpTransport)>[19@L94] new org.eclipse.jetty.server.Request}.<org.eclipse.jetty.server.Req
9. VarNode{<org.eclipse.jetty.server.Request: java.lang.String getPathInfo()>/%v1}
10. VarNode{<javax.servlet.http.HttpServletRequestWrapper: java.lang.String getPathInfo()>/%v2}
11. VarNode{<spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>/pathInfo}
12. VarNode{<spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>/segment2}
13. VarNode{<spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>/%v18}
14. VarNode{<spark.resource.ExternalResource: void <init>(java.lang.String)>/path}
15. VarNode{<spark.utils.StringUtils: java.lang.String cleanPath(java.lang.String)>/path}
16. VarNode{<spark.utils.StringUtils: java.lang.String replace(java.lang.String,java.lang.String,java.lang.String)>/inString}
17. VarNode{<spark.utils.ResourceUtils: java.net.URI toURI(java.lang.String)>/%v4}
18. VarNode{<spark.utils.ResourceUtils: java.net.URI toURI(java.lang.String)>/%v1}
19. VarNode{<spark.utils.ResourceUtils: java.net.URI toURI(java.net.URL)>/%v2}
20. VarNode{<spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>/%v16}
21. VarNode{<spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>/%v17}
22. <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/AbstractResourceHandler.java
   40 |     public AbstractFileResolvingResource getResource(HttpServletRequest request) throws MalformedURLException {
   41 |         String servletPath;
   42 |         String pathInfo;
   43 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   44 | 
   45 |         if (included) {
   46 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   47 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   48 | 
   49 |             if (servletPath == null && pathInfo == null) {
   50 |                 servletPath = request.getServletPath();
   51 |                 pathInfo = request.getPathInfo();
   52 |             }
   53 |         } else {
   54 |             servletPath = request.getServletPath();
   55 |             pathInfo = request.getPathInfo();
   56 |         }
   57 | 
   58 |         String pathInContext = addPaths(servletPath, pathInfo);
   59 |         return getResource(pathInContext);
   60 |     }
   61 | 
   62 |     /**

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   58 | 
   59 |     @Override
   60 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   61 |         if (path == null || !path.startsWith("/")) {
   62 |             throw new MalformedURLException(path);
   63 |         }
   64 | 
   65 |         try {
   66 |             path = UriPath.canonical(path);
   67 | 
   68 |             final String addedPath = addPaths(baseResource, path);
   69 | 
   70 |             ExternalResource resource = new ExternalResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             if (resource != null && resource.exists()) {
   82 |                 DirectoryTraversal.protectAgainstForExternal(resource.getPath());
   83 |                 return resource;
   84 |             } else {
   85 |                 return null;
   86 |             }
   87 | 
   88 |         } catch (DirectoryTraversal.DirectoryTraversalDetection directoryTraversalDetection) {
   89 |             throw directoryTraversalDetection;
   90 |         } catch (Exception e) {
   91 |             if (LOG.isDebugEnabled()) {
   92 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   93 |             }
   94 |         }
   95 |         return null;
   96 |     }
   97 | 
   98 | }

### <spark.resource.ExternalResource: void <init>(java.lang.String)>
file: spark/resource/ExternalResource.java
   36 |      *
   37 |      * @param path the path to the external resource
   38 |      */
   39 |     public ExternalResource(String path) {
   40 |         file = new File(StringUtils.cleanPath(path));
   41 |     }
   42 | 
   43 |     /**
   44 |      * Tests whether the file denoted by this abstract pathname is a

### <spark.utils.StringUtils: java.lang.String cleanPath(java.lang.String)>
file: spark/utils/StringUtils.java
  216 |      * @return the normalized path
  217 |      */
  218 |     public static String cleanPath(String path) {
  219 |         if (path == null) {
  220 |             return null;
  221 |         }
  222 |         String pathToUse = replace(path, WINDOWS_FOLDER_SEPARATOR, FOLDER_SEPARATOR);
  223 | 
  224 |         // Strip prefix from path to analyze, to not treat it as part of the
  225 |         // first path element. This is necessary to correctly parse paths like
  226 |         // "file:core/../core/io/Resource.class", where the ".." should just
  227 |         // strip the first "core" directory while keeping the "file:" prefix.
  228 |         int prefixIndex = pathToUse.indexOf(":");
  229 |         String prefix = "";
  230 |         if (prefixIndex != -1) {
  231 |             prefix = pathToUse.substring(0, prefixIndex + 1);
  232 |             pathToUse = pathToUse.substring(prefixIndex + 1);
  233 |         }
  234 |         if (pathToUse.startsWith(FOLDER_SEPARATOR)) {
  235 |             prefix = prefix + FOLDER_SEPARATOR;
  236 |             pathToUse = pathToUse.substring(1);
  237 |         }
  238 | 
  239 |         String[] pathArray = delimitedListToStringArray(pathToUse, FOLDER_SEPARATOR);
  240 |         List<String> pathElements = new LinkedList<>();
  241 |         int tops = 0;
  242 | 
  243 |         for (int i = pathArray.length - 1; i >= 0; i--) {
  244 |             String element = pathArray[i];
  245 |             if (CURRENT_PATH.equals(element)) {
  246 |                 // Points to current directory - drop it.
  247 |             } else if (TOP_PATH.equals(element)) {
  248 |                 // Registering top path found.
  249 |                 tops++;
  250 |             } else {
  251 |                 if (tops > 0) {
  252 |                     // Merging path element with element corresponding to top path.
  253 |                     tops--;
  254 |                 } else {
  255 |                     // Normal path element found.
  256 |                     pathElements.add(0, element);
  257 |                 }
  258 |             }
  259 |         }
  260 | 
  261 |         // Remaining top paths need to be retained.
  262 |         for (int i = 0; i < tops; i++) {
  263 |             pathElements.add(0, TOP_PATH);
  264 |         }
  265 | 
  266 |         return prefix + collectionToDelimitedString(pathElements, FOLDER_SEPARATOR);
  267 |     }
  268 | 
  269 |     /**

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 25/100 flow_id b5c1674436 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow b5c1674436
key        : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>@L180/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[60@L180] %v56 = invokevirtual old_uri.getQuery()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 26/100 flow_id 4ce220db31 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 4ce220db31
key        : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>@L187/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[75@L187] %v67 = invokevirtual %v66.getQuery()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 27/100 flow_id cc29054553 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow cc29054553
key        : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>@L195/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[91@L195] %v76 = invokevirtual old_uri.getQuery()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 28/100 flow_id bd3368115c (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow bd3368115c
key        : <org.eclipse.jetty.server.Request: java.lang.String getQueryString()>@L1141/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <org.eclipse.jetty.server.Request: java.lang.String getQueryString()>[2@L1141] %v3 = invokevirtual %v2.getQuery()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 29/100 flow_id 40a3b1c77e (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 40a3b1c77e
key        : <org.eclipse.jetty.server.Server: void handleAsync(org.eclipse.jetty.server.HttpChannel)>@L553/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <org.eclipse.jetty.server.Server: void handleAsync(org.eclipse.jetty.server.HttpChannel)>[21@L553] %v23 = invokevirtual uri.getQuery()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 30/100 flow_id 153c5ea061 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 153c5ea061
key        : <org.eclipse.jetty.servlet.ServletHandler: void notFound(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>@L1556/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <org.eclipse.jetty.servlet.ServletHandler: void notFound(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>[13@L1556] %v14 = invokeinterface request.getServletPath()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 31/100 flow_id e1b93f1b2b (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow e1b93f1b2b
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L50/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[17@L50] servletPath = invokeinterface request.getServletPath()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/AbstractResourceHandler.java
   40 |     public AbstractFileResolvingResource getResource(HttpServletRequest request) throws MalformedURLException {
   41 |         String servletPath;
   42 |         String pathInfo;
   43 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   44 | 
   45 |         if (included) {
   46 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   47 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   48 | 
   49 |             if (servletPath == null && pathInfo == null) {
   50 |                 servletPath = request.getServletPath();
   51 |                 pathInfo = request.getPathInfo();
   52 |             }
   53 |         } else {
   54 |             servletPath = request.getServletPath();
   55 |             pathInfo = request.getPathInfo();
   56 |         }
   57 | 
   58 |         String pathInContext = addPaths(servletPath, pathInfo);
   59 |         return getResource(pathInContext);
   60 |     }
   61 | 
   62 |     /**

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 32/100 flow_id c87d7475f8 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow c87d7475f8
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L51/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[18@L51] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/AbstractResourceHandler.java
   40 |     public AbstractFileResolvingResource getResource(HttpServletRequest request) throws MalformedURLException {
   41 |         String servletPath;
   42 |         String pathInfo;
   43 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   44 | 
   45 |         if (included) {
   46 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   47 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   48 | 
   49 |             if (servletPath == null && pathInfo == null) {
   50 |                 servletPath = request.getServletPath();
   51 |                 pathInfo = request.getPathInfo();
   52 |             }
   53 |         } else {
   54 |             servletPath = request.getServletPath();
   55 |             pathInfo = request.getPathInfo();
   56 |         }
   57 | 
   58 |         String pathInContext = addPaths(servletPath, pathInfo);
   59 |         return getResource(pathInContext);
   60 |     }
   61 | 
   62 |     /**

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 33/100 flow_id 3b74d0637a (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 3b74d0637a
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L54/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[20@L54] servletPath = invokeinterface request.getServletPath()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/AbstractResourceHandler.java
   40 |     public AbstractFileResolvingResource getResource(HttpServletRequest request) throws MalformedURLException {
   41 |         String servletPath;
   42 |         String pathInfo;
   43 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   44 | 
   45 |         if (included) {
   46 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   47 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   48 | 
   49 |             if (servletPath == null && pathInfo == null) {
   50 |                 servletPath = request.getServletPath();
   51 |                 pathInfo = request.getPathInfo();
   52 |             }
   53 |         } else {
   54 |             servletPath = request.getServletPath();
   55 |             pathInfo = request.getPathInfo();
   56 |         }
   57 | 
   58 |         String pathInContext = addPaths(servletPath, pathInfo);
   59 |         return getResource(pathInContext);
   60 |     }
   61 | 
   62 |     /**

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 34/100 flow_id 97393d333c (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 97393d333c
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L55/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[21@L55] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/AbstractResourceHandler.java
   40 |     public AbstractFileResolvingResource getResource(HttpServletRequest request) throws MalformedURLException {
   41 |         String servletPath;
   42 |         String pathInfo;
   43 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   44 | 
   45 |         if (included) {
   46 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   47 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   48 | 
   49 |             if (servletPath == null && pathInfo == null) {
   50 |                 servletPath = request.getServletPath();
   51 |                 pathInfo = request.getPathInfo();
   52 |             }
   53 |         } else {
   54 |             servletPath = request.getServletPath();
   55 |             pathInfo = request.getPathInfo();
   56 |         }
   57 | 
   58 |         String pathInContext = addPaths(servletPath, pathInfo);
   59 |         return getResource(pathInContext);
   60 |     }
   61 | 
   62 |     /**

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 35/100 flow_id de79c00dfb (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow de79c00dfb
key        : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>@L67/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[17@L67] servletPath = invokeinterface request.getServletPath()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/JarResourceHandler.java
   57 |         String servletPath;
   58 |         String pathInfo;
   59 | 
   60 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   61 | 
   62 |         if (included) {
   63 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   64 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   65 | 
   66 |             if (servletPath == null && pathInfo == null) {
   67 |                 servletPath = request.getServletPath();
   68 |                 pathInfo = request.getPathInfo();
   69 |             }
   70 |         } else {
   71 |             servletPath = request.getServletPath();
   72 |             pathInfo = request.getPathInfo();
   73 |         }
   74 | 
   75 |         String pathInContext = addPaths(servletPath, pathInfo);
   76 |         return getResourceStream(pathInContext);
   77 |     }
   78 | 
   79 |     private InputStream getResourceStream(String path) throws MalformedURLException {

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 36/100 flow_id d3d0d719ab (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow d3d0d719ab
key        : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>@L71/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[20@L71] servletPath = invokeinterface request.getServletPath()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/JarResourceHandler.java
   57 |         String servletPath;
   58 |         String pathInfo;
   59 | 
   60 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   61 | 
   62 |         if (included) {
   63 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   64 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   65 | 
   66 |             if (servletPath == null && pathInfo == null) {
   67 |                 servletPath = request.getServletPath();
   68 |                 pathInfo = request.getPathInfo();
   69 |             }
   70 |         } else {
   71 |             servletPath = request.getServletPath();
   72 |             pathInfo = request.getPathInfo();
   73 |         }
   74 | 
   75 |         String pathInContext = addPaths(servletPath, pathInfo);
   76 |         return getResourceStream(pathInContext);
   77 |     }
   78 | 
   79 |     private InputStream getResourceStream(String path) throws MalformedURLException {

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 37/100 flow_id 6764e622e6 (priority 1)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 6764e622e6
key        : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>@L72/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[21@L72] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/JarResourceHandler.java
   57 |         String servletPath;
   58 |         String pathInfo;
   59 | 
   60 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   61 | 
   62 |         if (included) {
   63 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   64 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   65 | 
   66 |             if (servletPath == null && pathInfo == null) {
   67 |                 servletPath = request.getServletPath();
   68 |                 pathInfo = request.getPathInfo();
   69 |             }
   70 |         } else {
   71 |             servletPath = request.getServletPath();
   72 |             pathInfo = request.getPathInfo();
   73 |         }
   74 | 
   75 |         String pathInContext = addPaths(servletPath, pathInfo);
   76 |         return getResourceStream(pathInContext);
   77 |     }
   78 | 
   79 |     private InputStream getResourceStream(String path) throws MalformedURLException {

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 38/100 flow_id 343e9be960 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 343e9be960
key        : <org.eclipse.jetty.security.authentication.LoginAuthenticator: javax.servlet.http.HttpSession renewSession(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>@L104/result => <org.eclipse.jetty.server.handler.ContextHandler: boolean checkContext(java.lang.String,org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletResponse)>@L977/0
source     : <org.eclipse.jetty.security.authentication.LoginAuthenticator: javax.servlet.http.HttpSession renewSession(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>[3@L104] httpSession = invokeinterface request.getSession(%ci0)/result
sink       : <org.eclipse.jetty.server.handler.ContextHandler: boolean checkContext(java.lang.String,org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletResponse)>[32@L977] invokeinterface response.sendRedirect(%v27)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2, v4 run2
N3 (iris-like run2): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.security.authentication.LoginAuthenticator: javax.servlet.http.HttpSession renewSession(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>, <org.eclipse.jetty.server.handler.ContextHandler: boolean checkContext(java.lang.String,org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletResponse)>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 39/100 flow_id 86729e308a (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 86729e308a
key        : <org.eclipse.jetty.server.handler.gzip.GzipHttpOutputInterceptor: void commit(java.nio.ByteBuffer,boolean,org.eclipse.jetty.util.Callback)>@L212/result => <org.eclipse.jetty.server.handler.ContextHandler: boolean checkContext(java.lang.String,org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletResponse)>@L977/0
source     : <org.eclipse.jetty.server.handler.gzip.GzipHttpOutputInterceptor: void commit(java.nio.ByteBuffer,boolean,org.eclipse.jetty.util.Callback)>[116@L212] etag = invokevirtual fields.get(%v84)/result
sink       : <org.eclipse.jetty.server.handler.ContextHandler: boolean checkContext(java.lang.String,org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletResponse)>[32@L977] invokeinterface response.sendRedirect(%v27)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2, v4 run2
N3 (iris-like run2): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.server.handler.ContextHandler: boolean checkContext(java.lang.String,org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletResponse)>, <org.eclipse.jetty.server.handler.gzip.GzipHttpOutputInterceptor: void commit(java.nio.ByteBuffer,boolean,org.eclipse.jetty.util.Callback)>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 40/100 flow_id dc17150d36 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow dc17150d36
key        : <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>@L102/result => <org.eclipse.jetty.server.handler.ContextHandler: boolean checkContext(java.lang.String,org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletResponse)>@L979/0
source     : <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>[14@L102] acceptType = invokeinterface httpRequest.getHeader(%c26)/result
sink       : <org.eclipse.jetty.server.handler.ContextHandler: boolean checkContext(java.lang.String,org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletResponse)>[37@L979] invokeinterface response.sendRedirect(%v30)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2, v4 run2
N3 (iris-like run2): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>

## Application-code evidence (route or reachable-method fallback)
### <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>
file: spark/http/matching/MatcherFilter.java
   85 |                          ServletResponse servletResponse,
   86 |                          FilterChain chain) throws IOException, ServletException {
   87 | 
   88 |         HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
   89 |         HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;
   90 | 
   91 |         // handle static resources
   92 |         boolean consumedByStaticFile = staticFiles.consume(httpRequest, httpResponse);
   93 | 
   94 |         if (consumedByStaticFile) {
   95 |             return;
   96 |         }
   97 | 
   98 |         String method = getHttpMethodFrom(httpRequest);
   99 | 
  100 |         String httpMethodStr = method.toLowerCase();
  101 |         String uri = httpRequest.getRequestURI();
  102 |         String acceptType = httpRequest.getHeader(ACCEPT_TYPE_REQUEST_MIME_HEADER);
  103 | 
  104 |         Body body = Body.create();
  105 | 
  106 |         RequestWrapper requestWrapper = RequestWrapper.create();
  107 |         ResponseWrapper responseWrapper = ResponseWrapper.create();
  108 | 
  109 |         Response response = RequestResponseFactory.create(httpResponse);
  110 | 
  111 |         HttpMethod httpMethod = HttpMethod.get(httpMethodStr);
  112 | 
  113 |         RouteContext context = RouteContext.create()
  114 |                 .withMatcher(routeMatcher)
      | ... (lines omitted) ...
  139 | 
  140 |         // If redirected and content is null set to empty string to not throw NotConsumedException
  141 |         if (body.notSet() && responseWrapper.isRedirected()) {
  142 |             body.set("");
  143 |         }
  144 | 
  145 |         if (body.notSet() && hasOtherHandlers) {
  146 |             if (servletRequest instanceof HttpRequestWrapper) {
  147 |                 ((HttpRequestWrapper) servletRequest).notConsumed(true);
  148 |                 return;
  149 |             }
  150 |         }
  151 | 
  152 |         if (body.notSet() && !externalContainer) {
  153 |             LOG.info("The requested route [{}] has not been mapped in Spark for {}: [{}]",
  154 |                 uri, ACCEPT_TYPE_REQUEST_MIME_HEADER, acceptType);
  155 |             httpResponse.setStatus(HttpServletResponse.SC_NOT_FOUND);
  156 |             body.set(String.format(NOT_FOUND));
  157 |         }
  158 | 
  159 |         if (body.isSet()) {
  160 |             body.serializeTo(httpResponse, serializerChain, httpRequest);
  161 | 
  162 |         } else if (chain != null) {
  163 |             chain.doFilter(httpRequest, httpResponse);
  164 |         }
  165 |     }
  166 | 
  167 |     private String getHttpMethodFrom(HttpServletRequest httpRequest) {
  168 |         String method = httpRequest.getHeader(HTTP_METHOD_OVERRIDE_HEADER);
```

---

## 41/100 flow_id c98ca754e7 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow c98ca754e7
key        : <org.eclipse.jetty.server.Request: int findServerPort()>@L1440/result => <org.eclipse.jetty.servlet.ServletHolder: void initJspServlet()>@L688/0
source     : <org.eclipse.jetty.server.Request: int findServerPort()>[12@L1440] %v11 = invokevirtual host.getValue()/result
sink       : <org.eclipse.jetty.servlet.ServletHolder: void initJspServlet()>[45@L688] invokespecial scratch#1.<init>(%v39)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.server.Request: int findServerPort()>, <org.eclipse.jetty.servlet.ServletHolder: void initJspServlet()>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 42/100 flow_id 6d6bc1e62a (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 6d6bc1e62a
key        : <org.eclipse.jetty.security.authentication.FormAuthenticator$FormRequest: java.util.Enumeration getHeaderNames()>@L476/result => <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>@L60/0
source     : <org.eclipse.jetty.security.authentication.FormAuthenticator$FormRequest: java.util.Enumeration getHeaderNames()>[0@L476] %v1 = invokespecial this.getHeaderNames()/result
sink       : <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>[10@L60] url = invokevirtual load_loader.getResource(name)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, v1 run0
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.security.authentication.FormAuthenticator$FormRequest: java.util.Enumeration getHeaderNames()>, <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 43/100 flow_id ebb152d46b (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow ebb152d46b
key        : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>@L411/result => <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>@L60/0
source     : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>[311@L411] %v200 = invokeinterface request.getContextPath()/result
sink       : <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>[10@L60] url = invokevirtual load_loader.getResource(name)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2, v4 run2
N3 (iris-like run2): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>, <spark.resource.ClassPathResource: void <init>(java.lang.String)>, <spark.resource.ClassPathResource: void <init>(java.lang.String,java.lang.ClassLoader)>, <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.ExternalResource: void <init>(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/AbstractResourceHandler.java
   40 |     public AbstractFileResolvingResource getResource(HttpServletRequest request) throws MalformedURLException {
   41 |         String servletPath;
   42 |         String pathInfo;
   43 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   44 | 
   45 |         if (included) {
   46 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   47 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   48 | 
   49 |             if (servletPath == null && pathInfo == null) {
   50 |                 servletPath = request.getServletPath();
   51 |                 pathInfo = request.getPathInfo();
   52 |             }
   53 |         } else {
   54 |             servletPath = request.getServletPath();
   55 |             pathInfo = request.getPathInfo();
   56 |         }
   57 | 
   58 |         String pathInContext = addPaths(servletPath, pathInfo);
   59 |         return getResource(pathInContext);
   60 |     }
   61 | 
   62 |     /**

### <spark.resource.ClassPathResource: void <init>(java.lang.String)>
file: spark/resource/ClassPathResource.java
   59 |      * @see spark.utils.ClassUtils#getDefaultClassLoader()
   60 |      */
   61 |     public ClassPathResource(String path) {
   62 |         this(path, null);
   63 |     }
   64 | 
   65 |     /**
   66 |      * Create a new ClassPathResource for ClassLoader usage.

### <spark.resource.ClassPathResource: void <init>(java.lang.String,java.lang.ClassLoader)>
file: spark/resource/ClassPathResource.java
   72 |      *                    or {@code null} for the thread context class loader
   73 |      * @see ClassLoader#getResourceAsStream(String)
   74 |      */
   75 |     public ClassPathResource(String path, ClassLoader classLoader) {
   76 |         Assert.notNull(path, "Path must not be null");
   77 |         String pathToUse = StringUtils.cleanPath(path);
   78 |         if (pathToUse.startsWith("/")) {
   79 |             pathToUse = pathToUse.substring(1);
   80 |         }
   81 |         this.path = pathToUse;
   82 |         this.classLoader = (classLoader != null ? classLoader : ClassUtils.getDefaultClassLoader());
   83 |     }
   84 | 
   85 |     /**
   86 |      * Create a new ClassPathResource with optional ClassLoader and Class.

### <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ClassPathResourceHandler.java
   59 | 
   60 |     @Override
   61 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   62 |         if (path == null || !path.startsWith("/")) {
   63 |             throw new MalformedURLException(path);
   64 |         }
   65 | 
   66 |         try {
   67 |             path = UriPath.canonical(path);
   68 | 
   69 |             final String addedPath = addPaths(baseResource, path);
   70 | 
   71 |             ClassPathResource resource = new ClassPathResource(addedPath);
   72 | 
   73 |             if (resource.exists() && resource.getFile().isDirectory()) {
   74 |                 if (welcomeFile != null) {
   75 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   76 |                 } else {
   77 |                     //  No welcome file configured, serve nothing since it's a directory
   78 |                     resource = null;
   79 |                 }
   80 |             }
   81 | 
   82 |             if (resource != null && resource.exists()) {
   83 |                 DirectoryTraversal.protectAgainstInClassPath(resource.getPath());
   84 |                 return resource;
   85 |             } else {
   86 |                 return null;
   87 |             }
   88 | 
   89 |         } catch (DirectoryTraversal.DirectoryTraversalDetection directoryTraversalDetection) {
   90 |             throw directoryTraversalDetection;
   91 |         } catch (Exception e) {
   92 |             if (LOG.isDebugEnabled()) {
   93 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   94 |             }
   95 |         }
   96 |         return null;
   97 |     }
   98 | 
   99 | }

### <spark.resource.ExternalResource: void <init>(java.lang.String)>
file: spark/resource/ExternalResource.java
   36 |      *
   37 |      * @param path the path to the external resource
   38 |      */
   39 |     public ExternalResource(String path) {
   40 |         file = new File(StringUtils.cleanPath(path));
   41 |     }
   42 | 
   43 |     /**
   44 |      * Tests whether the file denoted by this abstract pathname is a
```

---

## 44/100 flow_id dafd610606 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow dafd610606
key        : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>@L72/result => <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>@L60/0
source     : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[21@L72] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>[10@L60] url = invokevirtual load_loader.getResource(name)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>, <spark.resource.ClassPathResource: void <init>(java.lang.String)>, <spark.resource.ClassPathResource: void <init>(java.lang.String,java.lang.ClassLoader)>, <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.ExternalResource: void <init>(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/AbstractResourceHandler.java
   40 |     public AbstractFileResolvingResource getResource(HttpServletRequest request) throws MalformedURLException {
   41 |         String servletPath;
   42 |         String pathInfo;
   43 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   44 | 
   45 |         if (included) {
   46 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   47 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   48 | 
   49 |             if (servletPath == null && pathInfo == null) {
   50 |                 servletPath = request.getServletPath();
   51 |                 pathInfo = request.getPathInfo();
   52 |             }
   53 |         } else {
   54 |             servletPath = request.getServletPath();
   55 |             pathInfo = request.getPathInfo();
   56 |         }
   57 | 
   58 |         String pathInContext = addPaths(servletPath, pathInfo);
   59 |         return getResource(pathInContext);
   60 |     }
   61 | 
   62 |     /**

### <spark.resource.ClassPathResource: void <init>(java.lang.String)>
file: spark/resource/ClassPathResource.java
   59 |      * @see spark.utils.ClassUtils#getDefaultClassLoader()
   60 |      */
   61 |     public ClassPathResource(String path) {
   62 |         this(path, null);
   63 |     }
   64 | 
   65 |     /**
   66 |      * Create a new ClassPathResource for ClassLoader usage.

### <spark.resource.ClassPathResource: void <init>(java.lang.String,java.lang.ClassLoader)>
file: spark/resource/ClassPathResource.java
   72 |      *                    or {@code null} for the thread context class loader
   73 |      * @see ClassLoader#getResourceAsStream(String)
   74 |      */
   75 |     public ClassPathResource(String path, ClassLoader classLoader) {
   76 |         Assert.notNull(path, "Path must not be null");
   77 |         String pathToUse = StringUtils.cleanPath(path);
   78 |         if (pathToUse.startsWith("/")) {
   79 |             pathToUse = pathToUse.substring(1);
   80 |         }
   81 |         this.path = pathToUse;
   82 |         this.classLoader = (classLoader != null ? classLoader : ClassUtils.getDefaultClassLoader());
   83 |     }
   84 | 
   85 |     /**
   86 |      * Create a new ClassPathResource with optional ClassLoader and Class.

### <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ClassPathResourceHandler.java
   59 | 
   60 |     @Override
   61 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   62 |         if (path == null || !path.startsWith("/")) {
   63 |             throw new MalformedURLException(path);
   64 |         }
   65 | 
   66 |         try {
   67 |             path = UriPath.canonical(path);
   68 | 
   69 |             final String addedPath = addPaths(baseResource, path);
   70 | 
   71 |             ClassPathResource resource = new ClassPathResource(addedPath);
   72 | 
   73 |             if (resource.exists() && resource.getFile().isDirectory()) {
   74 |                 if (welcomeFile != null) {
   75 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   76 |                 } else {
   77 |                     //  No welcome file configured, serve nothing since it's a directory
   78 |                     resource = null;
   79 |                 }
   80 |             }
   81 | 
   82 |             if (resource != null && resource.exists()) {
   83 |                 DirectoryTraversal.protectAgainstInClassPath(resource.getPath());
   84 |                 return resource;
   85 |             } else {
   86 |                 return null;
   87 |             }
   88 | 
   89 |         } catch (DirectoryTraversal.DirectoryTraversalDetection directoryTraversalDetection) {
   90 |             throw directoryTraversalDetection;
   91 |         } catch (Exception e) {
   92 |             if (LOG.isDebugEnabled()) {
   93 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   94 |             }
   95 |         }
   96 |         return null;
   97 |     }
   98 | 
   99 | }

### <spark.resource.ExternalResource: void <init>(java.lang.String)>
file: spark/resource/ExternalResource.java
   36 |      *
   37 |      * @param path the path to the external resource
   38 |      */
   39 |     public ExternalResource(String path) {
   40 |         file = new File(StringUtils.cleanPath(path));
   41 |     }
   42 | 
   43 |     /**
   44 |      * Tests whether the file denoted by this abstract pathname is a
```

---

## 45/100 flow_id 63bc1d5d0e (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 63bc1d5d0e
key        : <org.eclipse.jetty.server.Request: java.lang.String getServerName()>@L1367/result => <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>@L54/0
source     : <org.eclipse.jetty.server.Request: java.lang.String getServerName()>[2@L1367] name = invokevirtual %v3.getHost()/result
sink       : <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>[4@L54] url = invokevirtual context_loader.getResource(name)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.server.Request: java.lang.String getServerName()>, <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 46/100 flow_id 89360276df (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 89360276df
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L51/result => <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>@L54/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[18@L51] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>[4@L54] url = invokevirtual context_loader.getResource(name)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/AbstractResourceHandler.java
   40 |     public AbstractFileResolvingResource getResource(HttpServletRequest request) throws MalformedURLException {
   41 |         String servletPath;
   42 |         String pathInfo;
   43 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   44 | 
   45 |         if (included) {
   46 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   47 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   48 | 
   49 |             if (servletPath == null && pathInfo == null) {
   50 |                 servletPath = request.getServletPath();
   51 |                 pathInfo = request.getPathInfo();
   52 |             }
   53 |         } else {
   54 |             servletPath = request.getServletPath();
   55 |             pathInfo = request.getPathInfo();
   56 |         }
   57 | 
   58 |         String pathInContext = addPaths(servletPath, pathInfo);
   59 |         return getResource(pathInContext);
   60 |     }
   61 | 
   62 |     /**
```

---

## 47/100 flow_id 995550e4c2 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 995550e4c2
key        : <org.eclipse.jetty.security.authentication.DigestAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>@L243/result => <org.eclipse.jetty.util.MultiPartInputStreamParser: void <init>(java.io.InputStream,java.lang.String,javax.servlet.MultipartConfigElement,java.io.File)>@L344/0
source     : <org.eclipse.jetty.security.authentication.DigestAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>[106@L243] domain = invokeinterface request.getContextPath()/result
sink       : <org.eclipse.jetty.util.MultiPartInputStreamParser: void <init>(java.io.InputStream,java.lang.String,javax.servlet.MultipartConfigElement,java.io.File)>[12@L344] invokespecial %v8.<init>(%v10)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2, v4 run2
N3 (iris-like run2): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.security.authentication.DigestAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>, <org.eclipse.jetty.util.MultiPartInputStreamParser: void <init>(java.io.InputStream,java.lang.String,javax.servlet.MultipartConfigElement,java.io.File)>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 48/100 flow_id cd2029e058 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow cd2029e058
key        : <org.eclipse.jetty.server.Request: java.lang.String getContentType()>@L658/result => <org.eclipse.jetty.util.MultiPartInputStreamParser: void <init>(java.io.InputStream,java.lang.String,javax.servlet.MultipartConfigElement,java.io.File)>@L344/0
source     : <org.eclipse.jetty.server.Request: java.lang.String getContentType()>[3@L658] content_type = invokevirtual %v5.get(%v6)/result
sink       : <org.eclipse.jetty.util.MultiPartInputStreamParser: void <init>(java.io.InputStream,java.lang.String,javax.servlet.MultipartConfigElement,java.io.File)>[12@L344] invokespecial %v8.<init>(%v10)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.server.Request: java.lang.String getContentType()>, <org.eclipse.jetty.util.MultiPartInputStreamParser: void <init>(java.io.InputStream,java.lang.String,javax.servlet.MultipartConfigElement,java.io.File)>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 49/100 flow_id bf42d39312 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow bf42d39312
key        : <org.eclipse.jetty.websocket.servlet.ServletUpgradeRequest: void <init>(javax.servlet.http.HttpServletRequest)>@L79/result => <org.eclipse.jetty.util.MultiPartInputStreamParser: void <init>(java.io.InputStream,java.lang.String,javax.servlet.MultipartConfigElement,java.io.File)>@L344/0
source     : <org.eclipse.jetty.websocket.servlet.ServletUpgradeRequest: void <init>(javax.servlet.http.HttpServletRequest)>[39@L79] %v36 = invokevirtual requestCookie.getName()/result
sink       : <org.eclipse.jetty.util.MultiPartInputStreamParser: void <init>(java.io.InputStream,java.lang.String,javax.servlet.MultipartConfigElement,java.io.File)>[12@L344] invokespecial %v8.<init>(%v10)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.util.MultiPartInputStreamParser: void <init>(java.io.InputStream,java.lang.String,javax.servlet.MultipartConfigElement,java.io.File)>, <org.eclipse.jetty.websocket.servlet.ServletUpgradeRequest: void <init>(javax.servlet.http.HttpServletRequest)>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 50/100 flow_id 0539adf28e (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 0539adf28e
key        : <org.eclipse.jetty.http.HttpFields: java.lang.String get(java.lang.String)>@L243/result => <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>@L460/0
source     : <org.eclipse.jetty.http.HttpFields: java.lang.String get(java.lang.String)>[10@L243] %v10 = invokevirtual f.getValue()/result
sink       : <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>[36@L460] invokespecial f.<init>(%v46)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.http.HttpFields: java.lang.String get(java.lang.String)>, <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 51/100 flow_id 532111cb7a (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 532111cb7a
key        : <org.eclipse.jetty.security.authentication.FormAuthenticator$FormRequest: java.lang.String getHeader(java.lang.String)>@L470/result => <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>@L460/0
source     : <org.eclipse.jetty.security.authentication.FormAuthenticator$FormRequest: java.lang.String getHeader(java.lang.String)>[7@L470] %v8 = invokespecial this.getHeader(name)/result
sink       : <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>[36@L460] invokespecial f.<init>(%v46)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.security.authentication.FormAuthenticator$FormRequest: java.lang.String getHeader(java.lang.String)>, <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 52/100 flow_id 6596b1486d (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 6596b1486d
key        : <org.eclipse.jetty.server.Request: java.lang.String getContentType()>@L658/result => <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>@L460/0
source     : <org.eclipse.jetty.server.Request: java.lang.String getContentType()>[3@L658] content_type = invokevirtual %v5.get(%v6)/result
sink       : <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>[36@L460] invokespecial f.<init>(%v46)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.server.Request: java.lang.String getContentType()>, <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 53/100 flow_id ec25fe348a (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow ec25fe348a
key        : <spark.Request: java.util.List getSplat(java.util.List,java.util.List)>@L513/result => <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>@L460/0
source     : <spark.Request: java.util.List getSplat(java.util.List,java.util.List)>[35@L513] decodedSplat = invokestatic java.net.URLDecoder.decode(%v27, %c26)/result
sink       : <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>[36@L460] invokespecial f.<init>(%v46)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.Request: java.util.List getSplat(java.util.List,java.util.List)>

## Application-code evidence (route or reachable-method fallback)
### <spark.Request: java.util.List getSplat(java.util.List,java.util.List)>
file: spark/Request.java
  488 |     }
  489 | 
  490 |     private static List<String> getSplat(List<String> request, List<String> matched) {
  491 |         int nbrOfRequestParts = request.size();
  492 |         int nbrOfMatchedParts = matched.size();
  493 | 
  494 |         boolean sameLength = (nbrOfRequestParts == nbrOfMatchedParts);
  495 | 
  496 |         List<String> splat = new ArrayList<>();
  497 | 
  498 |         for (int i = 0; (i < nbrOfRequestParts) && (i < nbrOfMatchedParts); i++) {
  499 | 
  500 |             String matchedPart = matched.get(i);
  501 | 
  502 |             if (SparkUtils.isSplat(matchedPart)) {
  503 | 
  504 |                 StringBuilder splatParam = new StringBuilder(request.get(i));
  505 | 
  506 |                 if (!sameLength && (i == (nbrOfMatchedParts - 1))) {
  507 |                     for (int j = i + 1; j < nbrOfRequestParts; j++) {
  508 |                         splatParam.append("/");
  509 |                         splatParam.append(request.get(j));
  510 |                     }
  511 |                 }
  512 |                 try {
  513 |                     String decodedSplat = URLDecoder.decode(splatParam.toString(), "UTF-8");
  514 |                     splat.add(decodedSplat);
  515 |                 } catch (UnsupportedEncodingException e) {
  516 |                 }
  517 |             }
  518 |         }
  519 | 
  520 |         return Collections.unmodifiableList(splat);
  521 |     }
  522 | 
  523 |     /**
```

---

## 54/100 flow_id f3fc57cc0d (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow f3fc57cc0d
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L50/result => <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>@L460/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[17@L50] servletPath = invokeinterface request.getServletPath()/result
sink       : <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>[36@L460] invokespecial f.<init>(%v46)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/AbstractResourceHandler.java
   40 |     public AbstractFileResolvingResource getResource(HttpServletRequest request) throws MalformedURLException {
   41 |         String servletPath;
   42 |         String pathInfo;
   43 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   44 | 
   45 |         if (included) {
   46 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   47 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   48 | 
   49 |             if (servletPath == null && pathInfo == null) {
   50 |                 servletPath = request.getServletPath();
   51 |                 pathInfo = request.getPathInfo();
   52 |             }
   53 |         } else {
   54 |             servletPath = request.getServletPath();
   55 |             pathInfo = request.getPathInfo();
   56 |         }
   57 | 
   58 |         String pathInContext = addPaths(servletPath, pathInfo);
   59 |         return getResource(pathInContext);
   60 |     }
   61 | 
   62 |     /**
```

---

## 55/100 flow_id fe49b966e4 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow fe49b966e4
key        : <spark.staticfiles.StaticFilesConfiguration: boolean consumeWithJarResourceHandler(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>@L120/result => <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>@L460/0
source     : <spark.staticfiles.StaticFilesConfiguration: boolean consumeWithJarResourceHandler(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>[13@L120] %v16 = invokeinterface httpRequest.getPathInfo()/result
sink       : <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>[36@L460] invokespecial f.<init>(%v46)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.staticfiles.StaticFilesConfiguration: boolean consumeWithJarResourceHandler(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>

## Application-code evidence (route or reachable-method fallback)
### <spark.staticfiles.StaticFilesConfiguration: boolean consumeWithJarResourceHandler(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>
file: spark/staticfiles/StaticFilesConfiguration.java
  111 | 
  112 |     private boolean consumeWithJarResourceHandler(HttpServletRequest httpRequest,
  113 |                                                   HttpServletResponse httpResponse) throws IOException {
  114 |         if (jarResourceHandlers != null) {
  115 | 
  116 |             for (JarResourceHandler jarResourceHandler : jarResourceHandlers) {
  117 |                 InputStream stream = jarResourceHandler.getResource(httpRequest);
  118 | 
  119 |                 if (stream != null) {
  120 |                     httpResponse.setHeader(MimeType.CONTENT_TYPE, MimeType.fromPathInfo(httpRequest.getPathInfo()));
  121 |                     customHeaders.forEach(httpResponse::setHeader); //add all user-defined headers to response
  122 |                     OutputStream wrappedOutputStream = GzipUtils.checkAndWrap(httpRequest, httpResponse, false);
  123 | 
  124 |                     IOUtils.copy(stream, wrappedOutputStream);
  125 |                     wrappedOutputStream.flush();
  126 |                     wrappedOutputStream.close();
  127 |                     return true;
  128 |                 }
  129 |             }
  130 |         }
  131 |         return false;
  132 |     }
  133 | 
  134 |     /**
```

---

## 56/100 flow_id 7671376aa5 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 7671376aa5
key        : <org.eclipse.jetty.http.HttpFields: java.lang.String toString()>@L660/result => <org.eclipse.jetty.util.resource.URLResource: java.io.File getFile()>@L183/0
source     : <org.eclipse.jetty.http.HttpFields: java.lang.String toString()>[14@L660] tmp#1 = invokevirtual field.getValue()/result
sink       : <org.eclipse.jetty.util.resource.URLResource: java.io.File getFile()>[14@L183] invokespecial %v9.<init>(%v11)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.http.HttpFields: java.lang.String toString()>, <org.eclipse.jetty.util.resource.URLResource: java.io.File getFile()>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 57/100 flow_id 79d672ed42 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 79d672ed42
key        : <org.eclipse.jetty.http.HttpParser: boolean parseHeaders(java.nio.ByteBuffer)>@L1002/result => <org.eclipse.jetty.util.resource.URLResource: java.io.File getFile()>@L183/0
source     : <org.eclipse.jetty.http.HttpParser: boolean parseHeaders(java.nio.ByteBuffer)>[192@L1002] v = invokevirtual field.getValue()/result
sink       : <org.eclipse.jetty.util.resource.URLResource: java.io.File getFile()>[14@L183] invokespecial %v9.<init>(%v11)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.http.HttpParser: boolean parseHeaders(java.nio.ByteBuffer)>, <org.eclipse.jetty.util.resource.URLResource: java.io.File getFile()>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 58/100 flow_id 0625b18faf (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 0625b18faf
key        : <org.eclipse.jetty.websocket.server.WebSocketUpgradeFilter: void init(javax.servlet.FilterConfig)>@L264/result => <org.eclipse.jetty.util.resource.URLResource: java.io.File getFile()>@L183/0
source     : <org.eclipse.jetty.websocket.server.WebSocketUpgradeFilter: void init(javax.servlet.FilterConfig)>[8@L264] max = invokeinterface config.getInitParameter(%c11)/result
sink       : <org.eclipse.jetty.util.resource.URLResource: java.io.File getFile()>[14@L183] invokespecial %v9.<init>(%v11)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.util.resource.URLResource: java.io.File getFile()>, <org.eclipse.jetty.websocket.server.WebSocketUpgradeFilter: void init(javax.servlet.FilterConfig)>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 59/100 flow_id 8efc8b3fbf (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 8efc8b3fbf
key        : <org.eclipse.jetty.http.HttpFields: java.util.Set getFieldNamesCollection()>@L110/result => <org.slf4j.impl.SimpleLogger: java.io.PrintStream computeTargetStream(java.lang.String)>@L219/0
source     : <org.eclipse.jetty.http.HttpFields: java.util.Set getFieldNamesCollection()>[10@L110] %v12 = invokevirtual f.getName()/result
sink       : <org.slf4j.impl.SimpleLogger: java.io.PrintStream computeTargetStream(java.lang.String)>[12@L219] invokespecial fos.<init>(logFile)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.http.HttpFields: java.util.Set getFieldNamesCollection()>, <org.slf4j.impl.SimpleLogger: java.io.PrintStream computeTargetStream(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 60/100 flow_id be9e197624 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow be9e197624
key        : <org.eclipse.jetty.server.session.SessionHandler: void checkRequestedSessionId(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest)>@L293/result => <org.slf4j.impl.SimpleLogger: java.io.PrintStream computeTargetStream(java.lang.String)>@L219/0
source     : <org.eclipse.jetty.server.session.SessionHandler: void checkRequestedSessionId(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest)>[60@L293] uri = invokeinterface request.getRequestURI()/result
sink       : <org.slf4j.impl.SimpleLogger: java.io.PrintStream computeTargetStream(java.lang.String)>[12@L219] invokespecial fos.<init>(logFile)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.server.session.SessionHandler: void checkRequestedSessionId(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest)>, <org.slf4j.impl.SimpleLogger: java.io.PrintStream computeTargetStream(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 61/100 flow_id 6532a8430b (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 6532a8430b
key        : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>@L68/result => <org.slf4j.impl.SimpleLogger: java.io.PrintStream computeTargetStream(java.lang.String)>@L219/0
source     : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[18@L68] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <org.slf4j.impl.SimpleLogger: java.io.PrintStream computeTargetStream(java.lang.String)>[12@L219] invokespecial fos.<init>(logFile)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/JarResourceHandler.java
   57 |         String servletPath;
   58 |         String pathInfo;
   59 | 
   60 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   61 | 
   62 |         if (included) {
   63 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   64 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   65 | 
   66 |             if (servletPath == null && pathInfo == null) {
   67 |                 servletPath = request.getServletPath();
   68 |                 pathInfo = request.getPathInfo();
   69 |             }
   70 |         } else {
   71 |             servletPath = request.getServletPath();
   72 |             pathInfo = request.getPathInfo();
   73 |         }
   74 | 
   75 |         String pathInContext = addPaths(servletPath, pathInfo);
   76 |         return getResourceStream(pathInContext);
   77 |     }
   78 | 
   79 |     private InputStream getResourceStream(String path) throws MalformedURLException {
```

---

## 62/100 flow_id 834d87688f (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 834d87688f
key        : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>@L34/result => <org.slf4j.impl.SimpleLogger: java.io.PrintStream computeTargetStream(java.lang.String)>@L219/0
source     : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>[2@L34] path = invokeinterface request.getRequestURI()/result
sink       : <org.slf4j.impl.SimpleLogger: java.io.PrintStream computeTargetStream(java.lang.String)>[12@L219] invokespecial fos.<init>(logFile)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>
file: spark/servlet/FilterTools.java
   31 |     }
   32 | 
   33 |     static String getRelativePath(HttpServletRequest request, String filterPath) {
   34 |         String path = request.getRequestURI();
   35 |         String contextPath = request.getContextPath();
   36 | 
   37 |         path = path.substring(contextPath.length());
   38 | 
   39 |         if (path.length() > 0) {
   40 |             path = path.substring(1);
   41 |         }
   42 | 
   43 |         if (!path.startsWith(filterPath) && filterPath.equals(path + SLASH)) {
   44 |             path += SLASH;
   45 |         }
   46 |         if (path.startsWith(filterPath)) {
   47 |             path = path.substring(filterPath.length());
   48 |         }
   49 | 
   50 |         if (!path.startsWith(SLASH)) {
   51 |             path = SLASH + path;
   52 |         }
   53 | 
   54 |         try {
   55 |             path = URLDecoder.decode(path, "UTF-8");
   56 |         } catch (UnsupportedEncodingException ex) {
   57 |             // this can't really ever happen
   58 |         }
   59 |         return path;
   60 |     }
   61 | 
   62 |     static String getFilterPath(FilterConfig config) {
```

---

## 63/100 flow_id 87ebf6a7e0 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 87ebf6a7e0
key        : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>@L55/result => <org.slf4j.impl.SimpleLogger: java.io.PrintStream computeTargetStream(java.lang.String)>@L219/0
source     : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>[39@L55] path#1 = invokestatic java.net.URLDecoder.decode(path#1, %c30)/result
sink       : <org.slf4j.impl.SimpleLogger: java.io.PrintStream computeTargetStream(java.lang.String)>[12@L219] invokespecial fos.<init>(logFile)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>
file: spark/servlet/FilterTools.java
   31 |     }
   32 | 
   33 |     static String getRelativePath(HttpServletRequest request, String filterPath) {
   34 |         String path = request.getRequestURI();
   35 |         String contextPath = request.getContextPath();
   36 | 
   37 |         path = path.substring(contextPath.length());
   38 | 
   39 |         if (path.length() > 0) {
   40 |             path = path.substring(1);
   41 |         }
   42 | 
   43 |         if (!path.startsWith(filterPath) && filterPath.equals(path + SLASH)) {
   44 |             path += SLASH;
   45 |         }
   46 |         if (path.startsWith(filterPath)) {
   47 |             path = path.substring(filterPath.length());
   48 |         }
   49 | 
   50 |         if (!path.startsWith(SLASH)) {
   51 |             path = SLASH + path;
   52 |         }
   53 | 
   54 |         try {
   55 |             path = URLDecoder.decode(path, "UTF-8");
   56 |         } catch (UnsupportedEncodingException ex) {
   57 |             // this can't really ever happen
   58 |         }
   59 |         return path;
   60 |     }
   61 | 
   62 |     static String getFilterPath(FilterConfig config) {
```

---

## 64/100 flow_id da2f4c2deb (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow da2f4c2deb
key        : DRIVER => <org.slf4j.impl.SimpleLogger: java.io.PrintStream computeTargetStream(java.lang.String)>@L219/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[10@L50] taintedPath = invokestatic nesy.Taint.src()/result
sink       : <org.slf4j.impl.SimpleLogger: java.io.PrintStream computeTargetStream(java.lang.String)>[12@L219] invokespecial fos.<init>(logFile)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <nesy.NesyDriver: void main(java.lang.String[])>, <org.slf4j.impl.SimpleLogger: java.io.PrintStream computeTargetStream(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 65/100 flow_id c8b563b12a (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow c8b563b12a
key        : <org.eclipse.jetty.http.HttpFields: java.util.Set getFieldNamesCollection()>@L110/result => <spark.embeddedserver.jetty.websocket.WebSocketServletContextHandlerFactory: org.eclipse.jetty.servlet.ServletContextHandler create(java.util.Map,java.util.Optional)>@L55/0
source     : <org.eclipse.jetty.http.HttpFields: java.util.Set getFieldNamesCollection()>[10@L110] %v12 = invokevirtual f.getName()/result
sink       : <spark.embeddedserver.jetty.websocket.WebSocketServletContextHandlerFactory: org.eclipse.jetty.servlet.ServletContextHandler create(java.util.Map,java.util.Optional)>[28@L55] invokespecial %v28.<init>(path)/0
fixed methods on this flow (GT): -
reported by: v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.embeddedserver.jetty.websocket.WebSocketServletContextHandlerFactory: org.eclipse.jetty.servlet.ServletContextHandler create(java.util.Map,java.util.Optional)>

## Application-code evidence (route or reachable-method fallback)
### <spark.embeddedserver.jetty.websocket.WebSocketServletContextHandlerFactory: org.eclipse.jetty.servlet.ServletContextHandler create(java.util.Map,java.util.Optional)>
file: spark/embeddedserver/jetty/websocket/WebSocketServletContextHandlerFactory.java
   42 |      */
   43 |     public static ServletContextHandler create(Map<String, WebSocketHandlerWrapper> webSocketHandlers,
   44 |                                                Optional<Integer> webSocketIdleTimeoutMillis) {
   45 |         ServletContextHandler webSocketServletContextHandler = null;
   46 |         if (webSocketHandlers != null) {
   47 |             try {
   48 |                 webSocketServletContextHandler = new ServletContextHandler(null, "/", true, false);
   49 |                 WebSocketUpgradeFilter webSocketUpgradeFilter = WebSocketUpgradeFilter.configureContext(webSocketServletContextHandler);
   50 |                 if (webSocketIdleTimeoutMillis.isPresent()) {
   51 |                     webSocketUpgradeFilter.getFactory().getPolicy().setIdleTimeout(webSocketIdleTimeoutMillis.get());
   52 |                 }
   53 |                 for (String path : webSocketHandlers.keySet()) {
   54 |                     WebSocketCreator webSocketCreator = WebSocketCreatorFactory.create(webSocketHandlers.get(path));
   55 |                     webSocketUpgradeFilter.addMapping(new ServletPathSpec(path), webSocketCreator);
   56 |                 }
   57 |             } catch (Exception ex) {
   58 |                 logger.error("creation of websocket context handler failed.", ex);
   59 |                 webSocketServletContextHandler = null;
   60 |             }
   61 |         }
   62 |         return webSocketServletContextHandler;
   63 |     }
   64 | 
   65 | }
```

---

## 66/100 flow_id 5c865fd068 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 5c865fd068
key        : <org.eclipse.jetty.websocket.servlet.UpgradeHttpServletRequest: void <init>(javax.servlet.http.HttpServletRequest)>@L130/result => <spark.embeddedserver.jetty.websocket.WebSocketServletContextHandlerFactory: org.eclipse.jetty.servlet.ServletContextHandler create(java.util.Map,java.util.Optional)>@L55/0
source     : <org.eclipse.jetty.websocket.servlet.UpgradeHttpServletRequest: void <init>(javax.servlet.http.HttpServletRequest)>[86@L130] %v54 = invokeinterface httpRequest.getServerName()/result
sink       : <spark.embeddedserver.jetty.websocket.WebSocketServletContextHandlerFactory: org.eclipse.jetty.servlet.ServletContextHandler create(java.util.Map,java.util.Optional)>[28@L55] invokespecial %v28.<init>(path)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.embeddedserver.jetty.websocket.WebSocketServletContextHandlerFactory: org.eclipse.jetty.servlet.ServletContextHandler create(java.util.Map,java.util.Optional)>

## Application-code evidence (route or reachable-method fallback)
### <spark.embeddedserver.jetty.websocket.WebSocketServletContextHandlerFactory: org.eclipse.jetty.servlet.ServletContextHandler create(java.util.Map,java.util.Optional)>
file: spark/embeddedserver/jetty/websocket/WebSocketServletContextHandlerFactory.java
   42 |      */
   43 |     public static ServletContextHandler create(Map<String, WebSocketHandlerWrapper> webSocketHandlers,
   44 |                                                Optional<Integer> webSocketIdleTimeoutMillis) {
   45 |         ServletContextHandler webSocketServletContextHandler = null;
   46 |         if (webSocketHandlers != null) {
   47 |             try {
   48 |                 webSocketServletContextHandler = new ServletContextHandler(null, "/", true, false);
   49 |                 WebSocketUpgradeFilter webSocketUpgradeFilter = WebSocketUpgradeFilter.configureContext(webSocketServletContextHandler);
   50 |                 if (webSocketIdleTimeoutMillis.isPresent()) {
   51 |                     webSocketUpgradeFilter.getFactory().getPolicy().setIdleTimeout(webSocketIdleTimeoutMillis.get());
   52 |                 }
   53 |                 for (String path : webSocketHandlers.keySet()) {
   54 |                     WebSocketCreator webSocketCreator = WebSocketCreatorFactory.create(webSocketHandlers.get(path));
   55 |                     webSocketUpgradeFilter.addMapping(new ServletPathSpec(path), webSocketCreator);
   56 |                 }
   57 |             } catch (Exception ex) {
   58 |                 logger.error("creation of websocket context handler failed.", ex);
   59 |                 webSocketServletContextHandler = null;
   60 |             }
   61 |         }
   62 |         return webSocketServletContextHandler;
   63 |     }
   64 | 
   65 | }
```

---

## 67/100 flow_id 536163385e (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 536163385e
key        : <org.eclipse.jetty.security.authentication.FormAuthenticator$FormRequest: java.lang.String getHeader(java.lang.String)>@L470/result => <spark.resource.ClassPathResource: boolean exists()>@L122/0
source     : <org.eclipse.jetty.security.authentication.FormAuthenticator$FormRequest: java.lang.String getHeader(java.lang.String)>[7@L470] %v8 = invokespecial this.getHeader(name)/result
sink       : <spark.resource.ClassPathResource: boolean exists()>[10@L122] url = invokevirtual %v6.getResource(%v7)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.ClassPathResource: boolean exists()>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.ClassPathResource: boolean exists()>
file: spark/resource/ClassPathResource.java
  116 |     @Override
  117 |     public boolean exists() {
  118 |         URL url;
  119 |         if (this.clazz != null) {
  120 |             url = this.clazz.getResource(this.path);
  121 |         } else {
  122 |             url = this.classLoader.getResource(this.path);
  123 |         }
  124 |         return (url != null);
  125 |     }
  126 | 
  127 |     /**
```

---

## 68/100 flow_id 3b5693d16b (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 3b5693d16b
key        : <org.eclipse.jetty.websocket.server.WebSocketUpgradeFilter: void init(javax.servlet.FilterConfig)>@L282/result => <spark.resource.ClassPathResource: boolean exists()>@L122/0
source     : <org.eclipse.jetty.websocket.server.WebSocketUpgradeFilter: void init(javax.servlet.FilterConfig)>[23@L282] max#3 = invokeinterface config.getInitParameter(%c21)/result
sink       : <spark.resource.ClassPathResource: boolean exists()>[10@L122] url = invokevirtual %v6.getResource(%v7)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.ClassPathResource: boolean exists()>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.ClassPathResource: boolean exists()>
file: spark/resource/ClassPathResource.java
  116 |     @Override
  117 |     public boolean exists() {
  118 |         URL url;
  119 |         if (this.clazz != null) {
  120 |             url = this.clazz.getResource(this.path);
  121 |         } else {
  122 |             url = this.classLoader.getResource(this.path);
  123 |         }
  124 |         return (url != null);
  125 |     }
  126 | 
  127 |     /**
```

---

## 69/100 flow_id 63ff0648be (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 63ff0648be
key        : <spark.http.matching.MatcherFilter: java.lang.String getHttpMethodFrom(javax.servlet.http.HttpServletRequest)>@L171/result => <spark.resource.ClassPathResource: boolean exists()>@L122/0
source     : <spark.http.matching.MatcherFilter: java.lang.String getHttpMethodFrom(javax.servlet.http.HttpServletRequest)>[3@L171] method = invokeinterface httpRequest.getMethod()/result
sink       : <spark.resource.ClassPathResource: boolean exists()>[10@L122] url = invokevirtual %v6.getResource(%v7)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2, v4 run2
N3 (iris-like run2): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.http.matching.MatcherFilter: java.lang.String getHttpMethodFrom(javax.servlet.http.HttpServletRequest)>, <spark.resource.ClassPathResource: boolean exists()>

## Application-code evidence (route or reachable-method fallback)
### <spark.http.matching.MatcherFilter: java.lang.String getHttpMethodFrom(javax.servlet.http.HttpServletRequest)>
file: spark/http/matching/MatcherFilter.java
  165 |     }
  166 | 
  167 |     private String getHttpMethodFrom(HttpServletRequest httpRequest) {
  168 |         String method = httpRequest.getHeader(HTTP_METHOD_OVERRIDE_HEADER);
  169 | 
  170 |         if (method == null) {
  171 |             method = httpRequest.getMethod();
  172 |         }
  173 |         return method;
  174 |     }
  175 | 
  176 |     public void destroy() {

### <spark.resource.ClassPathResource: boolean exists()>
file: spark/resource/ClassPathResource.java
  116 |     @Override
  117 |     public boolean exists() {
  118 |         URL url;
  119 |         if (this.clazz != null) {
  120 |             url = this.clazz.getResource(this.path);
  121 |         } else {
  122 |             url = this.classLoader.getResource(this.path);
  123 |         }
  124 |         return (url != null);
  125 |     }
  126 | 
  127 |     /**
```

---

## 70/100 flow_id 97316615c2 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 97316615c2
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L50/result => <spark.resource.ClassPathResource: boolean exists()>@L122/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[17@L50] servletPath = invokeinterface request.getServletPath()/result
sink       : <spark.resource.ClassPathResource: boolean exists()>[10@L122] url = invokevirtual %v6.getResource(%v7)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>, <spark.resource.ClassPathResource: void <init>(java.lang.String)>, <spark.resource.ClassPathResource: void <init>(java.lang.String,java.lang.ClassLoader)>, <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.ClassPathResource: boolean exists()>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>
file: spark/resource/AbstractResourceHandler.java
   40 |     public AbstractFileResolvingResource getResource(HttpServletRequest request) throws MalformedURLException {
   41 |         String servletPath;
   42 |         String pathInfo;
   43 |         boolean included = request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null;
   44 | 
   45 |         if (included) {
   46 |             servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
   47 |             pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
   48 | 
   49 |             if (servletPath == null && pathInfo == null) {
   50 |                 servletPath = request.getServletPath();
   51 |                 pathInfo = request.getPathInfo();
   52 |             }
   53 |         } else {
   54 |             servletPath = request.getServletPath();
   55 |             pathInfo = request.getPathInfo();
   56 |         }
   57 | 
   58 |         String pathInContext = addPaths(servletPath, pathInfo);
   59 |         return getResource(pathInContext);
   60 |     }
   61 | 
   62 |     /**

### <spark.resource.ClassPathResource: void <init>(java.lang.String)>
file: spark/resource/ClassPathResource.java
   59 |      * @see spark.utils.ClassUtils#getDefaultClassLoader()
   60 |      */
   61 |     public ClassPathResource(String path) {
   62 |         this(path, null);
   63 |     }
   64 | 
   65 |     /**
   66 |      * Create a new ClassPathResource for ClassLoader usage.

### <spark.resource.ClassPathResource: void <init>(java.lang.String,java.lang.ClassLoader)>
file: spark/resource/ClassPathResource.java
   72 |      *                    or {@code null} for the thread context class loader
   73 |      * @see ClassLoader#getResourceAsStream(String)
   74 |      */
   75 |     public ClassPathResource(String path, ClassLoader classLoader) {
   76 |         Assert.notNull(path, "Path must not be null");
   77 |         String pathToUse = StringUtils.cleanPath(path);
   78 |         if (pathToUse.startsWith("/")) {
   79 |             pathToUse = pathToUse.substring(1);
   80 |         }
   81 |         this.path = pathToUse;
   82 |         this.classLoader = (classLoader != null ? classLoader : ClassUtils.getDefaultClassLoader());
   83 |     }
   84 | 
   85 |     /**
   86 |      * Create a new ClassPathResource with optional ClassLoader and Class.

### <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ClassPathResourceHandler.java
   59 | 
   60 |     @Override
   61 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   62 |         if (path == null || !path.startsWith("/")) {
   63 |             throw new MalformedURLException(path);
   64 |         }
   65 | 
   66 |         try {
   67 |             path = UriPath.canonical(path);
   68 | 
   69 |             final String addedPath = addPaths(baseResource, path);
   70 | 
   71 |             ClassPathResource resource = new ClassPathResource(addedPath);
   72 | 
   73 |             if (resource.exists() && resource.getFile().isDirectory()) {
   74 |                 if (welcomeFile != null) {
   75 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   76 |                 } else {
   77 |                     //  No welcome file configured, serve nothing since it's a directory
   78 |                     resource = null;
   79 |                 }
   80 |             }
   81 | 
   82 |             if (resource != null && resource.exists()) {
   83 |                 DirectoryTraversal.protectAgainstInClassPath(resource.getPath());
   84 |                 return resource;
   85 |             } else {
   86 |                 return null;
   87 |             }
   88 | 
   89 |         } catch (DirectoryTraversal.DirectoryTraversalDetection directoryTraversalDetection) {
   90 |             throw directoryTraversalDetection;
   91 |         } catch (Exception e) {
   92 |             if (LOG.isDebugEnabled()) {
   93 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   94 |             }
   95 |         }
   96 |         return null;
   97 |     }
   98 | 
   99 | }

### <spark.resource.ClassPathResource: boolean exists()>
file: spark/resource/ClassPathResource.java
  116 |     @Override
  117 |     public boolean exists() {
  118 |         URL url;
  119 |         if (this.clazz != null) {
  120 |             url = this.clazz.getResource(this.path);
  121 |         } else {
  122 |             url = this.classLoader.getResource(this.path);
  123 |         }
  124 |         return (url != null);
  125 |     }
  126 | 
  127 |     /**
```

---

## 71/100 flow_id 594594303a (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 594594303a
key        : DRIVER => <spark.resource.ClassPathResource: boolean exists()>@L122/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[34@L14] %v30 = invokestatic nesy.Taint.src()/result
sink       : <spark.resource.ClassPathResource: boolean exists()>[10@L122] url = invokevirtual %v6.getResource(%v7)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.ClassPathResource: boolean exists()>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.ClassPathResource: boolean exists()>
file: spark/resource/ClassPathResource.java
  116 |     @Override
  117 |     public boolean exists() {
  118 |         URL url;
  119 |         if (this.clazz != null) {
  120 |             url = this.clazz.getResource(this.path);
  121 |         } else {
  122 |             url = this.classLoader.getResource(this.path);
  123 |         }
  124 |         return (url != null);
  125 |     }
  126 | 
  127 |     /**
```

---

## 72/100 flow_id f20067e1b4 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow f20067e1b4
key        : <org.eclipse.jetty.server.Request: java.lang.String getContentType()>@L658/result => <spark.resource.ClassPathResource: boolean exists()>@L120/0
source     : <org.eclipse.jetty.server.Request: java.lang.String getContentType()>[3@L658] content_type = invokevirtual %v5.get(%v6)/result
sink       : <spark.resource.ClassPathResource: boolean exists()>[6@L120] url = invokevirtual %v4.getResource(%v5)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.ClassPathResource: boolean exists()>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.ClassPathResource: boolean exists()>
file: spark/resource/ClassPathResource.java
  116 |     @Override
  117 |     public boolean exists() {
  118 |         URL url;
  119 |         if (this.clazz != null) {
  120 |             url = this.clazz.getResource(this.path);
  121 |         } else {
  122 |             url = this.classLoader.getResource(this.path);
  123 |         }
  124 |         return (url != null);
  125 |     }
  126 | 
  127 |     /**
```

---

## 73/100 flow_id e03ebeccbf (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow e03ebeccbf
key        : <org.eclipse.jetty.websocket.servlet.ServletUpgradeRequest: void <init>(javax.servlet.http.HttpServletRequest)>@L52/result => <spark.resource.ClassPathResource: boolean exists()>@L120/0
source     : <org.eclipse.jetty.websocket.servlet.ServletUpgradeRequest: void <init>(javax.servlet.http.HttpServletRequest)>[3@L52] %v11 = invokeinterface httpRequest.getRequestURL()/result
sink       : <spark.resource.ClassPathResource: boolean exists()>[6@L120] url = invokevirtual %v4.getResource(%v5)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.ClassPathResource: boolean exists()>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.ClassPathResource: boolean exists()>
file: spark/resource/ClassPathResource.java
  116 |     @Override
  117 |     public boolean exists() {
  118 |         URL url;
  119 |         if (this.clazz != null) {
  120 |             url = this.clazz.getResource(this.path);
  121 |         } else {
  122 |             url = this.classLoader.getResource(this.path);
  123 |         }
  124 |         return (url != null);
  125 |     }
  126 | 
  127 |     /**
```

---

## 74/100 flow_id 9cfcd5d80b (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 9cfcd5d80b
key        : <spark.QueryParamsMap: java.lang.String[] parseKey(java.lang.String)>@L130/result => <spark.resource.ClassPathResource: boolean exists()>@L120/0
source     : <spark.QueryParamsMap: java.lang.String[] parseKey(java.lang.String)>[8@L130] %v9 = invokevirtual m.group()/result
sink       : <spark.resource.ClassPathResource: boolean exists()>[6@L120] url = invokevirtual %v4.getResource(%v5)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, iris-like run2, v1 run1, v1 run2, v4 run2
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.QueryParamsMap: java.lang.String[] parseKey(java.lang.String)>, <spark.resource.ClassPathResource: boolean exists()>

## Application-code evidence (route or reachable-method fallback)
### <spark.QueryParamsMap: java.lang.String[] parseKey(java.lang.String)>
file: spark/QueryParamsMap.java
  124 |     }
  125 | 
  126 |     protected final String[] parseKey(String key) {
  127 |         Matcher m = KEY_PATTERN.matcher(key);
  128 | 
  129 |         if (m.find()) {
  130 |             return new String[] {cleanKey(m.group()), key.substring(m.end())};
  131 |         } else {
  132 |             return null; // NOSONAR
  133 |         }
  134 |     }
  135 | 

### <spark.resource.ClassPathResource: boolean exists()>
file: spark/resource/ClassPathResource.java
  116 |     @Override
  117 |     public boolean exists() {
  118 |         URL url;
  119 |         if (this.clazz != null) {
  120 |             url = this.clazz.getResource(this.path);
  121 |         } else {
  122 |             url = this.classLoader.getResource(this.path);
  123 |         }
  124 |         return (url != null);
  125 |     }
  126 | 
  127 |     /**
```

---

## 75/100 flow_id 1bbadae946 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 1bbadae946
key        : <org.eclipse.jetty.server.session.HashSessionManager: org.eclipse.jetty.server.session.HashedSession restoreSession(java.io.InputStream,org.eclipse.jetty.server.session.HashedSession)>@L644/result => <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>@L139/0
source     : <org.eclipse.jetty.server.session.HashSessionManager: org.eclipse.jetty.server.session.HashedSession restoreSession(java.io.InputStream,org.eclipse.jetty.server.session.HashedSession)>[3@L644] clusterId = invokevirtual di.readUTF()/result
sink       : <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>[4@L139] is = invokevirtual %v4.getResourceAsStream(%v5)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>
file: spark/resource/ClassPathResource.java
  135 |     @Override
  136 |     public InputStream getInputStream() throws IOException {
  137 |         InputStream is;
  138 |         if (this.clazz != null) {
  139 |             is = this.clazz.getResourceAsStream(this.path);
  140 |         } else {
  141 |             is = this.classLoader.getResourceAsStream(this.path);
  142 |         }
  143 |         if (is == null) {
  144 |             throw new FileNotFoundException(getDescription() + " cannot be opened because it does not exist");
  145 |         }
  146 |         return is;
  147 |     }
  148 | 
  149 |     /**
```

---

## 76/100 flow_id 2c728c9b33 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 2c728c9b33
key        : <org.eclipse.jetty.websocket.servlet.ServletUpgradeRequest: void <init>(javax.servlet.http.HttpServletRequest)>@L52/result => <spark.resource.ClassPathResource: java.net.URL getURL()>@L161/0
source     : <org.eclipse.jetty.websocket.servlet.ServletUpgradeRequest: void <init>(javax.servlet.http.HttpServletRequest)>[3@L52] %v11 = invokeinterface httpRequest.getRequestURL()/result
sink       : <spark.resource.ClassPathResource: java.net.URL getURL()>[4@L161] url = invokevirtual %v4.getResource(%v5)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.ClassPathResource: java.net.URL getURL()>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.ClassPathResource: java.net.URL getURL()>
file: spark/resource/ClassPathResource.java
  157 |     @Override
  158 |     public URL getURL() throws IOException {
  159 |         URL url;
  160 |         if (this.clazz != null) {
  161 |             url = this.clazz.getResource(this.path);
  162 |         } else {
  163 |             url = this.classLoader.getResource(this.path);
  164 |         }
  165 |         if (url == null) {
  166 |             throw new FileNotFoundException(getDescription() + " cannot be resolved to URL because it does not exist");
  167 |         }
  168 |         return url;
  169 |     }
  170 | 
  171 |     /**
```

---

## 77/100 flow_id e6c796c1c4 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow e6c796c1c4
key        : <org.eclipse.jetty.websocket.server.WebSocketUpgradeFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>@L177/result => <spark.resource.ExternalResource: void <init>(java.lang.String)>@L40/0
source     : <org.eclipse.jetty.websocket.server.WebSocketUpgradeFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>[28@L177] target = invokeinterface httpreq.getRequestURI()/result
sink       : <spark.resource.ExternalResource: void <init>(java.lang.String)>[3@L40] invokespecial %v2.<init>(%v3)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.ExternalResource: void <init>(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.ExternalResource: void <init>(java.lang.String)>
file: spark/resource/ExternalResource.java
   36 |      *
   37 |      * @param path the path to the external resource
   38 |      */
   39 |     public ExternalResource(String path) {
   40 |         file = new File(StringUtils.cleanPath(path));
   41 |     }
   42 | 
   43 |     /**
   44 |      * Tests whether the file denoted by this abstract pathname is a
```

---

## 78/100 flow_id f1e6570210 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow f1e6570210
key        : <org.eclipse.jetty.websocket.servlet.ServletUpgradeRequest: void <init>(javax.servlet.http.HttpServletRequest)>@L52/result => <spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>@L81/0
source     : <org.eclipse.jetty.websocket.servlet.ServletUpgradeRequest: void <init>(javax.servlet.http.HttpServletRequest)>[3@L52] %v11 = invokeinterface httpRequest.getRequestURL()/result
sink       : <spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>[6@L81] invokespecial %v28.<init>(path)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, v1 run0, v1 run1
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>, <spark.Service: spark.Service staticFileLocation(java.lang.String)>, <spark.Spark: void externalStaticFileLocation(java.lang.String)>, <spark.Spark: void staticFileLocation(java.lang.String)>, <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>
file: spark/Service.java
  247 |      * @return the object with external folder set
  248 |      */
  249 |     public synchronized Service externalStaticFileLocation(String externalFolder) {
  250 |         if (initialized && !isRunningFromServlet()) {
  251 |             throwBeforeRouteMappingException();
  252 |         }
  253 | 
  254 |         externalStaticFileFolder = externalFolder;
  255 | 
  256 |         if (!servletExternalStaticLocationSet) {
  257 |             staticFilesConfiguration.configureExternal(externalStaticFileFolder);
  258 |             servletExternalStaticLocationSet = true;
  259 |         } else {
  260 |             LOG.warn("External static file location has already been set");
  261 |         }
  262 |         return this;
  263 |     }
  264 | 
  265 |     /**

### <spark.Service: spark.Service staticFileLocation(java.lang.String)>
file: spark/Service.java
  224 |      * @return the object with folder set
  225 |      */
  226 |     public synchronized Service staticFileLocation(String folder) {
  227 |         if (initialized && !isRunningFromServlet()) {
  228 |             throwBeforeRouteMappingException();
  229 |         }
  230 | 
  231 |         staticFileFolder = folder;
  232 | 
  233 |         if (!servletStaticLocationSet) {
  234 |             staticFilesConfiguration.configure(staticFileFolder);
  235 |             servletStaticLocationSet = true;
  236 |         } else {
  237 |             LOG.warn("Static file location has already been set");
  238 |         }
  239 |         return this;
  240 |     }
  241 | 
  242 |     /**

### <spark.Spark: void externalStaticFileLocation(java.lang.String)>
file: spark/Spark.java
 1031 |      * @param externalFolder the external folder serving static files.
 1032 |      */
 1033 |     public static void externalStaticFileLocation(String externalFolder) {
 1034 |         getInstance().externalStaticFileLocation(externalFolder);
 1035 |     }
 1036 | 
 1037 |     /**
 1038 |      * Waits for the spark server to be initialized.

### <spark.Spark: void staticFileLocation(java.lang.String)>
file: spark/Spark.java
 1019 |      * @param folder the folder in classpath.
 1020 |      */
 1021 |     public static void staticFileLocation(String folder) {
 1022 |         getInstance().staticFileLocation(folder);
 1023 |     }
 1024 | 
 1025 |     /**
 1026 |      * Sets the external folder serving static files. <b>Observe: this method

### <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>
file: spark/resource/AbstractResourceHandler.java
   78 |      * @return Legally combined path segments.
   79 |      */
   80 |     public static String addPaths(String segment1, String segment2) {
   81 |         if (segment1 == null || segment1.length() == 0) {
   82 |             if (segment1 != null && segment2 == null) {
   83 |                 return segment1;
   84 |             }
   85 |             return segment2;
   86 |         }
   87 |         if (segment2 == null || segment2.length() == 0) {
   88 |             return segment1;
   89 |         }
   90 | 
   91 |         int split = segment1.indexOf(';');
   92 |         if (split < 0) {
   93 |             split = segment1.indexOf('?');
   94 |         }
   95 |         if (split == 0) {
   96 |             return segment2 + segment1;
   97 |         }
   98 |         if (split < 0) {
   99 |             split = segment1.length();
  100 |         }
  101 | 
  102 |         StringBuilder buf = new StringBuilder(segment1.length() + segment2.length() + 2);
  103 |         buf.append(segment1);
  104 | 
  105 |         if (buf.charAt(split - 1) == '/') {
  106 |             if (segment2.startsWith(SLASH)) {
  107 |                 buf.deleteCharAt(split - 1);
  108 |                 buf.insert(split - 1, segment2);
  109 |             } else {
  110 |                 buf.insert(split, segment2);
  111 |             }
  112 |         } else {
  113 |             if (segment2.startsWith(SLASH)) {
  114 |                 buf.insert(split, segment2);
  115 |             } else {
  116 |                 buf.insert(split, '/');
  117 |                 buf.insert(split + 1, segment2);
  118 |             }
  119 |         }
  120 | 
  121 |         return buf.toString();
  122 |     }
  123 | 
  124 | }

### <spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>
file: spark/resource/JarResourceHandler.java
   77 |     }
   78 | 
   79 |     private InputStream getResourceStream(String path) throws MalformedURLException {
   80 |         if (path == null || !path.startsWith("/")) {
   81 |             throw new MalformedURLException(path);
   82 |         }
   83 | 
   84 |         InputStream resourceStream = null;
   85 | 
   86 |         try {
   87 |             path = UriPath.canonical(path);
   88 |             path = addPaths(baseResource, path);
   89 | 
   90 |             if (isDirectory(path)) {
   91 |                 if (welcomeFileConfigured()) {
   92 |                     path = addPaths(path, welcomeFile);
   93 |                     resourceStream = loadStream(path);
   94 |                 }
   95 |             } else {
   96 |                 resourceStream = loadStream(path);
   97 |             }
   98 | 
   99 |         } catch (Exception e) {
  100 |             if (LOG.isDebugEnabled()) {
  101 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
  102 |             }
  103 |         }
  104 | 
  105 |         return resourceStream;
  106 |     }
  107 | 
  108 |     private InputStream loadStream(String path) {
```

---

## 79/100 flow_id 129fe9e368 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 129fe9e368
key        : <spark.staticfiles.StaticFilesConfiguration: boolean consume(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>@L82/result => <spark.staticfiles.StaticFilesConfiguration: boolean consume(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>@L81/0
source     : <spark.staticfiles.StaticFilesConfiguration: boolean consume(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>[17@L82] %v15 = invokeinterface httpRequest.getPathInfo()/result
sink       : <spark.staticfiles.StaticFilesConfiguration: boolean consume(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>[20@L81] invokeinterface %v9.warn(%v17)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, v1 run0, v1 run1, v2 run0, v2 run1
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.staticfiles.StaticFilesConfiguration: boolean consume(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>

## Application-code evidence (route or reachable-method fallback)
### <spark.staticfiles.StaticFilesConfiguration: boolean consume(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>
file: spark/staticfiles/StaticFilesConfiguration.java
   70 |     public boolean consume(HttpServletRequest httpRequest,
   71 |                            HttpServletResponse httpResponse) throws IOException {
   72 |         try {
   73 |             if (consumeWithFileResourceHandlers(httpRequest, httpResponse)) {
   74 |                 return true;
   75 |             }
   76 | 
   77 |             if (consumeWithJarResourceHandler(httpRequest, httpResponse)) {
   78 |                 return true;
   79 |             }
   80 |         } catch (DirectoryTraversal.DirectoryTraversalDetection directoryTraversalDetection) {
   81 |             LOG.warn(directoryTraversalDetection.getMessage() + " directory traversal detection for path: "
   82 |                              + httpRequest.getPathInfo());
   83 |         }
   84 |         return false;
   85 |     }
   86 | 
   87 | 
```

---

## 80/100 flow_id 5832b1d98e (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 5832b1d98e
key        : DRIVER => <spark.utils.ResourceUtils: java.io.File getFile(java.lang.String)>@L168/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[26@L70] taintedPath#2 = invokestatic nesy.Taint.src()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.lang.String)>[18@L168] url = invokevirtual %v18.getResource(path)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[26@L70] taintedPath#2 = invokestatic nesy.Taint.src()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/taintedPath#2}
3. VarNode{<spark.utils.ResourceUtils: java.io.File getFile(java.lang.String)>/resourceLocation}
4. VarNode{<spark.utils.ResourceUtils: java.io.File getFile(java.lang.String)>/path}
5. <spark.utils.ResourceUtils: java.io.File getFile(java.lang.String)>[18@L168] url = invokevirtual %v18.getResource(path)/0

## Application-code evidence (route or reachable-method fallback)
### <spark.utils.ResourceUtils: java.io.File getFile(java.lang.String)>
file: spark/utils/ResourceUtils.java
  161 |      *                               a file in the file system
  162 |      */
  163 |     public static File getFile(String resourceLocation) throws FileNotFoundException {
  164 |         Assert.notNull(resourceLocation, "Resource location must not be null");
  165 |         if (resourceLocation.startsWith(CLASSPATH_URL_PREFIX)) {
  166 |             String path = resourceLocation.substring(CLASSPATH_URL_PREFIX.length());
  167 |             String description = "class path resource [" + path + "]";
  168 |             URL url = ClassUtils.getDefaultClassLoader().getResource(path);
  169 |             if (url == null) {
  170 |                 throw new FileNotFoundException(
  171 |                         description + " cannot be resolved to absolute file path " +
  172 |                                 "because it does not reside in the file system"
  173 |                 );
  174 |             }
  175 |             return getFile(url, description);
  176 |         }
  177 |         try {
  178 |             // try URL
  179 |             return getFile(new URL(resourceLocation));
  180 |         } catch (MalformedURLException ex) {
  181 |             // no URL -> treat as file path
  182 |             return new File(resourceLocation);
  183 |         }
  184 |     }
  185 | 
```

---

## 81/100 flow_id dba2fa24b4 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow dba2fa24b4
key        : <org.eclipse.jetty.http.HttpFields: java.lang.String get(org.eclipse.jetty.http.HttpHeader)>@L226/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>@L258/0
source     : <org.eclipse.jetty.http.HttpFields: java.lang.String get(org.eclipse.jetty.http.HttpHeader)>[9@L226] %v9 = invokevirtual f.getValue()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>[19@L258] invokespecial %v14.<init>(%v15)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>
file: spark/utils/ResourceUtils.java
  248 |      *                               a file in the file system
  249 |      */
  250 |     public static File getFile(URI resourceUri, String description) throws FileNotFoundException {
  251 |         Assert.notNull(resourceUri, "Resource URI must not be null");
  252 |         if (!URL_PROTOCOL_FILE.equals(resourceUri.getScheme())) {
  253 |             throw new FileNotFoundException(
  254 |                     description + " cannot be resolved to absolute file path " +
  255 |                             "because it does not reside in the file system: " + resourceUri
  256 |             );
  257 |         }
  258 |         return new File(resourceUri.getSchemeSpecificPart());
  259 |     }
  260 | 
  261 |     /**
```

---

## 82/100 flow_id 955c2ff085 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 955c2ff085
key        : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>@L257/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>@L258/0
source     : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>[16@L257] %v28 = invokeinterface request.getServletPath()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>[19@L258] invokespecial %v14.<init>(%v15)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>
file: spark/utils/ResourceUtils.java
  248 |      *                               a file in the file system
  249 |      */
  250 |     public static File getFile(URI resourceUri, String description) throws FileNotFoundException {
  251 |         Assert.notNull(resourceUri, "Resource URI must not be null");
  252 |         if (!URL_PROTOCOL_FILE.equals(resourceUri.getScheme())) {
  253 |             throw new FileNotFoundException(
  254 |                     description + " cannot be resolved to absolute file path " +
  255 |                             "because it does not reside in the file system: " + resourceUri
  256 |             );
  257 |         }
  258 |         return new File(resourceUri.getSchemeSpecificPart());
  259 |     }
  260 | 
  261 |     /**
```

---

## 83/100 flow_id 9da6576286 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 9da6576286
key        : <org.eclipse.jetty.server.Server: void handleAsync(org.eclipse.jetty.server.HttpChannel)>@L562/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>@L258/0
source     : <org.eclipse.jetty.server.Server: void handleAsync(org.eclipse.jetty.server.HttpChannel)>[38@L562] %v38 = invokeinterface request.getMethod()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>[19@L258] invokespecial %v14.<init>(%v15)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2, v4 run2
N3 (iris-like run2): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>
file: spark/utils/ResourceUtils.java
  248 |      *                               a file in the file system
  249 |      */
  250 |     public static File getFile(URI resourceUri, String description) throws FileNotFoundException {
  251 |         Assert.notNull(resourceUri, "Resource URI must not be null");
  252 |         if (!URL_PROTOCOL_FILE.equals(resourceUri.getScheme())) {
  253 |             throw new FileNotFoundException(
  254 |                     description + " cannot be resolved to absolute file path " +
  255 |                             "because it does not reside in the file system: " + resourceUri
  256 |             );
  257 |         }
  258 |         return new File(resourceUri.getSchemeSpecificPart());
  259 |     }
  260 | 
  261 |     /**
```

---

## 84/100 flow_id c7aefb4da3 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow c7aefb4da3
key        : <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>@L102/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>@L258/0
source     : <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>[14@L102] acceptType = invokeinterface httpRequest.getHeader(%c26)/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>[19@L258] invokespecial %v14.<init>(%v15)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>
file: spark/http/matching/MatcherFilter.java
   85 |                          ServletResponse servletResponse,
   86 |                          FilterChain chain) throws IOException, ServletException {
   87 | 
   88 |         HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
   89 |         HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;
   90 | 
   91 |         // handle static resources
   92 |         boolean consumedByStaticFile = staticFiles.consume(httpRequest, httpResponse);
   93 | 
   94 |         if (consumedByStaticFile) {
   95 |             return;
   96 |         }
   97 | 
   98 |         String method = getHttpMethodFrom(httpRequest);
   99 | 
  100 |         String httpMethodStr = method.toLowerCase();
  101 |         String uri = httpRequest.getRequestURI();
  102 |         String acceptType = httpRequest.getHeader(ACCEPT_TYPE_REQUEST_MIME_HEADER);
  103 | 
  104 |         Body body = Body.create();
  105 | 
  106 |         RequestWrapper requestWrapper = RequestWrapper.create();
  107 |         ResponseWrapper responseWrapper = ResponseWrapper.create();
  108 | 
  109 |         Response response = RequestResponseFactory.create(httpResponse);
  110 | 
  111 |         HttpMethod httpMethod = HttpMethod.get(httpMethodStr);
  112 | 
  113 |         RouteContext context = RouteContext.create()
  114 |                 .withMatcher(routeMatcher)
      | ... (lines omitted) ...
  139 | 
  140 |         // If redirected and content is null set to empty string to not throw NotConsumedException
  141 |         if (body.notSet() && responseWrapper.isRedirected()) {
  142 |             body.set("");
  143 |         }
  144 | 
  145 |         if (body.notSet() && hasOtherHandlers) {
  146 |             if (servletRequest instanceof HttpRequestWrapper) {
  147 |                 ((HttpRequestWrapper) servletRequest).notConsumed(true);
  148 |                 return;
  149 |             }
  150 |         }
  151 | 
  152 |         if (body.notSet() && !externalContainer) {
  153 |             LOG.info("The requested route [{}] has not been mapped in Spark for {}: [{}]",
  154 |                 uri, ACCEPT_TYPE_REQUEST_MIME_HEADER, acceptType);
  155 |             httpResponse.setStatus(HttpServletResponse.SC_NOT_FOUND);
  156 |             body.set(String.format(NOT_FOUND));
  157 |         }
  158 | 
  159 |         if (body.isSet()) {
  160 |             body.serializeTo(httpResponse, serializerChain, httpRequest);
  161 | 
  162 |         } else if (chain != null) {
  163 |             chain.doFilter(httpRequest, httpResponse);
  164 |         }
  165 |     }
  166 | 
  167 |     private String getHttpMethodFrom(HttpServletRequest httpRequest) {
  168 |         String method = httpRequest.getHeader(HTTP_METHOD_OVERRIDE_HEADER);

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>
file: spark/utils/ResourceUtils.java
  248 |      *                               a file in the file system
  249 |      */
  250 |     public static File getFile(URI resourceUri, String description) throws FileNotFoundException {
  251 |         Assert.notNull(resourceUri, "Resource URI must not be null");
  252 |         if (!URL_PROTOCOL_FILE.equals(resourceUri.getScheme())) {
  253 |             throw new FileNotFoundException(
  254 |                     description + " cannot be resolved to absolute file path " +
  255 |                             "because it does not reside in the file system: " + resourceUri
  256 |             );
  257 |         }
  258 |         return new File(resourceUri.getSchemeSpecificPart());
  259 |     }
  260 | 
  261 |     /**
```

---

## 85/100 flow_id ef16108f02 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow ef16108f02
key        : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>@L34/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>@L258/0
source     : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>[2@L34] path = invokeinterface request.getRequestURI()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>[19@L258] invokespecial %v14.<init>(%v15)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v3 run0, v3 run1, v3-noV2 run0, v3-noV2 run1, v3-noV3 run0, v3-noV3 run1, v3-noval run0, v3-noval run1, v4 run0, v4 run1, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>
file: spark/servlet/FilterTools.java
   31 |     }
   32 | 
   33 |     static String getRelativePath(HttpServletRequest request, String filterPath) {
   34 |         String path = request.getRequestURI();
   35 |         String contextPath = request.getContextPath();
   36 | 
   37 |         path = path.substring(contextPath.length());
   38 | 
   39 |         if (path.length() > 0) {
   40 |             path = path.substring(1);
   41 |         }
   42 | 
   43 |         if (!path.startsWith(filterPath) && filterPath.equals(path + SLASH)) {
   44 |             path += SLASH;
   45 |         }
   46 |         if (path.startsWith(filterPath)) {
   47 |             path = path.substring(filterPath.length());
   48 |         }
   49 | 
   50 |         if (!path.startsWith(SLASH)) {
   51 |             path = SLASH + path;
   52 |         }
   53 | 
   54 |         try {
   55 |             path = URLDecoder.decode(path, "UTF-8");
   56 |         } catch (UnsupportedEncodingException ex) {
   57 |             // this can't really ever happen
   58 |         }
   59 |         return path;
   60 |     }
   61 | 
   62 |     static String getFilterPath(FilterConfig config) {

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>
file: spark/utils/ResourceUtils.java
  248 |      *                               a file in the file system
  249 |      */
  250 |     public static File getFile(URI resourceUri, String description) throws FileNotFoundException {
  251 |         Assert.notNull(resourceUri, "Resource URI must not be null");
  252 |         if (!URL_PROTOCOL_FILE.equals(resourceUri.getScheme())) {
  253 |             throw new FileNotFoundException(
  254 |                     description + " cannot be resolved to absolute file path " +
  255 |                             "because it does not reside in the file system: " + resourceUri
  256 |             );
  257 |         }
  258 |         return new File(resourceUri.getSchemeSpecificPart());
  259 |     }
  260 | 
  261 |     /**
```

---

## 86/100 flow_id 405b06ada9 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 405b06ada9
key        : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>@L55/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>@L258/0
source     : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>[39@L55] path#1 = invokestatic java.net.URLDecoder.decode(path#1, %c30)/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>[19@L258] invokespecial %v14.<init>(%v15)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>
file: spark/servlet/FilterTools.java
   31 |     }
   32 | 
   33 |     static String getRelativePath(HttpServletRequest request, String filterPath) {
   34 |         String path = request.getRequestURI();
   35 |         String contextPath = request.getContextPath();
   36 | 
   37 |         path = path.substring(contextPath.length());
   38 | 
   39 |         if (path.length() > 0) {
   40 |             path = path.substring(1);
   41 |         }
   42 | 
   43 |         if (!path.startsWith(filterPath) && filterPath.equals(path + SLASH)) {
   44 |             path += SLASH;
   45 |         }
   46 |         if (path.startsWith(filterPath)) {
   47 |             path = path.substring(filterPath.length());
   48 |         }
   49 | 
   50 |         if (!path.startsWith(SLASH)) {
   51 |             path = SLASH + path;
   52 |         }
   53 | 
   54 |         try {
   55 |             path = URLDecoder.decode(path, "UTF-8");
   56 |         } catch (UnsupportedEncodingException ex) {
   57 |             // this can't really ever happen
   58 |         }
   59 |         return path;
   60 |     }
   61 | 
   62 |     static String getFilterPath(FilterConfig config) {

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>
file: spark/utils/ResourceUtils.java
  248 |      *                               a file in the file system
  249 |      */
  250 |     public static File getFile(URI resourceUri, String description) throws FileNotFoundException {
  251 |         Assert.notNull(resourceUri, "Resource URI must not be null");
  252 |         if (!URL_PROTOCOL_FILE.equals(resourceUri.getScheme())) {
  253 |             throw new FileNotFoundException(
  254 |                     description + " cannot be resolved to absolute file path " +
  255 |                             "because it does not reside in the file system: " + resourceUri
  256 |             );
  257 |         }
  258 |         return new File(resourceUri.getSchemeSpecificPart());
  259 |     }
  260 | 
  261 |     /**
```

---

## 87/100 flow_id f4cfd3c44b (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow f4cfd3c44b
key        : DRIVER => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>@L258/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[10@L50] taintedPath = invokestatic nesy.Taint.src()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>[19@L258] invokespecial %v14.<init>(%v15)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v3 run0, v3 run1, v3-noV2 run0, v3-noV2 run1, v3-noV3 run0, v3-noV3 run1, v3-noval run0, v3-noval run1, v4 run0, v4 run1, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>
file: spark/utils/ResourceUtils.java
  248 |      *                               a file in the file system
  249 |      */
  250 |     public static File getFile(URI resourceUri, String description) throws FileNotFoundException {
  251 |         Assert.notNull(resourceUri, "Resource URI must not be null");
  252 |         if (!URL_PROTOCOL_FILE.equals(resourceUri.getScheme())) {
  253 |             throw new FileNotFoundException(
  254 |                     description + " cannot be resolved to absolute file path " +
  255 |                             "because it does not reside in the file system: " + resourceUri
  256 |             );
  257 |         }
  258 |         return new File(resourceUri.getSchemeSpecificPart());
  259 |     }
  260 | 
  261 |     /**
```

---

## 88/100 flow_id 180c31a8ef (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 180c31a8ef
key        : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>@L34/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>[2@L34] path = invokeinterface request.getRequestURI()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>
file: spark/servlet/FilterTools.java
   31 |     }
   32 | 
   33 |     static String getRelativePath(HttpServletRequest request, String filterPath) {
   34 |         String path = request.getRequestURI();
   35 |         String contextPath = request.getContextPath();
   36 | 
   37 |         path = path.substring(contextPath.length());
   38 | 
   39 |         if (path.length() > 0) {
   40 |             path = path.substring(1);
   41 |         }
   42 | 
   43 |         if (!path.startsWith(filterPath) && filterPath.equals(path + SLASH)) {
   44 |             path += SLASH;
   45 |         }
   46 |         if (path.startsWith(filterPath)) {
   47 |             path = path.substring(filterPath.length());
   48 |         }
   49 | 
   50 |         if (!path.startsWith(SLASH)) {
   51 |             path = SLASH + path;
   52 |         }
   53 | 
   54 |         try {
   55 |             path = URLDecoder.decode(path, "UTF-8");
   56 |         } catch (UnsupportedEncodingException ex) {
   57 |             // this can't really ever happen
   58 |         }
   59 |         return path;
   60 |     }
   61 | 
   62 |     static String getFilterPath(FilterConfig config) {

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 89/100 flow_id c565525ede (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow c565525ede
key        : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>@L55/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>[39@L55] path#1 = invokestatic java.net.URLDecoder.decode(path#1, %c30)/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>
file: spark/servlet/FilterTools.java
   31 |     }
   32 | 
   33 |     static String getRelativePath(HttpServletRequest request, String filterPath) {
   34 |         String path = request.getRequestURI();
   35 |         String contextPath = request.getContextPath();
   36 | 
   37 |         path = path.substring(contextPath.length());
   38 | 
   39 |         if (path.length() > 0) {
   40 |             path = path.substring(1);
   41 |         }
   42 | 
   43 |         if (!path.startsWith(filterPath) && filterPath.equals(path + SLASH)) {
   44 |             path += SLASH;
   45 |         }
   46 |         if (path.startsWith(filterPath)) {
   47 |             path = path.substring(filterPath.length());
   48 |         }
   49 | 
   50 |         if (!path.startsWith(SLASH)) {
   51 |             path = SLASH + path;
   52 |         }
   53 | 
   54 |         try {
   55 |             path = URLDecoder.decode(path, "UTF-8");
   56 |         } catch (UnsupportedEncodingException ex) {
   57 |             // this can't really ever happen
   58 |         }
   59 |         return path;
   60 |     }
   61 | 
   62 |     static String getFilterPath(FilterConfig config) {

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 90/100 flow_id ac1cb7b5f3 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow ac1cb7b5f3
key        : <spark.staticfiles.StaticFilesConfiguration: boolean consumeWithJarResourceHandler(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>@L120/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <spark.staticfiles.StaticFilesConfiguration: boolean consumeWithJarResourceHandler(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>[13@L120] %v16 = invokeinterface httpRequest.getPathInfo()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v4 run0, v4 run1, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.staticfiles.StaticFilesConfiguration: boolean consumeWithJarResourceHandler(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.staticfiles.StaticFilesConfiguration: boolean consumeWithJarResourceHandler(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>
file: spark/staticfiles/StaticFilesConfiguration.java
  111 | 
  112 |     private boolean consumeWithJarResourceHandler(HttpServletRequest httpRequest,
  113 |                                                   HttpServletResponse httpResponse) throws IOException {
  114 |         if (jarResourceHandlers != null) {
  115 | 
  116 |             for (JarResourceHandler jarResourceHandler : jarResourceHandlers) {
  117 |                 InputStream stream = jarResourceHandler.getResource(httpRequest);
  118 | 
  119 |                 if (stream != null) {
  120 |                     httpResponse.setHeader(MimeType.CONTENT_TYPE, MimeType.fromPathInfo(httpRequest.getPathInfo()));
  121 |                     customHeaders.forEach(httpResponse::setHeader); //add all user-defined headers to response
  122 |                     OutputStream wrappedOutputStream = GzipUtils.checkAndWrap(httpRequest, httpResponse, false);
  123 | 
  124 |                     IOUtils.copy(stream, wrappedOutputStream);
  125 |                     wrappedOutputStream.flush();
  126 |                     wrappedOutputStream.close();
  127 |                     return true;
  128 |                 }
  129 |             }
  130 |         }
  131 |         return false;
  132 |     }
  133 | 
  134 |     /**

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 91/100 flow_id c43a43deba (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow c43a43deba
key        : DRIVER => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[10@L50] taintedPath = invokestatic nesy.Taint.src()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 92/100 flow_id 7619bbff8d (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 7619bbff8d
key        : <org.eclipse.jetty.http.HttpField: java.lang.String toString()>@L370/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L222/base
source     : <org.eclipse.jetty.http.HttpField: java.lang.String toString()>[3@L370] %v4 = invokevirtual this.getName()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[24@L222] %v20 = invokevirtual resourceUrl.getFile()/base
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1
N3 (iris-like run1): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.utils.ResourceUtils: java.io.File getFile(java.lang.String)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.utils.ResourceUtils: java.io.File getFile(java.lang.String)>
file: spark/utils/ResourceUtils.java
  161 |      *                               a file in the file system
  162 |      */
  163 |     public static File getFile(String resourceLocation) throws FileNotFoundException {
  164 |         Assert.notNull(resourceLocation, "Resource location must not be null");
  165 |         if (resourceLocation.startsWith(CLASSPATH_URL_PREFIX)) {
  166 |             String path = resourceLocation.substring(CLASSPATH_URL_PREFIX.length());
  167 |             String description = "class path resource [" + path + "]";
  168 |             URL url = ClassUtils.getDefaultClassLoader().getResource(path);
  169 |             if (url == null) {
  170 |                 throw new FileNotFoundException(
  171 |                         description + " cannot be resolved to absolute file path " +
  172 |                                 "because it does not reside in the file system"
  173 |                 );
  174 |             }
  175 |             return getFile(url, description);
  176 |         }
  177 |         try {
  178 |             // try URL
  179 |             return getFile(new URL(resourceLocation));
  180 |         } catch (MalformedURLException ex) {
  181 |             // no URL -> treat as file path
  182 |             return new File(resourceLocation);
  183 |         }
  184 |     }
  185 | 

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL)>
file: spark/utils/ResourceUtils.java
  193 |      *                               a file in the file system
  194 |      */
  195 |     public static File getFile(URL resourceUrl) throws FileNotFoundException {
  196 |         return getFile(resourceUrl, "URL");
  197 |     }
  198 | 
  199 |     /**

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 93/100 flow_id 12ff11f774 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 12ff11f774
key        : DRIVER => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L222/base
source     : <nesy.NesyDriver: void main(java.lang.String[])>[26@L63] taintedPath#2 = invokestatic nesy.Taint.src()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[24@L222] %v20 = invokevirtual resourceUrl.getFile()/base
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[26@L63] taintedPath#2 = invokestatic nesy.Taint.src()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/taintedPath#2}
3. VarNode{<spark.utils.ResourceUtils: java.io.File getFile(java.lang.String)>/resourceLocation}
4. VarNode{<spark.utils.ResourceUtils: java.io.File getFile(java.lang.String)>/%v28}
5. VarNode{<spark.utils.ResourceUtils: java.io.File getFile(java.net.URL)>/resourceUrl}
6. VarNode{<spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>/resourceUrl}
7. <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[24@L222] %v20 = invokevirtual resourceUrl.getFile()/base

## Application-code evidence (route or reachable-method fallback)
### <spark.utils.ResourceUtils: java.io.File getFile(java.lang.String)>
file: spark/utils/ResourceUtils.java
  161 |      *                               a file in the file system
  162 |      */
  163 |     public static File getFile(String resourceLocation) throws FileNotFoundException {
  164 |         Assert.notNull(resourceLocation, "Resource location must not be null");
  165 |         if (resourceLocation.startsWith(CLASSPATH_URL_PREFIX)) {
  166 |             String path = resourceLocation.substring(CLASSPATH_URL_PREFIX.length());
  167 |             String description = "class path resource [" + path + "]";
  168 |             URL url = ClassUtils.getDefaultClassLoader().getResource(path);
  169 |             if (url == null) {
  170 |                 throw new FileNotFoundException(
  171 |                         description + " cannot be resolved to absolute file path " +
  172 |                                 "because it does not reside in the file system"
  173 |                 );
  174 |             }
  175 |             return getFile(url, description);
  176 |         }
  177 |         try {
  178 |             // try URL
  179 |             return getFile(new URL(resourceLocation));
  180 |         } catch (MalformedURLException ex) {
  181 |             // no URL -> treat as file path
  182 |             return new File(resourceLocation);
  183 |         }
  184 |     }
  185 | 

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL)>
file: spark/utils/ResourceUtils.java
  193 |      *                               a file in the file system
  194 |      */
  195 |     public static File getFile(URL resourceUrl) throws FileNotFoundException {
  196 |         return getFile(resourceUrl, "URL");
  197 |     }
  198 | 
  199 |     /**

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 94/100 flow_id d807e04e07 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow d807e04e07
key        : <org.eclipse.jetty.http.HttpField: java.lang.String toString()>@L369/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L222/0
source     : <org.eclipse.jetty.http.HttpField: java.lang.String toString()>[0@L369] v = invokevirtual this.getValue()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[25@L222] invokespecial %v19.<init>(%v20)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 95/100 flow_id 50a925b54f (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 50a925b54f
key        : <org.eclipse.jetty.http.HttpFields$1: java.lang.String nextElement()>@L305/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L222/0
source     : <org.eclipse.jetty.http.HttpFields$1: java.lang.String nextElement()>[4@L305] value = invokevirtual %v4.getValue()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[25@L222] invokespecial %v19.<init>(%v20)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 96/100 flow_id 20e2052f79 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 20e2052f79
key        : <org.eclipse.jetty.http.HttpFields: java.lang.String toString()>@L660/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L222/0
source     : <org.eclipse.jetty.http.HttpFields: java.lang.String toString()>[14@L660] tmp#1 = invokevirtual field.getValue()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[25@L222] invokespecial %v19.<init>(%v20)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 97/100 flow_id 372ac6f207 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 372ac6f207
key        : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>@L34/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L222/0
source     : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>[2@L34] path = invokeinterface request.getRequestURI()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[25@L222] invokespecial %v19.<init>(%v20)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>
file: spark/servlet/FilterTools.java
   31 |     }
   32 | 
   33 |     static String getRelativePath(HttpServletRequest request, String filterPath) {
   34 |         String path = request.getRequestURI();
   35 |         String contextPath = request.getContextPath();
   36 | 
   37 |         path = path.substring(contextPath.length());
   38 | 
   39 |         if (path.length() > 0) {
   40 |             path = path.substring(1);
   41 |         }
   42 | 
   43 |         if (!path.startsWith(filterPath) && filterPath.equals(path + SLASH)) {
   44 |             path += SLASH;
   45 |         }
   46 |         if (path.startsWith(filterPath)) {
   47 |             path = path.substring(filterPath.length());
   48 |         }
   49 | 
   50 |         if (!path.startsWith(SLASH)) {
   51 |             path = SLASH + path;
   52 |         }
   53 | 
   54 |         try {
   55 |             path = URLDecoder.decode(path, "UTF-8");
   56 |         } catch (UnsupportedEncodingException ex) {
   57 |             // this can't really ever happen
   58 |         }
   59 |         return path;
   60 |     }
   61 | 
   62 |     static String getFilterPath(FilterConfig config) {

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 98/100 flow_id 75e7902380 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 75e7902380
key        : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>@L55/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L222/0
source     : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>[39@L55] path#1 = invokestatic java.net.URLDecoder.decode(path#1, %c30)/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[25@L222] invokespecial %v19.<init>(%v20)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>
file: spark/servlet/FilterTools.java
   31 |     }
   32 | 
   33 |     static String getRelativePath(HttpServletRequest request, String filterPath) {
   34 |         String path = request.getRequestURI();
   35 |         String contextPath = request.getContextPath();
   36 | 
   37 |         path = path.substring(contextPath.length());
   38 | 
   39 |         if (path.length() > 0) {
   40 |             path = path.substring(1);
   41 |         }
   42 | 
   43 |         if (!path.startsWith(filterPath) && filterPath.equals(path + SLASH)) {
   44 |             path += SLASH;
   45 |         }
   46 |         if (path.startsWith(filterPath)) {
   47 |             path = path.substring(filterPath.length());
   48 |         }
   49 | 
   50 |         if (!path.startsWith(SLASH)) {
   51 |             path = SLASH + path;
   52 |         }
   53 | 
   54 |         try {
   55 |             path = URLDecoder.decode(path, "UTF-8");
   56 |         } catch (UnsupportedEncodingException ex) {
   57 |             // this can't really ever happen
   58 |         }
   59 |         return path;
   60 |     }
   61 | 
   62 |     static String getFilterPath(FilterConfig config) {

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 99/100 flow_id 29ab07c346 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 29ab07c346
key        : <spark.staticfiles.StaticFilesConfiguration: boolean consumeWithJarResourceHandler(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>@L120/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L222/0
source     : <spark.staticfiles.StaticFilesConfiguration: boolean consumeWithJarResourceHandler(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>[13@L120] %v16 = invokeinterface httpRequest.getPathInfo()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[25@L222] invokespecial %v19.<init>(%v20)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.staticfiles.StaticFilesConfiguration: boolean consumeWithJarResourceHandler(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.staticfiles.StaticFilesConfiguration: boolean consumeWithJarResourceHandler(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>
file: spark/staticfiles/StaticFilesConfiguration.java
  111 | 
  112 |     private boolean consumeWithJarResourceHandler(HttpServletRequest httpRequest,
  113 |                                                   HttpServletResponse httpResponse) throws IOException {
  114 |         if (jarResourceHandlers != null) {
  115 | 
  116 |             for (JarResourceHandler jarResourceHandler : jarResourceHandlers) {
  117 |                 InputStream stream = jarResourceHandler.getResource(httpRequest);
  118 | 
  119 |                 if (stream != null) {
  120 |                     httpResponse.setHeader(MimeType.CONTENT_TYPE, MimeType.fromPathInfo(httpRequest.getPathInfo()));
  121 |                     customHeaders.forEach(httpResponse::setHeader); //add all user-defined headers to response
  122 |                     OutputStream wrappedOutputStream = GzipUtils.checkAndWrap(httpRequest, httpResponse, false);
  123 | 
  124 |                     IOUtils.copy(stream, wrappedOutputStream);
  125 |                     wrappedOutputStream.flush();
  126 |                     wrappedOutputStream.close();
  127 |                     return true;
  128 |                 }
  129 |             }
  130 |         }
  131 |         return false;
  132 |     }
  133 | 
  134 |     /**

### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```

---

## 100/100 flow_id 00b5a94768 (priority 2)

```text
# spark/fixed (CVE-2016-9177, CWE-022) flow 00b5a94768
key        : DRIVER => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L222/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[10@L50] taintedPath = invokestatic nesy.Taint.src()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[25@L222] invokespecial %v19.<init>(%v20)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>
file: spark/utils/ResourceUtils.java
  208 |      *                               a file in the file system
  209 |      */
  210 |     public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
  211 |         Assert.notNull(resourceUrl, "Resource URL must not be null");
  212 |         if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
  213 |             throw new FileNotFoundException(
  214 |                     description + " cannot be resolved to absolute file path " +
  215 |                             "because it does not reside in the file system: " + resourceUrl
  216 |             );
  217 |         }
  218 |         try {
  219 |             return new File(toURI(resourceUrl).getSchemeSpecificPart());
  220 |         } catch (URISyntaxException ex) {
  221 |             // Fallback for URLs that are not valid URIs (should hardly ever happen).
  222 |             return new File(resourceUrl.getFile());
  223 |         }
  224 |     }
  225 | 
```
