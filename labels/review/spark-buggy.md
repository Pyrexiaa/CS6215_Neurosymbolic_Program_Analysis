# Labelling pack: spark / buggy

113 frozen sampled rows. Evidence uses the exact raw source and sink in the chosen run record. Existing labels remain unverified and are unchanged. A canonical key may still group different drivers or routes; inspect the attacker model before reusing a label. Original packets are retained in results/history/pre-evidence-refresh.tar.gz.

---

## 1/113 flow_id 83673012ef (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 83673012ef
key        : <org.eclipse.jetty.http.HttpParser: boolean parseHeaders(java.nio.ByteBuffer)>@L1001/result => <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L62/0
source     : <org.eclipse.jetty.http.HttpParser: boolean parseHeaders(java.nio.ByteBuffer)>[191@L1001] n = invokevirtual field.getName()/result
sink       : <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }
```

---

## 2/113 flow_id b00f309010 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow b00f309010
key        : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>@L383/result => <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L62/0
source     : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>[237@L383] buf#1 = invokeinterface request.getRequestURL()/result
sink       : <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource, ExternalResourceHandler.getResource
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>[237@L383] buf#1 = invokeinterface request.getRequestURL()/result
2. VarNode{<org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>/buf#1}
3. VarNode{<org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>/%v161}
4. VarNode{<org.eclipse.jetty.server.session.AbstractSession: void setAttribute(java.lang.String,java.lang.Object)>/value}
5. VarNode{<org.eclipse.jetty.server.session.AbstractSession: java.lang.Object changeAttribute(java.lang.String,java.lang.Object)>/value}
6. VarNode{<org.eclipse.jetty.server.session.MemSession: java.lang.Object doPutOrRemove(java.lang.String,java.lang.Object)>/value}
7. VarNode{<org.eclipse.jetty.server.session.MemSession: java.lang.Object doPutOrRemove(java.lang.String,java.lang.Object)>/%v5}
8. InstanceFieldNode{NewObj{<org.eclipse.jetty.server.session.HashSessionManager: org.eclipse.jetty.server.session.AbstractSession newSession(long,long,java.lang.String)>[0@L498] new org.eclipse.jetty.server.session.HashedSession}.<org.eclipse.jetty.server.session.MemSession: java.util.Map _attributes>
9. VarNode{<org.eclipse.jetty.server.session.MemSession: java.lang.Object doGet(java.lang.String)>/%v2}
10. VarNode{<org.eclipse.jetty.server.session.MemSession: java.lang.Object doGet(java.lang.String)>/%v3}
11. VarNode{<org.eclipse.jetty.server.session.AbstractSession: java.lang.Object getAttribute(java.lang.String)>/%v4}
12. VarNode{<org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>/%v48}
13. VarNode{<org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>/nuri}
14. VarNode{<org.eclipse.jetty.server.Response: java.lang.String encodeRedirectURL(java.lang.String)>/url}
15. VarNode{<org.eclipse.jetty.server.Response: java.lang.String encodeURL(java.lang.String)>/url}
16. VarNode{<org.eclipse.jetty.server.Response: java.lang.String encodeRedirectURL(java.lang.String)>/%v2}
17. VarNode{<org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>/%v61}
18. VarNode{<org.eclipse.jetty.server.Response: void sendRedirect(int,java.lang.String)>/location}
19. VarNode{<org.eclipse.jetty.util.URIUtil: java.lang.String canonicalPath(java.lang.String)>/path}
20. VarNode{<org.eclipse.jetty.server.Request: void setMetaData(org.eclipse.jetty.http.MetaData$Request)>/info}
21. VarNode{<org.eclipse.jetty.server.Request: void setPathInfo(java.lang.String)>/pathInfo}
22. InstanceFieldNode{NewObj{<org.eclipse.jetty.server.HttpChannel: void <init>(org.eclipse.jetty.server.Connector,org.eclipse.jetty.server.HttpConfiguration,org.eclipse.jetty.io.EndPoint,org.eclipse.jetty.server.HttpTransport)>[19@L94] new org.eclipse.jetty.server.Request}.<org.eclipse.jetty.server.Req
23. VarNode{<org.eclipse.jetty.server.Request: java.lang.String getPathInfo()>/%v1}
24. VarNode{<javax.servlet.http.HttpServletRequestWrapper: java.lang.String getPathInfo()>/%v2}
25. VarNode{<spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>/pathInfo}
26. VarNode{<spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>/segment2}
27. VarNode{<spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>/pathInContext}
28. VarNode{<spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>/path}
29. <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0

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

### <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ClassPathResourceHandler.java
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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }
```

---

## 3/113 flow_id 82dc6c9f84 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 82dc6c9f84
key        : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>@L180/result => <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L62/0
source     : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[60@L180] %v56 = invokevirtual old_uri.getQuery()/result
sink       : <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource, ExternalResourceHandler.getResource
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[60@L180] %v56 = invokevirtual old_uri.getQuery()/result
2. VarNode{<org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>/%v56}
3. InstanceFieldNode{NewObj{<org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[33@L163] new org.eclipse.jetty.server.Dispatcher$ForwardAttributes}.<org.eclipse.jetty.server.Dispatcher$ForwardAttributes: java.lang.
4. VarNode{<org.eclipse.jetty.server.Dispatcher$ForwardAttributes: java.lang.Object getAttribute(java.lang.String)>/%v20}
5. VarNode{<org.eclipse.jetty.server.Request: java.lang.Object getAttribute(java.lang.String)>/%v25}
6. VarNode{<javax.servlet.ServletRequestWrapper: java.lang.Object getAttribute(java.lang.String)>/%v3}
7. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>/%v13}
8. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>/servletPath}
9. VarNode{<spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>/segment1}
10. VarNode{<spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>/pathInContext}
11. VarNode{<spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>/path}
12. <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0

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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }
```

---

## 4/113 flow_id 1f5a25a24f (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 1f5a25a24f
key        : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>@L187/result => <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L62/0
source     : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[75@L187] %v67 = invokevirtual %v66.getQuery()/result
sink       : <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource, ExternalResourceHandler.getResource
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

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
11. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>/%v13}
12. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>/servletPath}
13. VarNode{<spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>/segment1}
14. VarNode{<spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>/pathInContext}
15. VarNode{<spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>/path}
16. <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0

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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }
```

---

## 5/113 flow_id 37a0eb6526 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 37a0eb6526
key        : <org.eclipse.jetty.server.Response: java.lang.String getHeader(java.lang.String)>@L765/result => <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L62/0
source     : <org.eclipse.jetty.server.Response: java.lang.String getHeader(java.lang.String)>[1@L765] %v3 = invokevirtual %v2.get(name)/result
sink       : <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }
```

---

## 6/113 flow_id 3a8485cfe2 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 3a8485cfe2
key        : <org.eclipse.jetty.server.session.HashSessionIdManager: void addSession(javax.servlet.http.HttpSession)>@L121/result => <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L62/0
source     : <org.eclipse.jetty.server.session.HashSessionIdManager: void addSession(javax.servlet.http.HttpSession)>[0@L121] %v7 = invokeinterface session.getId()/result
sink       : <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }
```

---

## 7/113 flow_id da9fdb3dd9 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow da9fdb3dd9
key        : <org.eclipse.jetty.server.session.SessionHandler: void checkRequestedSessionId(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest)>@L293/result => <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L62/0
source     : <org.eclipse.jetty.server.session.SessionHandler: void checkRequestedSessionId(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest)>[60@L293] uri = invokeinterface request.getRequestURI()/result
sink       : <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }
```

---

## 8/113 flow_id 81f305c38f (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 81f305c38f
key        : <org.eclipse.jetty.servlet.ServletHandler: void notFound(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>@L1554/result => <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L62/0
source     : <org.eclipse.jetty.servlet.ServletHandler: void notFound(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>[8@L1554] %v10 = invokeinterface request.getRequestURI()/result
sink       : <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }
```

---

## 9/113 flow_id 3791083f26 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 3791083f26
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L54/result => <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L62/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[20@L54] servletPath = invokeinterface request.getServletPath()/result
sink       : <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }
```

---

## 10/113 flow_id b766846503 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow b766846503
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L55/result => <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L62/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[21@L55] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }
```

---

## 11/113 flow_id 722d7aab92 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 722d7aab92
key        : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>@L68/result => <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L62/0
source     : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[18@L68] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource, ExternalResourceHandler.getResource
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[18@L68] pathInfo = invokeinterface request.getPathInfo()/result
2. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>/pathInfo}
3. VarNode{<spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>/segment2}
4. VarNode{<spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>/pathInContext}
5. VarNode{<spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>/path}
6. <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L62] invokespecial %v35.<init>(path)/0

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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }
```

---

## 12/113 flow_id 5bac33c247 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 5bac33c247
key        : <org.eclipse.jetty.http.HttpField: java.lang.String toString()>@L369/result => <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L61/0
source     : <org.eclipse.jetty.http.HttpField: java.lang.String toString()>[0@L369] v = invokevirtual this.getValue()/result
sink       : <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L61] invokespecial %v34.<init>(path)/0
fixed methods on this flow (GT): ExternalResourceHandler.getResource
reported by: iris-like run1, v1 run1
N3 (iris-like run1): vulnerable / exploitable (kept=True, v3_ok=None)

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
   57 | 
   58 |     @Override
   59 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   60 |         if (path == null || !path.startsWith("/")) {
   61 |             throw new MalformedURLException(path);
   62 |         }
   63 | 
   64 |         try {
   65 |             path = UriPath.canonical(path);
   66 | 
   67 |             final String addedPath = addPaths(baseResource, path);
   68 | 
   69 |             ExternalResource resource = new ExternalResource(addedPath);
   70 | 
   71 |             if (resource.exists() && resource.isDirectory()) {
   72 |                 if (welcomeFile != null) {
   73 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   74 |                 } else {
   75 |                     //  No welcome file configured, serve nothing since it's a directory
   76 |                     resource = null;
   77 |                 }
   78 |             }
   79 | 
   80 |             return (resource != null && resource.exists()) ? resource : null;
   81 |         } catch (Exception e) {
   82 |             if (LOG.isDebugEnabled()) {
   83 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   84 |             }
   85 |         }
   86 |         return null;
   87 |     }
   88 | 
   89 | }
```

---

## 13/113 flow_id fde695644f (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow fde695644f
key        : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>@L319/result => <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L61/0
source     : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>[144@L319] %v103 = invokeinterface request.getContextPath()/result
sink       : <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L61] invokespecial %v34.<init>(path)/0
fixed methods on this flow (GT): ExternalResourceHandler.getResource, ClassPathResourceHandler.getResource
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

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
13. VarNode{<spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>/pathInContext}
14. VarNode{<spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>/path}
15. <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L61] invokespecial %v34.<init>(path)/0

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
   57 | 
   58 |     @Override
   59 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   60 |         if (path == null || !path.startsWith("/")) {
   61 |             throw new MalformedURLException(path);
   62 |         }
   63 | 
   64 |         try {
   65 |             path = UriPath.canonical(path);
   66 | 
   67 |             final String addedPath = addPaths(baseResource, path);
   68 | 
   69 |             ExternalResource resource = new ExternalResource(addedPath);
   70 | 
   71 |             if (resource.exists() && resource.isDirectory()) {
   72 |                 if (welcomeFile != null) {
   73 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   74 |                 } else {
   75 |                     //  No welcome file configured, serve nothing since it's a directory
   76 |                     resource = null;
   77 |                 }
   78 |             }
   79 | 
   80 |             return (resource != null && resource.exists()) ? resource : null;
   81 |         } catch (Exception e) {
   82 |             if (LOG.isDebugEnabled()) {
   83 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   84 |             }
   85 |         }
   86 |         return null;
   87 |     }
   88 | 
   89 | }
```

---

## 14/113 flow_id 39728dba45 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 39728dba45
key        : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>@L409/result => <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L61/0
source     : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>[298@L409] %v192 = invokeinterface session.getId()/result
sink       : <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L61] invokespecial %v34.<init>(path)/0
fixed methods on this flow (GT): ExternalResourceHandler.getResource
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

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
   57 | 
   58 |     @Override
   59 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   60 |         if (path == null || !path.startsWith("/")) {
   61 |             throw new MalformedURLException(path);
   62 |         }
   63 | 
   64 |         try {
   65 |             path = UriPath.canonical(path);
   66 | 
   67 |             final String addedPath = addPaths(baseResource, path);
   68 | 
   69 |             ExternalResource resource = new ExternalResource(addedPath);
   70 | 
   71 |             if (resource.exists() && resource.isDirectory()) {
   72 |                 if (welcomeFile != null) {
   73 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   74 |                 } else {
   75 |                     //  No welcome file configured, serve nothing since it's a directory
   76 |                     resource = null;
   77 |                 }
   78 |             }
   79 | 
   80 |             return (resource != null && resource.exists()) ? resource : null;
   81 |         } catch (Exception e) {
   82 |             if (LOG.isDebugEnabled()) {
   83 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   84 |             }
   85 |         }
   86 |         return null;
   87 |     }
   88 | 
   89 | }
```

---

## 15/113 flow_id 690f7b93c1 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 690f7b93c1
key        : <org.eclipse.jetty.server.Response: java.lang.String getHeader(java.lang.String)>@L765/result => <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L61/0
source     : <org.eclipse.jetty.server.Response: java.lang.String getHeader(java.lang.String)>[1@L765] %v3 = invokevirtual %v2.get(name)/result
sink       : <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L61] invokespecial %v34.<init>(path)/0
fixed methods on this flow (GT): ExternalResourceHandler.getResource
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

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
   57 | 
   58 |     @Override
   59 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   60 |         if (path == null || !path.startsWith("/")) {
   61 |             throw new MalformedURLException(path);
   62 |         }
   63 | 
   64 |         try {
   65 |             path = UriPath.canonical(path);
   66 | 
   67 |             final String addedPath = addPaths(baseResource, path);
   68 | 
   69 |             ExternalResource resource = new ExternalResource(addedPath);
   70 | 
   71 |             if (resource.exists() && resource.isDirectory()) {
   72 |                 if (welcomeFile != null) {
   73 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   74 |                 } else {
   75 |                     //  No welcome file configured, serve nothing since it's a directory
   76 |                     resource = null;
   77 |                 }
   78 |             }
   79 | 
   80 |             return (resource != null && resource.exists()) ? resource : null;
   81 |         } catch (Exception e) {
   82 |             if (LOG.isDebugEnabled()) {
   83 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   84 |             }
   85 |         }
   86 |         return null;
   87 |     }
   88 | 
   89 | }
```

---

## 16/113 flow_id 825bb2990d (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 825bb2990d
key        : <org.eclipse.jetty.server.session.HashSessionManager: org.eclipse.jetty.server.session.HashedSession restoreSession(java.io.InputStream,org.eclipse.jetty.server.session.HashedSession)>@L644/result => <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L61/0
source     : <org.eclipse.jetty.server.session.HashSessionManager: org.eclipse.jetty.server.session.HashedSession restoreSession(java.io.InputStream,org.eclipse.jetty.server.session.HashedSession)>[3@L644] clusterId = invokevirtual di.readUTF()/result
sink       : <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L61] invokespecial %v34.<init>(path)/0
fixed methods on this flow (GT): ExternalResourceHandler.getResource
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

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
   57 | 
   58 |     @Override
   59 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   60 |         if (path == null || !path.startsWith("/")) {
   61 |             throw new MalformedURLException(path);
   62 |         }
   63 | 
   64 |         try {
   65 |             path = UriPath.canonical(path);
   66 | 
   67 |             final String addedPath = addPaths(baseResource, path);
   68 | 
   69 |             ExternalResource resource = new ExternalResource(addedPath);
   70 | 
   71 |             if (resource.exists() && resource.isDirectory()) {
   72 |                 if (welcomeFile != null) {
   73 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   74 |                 } else {
   75 |                     //  No welcome file configured, serve nothing since it's a directory
   76 |                     resource = null;
   77 |                 }
   78 |             }
   79 | 
   80 |             return (resource != null && resource.exists()) ? resource : null;
   81 |         } catch (Exception e) {
   82 |             if (LOG.isDebugEnabled()) {
   83 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   84 |             }
   85 |         }
   86 |         return null;
   87 |     }
   88 | 
   89 | }
```

---

## 17/113 flow_id 178c0f9d75 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 178c0f9d75
key        : <org.eclipse.jetty.websocket.server.WebSocketUpgradeFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>@L177/result => <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L61/0
source     : <org.eclipse.jetty.websocket.server.WebSocketUpgradeFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>[28@L177] target = invokeinterface httpreq.getRequestURI()/result
sink       : <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L61] invokespecial %v34.<init>(path)/0
fixed methods on this flow (GT): ExternalResourceHandler.getResource
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

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
   57 | 
   58 |     @Override
   59 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   60 |         if (path == null || !path.startsWith("/")) {
   61 |             throw new MalformedURLException(path);
   62 |         }
   63 | 
   64 |         try {
   65 |             path = UriPath.canonical(path);
   66 | 
   67 |             final String addedPath = addPaths(baseResource, path);
   68 | 
   69 |             ExternalResource resource = new ExternalResource(addedPath);
   70 | 
   71 |             if (resource.exists() && resource.isDirectory()) {
   72 |                 if (welcomeFile != null) {
   73 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   74 |                 } else {
   75 |                     //  No welcome file configured, serve nothing since it's a directory
   76 |                     resource = null;
   77 |                 }
   78 |             }
   79 | 
   80 |             return (resource != null && resource.exists()) ? resource : null;
   81 |         } catch (Exception e) {
   82 |             if (LOG.isDebugEnabled()) {
   83 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   84 |             }
   85 |         }
   86 |         return null;
   87 |     }
   88 | 
   89 | }
```

---

## 18/113 flow_id b0d6a0e501 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow b0d6a0e501
key        : <org.eclipse.jetty.websocket.servlet.UpgradeHttpServletRequest: void <init>(javax.servlet.http.HttpServletRequest)>@L114/result => <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>@L61/0
source     : <org.eclipse.jetty.websocket.servlet.UpgradeHttpServletRequest: void <init>(javax.servlet.http.HttpServletRequest)>[57@L114] %v35 = invokeinterface httpRequest.getHeaders(name)/result
sink       : <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>[6@L61] invokespecial %v34.<init>(path)/0
fixed methods on this flow (GT): ExternalResourceHandler.getResource
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

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
   57 | 
   58 |     @Override
   59 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   60 |         if (path == null || !path.startsWith("/")) {
   61 |             throw new MalformedURLException(path);
   62 |         }
   63 | 
   64 |         try {
   65 |             path = UriPath.canonical(path);
   66 | 
   67 |             final String addedPath = addPaths(baseResource, path);
   68 | 
   69 |             ExternalResource resource = new ExternalResource(addedPath);
   70 | 
   71 |             if (resource.exists() && resource.isDirectory()) {
   72 |                 if (welcomeFile != null) {
   73 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   74 |                 } else {
   75 |                     //  No welcome file configured, serve nothing since it's a directory
   76 |                     resource = null;
   77 |                 }
   78 |             }
   79 | 
   80 |             return (resource != null && resource.exists()) ? resource : null;
   81 |         } catch (Exception e) {
   82 |             if (LOG.isDebugEnabled()) {
   83 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   84 |             }
   85 |         }
   86 |         return null;
   87 |     }
   88 | 
   89 | }
```

---

## 19/113 flow_id f63f51f6d5 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow f63f51f6d5
key        : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>@L195/result => <spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>@L81/0
source     : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[91@L195] %v76 = invokevirtual old_uri.getQuery()/result
sink       : <spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>[6@L81] invokespecial %v28.<init>(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource, ExternalResourceHandler.getResource
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[91@L195] %v76 = invokevirtual old_uri.getQuery()/result
2. VarNode{<org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>/%v76}
3. VarNode{<org.eclipse.jetty.server.Request: void mergeQueryParameters(java.lang.String,java.lang.String,boolean)>/oldQuery}
4. VarNode{<org.eclipse.jetty.server.Request: void setQueryString(java.lang.String)>/queryString}
5. VarNode{<org.eclipse.jetty.http.HttpURI: void setQuery(java.lang.String)>/query}
6. InstanceFieldNode{NewObj{<org.eclipse.jetty.server.HttpChannelOverHttp: void <init>(org.eclipse.jetty.server.HttpConnection,org.eclipse.jetty.server.Connector,org.eclipse.jetty.server.HttpConfiguration,org.eclipse.jetty.io.EndPoint,org.eclipse.jetty.server.HttpTransport)>[15@L66] new org.eclipse.jet
7. VarNode{<org.eclipse.jetty.http.HttpURI: java.lang.String getQuery()>/%v1}
8. VarNode{<org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>/%v56}
9. InstanceFieldNode{NewObj{<org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[33@L163] new org.eclipse.jetty.server.Dispatcher$ForwardAttributes}.<org.eclipse.jetty.server.Dispatcher$ForwardAttributes: java.lang.
10. VarNode{<org.eclipse.jetty.server.Dispatcher$ForwardAttributes: java.lang.Object getAttribute(java.lang.String)>/%v20}
11. VarNode{<org.eclipse.jetty.server.Request: java.lang.Object getAttribute(java.lang.String)>/%v25}
12. VarNode{<javax.servlet.ServletRequestWrapper: java.lang.Object getAttribute(java.lang.String)>/%v3}
13. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>/%v13}
14. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>/servletPath}
15. VarNode{<spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>/segment1}
16. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>/pathInContext}
17. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>/path}
18. <spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>[6@L81] invokespecial %v28.<init>(path)/0

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
```

---

## 20/113 flow_id 32420b0972 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 32420b0972
key        : <org.eclipse.jetty.http.HttpParser: boolean parseHeaders(java.nio.ByteBuffer)>@L1002/result => <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>@L109/0
source     : <org.eclipse.jetty.http.HttpParser: boolean parseHeaders(java.nio.ByteBuffer)>[192@L1002] v = invokevirtual field.getValue()/result
sink       : <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>[1@L109] %v3 = invokevirtual %c2.getResourceAsStream(path)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>, <spark.Service: spark.Service staticFileLocation(java.lang.String)>, <spark.Spark: void externalStaticFileLocation(java.lang.String)>, <spark.Spark: void staticFileLocation(java.lang.String)>, <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>

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

## 21/113 flow_id 59609926d1 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 59609926d1
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L50/result => <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>@L109/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[17@L50] servletPath = invokeinterface request.getServletPath()/result
sink       : <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>[1@L109] %v3 = invokevirtual %c2.getResourceAsStream(path)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>, <spark.Service: spark.Service staticFileLocation(java.lang.String)>, <spark.Spark: void externalStaticFileLocation(java.lang.String)>, <spark.Spark: void staticFileLocation(java.lang.String)>, <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>

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

## 22/113 flow_id 1a649937fa (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 1a649937fa
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L51/result => <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>@L109/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[18@L51] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>[1@L109] %v3 = invokevirtual %c2.getResourceAsStream(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource, ExternalResourceHandler.getResource
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[18@L51] pathInfo = invokeinterface request.getPathInfo()/result
2. VarNode{<spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>/pathInfo}
3. VarNode{<spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>/segment2}
4. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>/path#2}
5. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>/path}
6. <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>[1@L109] %v3 = invokevirtual %c2.getResourceAsStream(path)/0

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

## 23/113 flow_id 0da199a211 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 0da199a211
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L54/result => <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>@L109/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[20@L54] servletPath = invokeinterface request.getServletPath()/result
sink       : <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>[1@L109] %v3 = invokevirtual %c2.getResourceAsStream(path)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run2, v3-noV2 run0, v3-noV3 run2, v3-noval run0, v4 run2
N3 (v3 run2): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>, <spark.Service: spark.Service staticFileLocation(java.lang.String)>, <spark.Spark: void externalStaticFileLocation(java.lang.String)>, <spark.Spark: void staticFileLocation(java.lang.String)>, <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>

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

## 24/113 flow_id a093bd337c (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow a093bd337c
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L55/result => <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>@L109/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[21@L55] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>[1@L109] %v3 = invokevirtual %c2.getResourceAsStream(path)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>, <spark.Service: spark.Service staticFileLocation(java.lang.String)>, <spark.Spark: void externalStaticFileLocation(java.lang.String)>, <spark.Spark: void staticFileLocation(java.lang.String)>, <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>

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

## 25/113 flow_id dccb4dad3e (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow dccb4dad3e
key        : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>@L67/result => <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>@L109/0
source     : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[17@L67] servletPath = invokeinterface request.getServletPath()/result
sink       : <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>[1@L109] %v3 = invokevirtual %c2.getResourceAsStream(path)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>, <spark.Service: spark.Service staticFileLocation(java.lang.String)>, <spark.Spark: void externalStaticFileLocation(java.lang.String)>, <spark.Spark: void staticFileLocation(java.lang.String)>, <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>

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

## 26/113 flow_id 58e1e93791 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 58e1e93791
key        : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>@L68/result => <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>@L109/0
source     : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[18@L68] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>[1@L109] %v3 = invokevirtual %c2.getResourceAsStream(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource, ExternalResourceHandler.getResource
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[18@L68] pathInfo = invokeinterface request.getPathInfo()/result
2. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>/pathInfo}
3. VarNode{<spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>/segment2}
4. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>/path#2}
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

## 27/113 flow_id fa1c1eb535 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow fa1c1eb535
key        : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>@L71/result => <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>@L109/0
source     : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[20@L71] servletPath = invokeinterface request.getServletPath()/result
sink       : <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>[1@L109] %v3 = invokevirtual %c2.getResourceAsStream(path)/0
fixed methods on this flow (GT): ClassPathResourceHandler.getResource, ExternalResourceHandler.getResource
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[20@L71] servletPath = invokeinterface request.getServletPath()/result
2. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>/servletPath}
3. VarNode{<spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>/segment1}
4. VarNode{<spark.resource.JarResourceHandler: java.io.InputStream getResourceStream(java.lang.String)>/path#2}
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

## 28/113 flow_id d19cdc2704 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow d19cdc2704
key        : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>@L72/result => <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>@L109/0
source     : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[21@L72] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>[1@L109] %v3 = invokevirtual %c2.getResourceAsStream(path)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>, <spark.Service: spark.Service staticFileLocation(java.lang.String)>, <spark.Spark: void externalStaticFileLocation(java.lang.String)>, <spark.Spark: void staticFileLocation(java.lang.String)>, <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>

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

## 29/113 flow_id ba411df1cf (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow ba411df1cf
key        : DRIVER => <spark.staticfiles.StaticFilesConfiguration: boolean configureJarCase(java.lang.String,spark.resource.ClassPathResource)>@L183/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[54@L72] %v35 = invokestatic nesy.Taint.src()/result
sink       : <spark.staticfiles.StaticFilesConfiguration: boolean configureJarCase(java.lang.String,spark.resource.ClassPathResource)>[8@L183] stream = invokevirtual %c9.getResourceAsStream(folder)/0
fixed methods on this flow (GT): StaticFilesConfiguration.configureJarCase, StaticFilesConfiguration.configure
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[54@L72] %v35 = invokestatic nesy.Taint.src()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v35}
3. VarNode{<spark.Spark: void staticFileLocation(java.lang.String)>/folder}
4. VarNode{<spark.Service: spark.Service staticFileLocation(java.lang.String)>/folder}
5. InstanceFieldNode{NewObj{<spark.Service: spark.Service ignite()>[0@L95] new spark.Service}.<spark.Service: java.lang.String staticFileFolder>}
6. VarNode{<spark.Service: spark.Service staticFileLocation(java.lang.String)>/%v7}
7. VarNode{<spark.staticfiles.StaticFilesConfiguration: void configure(java.lang.String)>/folder}
8. VarNode{<spark.staticfiles.StaticFilesConfiguration: boolean configureJarCase(java.lang.String,spark.resource.ClassPathResource)>/folder}
9. <spark.staticfiles.StaticFilesConfiguration: boolean configureJarCase(java.lang.String,spark.resource.ClassPathResource)>[8@L183] stream = invokevirtual %c9.getResourceAsStream(folder)/0

## Application-code evidence (route or reachable-method fallback)
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

### <spark.staticfiles.StaticFilesConfiguration: void configure(java.lang.String)>
file: spark/staticfiles/StaticFilesConfiguration.java
  148 |      * @param folder the location
  149 |      */
  150 |     public synchronized void configure(String folder) {
  151 |         Assert.notNull(folder, "'folder' must not be null");
  152 | 
  153 |         if (!staticResourcesSet) {
  154 |             try {
  155 |                 ClassPathResource resource = new ClassPathResource(folder);
  156 | 
  157 |                 if (configureJarCase(folder, resource)) {
  158 |                     return;
  159 |                 }
  160 | 
  161 |                 if (!resource.getFile().isDirectory()) {
  162 |                     LOG.error("Static resource location must be a folder");
  163 |                     return;
  164 |                 }
  165 | 
  166 |                 if (staticResourceHandlers == null) {
  167 |                     staticResourceHandlers = new ArrayList<>();
  168 |                 }
  169 | 
  170 |                 staticResourceHandlers.add(new ClassPathResourceHandler(folder, "index.html"));
  171 |                 LOG.info("StaticResourceHandler configured with folder = " + folder);
  172 |             } catch (IOException e) {
  173 |                 LOG.error("Error when creating StaticResourceHandler", e);
  174 |             }
  175 |             staticResourcesSet = true;
  176 |         }
  177 | 
  178 |     }
  179 | 
  180 |     private boolean configureJarCase(String folder, ClassPathResource resource) throws IOException {
  181 |         if (resource.getURL().getProtocol().equals("jar")) {

### <spark.staticfiles.StaticFilesConfiguration: boolean configureJarCase(java.lang.String,spark.resource.ClassPathResource)>
file: spark/staticfiles/StaticFilesConfiguration.java
  178 |     }
  179 | 
  180 |     private boolean configureJarCase(String folder, ClassPathResource resource) throws IOException {
  181 |         if (resource.getURL().getProtocol().equals("jar")) {
  182 | 
  183 |             InputStream stream = StaticFilesConfiguration.class.getResourceAsStream(folder);
  184 | 
  185 |             if (stream != null) {
  186 |                 if (jarResourceHandlers == null) {
  187 |                     jarResourceHandlers = new ArrayList<>();
  188 |                 }
  189 | 
  190 |                 // Add jar file resource handler
  191 |                 jarResourceHandlers.add(new JarResourceHandler(folder, "index.html"));
  192 |                 staticResourcesSet = true;
  193 |                 return true;
  194 |             } else {
  195 |                 LOG.error("Static file configuration failed.");
  196 |             }
  197 | 
  198 |         }
  199 |         return false;
  200 |     }
  201 | 
  202 |     /**
```

---

## 30/113 flow_id c84f553eac (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow c84f553eac
key        : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>@L383/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>[237@L383] buf#1 = invokeinterface request.getRequestURL()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

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

## 31/113 flow_id 4ce220db31 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 4ce220db31
key        : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>@L187/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[75@L187] %v67 = invokevirtual %v66.getQuery()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

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

## 32/113 flow_id cc29054553 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow cc29054553
key        : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>@L195/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[91@L195] %v76 = invokevirtual old_uri.getQuery()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

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

## 33/113 flow_id de9fcdcbd4 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow de9fcdcbd4
key        : <org.eclipse.jetty.server.Request: int findServerPort()>@L1440/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <org.eclipse.jetty.server.Request: int findServerPort()>[12@L1440] %v11 = invokevirtual host.getValue()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

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

## 34/113 flow_id 62b57b6091 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 62b57b6091
key        : <org.eclipse.jetty.server.Request: java.lang.String findServerName()>@L1386/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <org.eclipse.jetty.server.Request: java.lang.String findServerName()>[11@L1386] %v12 = invokevirtual host.getValue()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

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

## 35/113 flow_id bd3368115c (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow bd3368115c
key        : <org.eclipse.jetty.server.Request: java.lang.String getQueryString()>@L1141/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <org.eclipse.jetty.server.Request: java.lang.String getQueryString()>[2@L1141] %v3 = invokevirtual %v2.getQuery()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

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

## 36/113 flow_id f02599b836 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow f02599b836
key        : <org.eclipse.jetty.server.handler.gzip.GzipHandler: void handle(java.lang.String,org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>@L419/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <org.eclipse.jetty.server.handler.gzip.GzipHandler: void handle(java.lang.String,org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>[103@L419] etag = invokevirtual %v64.get(%v65)/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

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

## 37/113 flow_id 153c5ea061 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 153c5ea061
key        : <org.eclipse.jetty.servlet.ServletHandler: void notFound(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>@L1556/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <org.eclipse.jetty.servlet.ServletHandler: void notFound(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>[13@L1556] %v14 = invokeinterface request.getServletPath()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

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

## 38/113 flow_id e1b93f1b2b (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow e1b93f1b2b
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L50/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[17@L50] servletPath = invokeinterface request.getServletPath()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

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

## 39/113 flow_id c87d7475f8 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow c87d7475f8
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L51/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[18@L51] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>, <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

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

### <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ClassPathResourceHandler.java
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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   57 | 
   58 |     @Override
   59 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   60 |         if (path == null || !path.startsWith("/")) {
   61 |             throw new MalformedURLException(path);
   62 |         }
   63 | 
   64 |         try {
   65 |             path = UriPath.canonical(path);
   66 | 
   67 |             final String addedPath = addPaths(baseResource, path);
   68 | 
   69 |             ExternalResource resource = new ExternalResource(addedPath);
   70 | 
   71 |             if (resource.exists() && resource.isDirectory()) {
   72 |                 if (welcomeFile != null) {
   73 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   74 |                 } else {
   75 |                     //  No welcome file configured, serve nothing since it's a directory
   76 |                     resource = null;
   77 |                 }
   78 |             }
   79 | 
   80 |             return (resource != null && resource.exists()) ? resource : null;
   81 |         } catch (Exception e) {
   82 |             if (LOG.isDebugEnabled()) {
   83 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   84 |             }
   85 |         }
   86 |         return null;
   87 |     }
   88 | 
   89 | }

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

## 40/113 flow_id 3b74d0637a (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 3b74d0637a
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L54/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[20@L54] servletPath = invokeinterface request.getServletPath()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>, <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

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

### <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ClassPathResourceHandler.java
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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   57 | 
   58 |     @Override
   59 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   60 |         if (path == null || !path.startsWith("/")) {
   61 |             throw new MalformedURLException(path);
   62 |         }
   63 | 
   64 |         try {
   65 |             path = UriPath.canonical(path);
   66 | 
   67 |             final String addedPath = addPaths(baseResource, path);
   68 | 
   69 |             ExternalResource resource = new ExternalResource(addedPath);
   70 | 
   71 |             if (resource.exists() && resource.isDirectory()) {
   72 |                 if (welcomeFile != null) {
   73 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   74 |                 } else {
   75 |                     //  No welcome file configured, serve nothing since it's a directory
   76 |                     resource = null;
   77 |                 }
   78 |             }
   79 | 
   80 |             return (resource != null && resource.exists()) ? resource : null;
   81 |         } catch (Exception e) {
   82 |             if (LOG.isDebugEnabled()) {
   83 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   84 |             }
   85 |         }
   86 |         return null;
   87 |     }
   88 | 
   89 | }

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

## 41/113 flow_id 97393d333c (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 97393d333c
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L55/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[21@L55] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

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

## 42/113 flow_id de79c00dfb (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow de79c00dfb
key        : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>@L67/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[17@L67] servletPath = invokeinterface request.getServletPath()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

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

## 43/113 flow_id 10f4340490 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 10f4340490
key        : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>@L68/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[18@L68] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>, <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

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

### <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ClassPathResourceHandler.java
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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   57 | 
   58 |     @Override
   59 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   60 |         if (path == null || !path.startsWith("/")) {
   61 |             throw new MalformedURLException(path);
   62 |         }
   63 | 
   64 |         try {
   65 |             path = UriPath.canonical(path);
   66 | 
   67 |             final String addedPath = addPaths(baseResource, path);
   68 | 
   69 |             ExternalResource resource = new ExternalResource(addedPath);
   70 | 
   71 |             if (resource.exists() && resource.isDirectory()) {
   72 |                 if (welcomeFile != null) {
   73 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   74 |                 } else {
   75 |                     //  No welcome file configured, serve nothing since it's a directory
   76 |                     resource = null;
   77 |                 }
   78 |             }
   79 | 
   80 |             return (resource != null && resource.exists()) ? resource : null;
   81 |         } catch (Exception e) {
   82 |             if (LOG.isDebugEnabled()) {
   83 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   84 |             }
   85 |         }
   86 |         return null;
   87 |     }
   88 | 
   89 | }

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

## 44/113 flow_id d3d0d719ab (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow d3d0d719ab
key        : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>@L71/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[20@L71] servletPath = invokeinterface request.getServletPath()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>, <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

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

### <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ClassPathResourceHandler.java
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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   57 | 
   58 |     @Override
   59 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   60 |         if (path == null || !path.startsWith("/")) {
   61 |             throw new MalformedURLException(path);
   62 |         }
   63 | 
   64 |         try {
   65 |             path = UriPath.canonical(path);
   66 | 
   67 |             final String addedPath = addPaths(baseResource, path);
   68 | 
   69 |             ExternalResource resource = new ExternalResource(addedPath);
   70 | 
   71 |             if (resource.exists() && resource.isDirectory()) {
   72 |                 if (welcomeFile != null) {
   73 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   74 |                 } else {
   75 |                     //  No welcome file configured, serve nothing since it's a directory
   76 |                     resource = null;
   77 |                 }
   78 |             }
   79 | 
   80 |             return (resource != null && resource.exists()) ? resource : null;
   81 |         } catch (Exception e) {
   82 |             if (LOG.isDebugEnabled()) {
   83 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   84 |             }
   85 |         }
   86 |         return null;
   87 |     }
   88 | 
   89 | }

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

## 45/113 flow_id 6764e622e6 (priority 1)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 6764e622e6
key        : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>@L72/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[21@L72] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

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

## 46/113 flow_id c842e46023 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow c842e46023
key        : <org.eclipse.jetty.server.Request: java.lang.String getQueryString()>@L1141/result => <org.eclipse.jetty.servlet.ServletHolder: void initJspServlet()>@L688/0
source     : <org.eclipse.jetty.server.Request: java.lang.String getQueryString()>[2@L1141] %v3 = invokevirtual %v2.getQuery()/result
sink       : <org.eclipse.jetty.servlet.ServletHolder: void initJspServlet()>[45@L688] invokespecial scratch#1.<init>(%v39)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.server.Request: java.lang.String getQueryString()>, <org.eclipse.jetty.servlet.ServletHolder: void initJspServlet()>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 47/113 flow_id 285e39f5bc (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 285e39f5bc
key        : <org.eclipse.jetty.server.handler.gzip.GzipHttpOutputInterceptor: void commit(java.nio.ByteBuffer,boolean,org.eclipse.jetty.util.Callback)>@L212/result => <org.eclipse.jetty.servlet.ServletHolder: void initJspServlet()>@L688/0
source     : <org.eclipse.jetty.server.handler.gzip.GzipHttpOutputInterceptor: void commit(java.nio.ByteBuffer,boolean,org.eclipse.jetty.util.Callback)>[116@L212] etag = invokevirtual fields.get(%v84)/result
sink       : <org.eclipse.jetty.servlet.ServletHolder: void initJspServlet()>[45@L688] invokespecial scratch#1.<init>(%v39)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.server.handler.gzip.GzipHttpOutputInterceptor: void commit(java.nio.ByteBuffer,boolean,org.eclipse.jetty.util.Callback)>, <org.eclipse.jetty.servlet.ServletHolder: void initJspServlet()>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 48/113 flow_id 93c567d16c (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 93c567d16c
key        : <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>@L101/result => <org.eclipse.jetty.servlet.ServletHolder: void initJspServlet()>@L688/0
source     : <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>[12@L101] acceptType = invokeinterface httpRequest.getHeader(%c26)/result
sink       : <org.eclipse.jetty.servlet.ServletHolder: void initJspServlet()>[45@L688] invokespecial scratch#1.<init>(%v39)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>

## Application-code evidence (route or reachable-method fallback)
### <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>
file: spark/http/matching/MatcherFilter.java
   84 |                          ServletResponse servletResponse,
   85 |                          FilterChain chain) throws IOException, ServletException {
   86 | 
   87 |         HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
   88 |         HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;
   89 | 
   90 |         // handle static resources
   91 |         boolean consumedByStaticFile = staticFiles.consume(httpRequest, httpResponse);
   92 | 
   93 |         if (consumedByStaticFile) {
   94 |             return;
   95 |         }
   96 | 
   97 |         String method = getHttpMethodFrom(httpRequest);
   98 | 
   99 |         String httpMethodStr = method.toLowerCase();
  100 |         String uri = httpRequest.getRequestURI();
  101 |         String acceptType = httpRequest.getHeader(ACCEPT_TYPE_REQUEST_MIME_HEADER);
  102 | 
  103 |         Body body = Body.create();
  104 | 
  105 |         RequestWrapper requestWrapper = RequestWrapper.create();
  106 |         ResponseWrapper responseWrapper = ResponseWrapper.create();
  107 | 
  108 |         Response response = RequestResponseFactory.create(httpResponse);
  109 | 
  110 |         HttpMethod httpMethod = HttpMethod.get(httpMethodStr);
  111 | 
  112 |         RouteContext context = RouteContext.create()
  113 |                 .withMatcher(routeMatcher)
      | ... (lines omitted) ...
  137 |         }
  138 | 
  139 |         // If redirected and content is null set to empty string to not throw NotConsumedException
  140 |         if (body.notSet() && responseWrapper.isRedirected()) {
  141 |             body.set("");
  142 |         }
  143 | 
  144 |         if (body.notSet() && hasOtherHandlers) {
  145 |             if (servletRequest instanceof HttpRequestWrapper) {
  146 |                 ((HttpRequestWrapper) servletRequest).notConsumed(true);
  147 |                 return;
  148 |             }
  149 |         }
  150 | 
  151 |         if (body.notSet() && !externalContainer) {
  152 |             LOG.info("The requested route [" + uri + "] has not been mapped in Spark");
  153 |             httpResponse.setStatus(HttpServletResponse.SC_NOT_FOUND);
  154 |             body.set(String.format(NOT_FOUND));
  155 |         }
  156 | 
  157 |         if (body.isSet()) {
  158 |             body.serializeTo(httpResponse, serializerChain, httpRequest);
  159 | 
  160 |         } else if (chain != null) {
  161 |             chain.doFilter(httpRequest, httpResponse);
  162 |         }
  163 |     }
  164 | 
  165 |     private String getHttpMethodFrom(HttpServletRequest httpRequest) {
  166 |         String method = httpRequest.getHeader(HTTP_METHOD_OVERRIDE_HEADER);
```

---

## 49/113 flow_id 9a2131ac71 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 9a2131ac71
key        : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>@L401/result => <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>@L60/0
source     : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>[273@L401] %v176 = invokeinterface session.getId()/result
sink       : <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>[10@L60] url = invokevirtual load_loader.getResource(name)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, iris-like run2, v1 run1, v1 run2
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>, <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 50/113 flow_id a6fd982091 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow a6fd982091
key        : <org.eclipse.jetty.server.handler.gzip.GzipHandler: java.util.zip.Deflater getDeflater(org.eclipse.jetty.server.Request,long)>@L231/result => <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>@L60/0
source     : <org.eclipse.jetty.server.handler.gzip.GzipHandler: java.util.zip.Deflater getDeflater(org.eclipse.jetty.server.Request,long)>[5@L231] ua = invokevirtual %v7.get(%v8)/result
sink       : <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>[10@L60] url = invokevirtual load_loader.getResource(name)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.server.handler.gzip.GzipHandler: java.util.zip.Deflater getDeflater(org.eclipse.jetty.server.Request,long)>, <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 51/113 flow_id b62650655b (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow b62650655b
key        : DRIVER => <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>@L60/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[18@L40] %v15 = invokestatic nesy.Taint.src()/result
sink       : <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>[10@L60] url = invokevirtual load_loader.getResource(name)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

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

## 52/113 flow_id 9ac3743ab8 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 9ac3743ab8
key        : <org.eclipse.jetty.server.session.HashSessionIdManager: void removeSession(javax.servlet.http.HttpSession)>@L143/result => <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>@L54/0
source     : <org.eclipse.jetty.server.session.HashSessionIdManager: void removeSession(javax.servlet.http.HttpSession)>[1@L143] %v9 = invokeinterface session.getId()/result
sink       : <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>[4@L54] url = invokevirtual context_loader.getResource(name)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, iris-like run2, v1 run1, v1 run2, v2 run1, v2 run2, v3 run1, v3 run2, v3-noV2 run1, v3-noV2 run2, v3-noV3 run1, v3-noV3 run2, v3-noval run1, v3-noval run2, v4 run1, v4 run2
N3 (v3 run1): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.server.session.HashSessionIdManager: void removeSession(javax.servlet.http.HttpSession)>, <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 53/113 flow_id b4dd2564d1 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow b4dd2564d1
key        : <org.eclipse.jetty.server.session.SessionHandler: void checkRequestedSessionId(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest)>@L267/result => <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>@L54/0
source     : <org.eclipse.jetty.server.session.SessionHandler: void checkRequestedSessionId(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest)>[36@L267] requested_session_id = invokevirtual %v30.getValue()/result
sink       : <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>[4@L54] url = invokevirtual context_loader.getResource(name)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.server.session.SessionHandler: void checkRequestedSessionId(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest)>, <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 54/113 flow_id 2fe70b188e (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 2fe70b188e
key        : <org.eclipse.jetty.servlet.ServletHandler: void notFound(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>@L1554/result => <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>@L54/0
source     : <org.eclipse.jetty.servlet.ServletHandler: void notFound(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>[8@L1554] %v10 = invokeinterface request.getRequestURI()/result
sink       : <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>[4@L54] url = invokevirtual context_loader.getResource(name)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.servlet.ServletHandler: void notFound(org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>, <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 55/113 flow_id 6a573e41b1 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 6a573e41b1
key        : <org.eclipse.jetty.websocket.server.WebSocketServerFactory: boolean isUpgradeRequest(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>@L406/result => <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>@L54/0
source     : <org.eclipse.jetty.websocket.server.WebSocketServerFactory: boolean isUpgradeRequest(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>[8@L406] connection = invokeinterface request.getHeader(%c11)/result
sink       : <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>[4@L54] url = invokevirtual context_loader.getResource(name)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run1, v1 run1

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.websocket.server.WebSocketServerFactory: boolean isUpgradeRequest(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>, <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 56/113 flow_id da48aed262 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow da48aed262
key        : <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>@L101/result => <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>@L54/0
source     : <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>[12@L101] acceptType = invokeinterface httpRequest.getHeader(%c26)/result
sink       : <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>[4@L54] url = invokevirtual context_loader.getResource(name)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run1

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>

## Application-code evidence (route or reachable-method fallback)
### <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>
file: spark/http/matching/MatcherFilter.java
   84 |                          ServletResponse servletResponse,
   85 |                          FilterChain chain) throws IOException, ServletException {
   86 | 
   87 |         HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
   88 |         HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;
   89 | 
   90 |         // handle static resources
   91 |         boolean consumedByStaticFile = staticFiles.consume(httpRequest, httpResponse);
   92 | 
   93 |         if (consumedByStaticFile) {
   94 |             return;
   95 |         }
   96 | 
   97 |         String method = getHttpMethodFrom(httpRequest);
   98 | 
   99 |         String httpMethodStr = method.toLowerCase();
  100 |         String uri = httpRequest.getRequestURI();
  101 |         String acceptType = httpRequest.getHeader(ACCEPT_TYPE_REQUEST_MIME_HEADER);
  102 | 
  103 |         Body body = Body.create();
  104 | 
  105 |         RequestWrapper requestWrapper = RequestWrapper.create();
  106 |         ResponseWrapper responseWrapper = ResponseWrapper.create();
  107 | 
  108 |         Response response = RequestResponseFactory.create(httpResponse);
  109 | 
  110 |         HttpMethod httpMethod = HttpMethod.get(httpMethodStr);
  111 | 
  112 |         RouteContext context = RouteContext.create()
  113 |                 .withMatcher(routeMatcher)
      | ... (lines omitted) ...
  137 |         }
  138 | 
  139 |         // If redirected and content is null set to empty string to not throw NotConsumedException
  140 |         if (body.notSet() && responseWrapper.isRedirected()) {
  141 |             body.set("");
  142 |         }
  143 | 
  144 |         if (body.notSet() && hasOtherHandlers) {
  145 |             if (servletRequest instanceof HttpRequestWrapper) {
  146 |                 ((HttpRequestWrapper) servletRequest).notConsumed(true);
  147 |                 return;
  148 |             }
  149 |         }
  150 | 
  151 |         if (body.notSet() && !externalContainer) {
  152 |             LOG.info("The requested route [" + uri + "] has not been mapped in Spark");
  153 |             httpResponse.setStatus(HttpServletResponse.SC_NOT_FOUND);
  154 |             body.set(String.format(NOT_FOUND));
  155 |         }
  156 | 
  157 |         if (body.isSet()) {
  158 |             body.serializeTo(httpResponse, serializerChain, httpRequest);
  159 | 
  160 |         } else if (chain != null) {
  161 |             chain.doFilter(httpRequest, httpResponse);
  162 |         }
  163 |     }
  164 | 
  165 |     private String getHttpMethodFrom(HttpServletRequest httpRequest) {
  166 |         String method = httpRequest.getHeader(HTTP_METHOD_OVERRIDE_HEADER);
```

---

## 57/113 flow_id c6c4fe5ac6 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow c6c4fe5ac6
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L50/result => <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>@L54/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[17@L50] servletPath = invokeinterface request.getServletPath()/result
sink       : <org.eclipse.jetty.util.Loader: java.net.URL getResource(java.lang.Class,java.lang.String)>[4@L54] url = invokevirtual context_loader.getResource(name)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

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

## 58/113 flow_id 9780a5e40b (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 9780a5e40b
key        : <org.eclipse.jetty.http.HttpFields: java.util.Set getFieldNamesCollection()>@L110/result => <org.eclipse.jetty.util.MultiPartInputStreamParser: void <init>(java.io.InputStream,java.lang.String,javax.servlet.MultipartConfigElement,java.io.File)>@L344/0
source     : <org.eclipse.jetty.http.HttpFields: java.util.Set getFieldNamesCollection()>[10@L110] %v12 = invokevirtual f.getName()/result
sink       : <org.eclipse.jetty.util.MultiPartInputStreamParser: void <init>(java.io.InputStream,java.lang.String,javax.servlet.MultipartConfigElement,java.io.File)>[12@L344] invokespecial %v8.<init>(%v10)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.http.HttpFields: java.util.Set getFieldNamesCollection()>, <org.eclipse.jetty.util.MultiPartInputStreamParser: void <init>(java.io.InputStream,java.lang.String,javax.servlet.MultipartConfigElement,java.io.File)>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 59/113 flow_id 0b2acfb2b7 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 0b2acfb2b7
key        : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>@L284/result => <org.eclipse.jetty.util.MultiPartInputStreamParser: void <init>(java.io.InputStream,java.lang.String,javax.servlet.MultipartConfigElement,java.io.File)>@L344/0
source     : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>[49@L284] nuri = invokeinterface request.getContextPath()/result
sink       : <org.eclipse.jetty.util.MultiPartInputStreamParser: void <init>(java.io.InputStream,java.lang.String,javax.servlet.MultipartConfigElement,java.io.File)>[12@L344] invokespecial %v8.<init>(%v10)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, iris-like run2, v1 run1, v1 run2
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }

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

## 60/113 flow_id 5c3254b953 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 5c3254b953
key        : <org.eclipse.jetty.http.HttpField: java.lang.String toString()>@L369/result => <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>@L460/0
source     : <org.eclipse.jetty.http.HttpField: java.lang.String toString()>[0@L369] v = invokevirtual this.getValue()/result
sink       : <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>[36@L460] invokespecial f.<init>(%v46)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.http.HttpField: java.lang.String toString()>, <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 61/113 flow_id 04bcbf0cb0 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 04bcbf0cb0
key        : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>@L267/result => <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>@L460/0
source     : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>[30@L267] username = invokeinterface request.getParameter(%c37)/result
sink       : <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>[36@L460] invokespecial f.<init>(%v46)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>, <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 62/113 flow_id ef672a64e1 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow ef672a64e1
key        : <org.eclipse.jetty.websocket.servlet.UpgradeHttpServletRequest: void <init>(javax.servlet.http.HttpServletRequest)>@L114/result => <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>@L460/0
source     : <org.eclipse.jetty.websocket.servlet.UpgradeHttpServletRequest: void <init>(javax.servlet.http.HttpServletRequest)>[57@L114] %v35 = invokeinterface httpRequest.getHeaders(name)/result
sink       : <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>[36@L460] invokespecial f.<init>(%v46)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>, <org.eclipse.jetty.websocket.servlet.UpgradeHttpServletRequest: void <init>(javax.servlet.http.HttpServletRequest)>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 63/113 flow_id c241644344 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow c241644344
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L54/result => <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>@L460/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[20@L54] servletPath = invokeinterface request.getServletPath()/result
sink       : <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>[36@L460] invokespecial f.<init>(%v46)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

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

## 64/113 flow_id 7005123ae8 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 7005123ae8
key        : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>@L180/result => <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>@L464/0
source     : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[60@L180] %v56 = invokevirtual old_uri.getQuery()/result
sink       : <org.eclipse.jetty.util.MultiPartInputStreamParser: void parse()>[45@L464] invokespecial %v48.<init>(%v49, %v51)/0
fixed methods on this flow (GT): -
reported by: B2 run0

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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }

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

## 65/113 flow_id fec94a98c1 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow fec94a98c1
key        : <org.eclipse.jetty.http.HttpFields$1: java.lang.String nextElement()>@L305/result => <org.eclipse.jetty.util.resource.URLResource: java.io.File getFile()>@L183/0
source     : <org.eclipse.jetty.http.HttpFields$1: java.lang.String nextElement()>[4@L305] value = invokevirtual %v4.getValue()/result
sink       : <org.eclipse.jetty.util.resource.URLResource: java.io.File getFile()>[14@L183] invokespecial %v9.<init>(%v11)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.http.HttpFields$1: java.lang.String nextElement()>, <org.eclipse.jetty.util.resource.URLResource: java.io.File getFile()>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 66/113 flow_id 6713efd7e1 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 6713efd7e1
key        : <org.eclipse.jetty.http.HttpFields: java.util.Set getFieldNamesCollection()>@L110/result => <org.eclipse.jetty.util.resource.URLResource: java.io.File getFile()>@L183/0
source     : <org.eclipse.jetty.http.HttpFields: java.util.Set getFieldNamesCollection()>[10@L110] %v12 = invokevirtual f.getName()/result
sink       : <org.eclipse.jetty.util.resource.URLResource: java.io.File getFile()>[14@L183] invokespecial %v9.<init>(%v11)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.http.HttpFields: java.util.Set getFieldNamesCollection()>, <org.eclipse.jetty.util.resource.URLResource: java.io.File getFile()>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 67/113 flow_id ff183e0172 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow ff183e0172
key        : <org.eclipse.jetty.server.handler.gzip.GzipHandler: void handle(java.lang.String,org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>@L419/result => <org.eclipse.jetty.util.resource.URLResource: java.io.File getFile()>@L183/0
source     : <org.eclipse.jetty.server.handler.gzip.GzipHandler: void handle(java.lang.String,org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>[103@L419] etag = invokevirtual %v64.get(%v65)/result
sink       : <org.eclipse.jetty.util.resource.URLResource: java.io.File getFile()>[14@L183] invokespecial %v9.<init>(%v11)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <org.eclipse.jetty.server.handler.gzip.GzipHandler: void handle(java.lang.String,org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>, <org.eclipse.jetty.util.resource.URLResource: java.io.File getFile()>

## Application-code evidence (route or reachable-method fallback)
(no application code available)
```

---

## 68/113 flow_id 72785618eb (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 72785618eb
key        : <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>@L100/result => <org.slf4j.impl.SimpleLogger: java.io.PrintStream computeTargetStream(java.lang.String)>@L219/0
source     : <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>[10@L100] uri = invokeinterface httpRequest.getRequestURI()/result
sink       : <org.slf4j.impl.SimpleLogger: java.io.PrintStream computeTargetStream(java.lang.String)>[12@L219] invokespecial fos.<init>(logFile)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run2, v3 run2, v3-noV2 run2, v4 run0, v4 run1, v4 run2
N3 (v3 run2): not_vulnerable / not_dangerous_sink (kept=True, v3_ok=False)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>

## Application-code evidence (route or reachable-method fallback)
### <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>
file: spark/http/matching/MatcherFilter.java
   84 |                          ServletResponse servletResponse,
   85 |                          FilterChain chain) throws IOException, ServletException {
   86 | 
   87 |         HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
   88 |         HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;
   89 | 
   90 |         // handle static resources
   91 |         boolean consumedByStaticFile = staticFiles.consume(httpRequest, httpResponse);
   92 | 
   93 |         if (consumedByStaticFile) {
   94 |             return;
   95 |         }
   96 | 
   97 |         String method = getHttpMethodFrom(httpRequest);
   98 | 
   99 |         String httpMethodStr = method.toLowerCase();
  100 |         String uri = httpRequest.getRequestURI();
  101 |         String acceptType = httpRequest.getHeader(ACCEPT_TYPE_REQUEST_MIME_HEADER);
  102 | 
  103 |         Body body = Body.create();
  104 | 
  105 |         RequestWrapper requestWrapper = RequestWrapper.create();
  106 |         ResponseWrapper responseWrapper = ResponseWrapper.create();
  107 | 
  108 |         Response response = RequestResponseFactory.create(httpResponse);
  109 | 
  110 |         HttpMethod httpMethod = HttpMethod.get(httpMethodStr);
  111 | 
  112 |         RouteContext context = RouteContext.create()
  113 |                 .withMatcher(routeMatcher)
      | ... (lines omitted) ...
  137 |         }
  138 | 
  139 |         // If redirected and content is null set to empty string to not throw NotConsumedException
  140 |         if (body.notSet() && responseWrapper.isRedirected()) {
  141 |             body.set("");
  142 |         }
  143 | 
  144 |         if (body.notSet() && hasOtherHandlers) {
  145 |             if (servletRequest instanceof HttpRequestWrapper) {
  146 |                 ((HttpRequestWrapper) servletRequest).notConsumed(true);
  147 |                 return;
  148 |             }
  149 |         }
  150 | 
  151 |         if (body.notSet() && !externalContainer) {
  152 |             LOG.info("The requested route [" + uri + "] has not been mapped in Spark");
  153 |             httpResponse.setStatus(HttpServletResponse.SC_NOT_FOUND);
  154 |             body.set(String.format(NOT_FOUND));
  155 |         }
  156 | 
  157 |         if (body.isSet()) {
  158 |             body.serializeTo(httpResponse, serializerChain, httpRequest);
  159 | 
  160 |         } else if (chain != null) {
  161 |             chain.doFilter(httpRequest, httpResponse);
  162 |         }
  163 |     }
  164 | 
  165 |     private String getHttpMethodFrom(HttpServletRequest httpRequest) {
  166 |         String method = httpRequest.getHeader(HTTP_METHOD_OVERRIDE_HEADER);
```

---

## 69/113 flow_id d37dee2e0e (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow d37dee2e0e
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L50/result => <org.slf4j.impl.SimpleLogger: java.io.PrintStream computeTargetStream(java.lang.String)>@L219/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[17@L50] servletPath = invokeinterface request.getServletPath()/result
sink       : <org.slf4j.impl.SimpleLogger: java.io.PrintStream computeTargetStream(java.lang.String)>[12@L219] invokespecial fos.<init>(logFile)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3-noV2 run2, v3-noV3 run0, v3-noval run2, v4 run0
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

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

## 70/113 flow_id 980cc6c51a (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 980cc6c51a
key        : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>@L72/result => <org.slf4j.impl.SimpleLogger: java.io.PrintStream computeTargetStream(java.lang.String)>@L219/0
source     : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[21@L72] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <org.slf4j.impl.SimpleLogger: java.io.PrintStream computeTargetStream(java.lang.String)>[12@L219] invokespecial fos.<init>(logFile)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

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

## 71/113 flow_id 7d8797f40c (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 7d8797f40c
key        : <spark.http.matching.MatcherFilter: java.lang.String getHttpMethodFrom(javax.servlet.http.HttpServletRequest)>@L166/result => <spark.embeddedserver.jetty.websocket.WebSocketServletContextHandlerFactory: org.eclipse.jetty.servlet.ServletContextHandler create(java.util.Map,java.util.Optional)>@L55/0
source     : <spark.http.matching.MatcherFilter: java.lang.String getHttpMethodFrom(javax.servlet.http.HttpServletRequest)>[1@L166] method = invokeinterface httpRequest.getHeader(%c3)/result
sink       : <spark.embeddedserver.jetty.websocket.WebSocketServletContextHandlerFactory: org.eclipse.jetty.servlet.ServletContextHandler create(java.util.Map,java.util.Optional)>[29@L55] invokevirtual webSocketUpgradeFilter.addMapping(%v28, webSocketCreator)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2
N3 (iris-like run0): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.embeddedserver.jetty.websocket.WebSocketServletContextHandlerFactory: org.eclipse.jetty.servlet.ServletContextHandler create(java.util.Map,java.util.Optional)>, <spark.http.matching.MatcherFilter: java.lang.String getHttpMethodFrom(javax.servlet.http.HttpServletRequest)>

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

### <spark.http.matching.MatcherFilter: java.lang.String getHttpMethodFrom(javax.servlet.http.HttpServletRequest)>
file: spark/http/matching/MatcherFilter.java
  163 |     }
  164 | 
  165 |     private String getHttpMethodFrom(HttpServletRequest httpRequest) {
  166 |         String method = httpRequest.getHeader(HTTP_METHOD_OVERRIDE_HEADER);
  167 | 
  168 |         if (method == null) {
  169 |             method = httpRequest.getMethod();
  170 |         }
  171 |         return method;
  172 |     }
  173 | 
  174 |     public void destroy() {
```

---

## 72/113 flow_id 833889b14c (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 833889b14c
key        : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>@L401/result => <spark.resource.ClassPathResource: boolean exists()>@L122/0
source     : <org.eclipse.jetty.security.authentication.FormAuthenticator: org.eclipse.jetty.server.Authentication validateRequest(javax.servlet.ServletRequest,javax.servlet.ServletResponse,boolean)>[273@L401] %v176 = invokeinterface session.getId()/result
sink       : <spark.resource.ClassPathResource: boolean exists()>[10@L122] url = invokevirtual %v6.getResource(%v7)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, iris-like run2, v1 run1, v1 run2
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

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

## 73/113 flow_id 81aa8a3fbd (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 81aa8a3fbd
key        : <org.eclipse.jetty.server.ShutdownMonitor$ShutdownMonitorRunnable: void run()>@L124/result => <spark.resource.ClassPathResource: boolean exists()>@L122/0
source     : <org.eclipse.jetty.server.ShutdownMonitor$ShutdownMonitorRunnable: void run()>[30@L124] cmd = invokevirtual lin.readLine()/result
sink       : <spark.resource.ClassPathResource: boolean exists()>[10@L122] url = invokevirtual %v6.getResource(%v7)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

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

## 74/113 flow_id b655550d9d (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow b655550d9d
key        : <org.eclipse.jetty.websocket.server.WebSocketUpgradeFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>@L177/result => <spark.resource.ClassPathResource: boolean exists()>@L122/0
source     : <org.eclipse.jetty.websocket.server.WebSocketUpgradeFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>[28@L177] target = invokeinterface httpreq.getRequestURI()/result
sink       : <spark.resource.ClassPathResource: boolean exists()>[10@L122] url = invokevirtual %v6.getResource(%v7)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

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

## 75/113 flow_id 8aa7fa0ac1 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 8aa7fa0ac1
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L51/result => <spark.resource.ClassPathResource: boolean exists()>@L122/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[18@L51] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <spark.resource.ClassPathResource: boolean exists()>[10@L122] url = invokevirtual %v6.getResource(%v7)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v4 run0, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>, <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>, <spark.resource.ClassPathResource: boolean exists()>

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

### <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ClassPathResourceHandler.java
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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   57 | 
   58 |     @Override
   59 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   60 |         if (path == null || !path.startsWith("/")) {
   61 |             throw new MalformedURLException(path);
   62 |         }
   63 | 
   64 |         try {
   65 |             path = UriPath.canonical(path);
   66 | 
   67 |             final String addedPath = addPaths(baseResource, path);
   68 | 
   69 |             ExternalResource resource = new ExternalResource(addedPath);
   70 | 
   71 |             if (resource.exists() && resource.isDirectory()) {
   72 |                 if (welcomeFile != null) {
   73 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   74 |                 } else {
   75 |                     //  No welcome file configured, serve nothing since it's a directory
   76 |                     resource = null;
   77 |                 }
   78 |             }
   79 | 
   80 |             return (resource != null && resource.exists()) ? resource : null;
   81 |         } catch (Exception e) {
   82 |             if (LOG.isDebugEnabled()) {
   83 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   84 |             }
   85 |         }
   86 |         return null;
   87 |     }
   88 | 
   89 | }

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

## 76/113 flow_id bcdfbdee9d (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow bcdfbdee9d
key        : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>@L68/result => <spark.resource.ClassPathResource: boolean exists()>@L122/0
source     : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[18@L68] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <spark.resource.ClassPathResource: boolean exists()>[10@L122] url = invokevirtual %v6.getResource(%v7)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>, <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>, <spark.resource.ClassPathResource: boolean exists()>

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

### <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ClassPathResourceHandler.java
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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   57 | 
   58 |     @Override
   59 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   60 |         if (path == null || !path.startsWith("/")) {
   61 |             throw new MalformedURLException(path);
   62 |         }
   63 | 
   64 |         try {
   65 |             path = UriPath.canonical(path);
   66 | 
   67 |             final String addedPath = addPaths(baseResource, path);
   68 | 
   69 |             ExternalResource resource = new ExternalResource(addedPath);
   70 | 
   71 |             if (resource.exists() && resource.isDirectory()) {
   72 |                 if (welcomeFile != null) {
   73 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   74 |                 } else {
   75 |                     //  No welcome file configured, serve nothing since it's a directory
   76 |                     resource = null;
   77 |                 }
   78 |             }
   79 | 
   80 |             return (resource != null && resource.exists()) ? resource : null;
   81 |         } catch (Exception e) {
   82 |             if (LOG.isDebugEnabled()) {
   83 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   84 |             }
   85 |         }
   86 |         return null;
   87 |     }
   88 | 
   89 | }

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

## 77/113 flow_id 5a5f217372 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 5a5f217372
key        : <spark.utils.StringUtils: java.lang.String collectionToDelimitedString(java.util.Collection,java.lang.String,java.lang.String,java.lang.String)>@L356/result => <spark.resource.ClassPathResource: boolean exists()>@L122/0
source     : <spark.utils.StringUtils: java.lang.String collectionToDelimitedString(java.util.Collection,java.lang.String,java.lang.String,java.lang.String)>[11@L356] %v13 = invokeinterface it.next()/result
sink       : <spark.resource.ClassPathResource: boolean exists()>[10@L122] url = invokevirtual %v6.getResource(%v7)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2, v2 run2, v3 run2, v3-noV2 run2, v3-noV3 run2, v3-noval run2, v4 run2
N3 (v3 run2): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.ClassPathResource: boolean exists()>, <spark.utils.StringUtils: java.lang.String collectionToDelimitedString(java.util.Collection,java.lang.String,java.lang.String,java.lang.String)>

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

### <spark.utils.StringUtils: java.lang.String collectionToDelimitedString(java.util.Collection,java.lang.String,java.lang.String,java.lang.String)>
file: spark/utils/StringUtils.java
  347 |      * @return the delimited String
  348 |      */
  349 |     public static String collectionToDelimitedString(Collection<?> coll, String delim, String prefix, String suffix) {
  350 |         if (CollectionUtils.isEmpty(coll)) {
  351 |             return "";
  352 |         }
  353 |         StringBuilder sb = new StringBuilder();
  354 |         Iterator<?> it = coll.iterator();
  355 |         while (it.hasNext()) {
  356 |             sb.append(prefix).append(it.next()).append(suffix);
  357 |             if (it.hasNext()) {
  358 |                 sb.append(delim);
  359 |             }
  360 |         }
  361 |         return sb.toString();
  362 |     }
  363 | 
  364 |     /**
```

---

## 78/113 flow_id b0ff7d7476 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow b0ff7d7476
key        : <org.eclipse.jetty.server.session.HashSessionIdManager: void addSession(javax.servlet.http.HttpSession)>@L121/result => <spark.resource.ClassPathResource: boolean exists()>@L120/0
source     : <org.eclipse.jetty.server.session.HashSessionIdManager: void addSession(javax.servlet.http.HttpSession)>[0@L121] %v7 = invokeinterface session.getId()/result
sink       : <spark.resource.ClassPathResource: boolean exists()>[6@L120] url = invokevirtual %v4.getResource(%v5)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, iris-like run2, v1 run1, v1 run2, v2 run2, v3 run2, v3-noV2 run2, v3-noV3 run2, v3-noval run2, v4 run2
N3 (v3 run2): uncertain / insufficient_context (kept=True, v3_ok=None)

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

## 79/113 flow_id c59e765740 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow c59e765740
key        : <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>@L100/result => <spark.resource.ClassPathResource: boolean exists()>@L120/0
source     : <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>[10@L100] uri = invokeinterface httpRequest.getRequestURI()/result
sink       : <spark.resource.ClassPathResource: boolean exists()>[6@L120] url = invokevirtual %v4.getResource(%v5)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run2, v3 run2, v3-noV2 run2, v3-noV3 run2, v3-noval run2, v4 run0, v4 run2
N3 (v3 run2): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>, <spark.resource.ClassPathResource: boolean exists()>

## Application-code evidence (route or reachable-method fallback)
### <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>
file: spark/http/matching/MatcherFilter.java
   84 |                          ServletResponse servletResponse,
   85 |                          FilterChain chain) throws IOException, ServletException {
   86 | 
   87 |         HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
   88 |         HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;
   89 | 
   90 |         // handle static resources
   91 |         boolean consumedByStaticFile = staticFiles.consume(httpRequest, httpResponse);
   92 | 
   93 |         if (consumedByStaticFile) {
   94 |             return;
   95 |         }
   96 | 
   97 |         String method = getHttpMethodFrom(httpRequest);
   98 | 
   99 |         String httpMethodStr = method.toLowerCase();
  100 |         String uri = httpRequest.getRequestURI();
  101 |         String acceptType = httpRequest.getHeader(ACCEPT_TYPE_REQUEST_MIME_HEADER);
  102 | 
  103 |         Body body = Body.create();
  104 | 
  105 |         RequestWrapper requestWrapper = RequestWrapper.create();
  106 |         ResponseWrapper responseWrapper = ResponseWrapper.create();
  107 | 
  108 |         Response response = RequestResponseFactory.create(httpResponse);
  109 | 
  110 |         HttpMethod httpMethod = HttpMethod.get(httpMethodStr);
  111 | 
  112 |         RouteContext context = RouteContext.create()
  113 |                 .withMatcher(routeMatcher)
      | ... (lines omitted) ...
  137 |         }
  138 | 
  139 |         // If redirected and content is null set to empty string to not throw NotConsumedException
  140 |         if (body.notSet() && responseWrapper.isRedirected()) {
  141 |             body.set("");
  142 |         }
  143 | 
  144 |         if (body.notSet() && hasOtherHandlers) {
  145 |             if (servletRequest instanceof HttpRequestWrapper) {
  146 |                 ((HttpRequestWrapper) servletRequest).notConsumed(true);
  147 |                 return;
  148 |             }
  149 |         }
  150 | 
  151 |         if (body.notSet() && !externalContainer) {
  152 |             LOG.info("The requested route [" + uri + "] has not been mapped in Spark");
  153 |             httpResponse.setStatus(HttpServletResponse.SC_NOT_FOUND);
  154 |             body.set(String.format(NOT_FOUND));
  155 |         }
  156 | 
  157 |         if (body.isSet()) {
  158 |             body.serializeTo(httpResponse, serializerChain, httpRequest);
  159 | 
  160 |         } else if (chain != null) {
  161 |             chain.doFilter(httpRequest, httpResponse);
  162 |         }
  163 |     }
  164 | 
  165 |     private String getHttpMethodFrom(HttpServletRequest httpRequest) {
  166 |         String method = httpRequest.getHeader(HTTP_METHOD_OVERRIDE_HEADER);

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

## 80/113 flow_id 16c3cf872e (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 16c3cf872e
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L54/result => <spark.resource.ClassPathResource: boolean exists()>@L120/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[20@L54] servletPath = invokeinterface request.getServletPath()/result
sink       : <spark.resource.ClassPathResource: boolean exists()>[6@L120] url = invokevirtual %v4.getResource(%v5)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>, <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>, <spark.resource.ClassPathResource: boolean exists()>

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

### <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ClassPathResourceHandler.java
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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   57 | 
   58 |     @Override
   59 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   60 |         if (path == null || !path.startsWith("/")) {
   61 |             throw new MalformedURLException(path);
   62 |         }
   63 | 
   64 |         try {
   65 |             path = UriPath.canonical(path);
   66 | 
   67 |             final String addedPath = addPaths(baseResource, path);
   68 | 
   69 |             ExternalResource resource = new ExternalResource(addedPath);
   70 | 
   71 |             if (resource.exists() && resource.isDirectory()) {
   72 |                 if (welcomeFile != null) {
   73 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   74 |                 } else {
   75 |                     //  No welcome file configured, serve nothing since it's a directory
   76 |                     resource = null;
   77 |                 }
   78 |             }
   79 | 
   80 |             return (resource != null && resource.exists()) ? resource : null;
   81 |         } catch (Exception e) {
   82 |             if (LOG.isDebugEnabled()) {
   83 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   84 |             }
   85 |         }
   86 |         return null;
   87 |     }
   88 | 
   89 | }

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

## 81/113 flow_id 8646a7b988 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 8646a7b988
key        : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>@L34/result => <spark.resource.ClassPathResource: boolean exists()>@L120/0
source     : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>[2@L34] path = invokeinterface request.getRequestURI()/result
sink       : <spark.resource.ClassPathResource: boolean exists()>[6@L120] url = invokevirtual %v4.getResource(%v5)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.ClassPathResource: boolean exists()>, <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>

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

## 82/113 flow_id fea0e6db7a (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow fea0e6db7a
key        : DRIVER => <spark.resource.ClassPathResource: boolean exists()>@L120/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[18@L40] %v15 = invokestatic nesy.Taint.src()/result
sink       : <spark.resource.ClassPathResource: boolean exists()>[6@L120] url = invokevirtual %v4.getResource(%v5)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.ClassPathResource: boolean exists()>, <spark.utils.ResourceUtils: java.io.File getFile(java.lang.String)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

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

## 83/113 flow_id db209f77fa (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow db209f77fa
key        : <org.eclipse.jetty.security.authentication.FormAuthenticator$FormRequest: java.util.Enumeration getHeaders(java.lang.String)>@L484/result => <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>@L139/0
source     : <org.eclipse.jetty.security.authentication.FormAuthenticator$FormRequest: java.util.Enumeration getHeaders(java.lang.String)>[9@L484] %v9 = invokespecial this.getHeaders(name)/result
sink       : <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>[4@L139] is = invokevirtual %v4.getResourceAsStream(%v5)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run1
N3 (iris-like run1): unjudged / over-max-flows (kept=True, v3_ok=None)

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

## 84/113 flow_id dfe1fd2b8f (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow dfe1fd2b8f
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L51/result => <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>@L139/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[18@L51] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>[4@L139] is = invokevirtual %v4.getResourceAsStream(%v5)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run2, v3-noV2 run0, v3-noV3 run2, v3-noval run0, v4 run0, v4 run2
N3 (v3 run2): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>, <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>

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

## 85/113 flow_id 9ca29b9b6b (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 9ca29b9b6b
key        : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>@L72/result => <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>@L139/0
source     : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[21@L72] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>[4@L139] is = invokevirtual %v4.getResourceAsStream(%v5)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>, <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>

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

## 86/113 flow_id ae0160fc5b (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow ae0160fc5b
key        : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>@L180/result => <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>@L141/0
source     : <org.eclipse.jetty.server.Dispatcher: void forward(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.DispatcherType)>[60@L180] %v56 = invokevirtual old_uri.getQuery()/result
sink       : <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>[8@L141] is = invokevirtual %v6.getResourceAsStream(%v7)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>, <spark.resource.ClassPathResource: void <init>(java.lang.String)>, <spark.resource.ClassPathResource: void <init>(java.lang.String,java.lang.ClassLoader)>, <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>

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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }

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

## 87/113 flow_id 967407ccb8 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 967407ccb8
key        : <org.eclipse.jetty.server.ShutdownMonitor$ShutdownMonitorRunnable: void run()>@L124/result => <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>@L141/0
source     : <org.eclipse.jetty.server.ShutdownMonitor$ShutdownMonitorRunnable: void run()>[30@L124] cmd = invokevirtual lin.readLine()/result
sink       : <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>[8@L141] is = invokevirtual %v6.getResourceAsStream(%v7)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

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

## 88/113 flow_id 81ccc2b4b2 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 81ccc2b4b2
key        : <spark.utils.StringUtils: java.lang.String collectionToDelimitedString(java.util.Collection,java.lang.String,java.lang.String,java.lang.String)>@L356/result => <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>@L141/0
source     : <spark.utils.StringUtils: java.lang.String collectionToDelimitedString(java.util.Collection,java.lang.String,java.lang.String,java.lang.String)>[11@L356] %v13 = invokeinterface it.next()/result
sink       : <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>[8@L141] is = invokevirtual %v6.getResourceAsStream(%v7)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2, v2 run2, v3 run2, v3-noV2 run2, v3-noV3 run2, v3-noval run2, v4 run2
N3 (v3 run2): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>, <spark.utils.StringUtils: java.lang.String collectionToDelimitedString(java.util.Collection,java.lang.String,java.lang.String,java.lang.String)>

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

### <spark.utils.StringUtils: java.lang.String collectionToDelimitedString(java.util.Collection,java.lang.String,java.lang.String,java.lang.String)>
file: spark/utils/StringUtils.java
  347 |      * @return the delimited String
  348 |      */
  349 |     public static String collectionToDelimitedString(Collection<?> coll, String delim, String prefix, String suffix) {
  350 |         if (CollectionUtils.isEmpty(coll)) {
  351 |             return "";
  352 |         }
  353 |         StringBuilder sb = new StringBuilder();
  354 |         Iterator<?> it = coll.iterator();
  355 |         while (it.hasNext()) {
  356 |             sb.append(prefix).append(it.next()).append(suffix);
  357 |             if (it.hasNext()) {
  358 |                 sb.append(delim);
  359 |             }
  360 |         }
  361 |         return sb.toString();
  362 |     }
  363 | 
  364 |     /**
```

---

## 89/113 flow_id 0fa6f8d3cb (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 0fa6f8d3cb
key        : DRIVER => <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>@L141/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[18@L40] %v15 = invokestatic nesy.Taint.src()/result
sink       : <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>[8@L141] is = invokevirtual %v6.getResourceAsStream(%v7)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.ClassPathResource: java.io.InputStream getInputStream()>, <spark.utils.ResourceUtils: java.io.File getFile(java.lang.String)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

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

## 90/113 flow_id 4a0a7cac04 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 4a0a7cac04
key        : <org.eclipse.jetty.http.PreEncodedHttpField: void <clinit>()>@L54/result => <spark.resource.ClassPathResource: java.net.URL getURL()>@L161/0
source     : <org.eclipse.jetty.http.PreEncodedHttpField: void <clinit>()>[14@L54] %v13 = invokeinterface iter.next()/result
sink       : <spark.resource.ClassPathResource: java.net.URL getURL()>[4@L161] url = invokevirtual %v4.getResource(%v5)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2
N3 (iris-like run2): unjudged / over-max-flows (kept=True, v3_ok=None)

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

## 91/113 flow_id c6fb4c35c3 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow c6fb4c35c3
key        : <org.eclipse.jetty.server.Request: java.lang.String findServerName()>@L1386/result => <spark.resource.ClassPathResource: java.net.URL getURL()>@L161/0
source     : <org.eclipse.jetty.server.Request: java.lang.String findServerName()>[11@L1386] %v12 = invokevirtual host.getValue()/result
sink       : <spark.resource.ClassPathResource: java.net.URL getURL()>[4@L161] url = invokevirtual %v4.getResource(%v5)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2
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

## 92/113 flow_id 4b68888eda (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 4b68888eda
key        : <org.eclipse.jetty.server.Response: java.lang.String getHeader(java.lang.String)>@L765/result => <spark.resource.ClassPathResource: java.net.URL getURL()>@L161/0
source     : <org.eclipse.jetty.server.Response: java.lang.String getHeader(java.lang.String)>[1@L765] %v3 = invokevirtual %v2.get(name)/result
sink       : <spark.resource.ClassPathResource: java.net.URL getURL()>[4@L161] url = invokevirtual %v4.getResource(%v5)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2
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

## 93/113 flow_id 6f0902dff1 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 6f0902dff1
key        : <org.eclipse.jetty.websocket.servlet.UpgradeHttpServletRequest: void <init>(javax.servlet.http.HttpServletRequest)>@L130/result => <spark.resource.ClassPathResource: java.net.URL getURL()>@L161/0
source     : <org.eclipse.jetty.websocket.servlet.UpgradeHttpServletRequest: void <init>(javax.servlet.http.HttpServletRequest)>[86@L130] %v54 = invokeinterface httpRequest.getServerName()/result
sink       : <spark.resource.ClassPathResource: java.net.URL getURL()>[4@L161] url = invokevirtual %v4.getResource(%v5)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2
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

## 94/113 flow_id 9a1f37577d (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 9a1f37577d
key        : <spark.utils.StringUtils: java.lang.String collectionToDelimitedString(java.util.Collection,java.lang.String,java.lang.String,java.lang.String)>@L356/result => <spark.resource.ClassPathResource: java.net.URL getURL()>@L161/0
source     : <spark.utils.StringUtils: java.lang.String collectionToDelimitedString(java.util.Collection,java.lang.String,java.lang.String,java.lang.String)>[11@L356] %v13 = invokeinterface it.next()/result
sink       : <spark.resource.ClassPathResource: java.net.URL getURL()>[4@L161] url = invokevirtual %v4.getResource(%v5)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2, v2 run2, v3 run2, v3-noV2 run2, v3-noV3 run2, v3-noval run2, v4 run2
N3 (v3 run2): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.ClassPathResource: java.net.URL getURL()>, <spark.utils.StringUtils: java.lang.String collectionToDelimitedString(java.util.Collection,java.lang.String,java.lang.String,java.lang.String)>

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

### <spark.utils.StringUtils: java.lang.String collectionToDelimitedString(java.util.Collection,java.lang.String,java.lang.String,java.lang.String)>
file: spark/utils/StringUtils.java
  347 |      * @return the delimited String
  348 |      */
  349 |     public static String collectionToDelimitedString(Collection<?> coll, String delim, String prefix, String suffix) {
  350 |         if (CollectionUtils.isEmpty(coll)) {
  351 |             return "";
  352 |         }
  353 |         StringBuilder sb = new StringBuilder();
  354 |         Iterator<?> it = coll.iterator();
  355 |         while (it.hasNext()) {
  356 |             sb.append(prefix).append(it.next()).append(suffix);
  357 |             if (it.hasNext()) {
  358 |                 sb.append(delim);
  359 |             }
  360 |         }
  361 |         return sb.toString();
  362 |     }
  363 | 
  364 |     /**
```

---

## 95/113 flow_id 2e7cda7504 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 2e7cda7504
key        : <org.eclipse.jetty.server.session.HashSessionIdManager: void addSession(javax.servlet.http.HttpSession)>@L121/result => <spark.resource.ClassPathResource: java.net.URL getURL()>@L163/0
source     : <org.eclipse.jetty.server.session.HashSessionIdManager: void addSession(javax.servlet.http.HttpSession)>[0@L121] %v7 = invokeinterface session.getId()/result
sink       : <spark.resource.ClassPathResource: java.net.URL getURL()>[8@L163] url = invokevirtual %v6.getResource(%v7)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, iris-like run2, v1 run1, v1 run2, v2 run2, v3 run2, v3-noV2 run2, v3-noV3 run2, v3-noval run2, v4 run2
N3 (v3 run2): uncertain / insufficient_context (kept=True, v3_ok=None)

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

## 96/113 flow_id 6dd807827f (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 6dd807827f
key        : <org.eclipse.jetty.server.session.HashSessionManager: org.eclipse.jetty.server.session.HashedSession restoreSession(java.io.InputStream,org.eclipse.jetty.server.session.HashedSession)>@L644/result => <spark.resource.ClassPathResource: java.net.URL getURL()>@L163/0
source     : <org.eclipse.jetty.server.session.HashSessionManager: org.eclipse.jetty.server.session.HashedSession restoreSession(java.io.InputStream,org.eclipse.jetty.server.session.HashedSession)>[3@L644] clusterId = invokevirtual di.readUTF()/result
sink       : <spark.resource.ClassPathResource: java.net.URL getURL()>[8@L163] url = invokevirtual %v6.getResource(%v7)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

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

## 97/113 flow_id e118e9ee98 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow e118e9ee98
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L51/result => <spark.resource.ClassPathResource: java.net.URL getURL()>@L163/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[18@L51] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <spark.resource.ClassPathResource: java.net.URL getURL()>[8@L163] url = invokevirtual %v6.getResource(%v7)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run2): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>, <spark.resource.ClassPathResource: java.net.URL getURL()>

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

## 98/113 flow_id b938079283 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow b938079283
key        : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>@L34/result => <spark.resource.ClassPathResource: java.net.URL getURL()>@L163/0
source     : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>[2@L34] path = invokeinterface request.getRequestURI()/result
sink       : <spark.resource.ClassPathResource: java.net.URL getURL()>[8@L163] url = invokevirtual %v6.getResource(%v7)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.ClassPathResource: java.net.URL getURL()>, <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>

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

## 99/113 flow_id dad182fdd1 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow dad182fdd1
key        : <org.eclipse.jetty.server.ShutdownMonitor$ShutdownMonitorRunnable: void run()>@L124/result => <spark.resource.ExternalResource: java.io.InputStream getInputStream()>@L67/0
source     : <org.eclipse.jetty.server.ShutdownMonitor$ShutdownMonitorRunnable: void run()>[30@L124] cmd = invokevirtual lin.readLine()/result
sink       : <spark.resource.ExternalResource: java.io.InputStream getInputStream()>[2@L67] invokespecial %v1.<init>(%v2)/0
fixed methods on this flow (GT): -
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.ExternalResource: java.io.InputStream getInputStream()>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.ExternalResource: java.io.InputStream getInputStream()>
file: spark/resource/ExternalResource.java
   64 | 
   65 |     @Override
   66 |     public InputStream getInputStream() throws IOException {
   67 |         return new FileInputStream(file);
   68 |     }
   69 | 
   70 |     /**
```

---

## 100/113 flow_id 1ae7cf9d28 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 1ae7cf9d28
key        : <org.eclipse.jetty.websocket.servlet.UpgradeHttpServletRequest: void <init>(javax.servlet.http.HttpServletRequest)>@L130/result => <spark.resource.ExternalResource: java.io.InputStream getInputStream()>@L67/0
source     : <org.eclipse.jetty.websocket.servlet.UpgradeHttpServletRequest: void <init>(javax.servlet.http.HttpServletRequest)>[86@L130] %v54 = invokeinterface httpRequest.getServerName()/result
sink       : <spark.resource.ExternalResource: java.io.InputStream getInputStream()>[2@L67] invokespecial %v1.<init>(%v2)/0
fixed methods on this flow (GT): -
reported by: B2 run0

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.ExternalResource: java.io.InputStream getInputStream()>

## Application-code evidence (route or reachable-method fallback)
### <spark.resource.ExternalResource: java.io.InputStream getInputStream()>
file: spark/resource/ExternalResource.java
   64 | 
   65 |     @Override
   66 |     public InputStream getInputStream() throws IOException {
   67 |         return new FileInputStream(file);
   68 |     }
   69 | 
   70 |     /**
```

---

## 101/113 flow_id 226af1925d (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 226af1925d
key        : <org.eclipse.jetty.server.session.MemSession: java.lang.Object doGet(java.lang.String)>@L143/result => <spark.resource.ExternalResource: void <init>(java.lang.String)>@L40/0
source     : <org.eclipse.jetty.server.session.MemSession: java.lang.Object doGet(java.lang.String)>[1@L143] %v3 = invokeinterface %v2.get(name)/result
sink       : <spark.resource.ExternalResource: void <init>(java.lang.String)>[3@L40] invokespecial %v2.<init>(%v3)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2, v2 run2
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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }

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

## 102/113 flow_id 0b83b7e97c (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 0b83b7e97c
key        : <org.eclipse.jetty.websocket.servlet.UpgradeHttpServletRequest: void <init>(javax.servlet.http.HttpServletRequest)>@L130/result => <spark.resource.ExternalResource: void <init>(java.lang.String)>@L40/0
source     : <org.eclipse.jetty.websocket.servlet.UpgradeHttpServletRequest: void <init>(javax.servlet.http.HttpServletRequest)>[86@L130] %v54 = invokeinterface httpRequest.getServerName()/result
sink       : <spark.resource.ExternalResource: void <init>(java.lang.String)>[3@L40] invokespecial %v2.<init>(%v3)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

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

## 103/113 flow_id cce4b8cbce (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow cce4b8cbce
key        : <spark.http.matching.MatcherFilter: java.lang.String getHttpMethodFrom(javax.servlet.http.HttpServletRequest)>@L166/result => <spark.resource.ExternalResource: void <init>(java.lang.String)>@L40/0
source     : <spark.http.matching.MatcherFilter: java.lang.String getHttpMethodFrom(javax.servlet.http.HttpServletRequest)>[1@L166] method = invokeinterface httpRequest.getHeader(%c3)/result
sink       : <spark.resource.ExternalResource: void <init>(java.lang.String)>[3@L40] invokespecial %v2.<init>(%v3)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.http.matching.MatcherFilter: java.lang.String getHttpMethodFrom(javax.servlet.http.HttpServletRequest)>, <spark.resource.ExternalResource: void <init>(java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.http.matching.MatcherFilter: java.lang.String getHttpMethodFrom(javax.servlet.http.HttpServletRequest)>
file: spark/http/matching/MatcherFilter.java
  163 |     }
  164 | 
  165 |     private String getHttpMethodFrom(HttpServletRequest httpRequest) {
  166 |         String method = httpRequest.getHeader(HTTP_METHOD_OVERRIDE_HEADER);
  167 | 
  168 |         if (method == null) {
  169 |             method = httpRequest.getMethod();
  170 |         }
  171 |         return method;
  172 |     }
  173 | 
  174 |     public void destroy() {

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

## 104/113 flow_id a71efb4d38 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow a71efb4d38
key        : <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>@L100/result => <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>@L109/0
source     : <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>[10@L100] uri = invokeinterface httpRequest.getRequestURI()/result
sink       : <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>[1@L109] %v3 = invokevirtual %c2.getResourceAsStream(path)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run2, v3 run2, v3-noV2 run2, v3-noV3 run2, v3-noval run2, v4 run0, v4 run2
N3 (v3 run2): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.Service: spark.Service externalStaticFileLocation(java.lang.String)>, <spark.Service: spark.Service staticFileLocation(java.lang.String)>, <spark.Spark: void externalStaticFileLocation(java.lang.String)>, <spark.Spark: void staticFileLocation(java.lang.String)>, <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>, <spark.resource.JarResourceHandler: java.io.InputStream loadStream(java.lang.String)>

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
   84 |                          ServletResponse servletResponse,
   85 |                          FilterChain chain) throws IOException, ServletException {
   86 | 
   87 |         HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
   88 |         HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;
   89 | 
   90 |         // handle static resources
   91 |         boolean consumedByStaticFile = staticFiles.consume(httpRequest, httpResponse);
   92 | 
   93 |         if (consumedByStaticFile) {
   94 |             return;
   95 |         }
   96 | 
   97 |         String method = getHttpMethodFrom(httpRequest);
   98 | 
   99 |         String httpMethodStr = method.toLowerCase();
  100 |         String uri = httpRequest.getRequestURI();
  101 |         String acceptType = httpRequest.getHeader(ACCEPT_TYPE_REQUEST_MIME_HEADER);
  102 | 
  103 |         Body body = Body.create();
  104 | 
  105 |         RequestWrapper requestWrapper = RequestWrapper.create();
  106 |         ResponseWrapper responseWrapper = ResponseWrapper.create();
  107 | 
  108 |         Response response = RequestResponseFactory.create(httpResponse);
  109 | 
  110 |         HttpMethod httpMethod = HttpMethod.get(httpMethodStr);
  111 | 
  112 |         RouteContext context = RouteContext.create()
  113 |                 .withMatcher(routeMatcher)
      | ... (lines omitted) ...
  137 |         }
  138 | 
  139 |         // If redirected and content is null set to empty string to not throw NotConsumedException
  140 |         if (body.notSet() && responseWrapper.isRedirected()) {
  141 |             body.set("");
  142 |         }
  143 | 
  144 |         if (body.notSet() && hasOtherHandlers) {
  145 |             if (servletRequest instanceof HttpRequestWrapper) {
  146 |                 ((HttpRequestWrapper) servletRequest).notConsumed(true);
  147 |                 return;
  148 |             }
  149 |         }
  150 | 
  151 |         if (body.notSet() && !externalContainer) {
  152 |             LOG.info("The requested route [" + uri + "] has not been mapped in Spark");
  153 |             httpResponse.setStatus(HttpServletResponse.SC_NOT_FOUND);
  154 |             body.set(String.format(NOT_FOUND));
  155 |         }
  156 | 
  157 |         if (body.isSet()) {
  158 |             body.serializeTo(httpResponse, serializerChain, httpRequest);
  159 | 
  160 |         } else if (chain != null) {
  161 |             chain.doFilter(httpRequest, httpResponse);
  162 |         }
  163 |     }
  164 | 
  165 |     private String getHttpMethodFrom(HttpServletRequest httpRequest) {
  166 |         String method = httpRequest.getHeader(HTTP_METHOD_OVERRIDE_HEADER);

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

## 105/113 flow_id 268b43a5e9 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 268b43a5e9
key        : <org.eclipse.jetty.server.Request: java.lang.String getQueryString()>@L1141/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>@L258/0
source     : <org.eclipse.jetty.server.Request: java.lang.String getQueryString()>[2@L1141] %v3 = invokevirtual %v2.getQuery()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>[19@L258] invokespecial %v14.<init>(%v15)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2

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

## 106/113 flow_id a51b4eef2d (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow a51b4eef2d
key        : <org.eclipse.jetty.server.session.HashSessionIdManager: void addSession(javax.servlet.http.HttpSession)>@L121/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>@L258/0
source     : <org.eclipse.jetty.server.session.HashSessionIdManager: void addSession(javax.servlet.http.HttpSession)>[0@L121] %v7 = invokeinterface session.getId()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>[19@L258] invokespecial %v14.<init>(%v15)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, iris-like run2, v1 run1, v1 run2, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
N3 (v3 run1): uncertain / insufficient_context (kept=True, v3_ok=None)

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

## 107/113 flow_id ef16108f02 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow ef16108f02
key        : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>@L34/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>@L258/0
source     : <spark.servlet.FilterTools: java.lang.String getRelativePath(javax.servlet.http.HttpServletRequest,java.lang.String)>[2@L34] path = invokeinterface request.getRequestURI()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>[19@L258] invokespecial %v14.<init>(%v15)/0
fixed methods on this flow (GT): -
reported by: B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run1, v3 run1, v3-noV2 run1, v3-noV3 run1, v3-noval run1, v4 run1
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

## 108/113 flow_id 93687035c1 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 93687035c1
key        : <spark.utils.StringUtils: java.lang.String collectionToDelimitedString(java.util.Collection,java.lang.String,java.lang.String,java.lang.String)>@L356/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>@L258/0
source     : <spark.utils.StringUtils: java.lang.String collectionToDelimitedString(java.util.Collection,java.lang.String,java.lang.String,java.lang.String)>[11@L356] %v13 = invokeinterface it.next()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>[19@L258] invokespecial %v14.<init>(%v15)/0
fixed methods on this flow (GT): -
reported by: iris-like run2, v1 run2
N3 (iris-like run2): unjudged / over-max-flows (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.utils.ResourceUtils: java.io.File getFile(java.net.URI,java.lang.String)>, <spark.utils.StringUtils: java.lang.String collectionToDelimitedString(java.util.Collection,java.lang.String,java.lang.String,java.lang.String)>

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

### <spark.utils.StringUtils: java.lang.String collectionToDelimitedString(java.util.Collection,java.lang.String,java.lang.String,java.lang.String)>
file: spark/utils/StringUtils.java
  347 |      * @return the delimited String
  348 |      */
  349 |     public static String collectionToDelimitedString(Collection<?> coll, String delim, String prefix, String suffix) {
  350 |         if (CollectionUtils.isEmpty(coll)) {
  351 |             return "";
  352 |         }
  353 |         StringBuilder sb = new StringBuilder();
  354 |         Iterator<?> it = coll.iterator();
  355 |         while (it.hasNext()) {
  356 |             sb.append(prefix).append(it.next()).append(suffix);
  357 |             if (it.hasNext()) {
  358 |                 sb.append(delim);
  359 |             }
  360 |         }
  361 |         return sb.toString();
  362 |     }
  363 | 
  364 |     /**
```

---

## 109/113 flow_id df5f4d805e (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow df5f4d805e
key        : <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>@L100/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L219/0
source     : <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>[10@L100] uri = invokeinterface httpRequest.getRequestURI()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[20@L219] invokespecial %v15.<init>(%v17)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run2, v3 run2, v3-noV2 run2, v3-noV3 run2, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run2): uncertain / insufficient_context (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <spark.http.matching.MatcherFilter: void doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain)>
file: spark/http/matching/MatcherFilter.java
   84 |                          ServletResponse servletResponse,
   85 |                          FilterChain chain) throws IOException, ServletException {
   86 | 
   87 |         HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
   88 |         HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;
   89 | 
   90 |         // handle static resources
   91 |         boolean consumedByStaticFile = staticFiles.consume(httpRequest, httpResponse);
   92 | 
   93 |         if (consumedByStaticFile) {
   94 |             return;
   95 |         }
   96 | 
   97 |         String method = getHttpMethodFrom(httpRequest);
   98 | 
   99 |         String httpMethodStr = method.toLowerCase();
  100 |         String uri = httpRequest.getRequestURI();
  101 |         String acceptType = httpRequest.getHeader(ACCEPT_TYPE_REQUEST_MIME_HEADER);
  102 | 
  103 |         Body body = Body.create();
  104 | 
  105 |         RequestWrapper requestWrapper = RequestWrapper.create();
  106 |         ResponseWrapper responseWrapper = ResponseWrapper.create();
  107 | 
  108 |         Response response = RequestResponseFactory.create(httpResponse);
  109 | 
  110 |         HttpMethod httpMethod = HttpMethod.get(httpMethodStr);
  111 | 
  112 |         RouteContext context = RouteContext.create()
  113 |                 .withMatcher(routeMatcher)
      | ... (lines omitted) ...
  137 |         }
  138 | 
  139 |         // If redirected and content is null set to empty string to not throw NotConsumedException
  140 |         if (body.notSet() && responseWrapper.isRedirected()) {
  141 |             body.set("");
  142 |         }
  143 | 
  144 |         if (body.notSet() && hasOtherHandlers) {
  145 |             if (servletRequest instanceof HttpRequestWrapper) {
  146 |                 ((HttpRequestWrapper) servletRequest).notConsumed(true);
  147 |                 return;
  148 |             }
  149 |         }
  150 | 
  151 |         if (body.notSet() && !externalContainer) {
  152 |             LOG.info("The requested route [" + uri + "] has not been mapped in Spark");
  153 |             httpResponse.setStatus(HttpServletResponse.SC_NOT_FOUND);
  154 |             body.set(String.format(NOT_FOUND));
  155 |         }
  156 | 
  157 |         if (body.isSet()) {
  158 |             body.serializeTo(httpResponse, serializerChain, httpRequest);
  159 | 
  160 |         } else if (chain != null) {
  161 |             chain.doFilter(httpRequest, httpResponse);
  162 |         }
  163 |     }
  164 | 
  165 |     private String getHttpMethodFrom(HttpServletRequest httpRequest) {
  166 |         String method = httpRequest.getHeader(HTTP_METHOD_OVERRIDE_HEADER);

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

## 110/113 flow_id 43124cd193 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 43124cd193
key        : <org.eclipse.jetty.server.session.HashSessionIdManager: void removeSession(javax.servlet.http.HttpSession)>@L143/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L222/0
source     : <org.eclipse.jetty.server.session.HashSessionIdManager: void removeSession(javax.servlet.http.HttpSession)>[1@L143] %v9 = invokeinterface session.getId()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[25@L222] invokespecial %v19.<init>(%v20)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, iris-like run2, v1 run1, v1 run2, v2 run1, v2 run2, v3 run1, v3 run2, v3-noV2 run1, v3-noV2 run2, v3-noV3 run1, v3-noV3 run2, v3-noval run1, v3-noval run2, v4 run1, v4 run2
N3 (v3 run1): uncertain / insufficient_context (kept=True, v3_ok=None)

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

## 111/113 flow_id ab7da7fe6f (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow ab7da7fe6f
key        : <org.eclipse.jetty.server.session.HashSessionManager: org.eclipse.jetty.server.session.HashedSession restoreSession(java.io.InputStream,org.eclipse.jetty.server.session.HashedSession)>@L644/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L222/0
source     : <org.eclipse.jetty.server.session.HashSessionManager: org.eclipse.jetty.server.session.HashedSession restoreSession(java.io.InputStream,org.eclipse.jetty.server.session.HashedSession)>[3@L644] clusterId = invokevirtual di.readUTF()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[25@L222] invokespecial %v19.<init>(%v20)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3 run2, v3-noV2 run0, v3-noV2 run1, v3-noV2 run2, v3-noV3 run0, v3-noV3 run1, v3-noV3 run2, v3-noval run0, v3-noval run1, v3-noval run2, v4 run0, v4 run1, v4 run2
N3 (v3 run0): uncertain / insufficient_context (kept=True, v3_ok=None)

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

## 112/113 flow_id f389662b0a (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow f389662b0a
key        : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>@L54/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L222/0
source     : <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>[20@L54] servletPath = invokeinterface request.getServletPath()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[25@L222] invokespecial %v19.<init>(%v20)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>, <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

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

### <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ClassPathResourceHandler.java
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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   57 | 
   58 |     @Override
   59 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   60 |         if (path == null || !path.startsWith("/")) {
   61 |             throw new MalformedURLException(path);
   62 |         }
   63 | 
   64 |         try {
   65 |             path = UriPath.canonical(path);
   66 | 
   67 |             final String addedPath = addPaths(baseResource, path);
   68 | 
   69 |             ExternalResource resource = new ExternalResource(addedPath);
   70 | 
   71 |             if (resource.exists() && resource.isDirectory()) {
   72 |                 if (welcomeFile != null) {
   73 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   74 |                 } else {
   75 |                     //  No welcome file configured, serve nothing since it's a directory
   76 |                     resource = null;
   77 |                 }
   78 |             }
   79 | 
   80 |             return (resource != null && resource.exists()) ? resource : null;
   81 |         } catch (Exception e) {
   82 |             if (LOG.isDebugEnabled()) {
   83 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   84 |             }
   85 |         }
   86 |         return null;
   87 |     }
   88 | 
   89 | }

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

## 113/113 flow_id 5c166c6349 (priority 2)

```text
# spark/buggy (CVE-2016-9177, CWE-022) flow 5c166c6349
key        : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>@L68/result => <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>@L222/0
source     : <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>[18@L68] pathInfo = invokeinterface request.getPathInfo()/result
sink       : <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>[25@L222] invokespecial %v19.<init>(%v20)/0
fixed methods on this flow (GT): -
reported by: B1 run0, B2 run0, iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v2 run0, v2 run2, v3 run0, v3 run2, v3-noV2 run0, v3-noV2 run2, v3-noV3 run0, v3-noV3 run2, v3-noval run0, v3-noval run2, v4 run0, v4 run2
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <spark.resource.AbstractResourceHandler: java.lang.String addPaths(java.lang.String,java.lang.String)>, <spark.resource.AbstractResourceHandler: spark.resource.AbstractFileResolvingResource getResource(javax.servlet.http.HttpServletRequest)>, <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>, <spark.resource.JarResourceHandler: java.io.InputStream getResource(javax.servlet.http.HttpServletRequest)>, <spark.utils.ResourceUtils: java.io.File getFile(java.net.URL,java.lang.String)>

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

### <spark.resource.ClassPathResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ClassPathResourceHandler.java
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
   70 |             ClassPathResource resource = new ClassPathResource(addedPath);
   71 | 
   72 |             if (resource.exists() && resource.getFile().isDirectory()) {
   73 |                 if (welcomeFile != null) {
   74 |                     resource = new ClassPathResource(addPaths(resource.getPath(), welcomeFile));
   75 |                 } else {
   76 |                     //  No welcome file configured, serve nothing since it's a directory
   77 |                     resource = null;
   78 |                 }
   79 |             }
   80 | 
   81 |             return (resource != null && resource.exists()) ? resource : null;
   82 |         } catch (Exception e) {
   83 |             if (LOG.isDebugEnabled()) {
   84 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   85 |             }
   86 |         }
   87 |         return null;
   88 |     }
   89 | 
   90 | }

### <spark.resource.ExternalResourceHandler: spark.resource.AbstractFileResolvingResource getResource(java.lang.String)>
file: spark/resource/ExternalResourceHandler.java
   57 | 
   58 |     @Override
   59 |     protected AbstractFileResolvingResource getResource(String path) throws MalformedURLException {
   60 |         if (path == null || !path.startsWith("/")) {
   61 |             throw new MalformedURLException(path);
   62 |         }
   63 | 
   64 |         try {
   65 |             path = UriPath.canonical(path);
   66 | 
   67 |             final String addedPath = addPaths(baseResource, path);
   68 | 
   69 |             ExternalResource resource = new ExternalResource(addedPath);
   70 | 
   71 |             if (resource.exists() && resource.isDirectory()) {
   72 |                 if (welcomeFile != null) {
   73 |                     resource = new ExternalResource(addPaths(resource.getPath(), welcomeFile));
   74 |                 } else {
   75 |                     //  No welcome file configured, serve nothing since it's a directory
   76 |                     resource = null;
   77 |                 }
   78 |             }
   79 | 
   80 |             return (resource != null && resource.exists()) ? resource : null;
   81 |         } catch (Exception e) {
   82 |             if (LOG.isDebugEnabled()) {
   83 |                 LOG.debug(e.getClass().getSimpleName() + " when trying to get resource. " + e.getMessage());
   84 |             }
   85 |         }
   86 |         return null;
   87 |     }
   88 | 
   89 | }

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
