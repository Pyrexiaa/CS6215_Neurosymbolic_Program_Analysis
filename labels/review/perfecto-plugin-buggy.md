# Labelling pack: perfecto-plugin / buggy

4 frozen sampled rows. Evidence uses the exact raw source and sink in the chosen run record. Existing labels remain unverified and are unchanged. A canonical key may still group different drivers or routes; inspect the attacker model before reusing a label. Original packets are retained in results/history/pre-evidence-refresh.tar.gz.

---

## 1/4 flow_id 05a565b1c4 (priority 1)

```text
# perfecto-plugin/buggy (CVE-2020-2261, CWE-078) flow 05a565b1c4
key        : DRIVER => <io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>@L167/0[*]
source     : <nesy.NesyDriver: void main(java.lang.String[])>[56@L19] %v37 = invokestatic nesy.Taint.src()/result
sink       : <io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>[104@L167] process = invokevirtual %v93.exec(cmdArgs#1)/0[*]
fixed methods on this flow (GT): PerfectoBuildWrapper.getTunnelId, PerfectoBuildWrapper.PerfectoBuildWrapper
reported by: B2 run0, v4 run1, v4 run2

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[56@L19] %v37 = invokestatic nesy.Taint.src()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v37}
3. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: void <init>(org.jenkins_ci.plugins.run_condition.RunCondition,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String)>/pcParameters}
4. InstanceFieldNode{NewObj{<nesy.NesyDriver: void main(java.lang.String[])>[52@L19] new io.plugins.perfecto.PerfectoBuildWrapper}.<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String pcParameters>}
5. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>/%v87}
6. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>/%v88}
7. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>/%v90}
8. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>/%v91}
9. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>/%v92}
10. ArrayIndexNode{NewObj{<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>[81@L166] newarray java.lang.String[%ci3]}}
11. <io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>[104@L167] process = invokevirtual %v93.exec(cmdArgs#1)/0[*]

## Application-code evidence (route or reachable-method fallback)
### <io.plugins.perfecto.PerfectoBuildWrapper: void <init>(org.jenkins_ci.plugins.run_condition.RunCondition,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String)>
file: io/plugins/perfecto/PerfectoBuildWrapper.java
   73 | 	/**
   74 | 	 * The custom Tunnel Id name.
   75 | 	 */
   76 | 	private String tunnelIdCustomName = "tunnelId";
   77 | 	/**
   78 | 	 * Indicates whether Perfecto Connect should be started as part of the build.
   79 | 	 */
   80 | 	private boolean enablePerfectoConnect;
   81 | 	/**
   82 | 	 * The path of the Perfecto connect location.
   83 | 	 */
   84 | 	private String perfectoConnectLocation;
   85 | 	/**
   86 | 	 * The path of the Perfecto security token.
   87 | 	 */
   88 | 	private String perfectoSecurityToken;
   89 | 
   90 | 	/**
   91 | 	 * The Perfecto Connect parameters.
   92 | 	 */
   93 | 	private String pcParameters;
   94 | 
   95 | 	private String reuseTunnelId;
   96 | 
   97 | 	private PerfectoCredentials credentials;
   98 | 
   99 | 	@SuppressFBWarnings("SE_BAD_FIELD")
  100 | 	private RunCondition condition;
  101 | 	/**
  102 | 	 * @see CredentialsProvider
      | ... (lines omitted) ...
  123 | 	 * @param pcParameters              Perfecto Connect parameters
  124 | 	 * @param perfectoConnectLocation   Perfecto connect location
  125 | 	 * @param perfectoSecurityToken     Perfecto Security token.
  126 | 	 * @param perfectoConnectFile       Perfecto connect file name.
  127 | 	 * @param reuseTunnelId				Tunnel ID to reuse.
  128 | 	 */
  129 | 	@DataBoundConstructor
  130 | 	public PerfectoBuildWrapper(
  131 | 			RunCondition condition,
  132 | 			String credentialId,
  133 | 			String tunnelIdCustomName,
  134 | 			String pcParameters,
  135 | 			String perfectoConnectLocation,
  136 | 			String perfectoSecurityToken,
  137 | 			String perfectoConnectFile,
  138 | 			String reuseTunnelId
  139 | 			) {
  140 | 		this.perfectoConnectLocation = perfectoConnectLocation;
  141 | 		this.condition = condition;
  142 | 		if(tunnelIdCustomName.length()>1)
  143 | 			this.tunnelIdCustomName = tunnelIdCustomName;
  144 | 		this.credentialId = credentialId;
  145 | 		this.perfectoSecurityToken = perfectoSecurityToken;
  146 | 		this.pcParameters = pcParameters;
  147 | 		this.perfectoConnectFile = perfectoConnectFile;
  148 | 		this.reuseTunnelId = reuseTunnelId;
  149 | 	}
  150 | 
  151 | 	private String getTunnelId(String perfectoConnectLocation, String cloudName, String apiKey, BuildListener listener) throws IOException {
  152 | 		String tunnelId = null;

### <io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>
file: io/plugins/perfecto/PerfectoBuildWrapper.java
  149 | 	}
  150 | 
  151 | 	private String getTunnelId(String perfectoConnectLocation, String cloudName, String apiKey, BuildListener listener) throws IOException {
  152 | 		String tunnelId = null;
  153 | 		boolean isWindows = hudson.Functions.isWindows();
  154 | 		Process process;
  155 | 		if(perfectoConnectLocation.endsWith("/")||perfectoConnectLocation.endsWith("\\")) {
  156 | 			pcLocation = perfectoConnectLocation+perfectoConnectFile;
  157 | 		}else {
  158 | 			pcLocation = perfectoConnectLocation+File.separator+perfectoConnectFile;
  159 | 		}
  160 | 		String baseCommand = pcLocation.trim()+" start -c "+cloudName.trim()+".perfectomobile.com -s "+apiKey.trim();
  161 | 		listener.getLogger().println(pcLocation.trim()+" start -c "+cloudName.trim()+".perfectomobile.com -s <<TOKEN>> "+pcParameters.trim());
  162 | 		if (isWindows) {
  163 | 			String cmdArgs[] = {"cmd.exe", "/c", baseCommand+" "+pcParameters.trim()};
  164 | 			process = new ProcessBuilder(cmdArgs).redirectErrorStream(true).start();
  165 | 		} else {
  166 | 			String cmdArgs[] = {"bash", "-c", "(cd "+perfectoConnectLocation+"; "+baseCommand+" "+pcParameters.trim()+")"};
  167 | 			process = Runtime.getRuntime().exec(cmdArgs);
  168 | 		}
  169 | 		InputStream is = process.getInputStream();
  170 | 		BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
  171 | 		String s = null;
  172 | 		while ((s = reader.readLine()) != null) {
  173 | 			listener.getLogger().println(s);
  174 | 			Matcher m = Pattern.compile("^[A-Za-z0-9-]+$").matcher(s);
  175 | 			if (m.find()) {
  176 | 				tunnelId = m.group(0);
  177 | 				listener.getLogger().println("Tunnel Id : "+tunnelId);
  178 | 			}
  179 | 			if(s.contains("bash: ")) {
  180 | 				listener.fatalError("Perfecto Connect Path and Name is not Correct. Path Provided : '"+pcLocation+"'");
  181 | 				throw new IOException("Perfecto Connect Path and Name is not Correct. Path Provided : '"+pcLocation+"'");
  182 | 			}
  183 | 			if(s.contains("Can't start Perfecto Connect")||s.contains("failed to start")) {
  184 | 				listener.fatalError(tunnelId);
  185 | 				throw new IOException(tunnelId);
  186 | 			}
  187 | 		}
  188 | 		reader.close();
  189 | 		if(tunnelId == null) {
  190 | 			listener.fatalError("Unable to create tunnel ID. Kindly cross check your parameters or raise a Perfecto support case.");
  191 | 			throw new IOException("Unable to create tunnel ID. Kindly cross check your parameters or raise a Perfecto support case.");
  192 | 		}
  193 | 		return tunnelId;
  194 | 	}
  195 | 
  196 | 
```

---

## 2/4 flow_id dde7ff1fc9 (priority 1)

```text
# perfecto-plugin/buggy (CVE-2020-2261, CWE-078) flow dde7ff1fc9
key        : DRIVER => <io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>@L180/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[57@L19] %v38 = invokestatic nesy.Taint.src()/result
sink       : <io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>[141@L180] invokeinterface listener.fatalError(%v120)/0
fixed methods on this flow (GT): PerfectoBuildWrapper.getTunnelId, PerfectoBuildWrapper.setUp, PerfectoBuildWrapper.PerfectoBuildWrapper
reported by: iris-like run0, v1 run0, v4 run0
N3 (iris-like run0): uncertain /  (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[57@L19] %v38 = invokestatic nesy.Taint.src()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v38}
3. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: void <init>(org.jenkins_ci.plugins.run_condition.RunCondition,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String)>/perfectoConnectLocation}
4. InstanceFieldNode{NewObj{<nesy.NesyDriver: void main(java.lang.String[])>[52@L19] new io.plugins.perfecto.PerfectoBuildWrapper}.<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String perfectoConnectLocation>}
5. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: hudson.tasks.BuildWrapper$Environment setUp(hudson.model.AbstractBuild,hudson.Launcher,hudson.model.BuildListener)>/%v26}
6. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>/perfectoConnectLocation}
7. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>/%v27}
8. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>/%v29}
9. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>/%v30}
10. InstanceFieldNode{NewObj{<nesy.NesyDriver: void main(java.lang.String[])>[52@L19] new io.plugins.perfecto.PerfectoBuildWrapper}.<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String pcLocation>}
11. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>/%v116}
12. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>/%v118}
13. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>/%v119}
14. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>/%v120}
15. <io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>[141@L180] invokeinterface listener.fatalError(%v120)/0

## Application-code evidence (route or reachable-method fallback)
### <io.plugins.perfecto.PerfectoBuildWrapper: void <init>(org.jenkins_ci.plugins.run_condition.RunCondition,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String)>
file: io/plugins/perfecto/PerfectoBuildWrapper.java
   73 | 	/**
   74 | 	 * The custom Tunnel Id name.
   75 | 	 */
   76 | 	private String tunnelIdCustomName = "tunnelId";
   77 | 	/**
   78 | 	 * Indicates whether Perfecto Connect should be started as part of the build.
   79 | 	 */
   80 | 	private boolean enablePerfectoConnect;
   81 | 	/**
   82 | 	 * The path of the Perfecto connect location.
   83 | 	 */
   84 | 	private String perfectoConnectLocation;
   85 | 	/**
   86 | 	 * The path of the Perfecto security token.
   87 | 	 */
   88 | 	private String perfectoSecurityToken;
   89 | 
   90 | 	/**
   91 | 	 * The Perfecto Connect parameters.
   92 | 	 */
   93 | 	private String pcParameters;
   94 | 
   95 | 	private String reuseTunnelId;
   96 | 
   97 | 	private PerfectoCredentials credentials;
   98 | 
   99 | 	@SuppressFBWarnings("SE_BAD_FIELD")
  100 | 	private RunCondition condition;
  101 | 	/**
  102 | 	 * @see CredentialsProvider
      | ... (lines omitted) ...
  123 | 	 * @param pcParameters              Perfecto Connect parameters
  124 | 	 * @param perfectoConnectLocation   Perfecto connect location
  125 | 	 * @param perfectoSecurityToken     Perfecto Security token.
  126 | 	 * @param perfectoConnectFile       Perfecto connect file name.
  127 | 	 * @param reuseTunnelId				Tunnel ID to reuse.
  128 | 	 */
  129 | 	@DataBoundConstructor
  130 | 	public PerfectoBuildWrapper(
  131 | 			RunCondition condition,
  132 | 			String credentialId,
  133 | 			String tunnelIdCustomName,
  134 | 			String pcParameters,
  135 | 			String perfectoConnectLocation,
  136 | 			String perfectoSecurityToken,
  137 | 			String perfectoConnectFile,
  138 | 			String reuseTunnelId
  139 | 			) {
  140 | 		this.perfectoConnectLocation = perfectoConnectLocation;
  141 | 		this.condition = condition;
  142 | 		if(tunnelIdCustomName.length()>1)
  143 | 			this.tunnelIdCustomName = tunnelIdCustomName;
  144 | 		this.credentialId = credentialId;
  145 | 		this.perfectoSecurityToken = perfectoSecurityToken;
  146 | 		this.pcParameters = pcParameters;
  147 | 		this.perfectoConnectFile = perfectoConnectFile;
  148 | 		this.reuseTunnelId = reuseTunnelId;
  149 | 	}
  150 | 
  151 | 	private String getTunnelId(String perfectoConnectLocation, String cloudName, String apiKey, BuildListener listener) throws IOException {
  152 | 		String tunnelId = null;

### <io.plugins.perfecto.PerfectoBuildWrapper: hudson.tasks.BuildWrapper$Environment setUp(hudson.model.AbstractBuild,hudson.Launcher,hudson.model.BuildListener)>
file: io/plugins/perfecto/PerfectoBuildWrapper.java
  203 | 	 */
  204 | 	@Override
  205 | 	public Environment setUp(final AbstractBuild build, Launcher launcher, final BuildListener listener) throws IOException, InterruptedException {
  206 | 		listener.getLogger().println("Creating Tunnel Id........!");
  207 | 		logger.fine("Setting Perfecto Build Wrapper");
  208 | 
  209 | 		credentials = PerfectoCredentials.getPerfectoCredentials(build, this);
  210 | 		CredentialsProvider.track(build, credentials);
  211 | 
  212 | 		if(credentials==null && !reuseTunnelId.contains("-")) {
  213 | 			listener.fatalError("Credentials missing......");
  214 | 			throw new IOException("Credentials missing......");
  215 | 		}
  216 | 
  217 | 		if(!reuseTunnelId.contains("-")) {
  218 | 			final String apiKey = credentials.getPassword().getPlainText();
  219 | 			tunnelId = getTunnelId(perfectoConnectLocation, credentials.getCloudName(), apiKey, listener);
  220 | 		}
  221 | 		else
  222 | 			tunnelId = reuseTunnelId;
  223 | 		listener.getLogger().println("Tunnel Id created succesfully.");
  224 | 
  225 | 		return new Environment() {
  226 | 
  227 | 			/**
  228 | 			 * Updates the environment variable map to include the Perfecto specific environment variables applicable to the build.

### <io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>
file: io/plugins/perfecto/PerfectoBuildWrapper.java
  149 | 	}
  150 | 
  151 | 	private String getTunnelId(String perfectoConnectLocation, String cloudName, String apiKey, BuildListener listener) throws IOException {
  152 | 		String tunnelId = null;
  153 | 		boolean isWindows = hudson.Functions.isWindows();
  154 | 		Process process;
  155 | 		if(perfectoConnectLocation.endsWith("/")||perfectoConnectLocation.endsWith("\\")) {
  156 | 			pcLocation = perfectoConnectLocation+perfectoConnectFile;
  157 | 		}else {
  158 | 			pcLocation = perfectoConnectLocation+File.separator+perfectoConnectFile;
  159 | 		}
  160 | 		String baseCommand = pcLocation.trim()+" start -c "+cloudName.trim()+".perfectomobile.com -s "+apiKey.trim();
  161 | 		listener.getLogger().println(pcLocation.trim()+" start -c "+cloudName.trim()+".perfectomobile.com -s <<TOKEN>> "+pcParameters.trim());
  162 | 		if (isWindows) {
  163 | 			String cmdArgs[] = {"cmd.exe", "/c", baseCommand+" "+pcParameters.trim()};
  164 | 			process = new ProcessBuilder(cmdArgs).redirectErrorStream(true).start();
  165 | 		} else {
  166 | 			String cmdArgs[] = {"bash", "-c", "(cd "+perfectoConnectLocation+"; "+baseCommand+" "+pcParameters.trim()+")"};
  167 | 			process = Runtime.getRuntime().exec(cmdArgs);
  168 | 		}
  169 | 		InputStream is = process.getInputStream();
  170 | 		BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
  171 | 		String s = null;
  172 | 		while ((s = reader.readLine()) != null) {
  173 | 			listener.getLogger().println(s);
  174 | 			Matcher m = Pattern.compile("^[A-Za-z0-9-]+$").matcher(s);
  175 | 			if (m.find()) {
  176 | 				tunnelId = m.group(0);
  177 | 				listener.getLogger().println("Tunnel Id : "+tunnelId);
  178 | 			}
  179 | 			if(s.contains("bash: ")) {
  180 | 				listener.fatalError("Perfecto Connect Path and Name is not Correct. Path Provided : '"+pcLocation+"'");
  181 | 				throw new IOException("Perfecto Connect Path and Name is not Correct. Path Provided : '"+pcLocation+"'");
  182 | 			}
  183 | 			if(s.contains("Can't start Perfecto Connect")||s.contains("failed to start")) {
  184 | 				listener.fatalError(tunnelId);
  185 | 				throw new IOException(tunnelId);
  186 | 			}
  187 | 		}
  188 | 		reader.close();
  189 | 		if(tunnelId == null) {
  190 | 			listener.fatalError("Unable to create tunnel ID. Kindly cross check your parameters or raise a Perfecto support case.");
  191 | 			throw new IOException("Unable to create tunnel ID. Kindly cross check your parameters or raise a Perfecto support case.");
  192 | 		}
  193 | 		return tunnelId;
  194 | 	}
  195 | 
  196 | 
```

---

## 3/4 flow_id 21ba189d7d (priority 1)

```text
# perfecto-plugin/buggy (CVE-2020-2261, CWE-078) flow 21ba189d7d
key        : DRIVER => <io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>@L164/0[*]
source     : <nesy.NesyDriver: void main(java.lang.String[])>[56@L19] %v37 = invokestatic nesy.Taint.src()/result
sink       : <io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>[77@L164] invokespecial %v73.<init>(cmdArgs)/0[*]
fixed methods on this flow (GT): PerfectoBuildWrapper.getTunnelId, PerfectoBuildWrapper.PerfectoBuildWrapper
reported by: B2 run0, v4 run1, v4 run2

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[56@L19] %v37 = invokestatic nesy.Taint.src()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v37}
3. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: void <init>(org.jenkins_ci.plugins.run_condition.RunCondition,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String)>/pcParameters}
4. InstanceFieldNode{NewObj{<nesy.NesyDriver: void main(java.lang.String[])>[52@L19] new io.plugins.perfecto.PerfectoBuildWrapper}.<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String pcParameters>}
5. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>/%v69}
6. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>/%v70}
7. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>/%v71}
8. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>/%v72}
9. ArrayIndexNode{NewObj{<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>[61@L163] newarray java.lang.String[%ci3]}}
10. <io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>[77@L164] invokespecial %v73.<init>(cmdArgs)/0[*]

## Application-code evidence (route or reachable-method fallback)
### <io.plugins.perfecto.PerfectoBuildWrapper: void <init>(org.jenkins_ci.plugins.run_condition.RunCondition,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String)>
file: io/plugins/perfecto/PerfectoBuildWrapper.java
   73 | 	/**
   74 | 	 * The custom Tunnel Id name.
   75 | 	 */
   76 | 	private String tunnelIdCustomName = "tunnelId";
   77 | 	/**
   78 | 	 * Indicates whether Perfecto Connect should be started as part of the build.
   79 | 	 */
   80 | 	private boolean enablePerfectoConnect;
   81 | 	/**
   82 | 	 * The path of the Perfecto connect location.
   83 | 	 */
   84 | 	private String perfectoConnectLocation;
   85 | 	/**
   86 | 	 * The path of the Perfecto security token.
   87 | 	 */
   88 | 	private String perfectoSecurityToken;
   89 | 
   90 | 	/**
   91 | 	 * The Perfecto Connect parameters.
   92 | 	 */
   93 | 	private String pcParameters;
   94 | 
   95 | 	private String reuseTunnelId;
   96 | 
   97 | 	private PerfectoCredentials credentials;
   98 | 
   99 | 	@SuppressFBWarnings("SE_BAD_FIELD")
  100 | 	private RunCondition condition;
  101 | 	/**
  102 | 	 * @see CredentialsProvider
      | ... (lines omitted) ...
  123 | 	 * @param pcParameters              Perfecto Connect parameters
  124 | 	 * @param perfectoConnectLocation   Perfecto connect location
  125 | 	 * @param perfectoSecurityToken     Perfecto Security token.
  126 | 	 * @param perfectoConnectFile       Perfecto connect file name.
  127 | 	 * @param reuseTunnelId				Tunnel ID to reuse.
  128 | 	 */
  129 | 	@DataBoundConstructor
  130 | 	public PerfectoBuildWrapper(
  131 | 			RunCondition condition,
  132 | 			String credentialId,
  133 | 			String tunnelIdCustomName,
  134 | 			String pcParameters,
  135 | 			String perfectoConnectLocation,
  136 | 			String perfectoSecurityToken,
  137 | 			String perfectoConnectFile,
  138 | 			String reuseTunnelId
  139 | 			) {
  140 | 		this.perfectoConnectLocation = perfectoConnectLocation;
  141 | 		this.condition = condition;
  142 | 		if(tunnelIdCustomName.length()>1)
  143 | 			this.tunnelIdCustomName = tunnelIdCustomName;
  144 | 		this.credentialId = credentialId;
  145 | 		this.perfectoSecurityToken = perfectoSecurityToken;
  146 | 		this.pcParameters = pcParameters;
  147 | 		this.perfectoConnectFile = perfectoConnectFile;
  148 | 		this.reuseTunnelId = reuseTunnelId;
  149 | 	}
  150 | 
  151 | 	private String getTunnelId(String perfectoConnectLocation, String cloudName, String apiKey, BuildListener listener) throws IOException {
  152 | 		String tunnelId = null;

### <io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String getTunnelId(java.lang.String,java.lang.String,java.lang.String,hudson.model.BuildListener)>
file: io/plugins/perfecto/PerfectoBuildWrapper.java
  149 | 	}
  150 | 
  151 | 	private String getTunnelId(String perfectoConnectLocation, String cloudName, String apiKey, BuildListener listener) throws IOException {
  152 | 		String tunnelId = null;
  153 | 		boolean isWindows = hudson.Functions.isWindows();
  154 | 		Process process;
  155 | 		if(perfectoConnectLocation.endsWith("/")||perfectoConnectLocation.endsWith("\\")) {
  156 | 			pcLocation = perfectoConnectLocation+perfectoConnectFile;
  157 | 		}else {
  158 | 			pcLocation = perfectoConnectLocation+File.separator+perfectoConnectFile;
  159 | 		}
  160 | 		String baseCommand = pcLocation.trim()+" start -c "+cloudName.trim()+".perfectomobile.com -s "+apiKey.trim();
  161 | 		listener.getLogger().println(pcLocation.trim()+" start -c "+cloudName.trim()+".perfectomobile.com -s <<TOKEN>> "+pcParameters.trim());
  162 | 		if (isWindows) {
  163 | 			String cmdArgs[] = {"cmd.exe", "/c", baseCommand+" "+pcParameters.trim()};
  164 | 			process = new ProcessBuilder(cmdArgs).redirectErrorStream(true).start();
  165 | 		} else {
  166 | 			String cmdArgs[] = {"bash", "-c", "(cd "+perfectoConnectLocation+"; "+baseCommand+" "+pcParameters.trim()+")"};
  167 | 			process = Runtime.getRuntime().exec(cmdArgs);
  168 | 		}
  169 | 		InputStream is = process.getInputStream();
  170 | 		BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
  171 | 		String s = null;
  172 | 		while ((s = reader.readLine()) != null) {
  173 | 			listener.getLogger().println(s);
  174 | 			Matcher m = Pattern.compile("^[A-Za-z0-9-]+$").matcher(s);
  175 | 			if (m.find()) {
  176 | 				tunnelId = m.group(0);
  177 | 				listener.getLogger().println("Tunnel Id : "+tunnelId);
  178 | 			}
  179 | 			if(s.contains("bash: ")) {
  180 | 				listener.fatalError("Perfecto Connect Path and Name is not Correct. Path Provided : '"+pcLocation+"'");
  181 | 				throw new IOException("Perfecto Connect Path and Name is not Correct. Path Provided : '"+pcLocation+"'");
  182 | 			}
  183 | 			if(s.contains("Can't start Perfecto Connect")||s.contains("failed to start")) {
  184 | 				listener.fatalError(tunnelId);
  185 | 				throw new IOException(tunnelId);
  186 | 			}
  187 | 		}
  188 | 		reader.close();
  189 | 		if(tunnelId == null) {
  190 | 			listener.fatalError("Unable to create tunnel ID. Kindly cross check your parameters or raise a Perfecto support case.");
  191 | 			throw new IOException("Unable to create tunnel ID. Kindly cross check your parameters or raise a Perfecto support case.");
  192 | 		}
  193 | 		return tunnelId;
  194 | 	}
  195 | 
  196 | 
```

---

## 4/4 flow_id 20278dfc29 (priority 1)

```text
# perfecto-plugin/buggy (CVE-2020-2261, CWE-078) flow 20278dfc29
key        : DRIVER => <io.plugins.perfecto.credentials.PerfectoCredentials: hudson.util.FormValidation testAuthentication(java.lang.String,java.lang.String,java.lang.String)>@L111/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[7@L8] %v8 = invokestatic nesy.Taint.src()/result
sink       : <io.plugins.perfecto.credentials.PerfectoCredentials: hudson.util.FormValidation testAuthentication(java.lang.String,java.lang.String,java.lang.String)>[14@L111] invokespecial myURL.<init>(checkConnectionURL)/0
fixed methods on this flow (GT): DescriptorImpl.doAuthenticate
reported by: v1 run1, v2 run1

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[7@L8] %v8 = invokestatic nesy.Taint.src()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v8}
3. VarNode{<io.plugins.perfecto.credentials.PerfectoCredentials$DescriptorImpl: hudson.util.FormValidation doAuthenticate(java.lang.String,java.lang.String,java.lang.String)>/userName}
4. VarNode{<io.plugins.perfecto.credentials.PerfectoCredentials: hudson.util.FormValidation testAuthentication(java.lang.String,java.lang.String,java.lang.String)>/username}
5. VarNode{<io.plugins.perfecto.credentials.PerfectoCredentials: hudson.util.FormValidation testAuthentication(java.lang.String,java.lang.String,java.lang.String)>/%v14}
6. VarNode{<io.plugins.perfecto.credentials.PerfectoCredentials: hudson.util.FormValidation testAuthentication(java.lang.String,java.lang.String,java.lang.String)>/%v15}
7. VarNode{<io.plugins.perfecto.credentials.PerfectoCredentials: hudson.util.FormValidation testAuthentication(java.lang.String,java.lang.String,java.lang.String)>/%v16}
8. VarNode{<io.plugins.perfecto.credentials.PerfectoCredentials: hudson.util.FormValidation testAuthentication(java.lang.String,java.lang.String,java.lang.String)>/checkConnectionURL}
9. <io.plugins.perfecto.credentials.PerfectoCredentials: hudson.util.FormValidation testAuthentication(java.lang.String,java.lang.String,java.lang.String)>[14@L111] invokespecial myURL.<init>(checkConnectionURL)/0

## Application-code evidence (route or reachable-method fallback)
### <io.plugins.perfecto.credentials.PerfectoCredentials$DescriptorImpl: hudson.util.FormValidation doAuthenticate(java.lang.String,java.lang.String,java.lang.String)>
file: io/plugins/perfecto/credentials/PerfectoCredentials.java
  194 | 		@POST
  195 | 		public final FormValidation doAuthenticate(@QueryParameter("userName") String userName, @QueryParameter("cloudName") String cloudName,
  196 | 				@QueryParameter("apiKey") String apiKey) {
  197 | 			if (StringUtils.isBlank(userName) || StringUtils.isBlank(cloudName) || StringUtils.isBlank(apiKey)) {
  198 | 				return FormValidation.error(ERR_EMPTY_AUTH);
  199 | 			}
  200 | 			return testAuthentication(userName, cloudName, apiKey);
  201 | 		}
  202 | 
  203 | 		@POST

### <io.plugins.perfecto.credentials.PerfectoCredentials: hudson.util.FormValidation testAuthentication(java.lang.String,java.lang.String,java.lang.String)>
file: io/plugins/perfecto/credentials/PerfectoCredentials.java
  104 | 	}
  105 | 
  106 | 	public static FormValidation testAuthentication(final String username, final String cloudName, final String apikey) {
  107 | 		String checkConnectionURL = "https://"+cloudName+".perfectomobile.com/services/users/"+username+"?operation=info&securityToken="+apikey;
  108 | 		URL myURL;
  109 | 		HttpsURLConnection conn = null;
  110 | 		try {
  111 | 			myURL = new URL(checkConnectionURL);
  112 | 			conn = (HttpsURLConnection) myURL.openConnection();
  113 | 			conn.setRequestMethod("POST");
  114 | 			conn.setRequestProperty("Accept", "application/json");
  115 | 			int response = conn.getResponseCode();
  116 | 			System.out.println("response"+response);
  117 | 			if (response != 200) {
  118 | 				conn.disconnect();
  119 | 				return FormValidation.error(ERR_INVALID_AUTH+", HTTP error code : "+response);
  120 | 			}
  121 | 			conn.disconnect();
  122 | 		}catch(Exception e) {
  123 | 			if(conn != null) {
  124 | 				conn.disconnect();
  125 | 			}
  126 | 			System.out.println("exception: "+e);
  127 | 			return FormValidation.error(ERR_INVALID_AUTH);
  128 | 		}
  129 | 		System.out.println("success");
  130 | 		return FormValidation.ok(OK_VALID_AUTH);
  131 | 	}
  132 | 
  133 | 	public static PerfectoCredentials getCredentials(AbstractBuild build) {
```
