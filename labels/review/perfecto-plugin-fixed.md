# Labelling pack: perfecto-plugin / fixed

2 frozen sampled rows. Evidence uses the exact raw source and sink in the chosen run record. Existing labels remain unverified and are unchanged. A canonical key may still group different drivers or routes; inspect the attacker model before reusing a label. Original packets are retained in results/history/pre-evidence-refresh.tar.gz.

---

## 1/2 flow_id f88d0d638a (priority 1)

```text
# perfecto-plugin/fixed (CVE-2020-2261, CWE-078) flow f88d0d638a
key        : DRIVER => <io.plugins.perfecto.PerfectoBuildWrapper: hudson.tasks.CommandInterpreter getCommandInterpreter(hudson.Launcher,java.lang.String)>@L256/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[56@L19] %v37 = invokestatic nesy.Taint.src()/result
sink       : <io.plugins.perfecto.PerfectoBuildWrapper: hudson.tasks.CommandInterpreter getCommandInterpreter(hudson.Launcher,java.lang.String)>[7@L256] invokespecial %v6.<init>(script)/0
fixed methods on this flow (GT): PerfectoBuildWrapper.setUp, PerfectoBuildWrapper.PerfectoBuildWrapper
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run0, v4 run1, v4 run2
N3 (iris-like run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
1. <nesy.NesyDriver: void main(java.lang.String[])>[56@L19] %v37 = invokestatic nesy.Taint.src()/result
2. VarNode{<nesy.NesyDriver: void main(java.lang.String[])>/%v37}
3. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: void <init>(org.jenkins_ci.plugins.run_condition.RunCondition,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String)>/pcParameters}
4. InstanceFieldNode{NewObj{<nesy.NesyDriver: void main(java.lang.String[])>[52@L19] new io.plugins.perfecto.PerfectoBuildWrapper}.<io.plugins.perfecto.PerfectoBuildWrapper: java.lang.String pcParameters>}
5. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: hudson.tasks.BuildWrapper$Environment setUp(hudson.model.AbstractBuild,hudson.Launcher,hudson.model.BuildListener)>/%v90}
6. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: hudson.tasks.BuildWrapper$Environment setUp(hudson.model.AbstractBuild,hudson.Launcher,hudson.model.BuildListener)>/%v91}
7. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: hudson.tasks.BuildWrapper$Environment setUp(hudson.model.AbstractBuild,hudson.Launcher,hudson.model.BuildListener)>/%v92}
8. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: hudson.tasks.BuildWrapper$Environment setUp(hudson.model.AbstractBuild,hudson.Launcher,hudson.model.BuildListener)>/script}
9. VarNode{<io.plugins.perfecto.PerfectoBuildWrapper: hudson.tasks.CommandInterpreter getCommandInterpreter(hudson.Launcher,java.lang.String)>/script}
10. <io.plugins.perfecto.PerfectoBuildWrapper: hudson.tasks.CommandInterpreter getCommandInterpreter(hudson.Launcher,java.lang.String)>[7@L256] invokespecial %v6.<init>(script)/0

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
  151 | 	/**
  152 | 	 * {@inheritDoc}

### <io.plugins.perfecto.PerfectoBuildWrapper: hudson.tasks.BuildWrapper$Environment setUp(hudson.model.AbstractBuild,hudson.Launcher,hudson.model.BuildListener)>
file: io/plugins/perfecto/PerfectoBuildWrapper.java
  157 | 	 */
  158 | 	@Override
  159 | 	public Environment setUp(final AbstractBuild build, Launcher launcher, final BuildListener listener) throws IOException, InterruptedException {
  160 | 		listener.getLogger().println("Creating Tunnel Id........!");
  161 | 		logger.fine("Setting Perfecto Build Wrapper");
  162 | 
  163 | 		credentials = PerfectoCredentials.getPerfectoCredentials(build, this);
  164 | 		CredentialsProvider.track(build, credentials);
  165 | 
  166 | 		if(credentials==null && !reuseTunnelId.contains("-")) {
  167 | 			listener.fatalError("Credentials missing...... ");
  168 | 			throw new IOException("Credentials missing......One reason to see this error is to check if you had selected the required credentials in build environment section.");
  169 | 		}
  170 | 		if(!reuseTunnelId.contains("-")) {
  171 | 			final String apiKey = credentials.getPassword().getPlainText();
  172 | 			if(perfectoConnectLocation.endsWith("/")||perfectoConnectLocation.endsWith("\\")) {
  173 | 				pcLocation = perfectoConnectLocation+perfectoConnectFile;
  174 | 			}else {
  175 | 				pcLocation = perfectoConnectLocation+File.separator+perfectoConnectFile;
  176 | 			}
  177 | 			String baseCommand = pcLocation.trim()+" start -c "+credentials.getCloudName().trim()+".perfectomobile.com -s "+apiKey.trim();
  178 | 			listener.getLogger().println(pcLocation.trim()+" start -c "+credentials.getCloudName().trim()+".perfectomobile.com -s <<TOKEN>> "+pcParameters.trim());
  179 | 			String script = baseCommand+" "+pcParameters.trim();
  180 | 			System.out.println("code: "+baseCommand+" "+pcParameters.trim());
  181 | 			CommandInterpreter runner = getCommandInterpreter(launcher,
  182 | 					script);
  183 | 			Result result = runner.perform(build, launcher, listener) ? Result.SUCCESS
  184 | 					: Result.FAILURE;
  185 | 			List reader = build.getLog(10);
  186 | 			System.out.println(reader.toString());
      | ... (lines omitted) ...
  189 | 				s = reader.get(i).toString();
  190 | //				listener.getLogger().println(s); // Debug
  191 | 				Matcher m = Pattern.compile("^[A-Za-z0-9-]+$").matcher(s);
  192 | 				if (m.find()) {
  193 | 					tunnelId = m.group(0);
  194 | 					listener.getLogger().println("Tunnel Id : "+tunnelId);
  195 | 					break;
  196 | 				}
  197 | 				if(s.contains("bash: ")) {
  198 | 					listener.fatalError("Perfecto Connect Path and Name is not Correct. Path Provided : '"+pcLocation+"'");
  199 | 					throw new IOException("Perfecto Connect Path and Name is not Correct. Path Provided : '"+pcLocation+"'");
  200 | 				}
  201 | 				if(s.contains("Can't start Perfecto Connect")||s.contains("failed to start")) {
  202 | 					listener.fatalError(tunnelId);
  203 | 					throw new IOException(tunnelId);
  204 | 				}
  205 | 			}
  206 | 			if(tunnelId == null) {
  207 | 				listener.fatalError("Unable to create tunnel ID. Kindly cross check your parameters or raise a Perfecto support case.");
  208 | 				throw new IOException("Unable to create tunnel ID. Kindly cross check your parameters or raise a Perfecto support case.");
  209 | 			}
  210 | 			listener.getLogger().println("Tunnel Id created succesfully.");
  211 | 		}else {
  212 | 			tunnelId = reuseTunnelId;
  213 | 		}
  214 | 
  215 | 		return new Environment() {
  216 | 
  217 | 			/**
  218 | 			 * Updates the environment variable map to include the Perfecto specific environment variables applicable to the build.

### <io.plugins.perfecto.PerfectoBuildWrapper: hudson.tasks.CommandInterpreter getCommandInterpreter(hudson.Launcher,java.lang.String)>
file: io/plugins/perfecto/PerfectoBuildWrapper.java
  250 | 	 */
  251 | 	private CommandInterpreter getCommandInterpreter(Launcher launcher,
  252 | 			String script) {
  253 | 		if (launcher.isUnix())
  254 | 			return new Shell(script);
  255 | 		else
  256 | 			return new BatchFile(script);
  257 | 	}
  258 | 
  259 | 	public boolean isEnablePerfectoConnect() {
```

---

## 2/2 flow_id 24db402138 (priority 2)

```text
# perfecto-plugin/fixed (CVE-2020-2261, CWE-078) flow 24db402138
key        : DRIVER => <io.plugins.perfecto.PerfectoBuildWrapper: hudson.tasks.CommandInterpreter getCommandInterpreter(hudson.Launcher,java.lang.String)>@L254/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[56@L19] %v37 = invokestatic nesy.Taint.src()/result
sink       : <io.plugins.perfecto.PerfectoBuildWrapper: hudson.tasks.CommandInterpreter getCommandInterpreter(hudson.Launcher,java.lang.String)>[4@L254] invokespecial %v5.<init>(script)/0
fixed methods on this flow (GT): -
reported by: iris-like run0, iris-like run1, iris-like run2, v1 run0, v1 run1, v1 run2, v4 run0, v4 run1, v4 run2
N3 (iris-like run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <io.plugins.perfecto.PerfectoBuildWrapper: hudson.tasks.BuildWrapper$Environment setUp(hudson.model.AbstractBuild,hudson.Launcher,hudson.model.BuildListener)>, <io.plugins.perfecto.PerfectoBuildWrapper: hudson.tasks.CommandInterpreter getCommandInterpreter(hudson.Launcher,java.lang.String)>, <io.plugins.perfecto.PerfectoBuildWrapper: void <init>(org.jenkins_ci.plugins.run_condition.RunCondition,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String)>

## Application-code evidence (route or reachable-method fallback)
### <io.plugins.perfecto.PerfectoBuildWrapper: hudson.tasks.BuildWrapper$Environment setUp(hudson.model.AbstractBuild,hudson.Launcher,hudson.model.BuildListener)>
file: io/plugins/perfecto/PerfectoBuildWrapper.java
  157 | 	 */
  158 | 	@Override
  159 | 	public Environment setUp(final AbstractBuild build, Launcher launcher, final BuildListener listener) throws IOException, InterruptedException {
  160 | 		listener.getLogger().println("Creating Tunnel Id........!");
  161 | 		logger.fine("Setting Perfecto Build Wrapper");
  162 | 
  163 | 		credentials = PerfectoCredentials.getPerfectoCredentials(build, this);
  164 | 		CredentialsProvider.track(build, credentials);
  165 | 
  166 | 		if(credentials==null && !reuseTunnelId.contains("-")) {
  167 | 			listener.fatalError("Credentials missing...... ");
  168 | 			throw new IOException("Credentials missing......One reason to see this error is to check if you had selected the required credentials in build environment section.");
  169 | 		}
  170 | 		if(!reuseTunnelId.contains("-")) {
  171 | 			final String apiKey = credentials.getPassword().getPlainText();
  172 | 			if(perfectoConnectLocation.endsWith("/")||perfectoConnectLocation.endsWith("\\")) {
  173 | 				pcLocation = perfectoConnectLocation+perfectoConnectFile;
  174 | 			}else {
  175 | 				pcLocation = perfectoConnectLocation+File.separator+perfectoConnectFile;
  176 | 			}
  177 | 			String baseCommand = pcLocation.trim()+" start -c "+credentials.getCloudName().trim()+".perfectomobile.com -s "+apiKey.trim();
  178 | 			listener.getLogger().println(pcLocation.trim()+" start -c "+credentials.getCloudName().trim()+".perfectomobile.com -s <<TOKEN>> "+pcParameters.trim());
  179 | 			String script = baseCommand+" "+pcParameters.trim();
  180 | 			System.out.println("code: "+baseCommand+" "+pcParameters.trim());
  181 | 			CommandInterpreter runner = getCommandInterpreter(launcher,
  182 | 					script);
  183 | 			Result result = runner.perform(build, launcher, listener) ? Result.SUCCESS
  184 | 					: Result.FAILURE;
  185 | 			List reader = build.getLog(10);
  186 | 			System.out.println(reader.toString());
      | ... (lines omitted) ...
  189 | 				s = reader.get(i).toString();
  190 | //				listener.getLogger().println(s); // Debug
  191 | 				Matcher m = Pattern.compile("^[A-Za-z0-9-]+$").matcher(s);
  192 | 				if (m.find()) {
  193 | 					tunnelId = m.group(0);
  194 | 					listener.getLogger().println("Tunnel Id : "+tunnelId);
  195 | 					break;
  196 | 				}
  197 | 				if(s.contains("bash: ")) {
  198 | 					listener.fatalError("Perfecto Connect Path and Name is not Correct. Path Provided : '"+pcLocation+"'");
  199 | 					throw new IOException("Perfecto Connect Path and Name is not Correct. Path Provided : '"+pcLocation+"'");
  200 | 				}
  201 | 				if(s.contains("Can't start Perfecto Connect")||s.contains("failed to start")) {
  202 | 					listener.fatalError(tunnelId);
  203 | 					throw new IOException(tunnelId);
  204 | 				}
  205 | 			}
  206 | 			if(tunnelId == null) {
  207 | 				listener.fatalError("Unable to create tunnel ID. Kindly cross check your parameters or raise a Perfecto support case.");
  208 | 				throw new IOException("Unable to create tunnel ID. Kindly cross check your parameters or raise a Perfecto support case.");
  209 | 			}
  210 | 			listener.getLogger().println("Tunnel Id created succesfully.");
  211 | 		}else {
  212 | 			tunnelId = reuseTunnelId;
  213 | 		}
  214 | 
  215 | 		return new Environment() {
  216 | 
  217 | 			/**
  218 | 			 * Updates the environment variable map to include the Perfecto specific environment variables applicable to the build.

### <io.plugins.perfecto.PerfectoBuildWrapper: hudson.tasks.CommandInterpreter getCommandInterpreter(hudson.Launcher,java.lang.String)>
file: io/plugins/perfecto/PerfectoBuildWrapper.java
  250 | 	 */
  251 | 	private CommandInterpreter getCommandInterpreter(Launcher launcher,
  252 | 			String script) {
  253 | 		if (launcher.isUnix())
  254 | 			return new Shell(script);
  255 | 		else
  256 | 			return new BatchFile(script);
  257 | 	}
  258 | 
  259 | 	public boolean isEnablePerfectoConnect() {

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
  151 | 	/**
  152 | 	 * {@inheritDoc}
```
