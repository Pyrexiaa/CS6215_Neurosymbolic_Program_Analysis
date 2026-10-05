# Runtime CVE witnesses

Each witness (`witness/src/*.java`) exercises a specific CVE effect with attacker-controlled input
on the already-built buggy and fixed versions. These executable checks supplement the static
results. Re-run them with `python scripts/run_witnesses.py`; score configurations with
`python scripts/score_witnesses.py`.

## 1. Tested effect on each version

| Subject | CVE (class) | Witnessed source → sink | Buggy | Fixed |
| --- | --- | --- | :--: | :--: |
| zt-zip | CVE-2018-1002201 (CWE-22 Zip Slip) | ZipEntry.getName() → new File(outputDir,name) | **exploited** | blocked |
| spark | CVE-2016-9177 (CWE-22 path traversal) | request path → ClassPathResourceHandler.getResource | **exploited** | blocked |
| cron-utils | CVE-2021-41269 (CWE-94 EL injection) | @Cron String → buildConstraintViolationWithTemplate | **exploited** | blocked |
| perfecto-plugin | CVE-2020-2261 (CWE-78 command injection) | pcParameters → Runtime.exec(bash -c) | **exploited** | blocked |

Concrete evidence recorded in `witness-results.json`:

- **zt-zip (buggy)** — file written outside extraction dir=true, content='owned'
- **zt-zip (fixed)** — file written outside extraction dir=false, content=''
- **spark (buggy)** — resource exists=true path=spark/Spark.class outsideStaticRoot=true
- **spark (fixed)** — BLOCKED by fix: spark.staticfiles.DirectoryTraversal$DirectoryTraversalDetection: classpath
- **cron-utils (buggy)** — violation message='Failed to parse '*/ * * * * 49'. Missing steps for expression: */' (contains evaluated 49=true)
- **cron-utils (fixed)** — violation message='Error parsing the Cron expression' (contains evaluated 49=false)
- **perfecto-plugin (buggy)** — injected 'touch' executed on controller=true
- **perfecto-plugin (fixed)** — getTunnelId/Runtime.exec absent; pcParameters now flows to CommandInterpreter.perform on the build agent (authorised build step, not controller RCE)

## 2. Witness-confirmed detection per configuration (buggy versions)

A configuration is *witness-confirmed* on a CVE when a reported patch-relevant flow satisfies
the sink predicate in `scripts/score_witnesses.py`. For zt-zip, this also requires the vulnerable
argument rather than the trusted output directory. Perfecto-plugin's build-log and URL flows
do not qualify. Spark's predicate credits the handler-level resource read demonstrated by its
witness. This checks the sink family; it does not execute the reported static route.
Rates are shares of the three runs; B1/B2 are deterministic. The last column gives the report's
LLM-judged confirmed-detection count for comparison.

| config | zt-zip | spark | cron-utils | perfecto-plugin | witness n/4 | LLM-judged n/4 |
| --- | :--: | :--: | :--: | :--: | :--: | :--: |
| B1 | no (0.0) | no (0.0) | no (0.0) | no (0.0) | **0/4** | 0/4 |
| B2 | yes (1.0) | yes (1.0) | yes (1.0) | yes (1.0) | **4/4** | 4/4 |
| v1 | yes (1.0) | yes (1.0) | yes (0.667) | no (0.0) | **3/4** | 3/4 |
| v2 | yes (1.0) | yes (0.667) | yes (0.667) | no (0.0) | **3/4** | 2/4 |
| v3 | yes (1.0) | yes (0.667) | no (0.0) | no (0.0) | **2/4** | 1/4 |
| v4 | yes (1.0) | yes (0.667) | yes (0.667) | yes (0.667) | **4/4** | 3/4 |
| iris-like | yes (1.0) | yes (1.0) | no (0.0) | no (0.0) | **2/4** | 2/4 |

B1 qualifies on none of the four CVEs: its single patch-overlap flag for zt-zip concerns the trusted
output directory rather than the entry name used by the witness. v3's triage drops cron-utils;
v4 and B2 qualify on all four subjects. Witness counts equal the LLM-judged counts for B1, B2,
v1 and IRIS-style, and are one higher for v2, v3 and v4. The difference is Spark. Its witness
resolves a class outside the static root through the resource handler, while the fix blocks the
same input. The original judge marked those static flows FP. The witness demonstrates this
handler-level effect, but does not establish full HTTP request dispatch or validate every sampled
route. A blocked fixed-version witness also does not establish that the whole program is safe.
