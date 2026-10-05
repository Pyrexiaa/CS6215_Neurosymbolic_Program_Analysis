# Design

The study evaluates LLM assistance at three interfaces around Tai-e's taint analysis:

* **where execution starts** (entry points; N1),
* **which library methods matter** (taint specifications; N2),
* **which reported flows are real** (triage; N3).

Tai-e performs all propagation. Validators V1, V2 and V3 check the driver, specifications and triage decisions, but passing these checks does not establish security correctness. Invalid specifications are dropped; compilation or basic driver-check failures trigger a template fallback; invalid removal judgments keep the alarm. The V2/V3 ablations retain V1. The final design, NESY-TAINT (v4), adds entry checks, array-element sinks and trusted-sink protection to v3. These rules were developed on the evaluation subjects, not a held-out set.

## 1. Pipeline

| Stage | Kind | Input | Output | Code |
| --- | --- | --- | --- | --- |
| S1 fact extraction | symbolic | compiled classes, dependency jars, JDK 8 `rt.jar`, sources | app methods + line ranges, direct external calls after filtering common Object-method names (resolved to the declaring class), ranked entry candidates | `classfile.py`, `facts.py` |
| Template driver | symbolic | entry candidates | `nesy.NesyDriver.main` calling up to 300 entries with taint-API values for supported String/stream/file parameter types, over-approximating attacker control | `driver.py` |
| N1 driver synthesis | LLM | top 60 candidates, README excerpt, CWE | proposed driver intended to call *attacker-reachable* entries and taint attacker-controlled parameters; this intent may be wrong | `driver.py`, `prompts/n1_driver.md` |
| V1 | symbolic | N1 code | compiles with `javac --release 8` (≤3 LLM repair rounds with compiler errors); bytecode check that the driver calls app code and the taint API; compilation or basic-call failure triggers template fallback; v4 adds bytecode overload/declared-entry checks and a source-pattern receiver heuristic. A compiling driver can remain after a final entry-check warning, recorded in `entry_mismatches` | `driver.py` |
| N2 spec inference | LLM | external APIs in batches of 25, with real call-site lines; APIs already configured as sinks are shown with their configured index | labels: source / sink / transfer / sanitizer with index refs | `spec.py`, `prompts/n2_spec.md` |
| V2 | symbolic | N2 labels | labels refer to a batch id (grounded) or to a signature that must exist (class index / `javap`); ordinary/array index refs must exist and have a reference type; field existence/types are not checked (no accepted study label uses field refs); majority vote over 3 distinct sample positions, with duplicate proposals contributing at most once per position | `spec.py` |
| S2 propagation | symbolic | driver + layered taint config | Tai-e 0.5.4 pointer analysis (`cs: 1-call`) + taint analysis; flows + taint flow graph | `taie.py` |
| Flow filtering | symbolic | raw flows | drops JDK-internal endpoints and sinks inside the generated driver; merges flows with the same source, sink site and argument | `taie.py` |
| N3 triage | LLM | up to 200 flows per run; each receives a shortest available TFG route or reachable-method fallback across library gaps, plus bounded numbered snippets from up to six application methods | verdict + reason + cited lines | `triage.py`, `prompts/n3_triage.md` |
| V3 | symbolic | N3 answer | a `not_vulnerable` verdict may remove the flow only with valid citations to numbered lines actually shown in the evidence; omitted snippet gaps do not count. This checks evidence membership, not feasibility or the truth of the reason. Invalid or uncertain removals keep the flow. v4 also protects trusted sink signatures from dismissal as harmless | `triage.py` |

Spec layers are assembled into one Tai-e config directory per run (`work/runs/.../configs/<config>/run<k>/taint-config/`):

* `base/`: Tai-e's commonly-used sources, the CWE's sinks, and the string transfers.
* `driver-sources.yml`
* `manual/` (B2 only)
* `llm-inferred.yml` (v1–v4, their validator ablations and `iris-like`).
* `llm-array-elements.yml` (v4): an accepted sink on array argument `N` also produces a sink on its elements, `N[*]`.
* `taie-options.yml` enables call-site mode. For subjects using `only_app`, `only-app-chain-transfers.yml` preserves string-builder chaining.

If an N1 answer reaches the token limit without a Java code block, the driver builder retries once with twice the token budget. Compilation repair and template fallback still apply.

The trusted-sink rule blocks a `not_dangerous_sink` removal when the sink method is in the curated base specification or received unanimous N2 votes. It matches method signatures, not argument indexes. Other triage reasons can still remove the flow. N3's 200-flow limit is a review cap; excess flows remain reported without triage.

## 2. Design rationale and lineage

The components adapt established ideas to a common Tai-e pipeline, allowing comparison of specification inference, driver generation, triage and validation. The related-work citations are in `report/main_revised2.tex`.

| Component | Baseline limitation it targets | Closest prior work | What is different here |
| --- | --- | --- | --- |
| N1 + V1 | Libraries, plugins and framework applications need entry-point modelling before whole-program analysis | FlowDroid dummy main; JackEE rules; LLM fuzz-driver generation (ISSTA'24; compile feedback + retries) | An LLM writes the *static-analysis* driver; compile-repair loop; bytecode check; symbolic fallback |
| N2 + V2 | Base config misses library-specific sources/sinks (e.g. `File(File,String)` is a sink only on arg 0 in the commonly-used config) | SuSi, Seldon (non-LLM spec inference); IRIS (ICLR'25, LLM specs for CodeQL) | Targets Tai-e's index-ref format incl. transfers; labels grounded by batch id; V2 type/arity/existence checks; self-consistency voting; known sinks re-offered with their configured index |
| N3 + V3 | Over-approximation causes false alarms | IRIS contextual analysis; LLift (OOPSLA'24); LLM4PFA; Wen et al. 2024 | Tai-e's own TFG route is the evidence; V3 rejects citations outside the shown evidence (idea from LLMSAN) |
| Validators | LLM hallucination | LLMDFA / NESA principle: parsers for syntax, LLM for semantics | Applied to all three LLM outputs; `v3-noV2`, `v3-noV3` and `v3-noval` isolate V2/V3 policy changes while retaining V1 |

**Implemented but not evaluated:** `spec.mode: demand` restricts API candidates to methods represented in a successful preliminary B1 taint flow graph. It requires that saved B1 run and graph. The released study uses `mode: full`; there are no demand-mode comparison results.

## 3. Shared baseline configuration

The following settings apply to every configuration. Their values are recorded in `config/experiment.yaml` and `config/subjects.yaml`.

### 3.1 `taie.cs: 1-call`

Every configuration uses one-call-site context sensitivity (`1-call`). Separating call contexts limits taint merging through shared `StringBuilder` return values. The setting is fixed across subjects and configurations. Perfecto-plugin uses application-only analysis with chaining transfers to fit the resource budget (Section 3.3).

### 3.2 Excluding `getChars(int,int,char[],int)` transfers

The base configuration excludes three `getChars` transfers to prevent taint from spreading through shared JDK buffers:

1. `<String: void getChars(int,int,char[],int)>` (base → arg 2) taints the *internal* `char[]` of every `StringBuilder`, because the JDK itself calls it inside `append`.
2. `String(char[],...)` then taints every `toString()` result.

`config/cwe.yaml → common.exclude_lines` drops these 3 entries when the base config is assembled. B1 is therefore a configured Tai-e baseline, not an unmodified default configuration.

### 3.3 Call-site mode and driver compilation

* Tai-e's taint **call-site mode** is on for every configuration (`taie.call_site_mode`). Sources and sinks declared on library interfaces without an implementation in the analysed program would otherwise never match.
* Drivers are compiled with `-proc:none`, so annotation processors on a subject's class path (e.g. Lombok) cannot break compilation.

Large subjects can be analysed without library bodies (`taie: {only_app: true}` per subject). Chaining transfers for `StringBuilder`/`StringBuffer` are then added automatically; this is used for perfecto-plugin.

### 3.4 Template driver

The template driver is the same for B1, B2, v1 and `iris-like`. It passes taint to every String/stream/file parameter of the ranked public API, which deliberately over-approximates attacker control. It creates one receiver object per class (constructor arguments tainted), calls its setters first and then its other public methods on that same object, so taint stored in fields by a constructor or setter reaches later methods. For example, it taints the *destination directory* of `ZipUtil.unpack`.

When the driver taints an input that the attacker cannot control, the resulting false alarm belongs to the `DRV` category. The zt-zip output-directory argument is one such case. N1 aims to improve the attacker model, but its judgments can also be wrong.

### 3.5 Flow identity

Tai-e reports one flow per (source call site, sink call site). Driver call sites are collapsed into `DRIVER`, so a flow key is `source => sink-method@line/index`. This supports alarm-set comparison across drivers and configurations, but the same key can stand for different tainted entry arguments or routes. A reused TP/FP label assumes the attacker model and security meaning are shared; one representative evidence route does not prove that assumption.

## 4. Caching and reproducibility

* Transport-backed LLM response keys include the requested model, a SHA-256 endpoint hash, `extra_body`, rendered messages, temperature, token limit and sample index. Credentials and the plaintext endpoint are not stored in the cache identity. Reusing a matching cached response avoids a fresh API request; changed inputs or missing answers may require new requests.
* Legacy raw answers are retained but are not silently reused under the stronger key. Reuse requires explicitly registering verified original endpoint/model/request-body provenance and an allowed served-model list. Matching legacy hits are lazily promoted to the new key. This is a one-time provenance attestation, not permission to bless arbitrary old outputs. Mock/offline clients retain their historical key behavior and do not make API requests.
* Template, N1 and N2 stage sidecars fingerprint settings, extracted facts, source/build/dependency/JRE content, relevant implementation modules, model/transport identity, and prompt/version dependencies. N1 includes repair prompts/settings and fallback versions; N2 includes voting versions and the base configuration. Missing or mismatching identities cause reconstruction. Legacy stage metadata requires explicit verified adoption; matching template fallbacks can then be reused without discarding the original driver history.
* The Tai-e cache also fingerprints subject bytecode, dependencies, JRE and analyzer JAR, as well as driver/configuration inputs. Changing these invalidates propagation reuse. A new symbolic cache key can require a Tai-e rerun while still reusing validated LLM responses.
* Run `k` uses run-derived sample indexes. Nonzero-temperature calls send a derived seed; temperature-0 calls send no API seed. These are reproducible request definitions and run-indexed repetitions, not a guarantee of independent draws or bit-identical fresh hosted answers. Sharing cached stages between configurations makes ablations paired by design.
* A hosted `default` alias can change its served model without changing the requested alias. Cache identity cannot detect an unannounced remote model revision. Record the served models and pin an explicit model identifier when the service supports it. Run records preserve model/served-model information, prompt hashes and Tai-e settings.
* `response_latency_s` records the original model generation time on fresh and cached replies; `latency_s` records only fresh-request time. Older usage files lack `response_latency_s` and require explicit provenance-aware reconciliation before mixing cost totals. Cache replay is cheaper to execute than the original analysis; do not present replay wall time as first-execution cost.

Matching inputs and available archived answers support replay. The released `results/raw/llm-responses.tar.gz` contains the 5,009 original and correction response JSONs for inspection; these historical keys are not automatically trusted by the stronger transport cache. `results/provenance/` records the correction and cost accounting. Fresh endpoint calls, changed dependencies or changed model aliases can produce different results.

## 5. Known limitations

* **Detection evidence.** Patch-method overlap may credit flows unrelated to the CVE. `confirmed_detected_rate` is a separate check using provisional LLM labels. Runtime witnesses demonstrate the four CVE effects, and witness scoring checks patch-relevant alarms against subject-specific sink predicates; it does not validate every static route. Corrected label precision uses the frozen probability sample (`docs/precision-estimation.md`).
* **Fixed versions.** The fixed version is the last fix commit, except for cron-utils (backported fix, because the upstream fix also moved to Java 16) and perfecto-plugin (the next commit, because the fix commit does not compile). See `config/subjects.yaml`.
* **Data leakage and version contrast.** The model may have seen these public CVEs. Independently inferred buggy/fixed drivers and specifications confound the observed alarm differential. The completed frozen-input extension in `results/extensions/controlled-pair/` provides a narrower pre-triage comparison; perfecto-plugin still has a dependency-change confound. v4 was developed on these same subjects, so its improvement is not a held-out estimate.
* **Labels and curated specifications.** The original flow labels came from one LLM judge without human verification and with access to available triage verdicts. Shared rules can introduce correlated judgments. B2 is a curated specification whose preparation and limitations are documented in the report. `docs/evaluation.md` separates original labels, witness checks and the later adjudication pass.
* **The mock LLM.** `nesy/mock.py` exists only for tests and dry runs. Mock results are not study evidence.
