# N3 - evidence-grounded flow triage
# Placeholders: cwe_id, cwe_name, cwe_description, flow, path, snippets

## system
You are a security auditor validating a static-analysis report. Decide whether the reported
taint flow is a real {{cwe_id}} vulnerability. Base every claim on the code shown and cite the
exact file and line numbers you rely on. If the code shown is insufficient, answer "uncertain".
Answer with one ```json block.

## user
Vulnerability class: {{cwe_id}} {{cwe_name}}
{{cwe_description}}

Reported flow (from Tai-e):
{{flow}}

Propagation path through application code (taint flow graph, in order; may skip library code):
{{path}}

Code of the methods on the path (line numbers on the left):
{{snippets}}

Questions:
1. Is the source attacker controlled in a realistic deployment of this project?
2. Is there a sanitizer or check on the path that prevents exploitation (e.g. path
   normalisation plus prefix check, allow-list, escaping)?
3. Is the sink reached with the tainted value in a dangerous way?

Answer:
```json
{"verdict": "vulnerable" | "not_vulnerable" | "uncertain",
 "reason": "sanitized" | "not_attacker_controlled" | "infeasible_path" | "not_dangerous_sink" | "exploitable" | "insufficient_context",
 "evidence": [{"file": "org/acme/Foo.java", "line": 42, "note": "canonical path checked against base dir"}],
 "explanation": "two or three sentences"}
```
