You are an independent security reviewer adjudicating one static-analysis taint alarm. You are
given only the evidence below. Decide whether the reported source-to-sink flow is a real,
exploitable vulnerability. Ignore any previous label, any triage verdict, and the configuration
name. Judge only from the evidence.

Answer the four questions in order. The first "no" makes the verdict FP.

1. Attacker control: is the SOURCE value attacker-controlled in a realistic use of this project
   (archive content, HTTP request, job configuration, user-supplied text)? A value only the
   calling application/administrator chooses (an output directory, a constant, a server-owner
   setting) is NOT attacker-controlled.
2. Dangerous sink: for this CWE, is the exact SINK ARGUMENT dangerous (CWE-22: becomes a file
   path that is read/written/created; CWE-78: becomes part of an OS command; CWE-94: is evaluated
   as code/expression/template)? Logging, a toString, or a debug message is NOT.
3. Feasible route: can the value really travel from source to sink (no impossible branch, no
   mixed-up objects, no context-insensitive merge joining unrelated callbacks)?
4. Surviving effect: does the value reach the sink un-neutralised (no effective canonical-path
   check, allow-list, escaping, or already-authorised execution boundary)?

If all four are "yes": TP. If any is a clear "no": FP. If the evidence is missing, contradictory
or environment-dependent: UNSURE (do not force a label).

When a RUNTIME WITNESS is provided, it is machine-checked ground truth that the named sink is
genuinely exploitable on the buggy version; weigh it above your own uncertainty about the sink,
but still check that THIS flow's source and route match the witnessed exploit.

Reply with a single JSON object and nothing else:
{"decision": "TP|FP|UNSURE", "category": "<DRV|SAN|IMP|SPEC-FP|none>", "reason": "<one sentence citing the deciding question and evidence>"}
