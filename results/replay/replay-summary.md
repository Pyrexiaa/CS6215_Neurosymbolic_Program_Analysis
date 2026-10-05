# B1/B2 baseline replay vs archived records

Independent re-execution of the symbolic baselines (B1, B2) on the four subjects, buggy and
fixed, in a clean environment (JDK 17 + the recorded Zulu JDK 8 `rt.jar` + Tai-e 0.5.4, subject
classpaths from the saved `*.layout.json`). No LLM calls. Produced by re-running
`python -m nesy run <subject> --configs B1,B2` and comparing flow records.

**Result: all 16 records reproduced exactly** — identical raw counts, reported-flow
counts, patch-relevant counts, detection flags and reported flow-key sets.

| subject | version | config | raw (arch=replay) | reported | patch-rel | detected | flow keys |
| --- | --- | --- | ---: | ---: | ---: | :--: | :--: |
| cron-utils | buggy | B1 | 0 | 0 | 0 | False | identical |
| cron-utils | buggy | B2 | 31 | 1 | 1 | True | identical |
| cron-utils | fixed | B1 | 0 | 0 | 0 | False | identical |
| cron-utils | fixed | B2 | 0 | 0 | 0 | False | identical |
| perfecto-plugin | buggy | B1 | 0 | 0 | 0 | False | identical |
| perfecto-plugin | buggy | B2 | 12 | 2 | 2 | True | identical |
| perfecto-plugin | fixed | B1 | 0 | 0 | 0 | False | identical |
| perfecto-plugin | fixed | B2 | 0 | 0 | 0 | False | identical |
| spark | buggy | B1 | 15610 | 489 | 0 | False | identical |
| spark | buggy | B2 | 24396 | 974 | 11 | True | identical |
| spark | fixed | B1 | 15726 | 498 | 0 | False | identical |
| spark | fixed | B2 | 24574 | 991 | 11 | True | identical |
| zt-zip | buggy | B1 | 7416 | 7 | 2 | True | identical |
| zt-zip | buggy | B2 | 20602 | 534 | 114 | True | identical |
| zt-zip | fixed | B1 | 7980 | 7 | 2 | True | identical |
| zt-zip | fixed | B2 | 21634 | 534 | 114 | True | identical |
