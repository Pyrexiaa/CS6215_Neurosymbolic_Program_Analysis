# Labelling pack: cron-utils / fixed

2 frozen sampled rows. Evidence uses the exact raw source and sink in the chosen run record. Existing labels remain unverified and are unchanged. A canonical key may still group different drivers or routes; inspect the attacker model before reusing a label. Original packets are retained in results/history/pre-evidence-refresh.tar.gz.

---

## 1/2 flow_id d06c28ee07 (priority 2)

```text
# cron-utils/fixed (CVE-2021-41269, CWE-094) flow d06c28ee07
key        : DRIVER => <com.cronutils.StringValidations: java.util.regex.Pattern buildWordsPattern(java.util.Set)>@L73/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[2@L26] taintedCronString = invokestatic nesy.Taint.src()/result
sink       : <com.cronutils.StringValidations: java.util.regex.Pattern buildWordsPattern(java.util.Set)>[10@L73] %v12 = invokestatic java.util.regex.Pattern.compile(%v11)/0
fixed methods on this flow (GT): -
reported by: iris-like run1, v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3-noV2 run0, v3-noV3 run0, v3-noval run0, v4 run0
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <com.cronutils.StringValidations: java.util.regex.Pattern buildWordsPattern(java.util.Set)>

## Application-code evidence (route or reachable-method fallback)
### <com.cronutils.StringValidations: java.util.regex.Pattern buildWordsPattern(java.util.Set)>
file: com/cronutils/StringValidations.java
   65 | 
   66 |     @VisibleForTesting
   67 |     Pattern buildWordsPattern(final Set<String> words) {
   68 |         final StringBuilder builder = new StringBuilder(ESCAPED_START);
   69 |         final Iterator<String> iterator = words.iterator();
   70 | 
   71 |         if (!iterator.hasNext()) {
   72 |             builder.append(ESCAPED_END);
   73 |             return Pattern.compile(builder.toString());
   74 |         }
   75 |         final String next = iterator.next();
   76 |         builder.append(next);
   77 |         while (iterator.hasNext()) {
   78 |             builder.append("|");
   79 |             builder.append(iterator.next());
   80 |         }
   81 |         builder.append(ESCAPED_END);
   82 |         return Pattern.compile(builder.toString());
   83 |     }
   84 | }
```

---

## 2/2 flow_id b82b6c816c (priority 2)

```text
# cron-utils/fixed (CVE-2021-41269, CWE-094) flow b82b6c816c
key        : DRIVER => <com.cronutils.StringValidations: java.util.regex.Pattern buildWordsPattern(java.util.Set)>@L82/0
source     : <nesy.NesyDriver: void main(java.lang.String[])>[2@L26] taintedCronString = invokestatic nesy.Taint.src()/result
sink       : <com.cronutils.StringValidations: java.util.regex.Pattern buildWordsPattern(java.util.Set)>[26@L82] %v21 = invokestatic java.util.regex.Pattern.compile(%v20)/0
fixed methods on this flow (GT): -
reported by: v1 run0, v1 run1, v1 run2, v2 run0, v2 run1, v2 run2, v3 run0, v3 run1, v3-noV2 run0, v3-noV2 run1, v3-noV3 run0, v3-noV3 run1, v3-noval run0, v3-noval run1, v4 run0, v4 run1
N3 (v3 run0): vulnerable / exploitable (kept=True, v3_ok=None)

## Route (taint flow graph)
(no complete application-code path in the taint flow graph; the flow passes through library code). Methods involved: <com.cronutils.StringValidations: java.util.regex.Pattern buildWordsPattern(java.util.Set)>

## Application-code evidence (route or reachable-method fallback)
### <com.cronutils.StringValidations: java.util.regex.Pattern buildWordsPattern(java.util.Set)>
file: com/cronutils/StringValidations.java
   65 | 
   66 |     @VisibleForTesting
   67 |     Pattern buildWordsPattern(final Set<String> words) {
   68 |         final StringBuilder builder = new StringBuilder(ESCAPED_START);
   69 |         final Iterator<String> iterator = words.iterator();
   70 | 
   71 |         if (!iterator.hasNext()) {
   72 |             builder.append(ESCAPED_END);
   73 |             return Pattern.compile(builder.toString());
   74 |         }
   75 |         final String next = iterator.next();
   76 |         builder.append(next);
   77 |         while (iterator.hasNext()) {
   78 |             builder.append("|");
   79 |             builder.append(iterator.next());
   80 |         }
   81 |         builder.append(ESCAPED_END);
   82 |         return Pattern.compile(builder.toString());
   83 |     }
   84 | }
```
