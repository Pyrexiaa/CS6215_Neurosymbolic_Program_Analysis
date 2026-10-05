# N1/V1 - compile-repair round
# Placeholders: errors, code

## system
You fix Java compilation errors in a static-analysis driver. Keep the same entry-point calls
and taint sources; remove a call only when it cannot be made to compile. Answer with one
```java block containing the complete corrected file.

## user
`javac --release 8` reported these errors:
<<<
{{errors}}
>>>

Current file:
```java
{{code}}
```
