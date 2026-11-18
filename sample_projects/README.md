# Sample projects (intentionally flawed)

These three small projects exist **only** to demonstrate and test CodeSentinel. They contain deliberate
vulnerabilities, code slop and unfinished work. All credentials in them are fake (documented AWS example key,
made-up strings). **Never deploy or copy this code.**

| Project | Stack | Planted issue classes |
|---|---|---|
| `python_project` | Flask | SQL/command injection, pickle/yaml, weak hash, debug mode, empty except, TODOs, duplicates |
| `java_project` | Spring Boot | SQL concat, MD5, hard-coded password, empty catch, @RequestBody w/o @Valid, CSRF disabled |
| `javascript_project` | Express | exec injection, innerHTML, eval, path traversal, JWT decode, console.log, unused deps |

Each project also contains *safe* code (parameterised queries, abstract base classes, intentional no-ops) so the
scanner's false-positive handling can be observed.
