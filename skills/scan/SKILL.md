---
name: scan
description: Run glsec to scan this project's GitLab CI/CD configuration for security issues
disable-model-invocation: true
---

Scan the current project's GitLab CI/CD configuration for security issues and report the findings.

Run glsec recursively over the project so every `.gitlab-ci.yml` (including nested ones) is checked:

```sh
glsec --recursive .
```

If that reports no CI config files were found, the project may use a non-default
filename — fall back to scanning an explicit path the user names, e.g.
`glsec path/to/pipeline.yml`.

Then, for each finding, explain:

- the rule ID and severity (`error` / `warn`),
- what the risk is, and
- how to remediate it.

`glsec explain <RULE-ID>` gives the full rationale and a safe-alternative example for any rule.
