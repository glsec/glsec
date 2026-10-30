# ShellCheck integration

glsec can optionally pass `script:`, `before_script:`, and `after_script:` blocks to [ShellCheck](https://www.shellcheck.net/) for deeper shell analysis. This is **opt-in** and requires ShellCheck to be installed separately.

Enable it in `.glsec.yml`:

```yaml
shellcheck:
  enabled: true
```

glsec runs `shellcheck` from `PATH`. To use another binary, pass `--shellcheck-path /opt/bin/shellcheck`. A `path:` under `shellcheck:` is honoured only in a config file given with `--config`; in a `.glsec.yml` that glsec picks up from the working directory it is ignored with a warning, because that file usually comes from the repository being scanned, and a merge request could otherwise point it at a program of its own.

ShellCheck findings are reported alongside GL findings and use `SC` rule IDs:

```
WARN   .gitlab-ci.yml:12  SC2086  [build]  Double quote to prevent globbing and word splitting.
```

If the ShellCheck binary is not found, glsec prints a warning to stderr and continues scanning normally. A ShellCheck that is there but fails (an exit code above 1, or output that isn't its JSON) or takes longer than 30 seconds for one job stops the scan with exit 2, with the job and ShellCheck's error message: ShellCheck was turned on, so a run without its findings must not pass as clean.

**Suppressing specific codes** — inline:

```yaml
  script:
    - echo $CI_COMMIT_REF_NAME  # glsec:ignore SC2086 -- set by platform
```

Or globally in `.glsec.yml`:

```yaml
rules:
  SC2086: off
```

ShellCheck's own inline directives (`# shellcheck disable=SC2086`) are also respected. `--no-ignores` bypasses glsec's suppressions (inline `# glsec:ignore` and the `.glsec-ignore` baseline) but **not** ShellCheck's native `# shellcheck disable=` directives, which are handled inside ShellCheck itself.
