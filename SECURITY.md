# Security Policy

## Reporting a vulnerability

Please report security issues through [GitHub private vulnerability reporting](https://github.com/glsec/glsec/security/advisories/new). Do not open a public issue for a suspected vulnerability.

You will get an initial response within 14 days. After that:

1. We confirm or rule out the issue and keep you informed while we work on it.
2. A confirmed vulnerability is fixed in a release within 90 days of the report, sooner for anything severe. If a fix needs longer, we agree a new date with you before the 90 days run out.
3. We publish the fix and a [GitHub security advisory](https://github.com/glsec/glsec/security/advisories) at the same time, request a CVE for it, and name the advisory in the release notes. You are credited in the advisory unless you would rather stay anonymous.

Please keep the issue private until the advisory is published. If we don't respond within 14 days, you may disclose it after the 90 days.

## Published vulnerabilities

Every confirmed vulnerability in glsec is published as a [security advisory](https://github.com/glsec/glsec/security/advisories) with the affected and fixed versions, and mentioned in the release notes of the fixing release. Vulnerabilities in dependencies that affect glsec are fixed in a release and named in its release notes.

| Advisory | Severity | Affected | Fixed | Summary |
|---|---|---|---|---|
| [GHSA-pfj6-q8r7-c768](https://github.com/glsec/glsec/security/advisories/GHSA-pfj6-q8r7-c768) | High | 1.2.0 – 1.21.1 | 1.22.0 | A repository's `.glsec.yml` could make glsec run a program through `shellcheck.path` |
| [GHSA-ggp8-xppq-737m](https://github.com/glsec/glsec/security/advisories/GHSA-ggp8-xppq-737m) | Medium | up to 1.21.1 | 1.22.0 | A crafted pipeline file could exhaust time or memory, inject into text output, or be read through a symbolic link |
| [GHSA-7vgh-xjjq-3wgv](https://github.com/glsec/glsec/security/advisories/GHSA-7vgh-xjjq-3wgv) | Low | 1.0.1 – 1.21.0 | 1.21.1 | Child pipeline paths outside the repository were read and quoted |

## Vulnerabilities that don't affect glsec

Scanners sometimes report a vulnerability in a dependency, the Go standard library or the base image that glsec doesn't reach. When such a report reaches users, for example through a CVE in a scanner's output for the container image, we publish an [OpenVEX](https://openvex.dev) statement saying that glsec is `not_affected`, with the justification (such as `vulnerable_code_not_in_execute_path`). The statements go into `vex/glsec.openvex.json` in this repository and are attached to the next release, so scanners such as Trivy can read them (`trivy image --vex …`). A vulnerability that does affect glsec is fixed in a release instead, as described above.

## Supported versions

Only the latest release receives security fixes. glsec is a single static binary with no runtime dependencies, so upgrading means replacing the binary or bumping the image tag.

## Trust boundary

glsec reads `.gitlab-ci.yml` files that may be written by untrusted parties, and it runs inside CI pipelines. Scanning a fork's merge request pipeline is a core use case, so attacker-authored input is expected rather than exceptional. The boundary follows from that.

### In scope

Report these privately:

- glsec crashing, hanging, or exhausting memory on a crafted input file
- glsec executing attacker-controlled content, or otherwise acting on input beyond reading and analysing it, including through a `.glsec.yml` in the scanned repository
- glsec reading or printing files outside the scanned repository
- output that escapes its report format (SARIF, JUnit, Code Climate, JSON) and injects content into a consuming system such as a security dashboard, or text output that forges or hides lines in a terminal or job log
- a vulnerability in a bundled dependency that is reachable from glsec
- anything in the release or distribution path: the published container image, release artifacts, provenance, or signatures

### Not a vulnerability

These are ordinary bugs or feature requests. Please open a normal issue instead:

- glsec not flagging an insecure pattern (a false negative). Missing rule coverage is a feature request
- glsec flagging something that is actually fine (a false positive)
- disagreement about a rule's severity or wording
- an insecure configuration that glsec correctly reports in your pipeline. That is a finding about your pipeline, not about glsec

### Properties you can rely on

These hold for the current release and are worth knowing before spending time probing:

- **No network access.** glsec makes no HTTP or TLS calls. It does not resolve `include:` targets, fetch remote templates, or contact any service.
- **No catastrophic backtracking.** Rules use Go's standard `regexp` package (RE2), which matches in linear time. Linear regular expressions alone do not bound a scan, though: the rules' own loops and the expansion of aliases and `!reference` tags have to stay bounded too, and a case where they don't is in scope.
- **No shell invocation.** The only external process is ShellCheck, and only when it is explicitly enabled. Its arguments are passed as a list with no shell involved, and the script under analysis is handed over in a temporary file rather than on a command line. Its path comes only from `--shellcheck-path` or a config file passed with `--config`, never from a `.glsec.yml` that glsec finds in the scanned directory.
- **A repository's `.glsec.yml` is not fully trusted, but it does shape the scan.** It cannot make glsec run anything, but it can turn rules off, lower severities and exclude paths. When the repository is untrusted, run glsec with `--no-repo-config` (and `--config` for your own settings) and `--no-ignores`, so neither its configuration nor its suppressions apply. See [Scanning repositories you don't trust](docs/usage.md#scanning-repositories-you-dont-trust).

## Verifying releases

Releases are signed and carry build provenance. See [Verifying a release](docs/verifying-releases.md).
