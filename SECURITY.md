# Security Policy

## Reporting a vulnerability

Please report security issues through [GitHub private vulnerability reporting](https://github.com/glsec/glsec/security/advisories/new). Do not open a public issue for a suspected vulnerability.

If the report is confirmed we will agree a disclosure timeline with you, and credit you in the advisory unless you would rather stay anonymous.

## Supported versions

Only the latest release receives security fixes. glsec is a single static binary with no runtime dependencies, so upgrading means replacing the binary or bumping the image tag.

## Trust boundary

glsec reads `.gitlab-ci.yml` files that may be written by untrusted parties, and it runs inside CI pipelines. Scanning a fork's merge request pipeline is a core use case, so attacker-authored input is expected rather than exceptional. The boundary follows from that.

### In scope

Report these privately:

- glsec crashing, hanging, or exhausting memory on a crafted input file
- glsec executing attacker-controlled content, or otherwise acting on input beyond reading and analysing it
- output that escapes its report format (SARIF, JUnit, Code Climate, JSON) and injects content into a consuming system such as a security dashboard
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
- **No catastrophic backtracking.** Rules use Go's standard `regexp` package (RE2), which matches in linear time, so a crafted script line cannot make matching blow up.
- **No shell invocation.** The only external process is ShellCheck, and only when it is explicitly enabled. Its arguments are passed as a list with no shell involved, and the script under analysis is handed over in a temporary file rather than on a command line.

## Verifying releases

Releases are signed and carry build provenance. See [Verifying a release](README.md#verifying-a-release).
