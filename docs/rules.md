# glsec Rules

Rules are grouped by [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/). Each rule links to its full documentation with risk description, trigger examples, and safe alternatives.

---

## Credential Hygiene — [CICD-SEC-6](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-06-Insufficient-Credential-Hygiene)

Secrets hardcoded, leaked through logs, or forwarded to unintended consumers.

| ID | Severity | Description |
|----|----------|-------------|
| [GL005](rules/GL005.md) | `warn`  | Sensitive file patterns in `artifacts:` paths |
| [GL027](rules/GL027.md) | `warn`  | Secret-like variable defined without `masked: true` |
| [GL004](rules/GL004.md) | `warn`  | `CI_JOB_TOKEN` forwarded to a non-GitLab host |
| [GL006](rules/GL006.md) | `error` | Hardcoded secret in `variables:` block |
| [GL036](rules/GL036.md) | `warn`  | Connection string with embedded credentials (`scheme://user:pass@host`) in `variables:` block |
| [GL010](rules/GL010.md) | `warn`  | `trigger: forward: pipeline_variables: true` leaks secrets to downstream pipeline (GitLab ≥ 14.9) |
| [GL037](rules/GL037.md) | `warn`  | `trigger:` job without `inherit: variables: false` — top-level secrets implicitly forwarded to downstream |
| [GL014](rules/GL014.md) | `warn`  | `dotenv` artifact captures all environment variables including secrets (GitLab ≥ 12.9) |
| [GL018](rules/GL018.md) | `warn`  | Secret variable re-exported at pipeline level — available to all jobs including untrusted ones |
| [GL021](rules/GL021.md) | `warn`  | Secret variable value printed to job log via `echo`/`printf` |
| [GL032](rules/GL032.md) | `warn`  | SSH private key written to file via `echo` — key appears in job logs when debug tracing is active |
| [GL033](rules/GL033.md) | `error` | `CI_DEBUG_TRACE: "true"` committed — shell tracing dumps all variable values including secrets to job logs |
| [GL029](rules/GL029.md) | `warn`  | `docker login -p` exposes password in process table — use `--password-stdin` instead |
| [GL035](rules/GL035.md) | `warn`  | `git` command uses URL with embedded credentials (`user:token@host`) — token appears in job logs |
| [GL038](rules/GL038.md) | `error` | Hardcoded credential literal passed to CLI tool in script (`sqlcmd -P`, `mysql -p`, `PGPASSWORD=`, etc.) |
| [GL040](rules/GL040.md) | `warn`  | Script uses plain `ftp://` — credentials and content transmitted unencrypted |

---

## Dependency & Image Pinning — [CICD-SEC-3](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse)

Mutable references that allow silent substitution of images, templates, or packages.

| ID | Severity | Description |
|----|----------|-------------|
| [GL001](rules/GL001.md) | `error` | Mutable image tag (`latest`, no tag, non-digest pin) |
| [GL003](rules/GL003.md) | `error` | Remote `include:` with mutable or missing `ref` |
| [GL011](rules/GL011.md) | `error` | Download-and-execute pattern in script (`curl \| bash`, `wget \| sh`) |
| [GL016](rules/GL016.md) | varies  | HTTP instead of HTTPS (`include:remote`, scripts, variables) |
| [GL022](rules/GL022.md) | `warn`  | Package manager install without version pin or explicit update-to-latest in CI |
| [GL023](rules/GL023.md) | `warn`  | Lockfile not enforced (`npm install` instead of `npm ci`, `yarn install` without `--frozen-lockfile`, etc.) |
| [GL026](rules/GL026.md) | `warn`  | `git clone`/`checkout` uses a mutable ref (branch or tag) instead of a pinned commit SHA |

---

## Poisoned Pipeline Execution — [CICD-SEC-4](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution) / [CICD-SEC-8](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-08-Ungoverned-Usage-of-3rd-Party-Services)

User-controlled inputs and unversioned component references that allow malicious code to run inside the pipeline.

| ID | Severity | Description |
|----|----------|-------------|
| [GL002](rules/GL002.md) | `warn`  | User-controlled CI variable used unquoted in script |
| [GL007](rules/GL007.md) | `error` | CI variable interpolation in `image:` reference |
| [GL015](rules/GL015.md) | `warn`  | Docker image tag built from user-controlled variable (`$CI_COMMIT_REF_SLUG` etc.) |
| [GL025](rules/GL025.md) | `warn`  | `curl`/`wget` uses a user-controlled CI variable — attacker can redirect the request to an arbitrary host |
| [GL041](rules/GL041.md) | `warn`  | `include: component:` without a pinned semver tag or commit SHA |
| [GL044](rules/GL044.md) | `warn`  | MR-triggered job checks out `$CI_MERGE_REQUEST_SOURCE_BRANCH_SHA` — executes attacker-controlled code with `$CI_JOB_TOKEN` access |

---

## Supply Chain Integrity — [CICD-SEC-9](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation)

Downloads and executions that bypass integrity checks, enabling tampering mid-pipeline.

| ID | Severity | Description |
|----|----------|-------------|
| [GL020](rules/GL020.md) | `warn`  | File downloaded with `curl`/`wget` without checksum verification before execution |

---

## Pipeline Flow & Access Control — [CICD-SEC-1](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-01-Insufficient-Flow-Control-Mechanisms) / [CICD-SEC-5](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-05-Insufficient-PBAC)

Gates bypassed, runners untrusted, or downstream pipelines outside access control.

| ID | Severity | Description |
|----|----------|-------------|
| [GL008](rules/GL008.md) | `warn`  | `allow_failure: true` on a GitLab security scan job |
| [GL012](rules/GL012.md) | `warn`  | `when: always` on a deploy/release job bypasses upstream quality gates |
| [GL013](rules/GL013.md) | `warn`  | Production deploy job has no `rules:` or `only:` branch restriction |
| [GL019](rules/GL019.md) | `warn`  | Deploy/publish job has no `resource_group:` — concurrent runs risk race conditions or partial deploys |
| [GL034](rules/GL034.md) | `warn`  | `trigger:` job without `strategy: depend` — child pipeline failures are silently ignored |
| [GL039](rules/GL039.md) | `warn`  | Security audit tool silenced with `\|\| true` — failures discarded, pipeline always green |
| [GL009](rules/GL009.md) | `warn`  | Overly broad OIDC `id_tokens` audience (GitLab ≥ 15.7) |
| [GL017](rules/GL017.md) | `warn`  | Deploy/publish job has no `tags:` — can run on any runner including untrusted self-hosted |
| [GL043](rules/GL043.md) | `warn`  | Unanchored regex on user-controlled variable in `rules:if` — prefix match can be bypassed by crafting a matching value |

---

## Insecure Configuration — [CICD-SEC-7](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-07-Insecure-System-Configuration)

Misconfigured CI settings that expand the attack surface or leak build context.

| ID | Severity | Description |
|----|----------|-------------|
| [GL024](rules/GL024.md) | `warn`  | Shell pipe without `set -o pipefail` — failures in all but the last command are silently ignored |
| [GL028](rules/GL028.md) | `warn`  | `artifacts: untracked: true` without `paths:` or `exclude:` may archive `.env`, keys, and other sensitive files |
| [GL030](rules/GL030.md) | `warn`  | `ssh-keyscan` at runtime blindly trusts the remote host key — MITM risk on shared runner networks |
| [GL031](rules/GL031.md) | `error` | `DOCKER_TLS_CERTDIR: ""` disables Docker daemon TLS — exposes port 2375 unauthenticated on the runner network |
| [GL042](rules/GL042.md) | `warn`  | TLS certificate verification disabled (`curl -k`, `wget --no-check-certificate`, `GIT_SSL_NO_VERIFY`, etc.) |
