# CI integration

Running glsec in GitLab CI, GitHub Actions and MegaLinter, the reports for merge requests and the vulnerability report, the pipeline inventory, the pre-commit hook and the Claude Code plugin. The flags and report formats are described in [Using glsec](usage.md).

> **Runnable examples for every pattern below:** [gitlab.com/glsec-io/examples](https://gitlab.com/glsec-io/examples) — [Catalog component](https://gitlab.com/glsec-io/examples/component) · [Catalog + Code Quality](https://gitlab.com/glsec-io/examples/component-code-quality) · [Docker image](https://gitlab.com/glsec-io/examples/docker) · [Binary download](https://gitlab.com/glsec-io/examples/binary)

## GitLab CI Catalog component (recommended)

Use the official component from the [GitLab CI Catalog](https://gitlab.com/explore/catalog/glsec-io/glsec) — no need to manage image pins or script wiring yourself:

```yaml
include:
  - component: gitlab.com/glsec-io/glsec/glsec@v1.0.26

stages:
  - test
```

To see findings in merge requests, add the `glsec-code-quality` template. The merge request's Code Quality report works on **all GitLab tiers**; with Ultimate the findings also appear inline in the diff:

```yaml
include:
  - component: gitlab.com/glsec-io/glsec/glsec-code-quality@v1.0.26

stages:
  - test
```

Pin to an explicit component tag (not `@~latest`) — glsec's own GL003 / GL041 rules flag floating refs.

**Coloured output in CI logs:** glsec auto-disables ANSI colors when stdout is not a terminal (the standard convention). Force colors back on by setting `FORCE_COLOR=1` (or `CLICOLOR_FORCE=1`) in your pipeline variables:

```yaml
variables:
  FORCE_COLOR: "1"
```

**Component repo and full input reference:** https://gitlab.com/glsec-io/glsec

**Runnable example projects:** https://gitlab.com/glsec-io/examples

## GitLab CI — Docker image

If you need more control than the Catalog component offers, use the pre-built image from GHCR directly:

```yaml
glsec:
  stage: test
  image:
    name: ghcr.io/glsec/glsec:1.25.0
    entrypoint: [""]
  script:
    - glsec .gitlab-ci.yml
```

The `entrypoint: [""]` override is required: the image sets `ENTRYPOINT ["glsec"]` for `docker run` convenience, which conflicts with GitLab Runner's shell wrapper. Pin to a specific tag (`1.25.0`, not `:latest`) for reproducible pipelines.

## GitLab CI — binary download

For pipelines that cannot pull from GHCR:

```yaml
variables:
  GLSEC_VERSION: "1.25.0"

glsec:
  stage: test
  image: alpine:3.20
  before_script:
    - apk add --no-cache curl tar
    - curl -sSLO "https://github.com/glsec/glsec/releases/download/v${GLSEC_VERSION}/glsec_${GLSEC_VERSION}_linux_amd64.tar.gz"
    - curl -sSL "https://github.com/glsec/glsec/releases/download/v${GLSEC_VERSION}/checksums.txt" | grep "glsec_${GLSEC_VERSION}_linux_amd64.tar.gz" | sha256sum -c
    - tar xzf "glsec_${GLSEC_VERSION}_linux_amd64.tar.gz"
  script:
    - ./glsec .gitlab-ci.yml
```

## GitLab Code Quality integration

Show findings in the merge request's **Code Quality report**, on all GitLab tiers. With Ultimate they also appear inline in the diff, and Premium adds a Code Quality tab to the pipeline ([GitLab's tier overview](https://docs.gitlab.com/ci/testing/code_quality/)). The easiest path is the `glsec-code-quality` template from the [Catalog component](#gitlab-ci-catalog-component-recommended) above. The equivalent manual setup:

```yaml
glsec:
  stage: test
  image:
    name: ghcr.io/glsec/glsec:1.25.0
    entrypoint: [""]
  script:
    # exit 1 means findings, which the report shows; let exit 2 fail the job
    - glsec --format codeclimate .gitlab-ci.yml > gl-code-quality.json || [ $? -eq 1 ]
  artifacts:
    when: always
    reports:
      codequality: gl-code-quality.json
```

Severity mapping (glsec → Code Climate): `error` → `critical`, `warn` → `major`, `info` → `info`.

## GitLab vulnerability report and security widget (Ultimate)

On GitLab Ultimate, `--format gitlab-sast` (glsec 1.25.0 and later) writes a SAST report in GitLab's security report schema (version 15.2.1). Uploaded as `artifacts:reports:sast`, the findings appear in the project's **vulnerability report**, where they can be triaged, and in the merge request's **security widget**, which lists the findings the merge request adds:

```yaml
glsec-sast:
  stage: test
  image:
    name: ghcr.io/glsec/glsec:1.25.0
    entrypoint: [""]
  script:
    - glsec --format gitlab-sast --no-exit-codes .gitlab-ci.yml > gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

Each finding becomes one vulnerability:

| Report field | From glsec |
|---|---|
| name | rule ID and title, e.g. `GL001: Mutable image tag` |
| severity | `error` → High, `warn` → Medium, `info` → Low |
| identifiers | the rule ID with a link to its page (primary), the CWE, the OWASP CICD-SEC category |
| location | file and line |
| description, solution | the finding's message and job, and the link to the rule page |

Things to know:

- On Free and Premium, GitLab accepts the report but doesn't show it. Use [Code Quality](#gitlab-code-quality-integration) there; on Ultimate both can run side by side.
- GitLab matches a finding from one pipeline to the next by its file and line. A merge request that adds or removes lines above an unchanged finding shows it in the widget as fixed and as new.
- `--no-exit-codes` keeps the job green, so the report is uploaded. To fail the pipeline on findings as well, run glsec a second time without it, or use a [pipeline execution policy](https://gitlab.com/glsec-io/glsec#enforcing-glsec-with-a-pipeline-execution-policy).

## Pipeline inventory (CycloneDX)

`glsec inventory` lists what a pipeline pulls in as a [CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/) bill of materials, so SBOM tools such as Dependency-Track can track it next to your application's dependencies. It reports no findings and exits 0, or 2 when the file can't be read. With `--format jobs` it lists the jobs glsec scans instead, as JSON with name and line: the visible jobs of the pipeline, without hidden templates.

```sh
glsec inventory .gitlab-ci.yml > pipeline.cdx.json
```

| Listed | CycloneDX type | Name and version |
|---|---|---|
| `image:` of every job, through `extends:`, anchors, `default:` and a top-level `image:` | `container` | image and tag or digest, with a `pkg:docker` purl |
| `services:` | `container` | the same |
| `include: component:` | `library` | component path and version |
| `include: project:` | `library` | project and `ref:`, the files as `glsec:file` properties |
| `include: remote:` (and a URL written as a plain string) | `library` | the URL, also as a `distribution` reference |
| `include: template:` | `library` | template name |

Includes of `trigger:` jobs count too. Every component carries these properties:

- `glsec:kind`: `image`, `service`, `component`, `project`, `remote` or `template`
- `glsec:pinning`:
  - `digest`: an image digest, or `integrity:` on a remote include
  - `sha`: a full commit SHA
  - `version`: an exact version, or a tag that isn't a known moving one
  - `mutable`: for example `latest`, `17`, `main`, `~latest` or `@1.2`
  - `none`: no tag or ref
  - `unresolved`: the reference contains a CI variable or input
  - `gitlab`: a template, which moves with your GitLab version
- `glsec:job`: each job that uses an image or service
- `glsec:line`: where the reference first appears

The pipeline file is the BOM's `metadata.component`; a single `dependencies` entry links it to every component. Jobs are not components of their own, since they are not software a BOM tool could track; the image properties name them instead.

The output depends only on the pipeline: there is no timestamp, and the serial number is derived from the content, so an unchanged pipeline gives a byte-identical BOM and diffs stay clean. Upload it to Dependency-Track as a project BOM (`PUT /api/v1/bom`) or with any CycloneDX-aware tool.

Like the rest of glsec it works offline: includes are listed, not fetched, so what an include or component brings in itself is not part of the BOM. `local:` and `artifact:` includes are left out, since they come from the repository or the pipeline. There is no vulnerability data; an SBOM tool adds that from the purls.

## GitHub Actions

```yaml
- name: Run glsec
  env:
    GLSEC_VERSION: "1.25.0"
  run: |
    curl -sSLO "https://github.com/glsec/glsec/releases/download/v${GLSEC_VERSION}/glsec_${GLSEC_VERSION}_linux_amd64.tar.gz"
    tar xzf "glsec_${GLSEC_VERSION}_linux_amd64.tar.gz"
    ./glsec .gitlab-ci.yml
```

## MegaLinter

glsec ships a [MegaLinter](https://megalinter.io) plugin. Add it to `.mega-linter.yml`:

```yaml
PLUGINS:
  - https://raw.githubusercontent.com/glsec/glsec/v1.25.0/mega-linter-plugin-glsec/glsec.megalinter-descriptor.yml
```

The linter key is `GITLAB_GLSEC`. It lints files named `.gitlab-ci.yml` or `*.gitlab-ci.yml` (`.yaml` too); widen that with `GITLAB_GLSEC_FILE_NAMES_REGEX`. Extra flags go in `GITLAB_GLSEC_ARGUMENTS`, or in a `.glsec.yml` at the repository root. With `SARIF_REPORTER: true`, findings are included in MegaLinter's SARIF report.

The plugin downloads the glsec release pinned in its [descriptor](../mega-linter-plugin-glsec/glsec.megalinter-descriptor.yml) and verifies it against `checksums.txt` before installing. The descriptor decides what gets installed, so load it from a release tag as above: a tag can't change under you, and moving to a new glsec version is a one-line change you can review. Loading it from `main` instead installs whatever the descriptor on `main` says at the time of each run.

## Pre-commit hook

glsec ships a [pre-commit](https://pre-commit.com/) hook so `.gitlab-ci.yml` issues are caught before they're pushed. Add this to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/glsec/glsec
    rev: v1.25.0
    hooks:
      - id: glsec
```

Then `pre-commit install` once; the hook runs on every commit that touches a matching file. Run it across the whole tree at any time with `pre-commit run glsec --all-files`.

Three hook variants are provided — pick the one that fits how you install glsec:

| Hook id | `language` | Use when |
|---------|------------|----------|
| `glsec` | `golang` | Default — pre-commit builds glsec from source at the pinned `rev` (needs a Go toolchain; no separate install). |
| `glsec-system` | `system` | You already have a `glsec` binary on `PATH` (fastest; version is whatever is installed). |
| `glsec-docker` | `docker_image` | You'd rather not install anything but Docker — runs `ghcr.io/glsec/glsec` (pin the image version in your own config if reproducibility matters). |

By default the hook only matches files named `.gitlab-ci.yml`. To also scan custom CI-config names/paths (see `--recursive --name`), override `files:`:

```yaml
      - id: glsec
        files: '(^|/)[^/]*\.gitlab-ci\.yml$'   # also matches *.gitlab-ci.yml
```

The hook exits non-zero (failing the commit) on `error` findings or parse errors, matching glsec's normal [exit codes](usage.md#exit-codes).

## Claude Code plugin

glsec ships as a [Claude Code](https://claude.com/claude-code) plugin so Claude can scan your GitLab CI config on demand and as you edit it. Install it from glsec's own marketplace:

```
/plugin marketplace add glsec/glsec
/plugin install glsec@glsec
```

The marketplace installs the plugin from the commit of the latest release tag, not from `main`, so changes merged after a release reach you only with the next one.

This adds:

- **`/glsec:scan`** — a command that runs glsec over the project and has Claude explain and remediate each finding.
- **An edit hook** — after Claude writes or edits a `.gitlab-ci.yml` (or a `.gitlab/*.yml`) file, glsec scans it automatically and surfaces any findings.

No Go toolchain is required: the plugin bundles a small POSIX wrapper that resolves a `glsec` binary in order of preference:

1. an existing one on your `PATH`, if it is at least the version the plugin pins. Empty and relative `PATH` entries are skipped, since the hook runs inside whatever project is open;
2. a cached download;
3. the prebuilt release asset, downloaded, **verified against `checksums.txt`** and, if [cosign](https://github.com/sigstore/cosign) or an authenticated [GitHub CLI](https://cli.github.com/) with `gh attestation` is installed, **against its signed build provenance** (see [Verifying a release](verifying-releases.md)), then cached. Without either tool it says on stderr that only the checksum was checked.

Supported on **Linux and macOS** (amd64/arm64); the wrapper needs `curl` or `wget`, and the edit hook needs `jq`. On other platforms it prints an install hint instead.
