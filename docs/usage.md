# Using glsec

Every flag, the report formats, the exit codes and the configuration. For installing glsec see the [README](../README.md#install); for running it in CI, [CI integration](ci-integration.md).

## Command line

Flags may appear before or after file names: `glsec .gitlab-ci.yml --format json` works like `glsec --format json .gitlab-ci.yml`. The same parsing applies to `explain`, `list` and `inventory`. Use `--` to end flag parsing; for example, `glsec -- --format` scans a file literally named `--format`.

```sh
# scan a file (exits 1 on error findings, 0 if clean, 2 on parse error)
glsec .gitlab-ci.yml

# scan multiple files or a glob in one run
glsec .gitlab-ci.yml pipelines/deploy.yml
glsec pipelines/*.yml

# scan a directory: its .gitlab-ci.yml (an error names the directory when it has none)
glsec sub

# read the pipeline from stdin, e.g. the staged version in a git hook
git show :.gitlab-ci.yml | glsec --stdin-filename .gitlab-ci.yml -

# recursively scan a tree for all .gitlab-ci.yml files
glsec --recursive .

# also pick up CI configs with non-default names/paths during a recursive scan
glsec --recursive --name '*.gitlab-ci.yml' --name 'ci/pipeline.yml' .

# CI/CD Catalog component templates are detected automatically: a `spec:` header
# followed by the template body. glsec lints the body, checks the declared inputs,
# and skips whole-pipeline rules that a template fragment cannot satisfy. A root
# .gitlab-ci.yml with a `spec:` header (pipeline inputs) is still a full pipeline.
glsec templates/my-component.yml

# jobs written with `run:` (CI/CD Steps) are scanned too — every script rule and
# the ShellCheck integration read each step's `script:` the same way they read
# `script:`, `before_script:`, and `after_script:`.
glsec .gitlab-ci.yml

# aligned table view, easier to scan when there are many findings
glsec --format table .gitlab-ci.yml

# JSON output for machine consumption
glsec --format json .gitlab-ci.yml

# SARIF output for GitHub Code Scanning
glsec --format sarif .gitlab-ci.yml > gl.sarif

# JSON carries the OWASP CICD-SEC and ASVS V14 mappings per finding, SARIF also CWE.
# Each SARIF rule has a title, help with a safe alternative, CWE tags and a
# security severity, and links to its page on glsec.github.io; example workflow:
# https://github.com/glsec/example-github-code-scanning

# Code Climate output for GitLab Code Quality (merge request report on all tiers,
# inline in the diff with Ultimate)
glsec --format codeclimate .gitlab-ci.yml > gl-code-quality.json

# JUnit output for the pipeline Tests tab / MR test widget (works on all tiers)
glsec --format junit .gitlab-ci.yml > glsec-junit.xml

# GitLab SAST report for the vulnerability report and MR security widget (Ultimate)
glsec --format gitlab-sast .gitlab-ci.yml > gl-sast-report.json

# your own report layout from a Go text/template (see Report templates)
glsec --format template --template docs/templates/csv.tmpl .gitlab-ci.yml > glsec.csv

# treat warn findings as hard failures (exit 1)
glsec --strict .gitlab-ci.yml

# advisory mode: always exit 0, even with findings
glsec --no-exit-codes .gitlab-ci.yml

# skip rules for keywords your GitLab version doesn't have yet
glsec --gitlab-version 16.0 .gitlab-ci.yml

# no ANSI colours (also when NO_COLOR is set)
glsec --no-color .gitlab-ci.yml

# exclude a file or directory from scanning
glsec --exclude vendor/ .gitlab-ci.yml

# run only specific rules (comma-separated or repeated); an unknown rule ID is an error
glsec --only GL001,GL003 .gitlab-ci.yml

# skip specific rules; an unknown rule ID only warns
glsec --skip GL008,GL022 .gitlab-ci.yml

# CycloneDX BOM of the images and includes the pipeline pulls in (see Pipeline inventory)
glsec inventory .gitlab-ci.yml > pipeline.cdx.json

# list all rules (ID, severity, OWASP, description); --format json / --owasp also supported
glsec list
glsec list --owasp CICD-SEC-4

# explain a specific rule
glsec explain GL001

# baseline existing findings so only new violations are reported
glsec --generate-ignore .gitlab-ci.yml
glsec .gitlab-ci.yml  # now exits 0; new violations will be caught

# audit mode: report everything, bypassing all glsec suppressions
glsec --no-ignores .gitlab-ci.yml  # ignores inline # glsec:ignore and the .glsec-ignore baseline

# scan a repository you don't trust: its .glsec.yml and suppressions don't apply
glsec --no-repo-config --no-ignores .gitlab-ci.yml

# gate MRs on "don't make it worse": fail only on findings not in the baseline
glsec --new-only .gitlab-ci.yml                       # diff against .glsec-ignore
glsec --new-only --baseline main.json .gitlab-ci.yml  # diff against a saved JSON snapshot
```

JSON, SARIF, Code Quality, JUnit and GitLab SAST reports write file paths inside the working directory, relative or absolute, as relative paths with `/` separators, also on Windows. Paths outside that directory retain their supplied spelling; SARIF, whose locations are URIs, writes an absolute one as a `file://` URI and percent-encodes characters such as spaces. SARIF marks locations inside the working directory with `uriBaseId: "%SRCROOT%"` so code scanning can resolve them against the source root. This avoids publishing runner directory names for files inside the checkout.

A file named `-` reads the pipeline from stdin, with the same size limit as a file. `--stdin-filename` gives it a path: the one reports name, `exclude_paths` and `.glsec-ignore` entries match, and component-template detection uses; `include: local` files and child pipelines are read relative to it, from disk, so in a git hook they come from the working tree, not the index. Without `--stdin-filename` the input is named `<stdin>`, treated as a root pipeline, and its local includes are not read (glsec says so on stderr). `.glsec.yml` is looked up as usual. Stdin input never uses the result cache, and `-` can't be combined with other files or `--recursive`.

`--generate-ignore` rewrites only the entries the run could have reported: those for a file it scanned and a rule that ran. Entries for other pipeline files, and for rules left out with `--only`, `--skip` or `.glsec.yml`, stay as they are, and so do comments and an entry's `exp:` date when the finding is still there. `glsec --generate-ignore --only GL001 .gitlab-ci.yml` refreshes the GL001 entries and keeps the rest.

Flags that contradict each other aren't resolved silently. `--generate-ignore` writes a new baseline and can't be combined with `--new-only` or `--baseline`, which diff against one; `--no-ignores` reports every finding and can't be combined with them either, since they leave out the baselined ones. Both stop glsec with exit 2. Where a flag only has no effect, glsec warns and runs as it would without it: `--format` with `--generate-ignore`, which prints no report; `--strict` with `--no-exit-codes`, also when they come from `.glsec.yml`; and files or other flags with `--clear-cache`, which only empties the cache.

## Report templates

`--format template --template <file>` renders the report with a Go [`text/template`](https://pkg.go.dev/text/template) file, for formats glsec doesn't write itself: CSV for a spreadsheet, a Markdown summary for a merge request comment, a checkstyle file for another CI server. The template path is accepted on the command line only, never from `.glsec.yml`: the config file comes from the scanned repository, which must not decide what glsec writes in CI.

The template is executed with:

| Field | Content |
|---|---|
| `.Findings` | One entry per finding, with the fields of the JSON report: `.Rule`, `.Severity` (`error`, `warn`, `info`), `.Job`, `.File`, `.Line`, `.Message`, `.OWASP` and `.ASVS` (lists) |
| `.Errors` | Files glsec could not scan, with `.File` and `.Message` (see Exit codes) |
| `.Summary` | `.Error`, `.Warn` and `.Info`: the number of findings per severity; `.Files` and `.Jobs`: the number of files and jobs scanned |
| `.Version` | The glsec version |

Besides the built-in functions of `text/template`, a template can use `upper`, `lower`, `join` (`{{join .OWASP ", "}}`) and one escape per output syntax. Job names, paths and messages come from the scanned file, so pass every one of them through the escape for the format you write:

| Function | Use |
|---|---|
| `escapeCSV` | A quoted CSV field. A value starting with `=`, `+`, `-` or `@` gets a leading `'`, so a spreadsheet shows it as text instead of running it as a formula. |
| `escapeMarkdown` | Text in Markdown, also in a table cell: `\|` and other Markdown syntax are escaped, and so is HTML. |
| `markdownCode` | A complete Markdown code span, also in a table cell (a `\|` is escaped for the table). Use it for job names, paths and messages in a GitLab comment: inside a code span GitLab renders no Markdown or HTML and resolves no references, so a job named `@all` can't notify every project member and `#123` doesn't link an issue. |
| `escapeXML` | XML text or an attribute value. |

`escapeCSV`, `escapeMarkdown` and `markdownCode` also show control and bidirectional characters escaped, as the text output does, so a line break or a right-to-left override in a job name can't break a row or reorder the text.

Two examples to start from: [`docs/templates/csv.tmpl`](templates/csv.tmpl) (one row per finding) and [`docs/templates/mr-comment.md.tmpl`](templates/mr-comment.md.tmpl) (a severity summary and a table, for `glab mr note`). A template that fails to parse stops glsec before the scan; one that fails while it runs writes no partial report. Both exit 2.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No `error`-severity findings (warn-only findings exit 0 by default) |
| 1 | One or more `error` findings; or a `warn` finding when `--strict` is set (`info` findings never fail the run) |
| 2 | Usage error (including an unknown rule ID in `--only`, or `--only` and `--skip` that leave no rule), file could not be parsed, a suppression policy violation, or with `--strict`, every file excluded |

On exit 2 after the scan started, the machine-readable reports still list the findings of the files that were scanned and say which file failed and why, so a failed scan doesn't read as a clean one: an `errors` array in `json`, a `blocker` issue with check name `glsec-error` in `codeclimate`, an unsuccessful invocation with the error as a notification in `sarif`, a test case with an `<error>` in `junit`, `scan.status: failure` with a `fatal` message in `gitlab-sast`, and `.Errors` in a template. A usage or config error stops glsec before it writes a report.

glsec reads only regular files of up to 64 MB as pipelines: a FIFO, a device, a directory or a larger file is an exit 2 for the file named on the command line, and a child pipeline file like that is skipped with a warning.

Use `--strict` to treat `warn` findings as hard failures (exit 1). Use `--no-exit-codes` to always exit 0 regardless of findings (advisory/informational mode). All flags can also be set in [`.glsec.yml`](#configuration-file):

```yaml
strict: true        # warn findings cause exit 1
no-exit-codes: true # never exit 1 (overrides strict, with a warning)

# Optional container-image policies (GL065 and GL001):
allowed_registries: []       # empty permits any registry
require_image_digest: false  # true also warns on version tags without a digest

exclude_paths:
  - legacy/.gitlab-ci.yml
  - infra/old-pipelines/**
  - vendor/

recursive_patterns:    # extra CI-config names/paths for --recursive (default: .gitlab-ci.yml)
  - '*.gitlab-ci.yml'   # no "/" → matched against the basename
  - ci/pipeline.yml     # contains "/" → matched against the path relative to each scanned dir
```

If the exclusions cover every file glsec was asked to scan, it says so on stderr instead of finishing silently; with `--strict` that is an error (exit 2).

## Configuration file

glsec reads `.glsec.yml` from the working directory, or the file passed with `--config`. [`docs/glsec.example.yml`](glsec.example.yml) shows every key with an example value. An unknown key, severity or value type stops glsec with exit 2; an unknown rule ID under `rules:` only gets a warning, so a file written for a newer glsec still works with an older one.

[`schema/glsec.schema.json`](../schema/glsec.schema.json) is a JSON schema of the file, for completion and validation in editors. It is listed in the [SchemaStore](https://www.schemastore.org) catalog, so editors that use it (VS Code's YAML extension, JetBrains IDEs, Neovim with the YAML language server and SchemaStore) apply it to `.glsec.yml` on their own. For a config file with another name, or an editor without the catalog, name the schema in a comment on the first line:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/glsec/glsec/main/schema/glsec.schema.json
```

## Baseline diff (`--new-only`)

For adopting glsec on an established pipeline without drowning in pre-existing findings, `--new-only` reports — and fails — only on findings **not** in a baseline, leaving the existing backlog out of the way. It honours `--strict` and `min-severity`, so the exit code reflects new findings alone.

Two baseline sources are supported:

- **`.glsec-ignore`** (default, no flag needed) — the file written by `--generate-ignore`. Matched on `(rule, file)`, since that format carries no message.
- **`--baseline <file.json>`** — a snapshot saved from a prior `--format json` run (e.g. a scan of the target branch). Matched on `(rule, file, message)`.

Matching is **line-insensitive**: a finding that merely shifts to a different line because unrelated content moved is recognised as the same finding and stays in the baseline, rather than resurfacing as "new". Duplicates are tracked by count, so a genuinely new third occurrence of an already-baselined finding is still reported. The JSON snapshot matches more precisely (it has the message); the `.glsec-ignore` baseline is the simple, zero-setup case. In `--new-only` mode the `.glsec-ignore` line suppression is replaced by this diff; inline `# glsec:ignore` directives still apply.

Snapshot the base branch at the **same path** (the `file` field is part of the match), then fail only on what the MR adds:

```bash
git checkout origin/main -- .gitlab-ci.yml
glsec --format json .gitlab-ci.yml > base.json
git checkout HEAD -- .gitlab-ci.yml
glsec --new-only --baseline base.json .gitlab-ci.yml
```

## Suppressions

Silence a finding on a single line with an inline comment, optionally with a reason after `--`:

```yaml
build:
  image: node:latest  # glsec:ignore GL001 -- base image is pinned by the platform
```

A suppression can also carry an **expiry date**, so accepted risk gets re-reviewed instead of becoming permanent:

```yaml
deploy:
  script:
    - ./deploy.sh  # glsec:ignore GL013 exp:2026-12-01 -- accepted until the migration lands
```

Once the date has passed the suppression stops applying, the finding is reported again, and glsec notes on stderr that the suppression expired, so a finding that reappears is traceable to the date rather than looking like a new violation. The expiry date itself is inclusive. A malformed date counts as expired, so a typo surfaces the finding rather than hiding it forever.

The same token works in the `.glsec-ignore` baseline, appended to a line:

```
.gitlab-ci.yml:14 GL013 exp:2026-12-01
```

Entries without the token never expire, so existing ignore files keep working unchanged.

Suppressed findings stay visible, so a merge request that adds a suppression doesn't look like one that fixes the problem. They never fail the run:

- `text` and `table` end with a summary line: `2 findings suppressed (1 inline, 1 .glsec-ignore); run with --no-ignores to show them`.
- `sarif` lists them as results with `suppressions`: `kind` is `inSource` for an inline comment and `external` for `.glsec-ignore`, `justification` is the reason, and `properties.expires` the expiry date. Code scanning shows them as suppressed rather than open.
- `json` lists them in a separate `suppressed` array, so consumers of `findings` see what they saw before. Each entry has the fields of a finding plus `suppression`: `source` (`inline` or `ignore-file`) and, when given, `reason` and `expires`. A JSON snapshot with this array still works as `--baseline`; its suppressed entries aren't part of the baseline.
- `codeclimate`, `junit`, `gitlab-sast` and templates leave them out: these formats have no suppressed state, and an entry would count as an open issue or a failed test.

An expired suppression doesn't count: its finding is reported as before. With `--no-ignores` every finding is reported and nothing is suppressed.

To stop undocumented suppressions creeping in, require a reason:

```sh
glsec --require-ignore-reason .gitlab-ci.yml
```

```yaml
# .glsec.yml
require_ignore_reason: true
```

Any inline `# glsec:ignore` without a `-- reason` is then reported with its file and line, and glsec exits 2. Off by default, so existing suppressions keep working. The `.glsec-ignore` baseline is exempt because its format has no reason column. Note that enabling this disables the result cache: the check runs while findings are collected, so a cache hit would skip it.

## Scanning repositories you don't trust

`.glsec.yml`, `.glsec-ignore` and inline `# glsec:ignore` comments normally live in the repository being scanned. That is what you want when a project checks itself, but not when the check is meant to hold a repository to a standard it can't change: a pipeline execution or compliance policy, a central job that scans other projects, or a reviewer checking out a fork. There the repository could turn rules off, exclude files or suppress findings.

```sh
glsec --no-repo-config --no-ignores .gitlab-ci.yml
glsec --no-repo-config --no-ignores --config /policies/glsec.yml .gitlab-ci.yml  # your own settings
```

`--no-repo-config` ignores a `.glsec.yml` in the working directory (glsec says so on stderr); a file passed with `--config` is still read. `--no-ignores` drops all suppressions. Neither is needed when a project scans its own merge requests in its own pipeline, since the author can change the pipeline itself there.

With the GitLab component, set the inputs `no_repo_config: true` and `no_ignores: true` (component v1.0.25 or later). To make glsec mandatory for a group on GitLab Ultimate, run the component from a pipeline execution policy; the [component README](https://gitlab.com/glsec-io/glsec#enforcing-glsec-with-a-pipeline-execution-policy) has a tested example, including the `rules:` the job needs there to run in merge request pipelines.

## Result cache

glsec caches results in `$XDG_CACHE_HOME/glsec` (`~/.cache/glsec` by default), keyed on the glsec version, the date, the scanned files, the config and the suppressions, so an unchanged pipeline is not scanned twice on the same day. Entries from earlier days can't be hit again and are removed when glsec stores a new one. `--no-cache` skips it for one run; `--clear-cache` empties it.

In CI (`CI=true`) glsec doesn't use the cache: a job starts in a fresh container, so the cache would only help if the project kept it between pipelines with `cache:`, which takes longer than the scan and shares a file that decides what glsec reports. `--cache` turns it on for such a run anyway; `--no-cache` wins over it.

A cached result decides what glsec reports, so glsec only uses a cache directory that belongs to the current user and that nobody else can write to, reads only regular files from it, and never uses a cache that lies inside the directory of the pipeline being scanned (as with `XDG_CACHE_HOME=$CI_PROJECT_DIR/.cache`), where the repository could ship entries of its own.

## Secrets in reports

glsec masks the secret values it recognises before it writes a report, in every format, in finding messages and in the source lines of the text output: the token formats GL006 knows, the password in `scheme://user:password@host`, `Authorization: Bearer|Basic|Token …`, `PRIVATE-TOKEN:` / `JOB-TOKEN:` headers, `curl -u user:password`, `--password …`, and the value of a variable whose name ends in `_TOKEN`, `_SECRET`, `_PASSWORD`, `_KEY` and the like. A masked value keeps its length and a short prefix (`ghp_************`), so the caret under the source line still points at the right column. Variable references such as `$TOKEN` stay as they are.

The value is in the repository anyway, but a report travels further: into job logs, which are often public, Code Quality and JUnit artifacts, code scanning, and pasted bug reports. GitLab's log masking doesn't catch it, since it isn't a CI/CD variable. `--no-redact` shows the values for local debugging. It is a command-line flag only: `.glsec.yml` comes from the repository being scanned, so it can't turn masking off.

## Shell assumptions

The script-analysis rules (e.g. GL002, GL024, GL025, GL047, GL048, GL050) assume **POSIX shell** (`bash`/`sh`) semantics — the default for Linux and macOS runners. PowerShell pipelines on Windows runners use different syntax (`$env:VAR` instead of `$VAR`, `Invoke-WebRequest` instead of `curl`, etc.), so these rules will not match them. GL011 also recognises PowerShell download-and-execute (`iwr URL | iex`, `iex (irm URL)`), and GL021 recognises secret variables printed by PowerShell commands such as `Write-Host` and `Write-Output`. **A Windows-runner job that emits no findings has not been meaningfully checked for shell issues** — don't treat the absence of findings there as a clean bill of health. GL024 skips jobs whose runner tags contain `windows`, because PowerShell has no `pipefail`.

## Variables in `rules:`

Rules that check variable values read every `variables:` block GitLab can apply: top-level, `default:`, per job, and the `variables:` of each `workflow:rules` and job `rules:` entry. A value moved into a rule is committed in the file all the same, so it is reported where it is set. glsec doesn't evaluate the `if:` conditions; [GL082](rules/GL082.md) alone skips rules that only match scheduled pipelines.

## Reusable configuration

glsec resolves YAML anchors, aliases and merge keys (`&anchor` / `*alias` / `<<: *anchor`) and GitLab [`!reference` tags](https://docs.gitlab.com/ci/yaml/yaml_optimization/#reference-tags) that point within the same file. Content pulled in either way is analysed as if it were inlined into the job that uses it, so issues hidden in shared `.template` blocks are caught. A finding in an anchor that several jobs share is reported once, at the anchor. References that resolve into `include:`d files are not yet expanded.

Local files are scanned along with the pipeline that uses them: the files a top-level `include:` pulls in with `local:` (or the string shorthand), and local child pipelines, every `trigger: include:` entry that names a local file (a path, `local:`, as a list or a single entry). Both are followed recursively, with paths taken from the repository root as GitLab does. The root is the directory of the pipeline file you scan. `include: local` paths may use GitLab's wildcards (`ci/*.yml`, `ci/**.yml`); a path built from a variable or an input can't be resolved without the pipeline and is skipped, and an entry's `rules:` don't matter, since the file may be included. Remote, `artifact:`, `project:`, `template:` and `component:` includes are not fetched, and a missing file only produces a warning. A path that leads outside the root, through `..` or a symbolic link, is skipped with a warning; GitLab rejects such includes too.

GitLab merges included files into one configuration, and glsec checks each file with the others' global keywords (`workflow:`, `default:`, `variables:`, `stages:`, …) and hidden jobs around it: a job in `ci/deploy.yml` is guarded by the `workflow:rules` of `.gitlab-ci.yml`, and `workflow:` in an included file counts for the root. Findings stay in the file that has the configuration, and a check that needs a whole pipeline, such as a missing `workflow:` (GL053), is made once, on the root. A file named on the command line that an earlier pipeline already included isn't scanned a second time.
