# Roadmap

This is where glsec is heading over the next 12 months (until October 2027). It is a direction, not a promise: priorities change with what users report. Work is tracked in [issues](https://github.com/glsec/glsec/issues); anything here without an issue yet gets one before it is started.

## Planned

**Rules**

- Keep the rule set current with GitLab: new keywords and features as GitLab releases them, and new rules where real pipelines show a pattern that leads to a vulnerability. New rules are checked against over 1,000 real pipelines for false positives before a release.
- Pinning checks for `run:` function and step references once GitLab Functions leaves the experiment stage (#470).

**Analysis**

- Finish `extends:` and `default:` inheritance: most rules that read inherited keys follow `extends:` within a file and `default:` today; still missing are `default:` in the deep merge of `extends:`, GL001, and templates that come from another included file, so findings and suppressions follow what GitLab actually runs.

**Usability**

- `--fix` for findings with a mechanical, safe fix, such as pinning an image to a digest.
- Custom rules written in a simple YAML format, with a command to test them against example files.

**Project**

- Signed release tags, in addition to the signed release artifacts.

## Not planned

glsec stays an offline, static analyser of pipeline files. These are deliberately out of scope:

- Calling the GitLab API, for example to check project settings, protected branches or CI/CD variables.
- Fetching remote, project, template or component includes over the network.
- Scanning container images or dependencies for known vulnerabilities; tools such as Trivy or OSV-Scanner do that.

Suggestions are welcome as [issues](https://github.com/glsec/glsec/issues/new/choose).
