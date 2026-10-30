# Governance

glsec has two maintainers. This document says who decides what, who can reach the project's sensitive resources, and how that changes when more people join.

## Roles

**Maintainer.** Decides what goes into glsec and when it is released. A maintainer:

- reviews and merges pull requests into `main`;
- triages issues and answers reports of false positives, false negatives and bugs;
- handles vulnerability reports as described in [SECURITY.md](SECURITY.md), including advisories and fixes;
- cuts releases as described in [RELEASING.md](RELEASING.md): tag, release notes, the PyPI upload, the Claude Code plugin pin and the GitLab CI/CD Catalog component;
- keeps the project's security settings in place: branch protection, required checks, two-factor authentication, signed releases.

**Contributor.** Anyone who opens an issue or a pull request. Contributors don't need any access; how to contribute is in [CONTRIBUTING.md](CONTRIBUTING.md).

Decisions are made by the maintainers, in the open: in issues and pull requests on GitHub.

## Members with access to sensitive resources

| Person | Access |
|---|---|
| Nicolai Ehrhardt ([@predictor2718](https://github.com/predictor2718)) | Owner of the GitHub organization `glsec`: repository admin, branch protection, releases, GitHub Actions settings, the container image on `ghcr.io/glsec/glsec`, security advisories. Owner of the GitLab group `glsec-io`: the CI/CD Catalog component, the example repositories and the CI Lint project `cli-lint`. Owner of the PyPI project `glsec` and the only reviewer of the `pypi` deployment environment. Account owner for Codecov and the OpenSSF Best Practices entry. |
| [@luma434](https://github.com/luma434) | Owner of the GitHub organization `glsec`, with the same GitHub access as above. |

Nobody else has write access to any of these. The GitHub organization requires two-factor authentication for all members and allows only secure methods: an authenticator app (TOTP), a security key or passkey, or GitHub Mobile. SMS is not accepted.

## Secrets and credentials

glsec is built so that there are as few secrets as possible:

- **One stored secret in CI.** The GitHub workflows use the `GITHUB_TOKEN` that GitHub issues per run, with the least permissions each job needs, and OIDC tokens for Sigstore, Codecov and PyPI; all of them expire when the run ends. The one stored secret is `GITLAB_LINT_TOKEN`, which the job that checks fixtures and doc examples with GitLab's CI Lint API uses: a fine-grained GitLab token limited to the `glsec-io/cli-lint` project with only the permissions "CI Config: Validate" and "Metadata: Read". GitHub doesn't pass it to workflows of pull requests from forks. The GitLab projects store no CI/CD variables.
- **No signing keys.** Releases are signed keylessly: GitHub Actions obtains a short-lived certificate from Sigstore for each run, so there is no key to hold, rotate or hand over.
- **Personal tokens.** The maintainer's GitLab access tokens, used to release the CI/CD Catalog component, are created for a task with the narrowest scope and an expiry of at most 30 days, kept only on the maintainer's machine with owner-only file permissions, and revoked when the task is done. They are never put in a repository, an issue or a CI variable; the CI Lint token above is the one exception, and it can only validate CI configuration.
- **Accounts.** GitHub, GitLab, PyPI, Codecov and bestpractices.dev are accessed with two-factor authentication; access is listed above.

A secret CI needs is limited to what the job needs, given to that job only, and rotated at least once a year and whenever someone with access leaves. Any secret that may have leaked is revoked at once, and the leak is handled as a vulnerability under [SECURITY.md](SECURITY.md).

## Granting access

Write or admin access is given only to a person who has contributed to glsec over a period of time and whom the maintainer knows to work carefully, and only the access the role needs. Every new member must have two-factor authentication on GitHub and GitLab; GitHub enforces it for the organization, on GitLab it is checked before access is given. Changes to this list are made in this file, in a pull request.
