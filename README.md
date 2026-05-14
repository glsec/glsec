<p align="center">
  <img src="assets/logo.png" alt="glsec" width="400">
</p>

# glsec

GitLab CI security linter — find misconfigurations and vulnerabilities in `.gitlab-ci.yml` files.

```
$ glsec .gitlab-ci.yml

ERROR  .gitlab-ci.yml:4   GL001  mutable image tag "node:latest" — pin to a specific version or digest
WARN   .gitlab-ci.yml:12  GL002  unquoted user-controlled variable $CI_COMMIT_REF_NAME in script
ERROR  .gitlab-ci.yml:21  GL003  project include missing "ref" — defaults to mutable HEAD
```

## Install

```sh
go install github.com/glsec/glsec@latest
```

Binary downloads and Homebrew coming soon.

## Usage

```sh
# scan a file
glsec .gitlab-ci.yml

# scan with JSON output
glsec --format json .gitlab-ci.yml

# set minimum severity
glsec --severity error .gitlab-ci.yml

# restrict to trusted registries
glsec --registry-allowlist registry.company.com .gitlab-ci.yml
```

## Rules

| ID    | Severity | Description                                  |
|-------|----------|----------------------------------------------|
| GL001 | error    | Mutable image tag (`latest`, no tag, etc.)   |
| GL002 | warn     | Unquoted user-controlled variable in script  |
| GL003 | error    | Remote `include:` without SHA/tag pinning    |
| GL004 | warn     | `CI_JOB_TOKEN` sent to non-GitLab host       |
| GL005 | warn     | Sensitive artifact paths or missing expiry   |

## GitLab CI integration

```yaml
glsec:
  image: golang:1.22-alpine
  script:
    - go install github.com/glsec/glsec@latest
    - glsec .gitlab-ci.yml
```

## License

Apache 2.0
