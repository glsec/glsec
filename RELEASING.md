# Releasing glsec

The steps a maintainer follows for a release `vX.Y.Z`. Most of the publishing is automated; this list covers what isn't, in order.

## Before the release

1. **Open bugs.** Check the open `bug` issues and decide which ones the release waits for.
2. **New rules against real pipelines.** Scan pipelines from public projects with the new build and look at every finding of a new or changed rule for false positives. Compare against the last release's findings with `--no-cache`, from an empty directory so no `.glsec.yml` is picked up. Fix what you find before tagging.
3. **Parser against GitLab.** Run [`ci-lint-diff.py`](CONTRIBUTING.md#fixture-validation) over the same kind of pipeline set. No file may be in the group "GitLab accepts, glsec exits 2", and every file in "both accept, jobs differ" needs a reason (#930).
4. **GitLab component templates.** Scan the templates of the [CI/CD Catalog component](https://gitlab.com/glsec-io/glsec) with the new build and `--strict`. They run glsec on themselves after the bump, so a new finding there blocks the component release.
5. **Version pins.** Open a pull request `chore: bump version refs to X.Y.Z` that moves every pinned version in the README and `docs/*.md`, `.claude-plugin/plugin.json`, `bin/glsec` and the MegaLinter descriptor. CI's "Check version pins agree" fails on any it misses. Leave the plugin source pin in `.claude-plugin/marketplace.json` alone: it needs the tag commit, which doesn't exist yet.

## Cutting the release

6. Tag `vX.Y.Z` on `main` once CI on that commit is green, and push the tag. The Release and Docker workflows both refuse to run until CI passed for the tagged commit; if it was still running, re-run them when it has passed. The Release workflow builds the binaries, checksums, SBOMs and signed provenance, and creates the GitHub release; the Docker workflow builds, signs and pushes the image. When it succeeds, the PyPI workflow builds the wheels from those release archives and waits for a maintainer's approval in the `pypi` environment.
7. **Release notes.** Above the generated changelog, write a `## Highlights` section by hand: two to four sentences on what changed, the number of new rules and anything users need to do on upgrade (for example changed fingerprints or rule IDs). Name every security advisory the release fixes. End with one line asking for a star if glsec is useful. The OpenSSF Best Practices badge counts on human-written notes for every release.

## After the release

8. **PyPI.** Approve the `pypi` deployment, then check that `pipx install glsec==X.Y.Z` works.
9. **Plugin pin.** Open a follow-up pull request that sets `ref` and `sha` in `.claude-plugin/marketplace.json` to the new tag and its commit. It touches a sensitive path, so it needs the `sensitive-paths-reviewed` label.
10. **Homebrew and website.** Run the tap's update workflow (`gh workflow run update.yml -R glsec/homebrew-tap`) and the website's build (`gh workflow run deploy.yml -R glsec/glsec.github.io`); otherwise their daily runs pick the release up within a day. aqua's registry picks up new releases by itself.
11. **GitLab component.** For a minor or major release (a patch release may skip this step): in [glsec-io/glsec](https://gitlab.com/glsec-io/glsec), bump the default `version:` of both templates, the README examples and the image of the self-lint job. Merge after a green pipeline, then tag the next component version `v1.0.N` and create a GitLab release on that tag: the release is what publishes the version to the CI/CD Catalog. Afterwards, move the `@v1.0.N` examples in the README and `docs/ci-integration.md`, and the component version and glsec version (image tag, `GLSEC_VERSION`, archive name) in the [example projects](https://gitlab.com/glsec-io/examples). The weekly `examples-in-sync` check opens an issue when the examples drift.
12. **Advisories.** Publish any security advisory the release fixes, if it isn't public yet.
