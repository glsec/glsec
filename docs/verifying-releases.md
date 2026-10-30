# Verifying a release

Every release is signed and carries build provenance, so you can confirm an artifact really came from this repository's workflow before trusting it. Signing is keyless through [Sigstore](https://www.sigstore.dev/), so there is no public key to fetch or rotate.

The release binaries and the container image meet [SLSA](https://slsa.dev/spec/v1.0/levels) **Build Level 3** from 1.21.0 on: they are built in reusable workflows (`build-release.yml`, `build-image.yml`) that the release workflow only calls, so the build workflow, not the workflow a tag push triggers, signs the provenance. That is the isolation GitHub documents as [SLSA v1 Build Level 3 for artifact attestations](https://docs.github.com/actions/security-guides/using-artifact-attestations-and-reusable-workflows-to-achieve-slsa-v1-build-level-3). Releases 1.11.0 to 1.20.0 meet Build Level 2: their provenance is signed by GitHub's hosted build platform, but by the release workflow itself.

**Release binaries** carry a SLSA provenance attestation. Verify a downloaded archive with the [GitHub CLI](https://cli.github.com/); `--signer-workflow` requires that the build workflow signed it (Build Level 3):

```sh
gh attestation verify glsec_1.24.1_linux_amd64.tar.gz --owner glsec \
  --signer-workflow glsec/glsec/.github/workflows/build-release.yml
```

For releases before 1.21.0, drop `--signer-workflow`.

The same attestation is attached to each release as `glsec_<version>.sigstore.json` (Sigstore bundle) and `glsec_<version>.intoto.jsonl` (its DSSE envelope), so you can also verify without the GitHub API, for example from a mirror:

```sh
cosign verify-blob-attestation \
  --bundle glsec_1.24.1.sigstore.json --new-bundle-format --type slsaprovenance1 \
  --certificate-identity-regexp '^https://github.com/glsec/glsec/\.github/workflows/(build-)?release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  glsec_1.24.1_linux_amd64.tar.gz
```

One bundle covers every archive and `checksums.txt`. Releases from 1.11.0 on carry these files; in 1.11.0 the bundle covers the archives but not `checksums.txt`, and older releases have no provenance. The identity regex accepts `release.yml`, which signed releases before 1.21.0, and `build-release.yml`, which signs them from 1.21.0 on; use only the latter to require Build Level 3.

**The container image** is signed with [cosign](https://github.com/sigstore/cosign) and carries provenance plus an SBOM attestation:

```sh
cosign verify ghcr.io/glsec/glsec:1.24.1 \
  --certificate-identity-regexp 'https://github.com/glsec/glsec/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# list everything attached to the image (signature, provenance, SBOM)
cosign tree --experimental-oci11 ghcr.io/glsec/glsec:1.24.1
```

To require Build Level 3 provenance for the image (1.21.0 and later):

```sh
gh attestation verify oci://ghcr.io/glsec/glsec:1.24.1 --owner glsec \
  --signer-workflow glsec/glsec/.github/workflows/build-image.yml
```

The two `--certificate-*` flags are what bind the signature to this repository's GitHub Actions workflow. Without them `cosign verify` accepts a signature from any identity, which defeats the point.

Use cosign v3 or newer. The image is signed in Sigstore's bundle format and the attestations are stored as OCI referrers, so cosign v2 reports `no signatures found`, and `cosign tree` without `--experimental-oci11` shows nothing.

**Checksums** are published as `checksums.txt` next to the archives:

```sh
curl -sSLO https://github.com/glsec/glsec/releases/download/v1.24.1/checksums.txt
sha256sum -c checksums.txt --ignore-missing
```

`checksums.txt` is itself attested, so you can verify the checksums file first and then trust every digest it lists:

```sh
gh attestation verify checksums.txt --owner glsec
```

**Reproducing a release**: release builds are reproducible from 1.21.0 on. Check out the tag and build it with the Go version from `go.mod` (the `toolchain` line from 1.24.1 on, before that the `go` line) and exactly the GoReleaser version pinned in `.github/workflows/build-release.yml` (v2.18.3 for 1.21.0); another GoReleaser version packs the archives differently. The archives must match the published `checksums.txt`:

```sh
VERSION=1.24.1
git clone https://github.com/glsec/glsec && cd glsec
git checkout "v${VERSION}"
goreleaser release --clean --skip=publish,sbom
curl -sSL "https://github.com/glsec/glsec/releases/download/v${VERSION}/checksums.txt" | grep -v '\.sbom\.json$' > published.txt
(cd dist && sha256sum -c ../published.txt)
```

The SBOM files are left out because syft writes timestamps into them; they are not part of the provenance either. CI checks on every change to the build that two builds of the same commit are identical.

**SBOMs**: the container image carries its SBOM as a signed attestation, listed by `cosign tree` above. The per-archive `.sbom.json` files are published as plain release assets rather than attestations, deliberately. Each contains four entries: glsec itself, its single dependency `gopkg.in/yaml.v3`, the Go standard library, and the archive's own digest. That is the same information `go.mod` already makes public, and the archive it describes is covered by provenance, so a swapped SBOM cannot make a tampered archive verify. If you need an SBOM you can trust end to end, use the image attestation or regenerate one from a verified archive with [syft](https://github.com/anchore/syft).
