# Copyright The glsec Authors
# SPDX-License-Identifier: Apache-2.0
"""Pack the release binaries into platform wheels for PyPI (#911).

    build-wheels.py VERSION DIST OUT

Reads glsec_VERSION_<os>_<arch>.tar.gz / .zip from DIST, which pypi.yml has
already checked against checksums.txt and the build provenance, and writes one
wheel per platform to OUT. The binary goes under glsec-VERSION.data/scripts/,
so pip, pipx and uv install it straight onto PATH: no Python wrapper, nothing
downloaded at install time. The same archives always give the same wheels.
"""
import base64
import hashlib
import io
import sys
import tarfile
import zipfile
from pathlib import Path

# The Go binaries are static (CGO_ENABLED=0), so one Linux build serves both
# glibc and musl. Go needs macOS 11 or later.
PLATFORMS = {
    "linux_amd64": ["manylinux_2_17_x86_64", "manylinux2014_x86_64", "musllinux_1_1_x86_64"],
    "linux_arm64": ["manylinux_2_17_aarch64", "manylinux2014_aarch64", "musllinux_1_1_aarch64"],
    "darwin_amd64": ["macosx_11_0_x86_64"],
    "darwin_arm64": ["macosx_11_0_arm64"],
    "windows_amd64": ["win_amd64"],
    "windows_arm64": ["win_arm64"],
}

DESCRIPTION = """\
# glsec

Security linter for GitLab CI/CD pipelines. glsec reads `.gitlab-ci.yml` and
reports mutable images, unpinned includes, hardcoded secrets, script
injection, token exfiltration, unrestricted OIDC tokens and more, mapped to
the OWASP Top 10 CI/CD Security Risks. It runs offline and needs no access to
your GitLab instance.

```sh
pipx install glsec      # or: uv tool install glsec
uvx glsec .gitlab-ci.yml
```

This package ships the prebuilt binary of the GitHub release with the same
version; the archive it was taken from carries build provenance from the
release workflow. Documentation, rules and other install methods:
https://github.com/glsec/glsec
"""

# Fixed timestamp for every entry, so a rebuild gives identical wheels.
ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def binary(archive):
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as z:
            return z.read("glsec.exe"), "glsec.exe"
    with tarfile.open(archive) as t:
        return t.extractfile("glsec").read(), "glsec"


def record_hash(data):
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return "sha256=" + digest.decode()


def metadata(version):
    lines = [
        "Metadata-Version: 2.4",
        "Name: glsec",
        f"Version: {version}",
        "Summary: Security linter for GitLab CI/CD pipelines",
        "License-Expression: Apache-2.0",
        "License-File: LICENSE",
        "Project-URL: Homepage, https://glsec.github.io",
        "Project-URL: Source, https://github.com/glsec/glsec",
        "Project-URL: Issues, https://github.com/glsec/glsec/issues",
        "Project-URL: Changelog, https://github.com/glsec/glsec/releases",
        "Keywords: gitlab,ci,cd,security,linter,sast,supply-chain",
        "Classifier: Environment :: Console",
        "Classifier: Intended Audience :: Developers",
        "Classifier: Operating System :: OS Independent",
        "Classifier: Topic :: Security",
        "Classifier: Topic :: Software Development :: Quality Assurance",
        "Description-Content-Type: text/markdown",
    ]
    return ("\n".join(lines) + "\n\n" + DESCRIPTION).encode()


def wheel(version, platform, exe, exe_name, license_text, out):
    tags = PLATFORMS[platform]
    name = f"glsec-{version}-py3-none-{'.'.join(tags)}.whl"
    dist_info = f"glsec-{version}.dist-info"
    wheel_meta = "Wheel-Version: 1.0\nGenerator: glsec build-wheels.py\nRoot-Is-Purelib: false\n"
    wheel_meta += "".join(f"Tag: py3-none-{t}\n" for t in tags)
    files = [
        (f"glsec-{version}.data/scripts/{exe_name}", exe, 0o755),
        (f"{dist_info}/METADATA", metadata(version), 0o644),
        (f"{dist_info}/WHEEL", wheel_meta.encode(), 0o644),
        (f"{dist_info}/licenses/LICENSE", license_text, 0o644),
    ]
    record = "".join(f"{path},{record_hash(data)},{len(data)}\n" for path, data, _ in files)
    record += f"{dist_info}/RECORD,,\n"
    files.append((f"{dist_info}/RECORD", record.encode(), 0o644))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for path, data, mode in files:
            info = zipfile.ZipInfo(path, ZIP_TIME)
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    (out / name).write_bytes(buf.getvalue())
    return name


def main():
    version, dist, out = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    out.mkdir(parents=True, exist_ok=True)
    license_text = None
    for platform in PLATFORMS:
        ext = "zip" if platform.startswith("windows") else "tar.gz"
        archive = dist / f"glsec_{version}_{platform}.{ext}"
        if license_text is None and ext == "tar.gz":
            with tarfile.open(archive) as t:
                license_text = t.extractfile("LICENSE").read()
        exe, exe_name = binary(archive)
        print(wheel(version, platform, exe, exe_name, license_text, out))


if __name__ == "__main__":
    main()
