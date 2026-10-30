#!/usr/bin/env bash
# Copyright The glsec Authors
# SPDX-License-Identifier: Apache-2.0
#
# Smoke test of a packaged glsec (#929): the image, a wheel or a release
# archive, run the way users run it.
#
#   smoke-test.sh VERSION COMMAND...
#
# COMMAND is how to start glsec, for example `./glsec` or
# `docker run --rm -v "$PWD/testdata:/src/testdata:ro" -w /src glsec:ci`.
# Checks that `--version` reports VERSION and that a scan of a fixture with a
# known finding exits 1 and reports it. Run it from the repository root.
set -euo pipefail

want=$1
shift
fixture=testdata/fixtures/gl001-mutable-images.yml

version=$("$@" --version)
echo "$version"
if [[ "$version" != "glsec $want "* ]]; then
  echo "::error::expected version $want, got: $version"
  exit 1
fi

code=0
report=$("$@" --no-cache --no-repo-config --format json "$fixture") || code=$?
if [ "$code" != 1 ]; then
  echo "$report"
  echo "::error::scanning $fixture exited $code, expected 1 (findings)"
  exit 1
fi
if ! grep -qE '"rule": *"GL001"' <<< "$report"; then
  echo "$report"
  echo "::error::scanning $fixture reported no GL001 finding"
  exit 1
fi
echo "smoke test passed: glsec $want starts and reports GL001"
