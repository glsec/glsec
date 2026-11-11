#!/usr/bin/env bash
# Copyright The glsec Authors
# SPDX-License-Identifier: Apache-2.0
#
# List GitLab's maintained CI/CD templates (lib/gitlab/ci/templates/*.gitlab-ci.yml
# in gitlab-org/gitlab), one relative path per line, sorted. These are the tools
# GitLab recommends running inside a pipeline (Docker, Kaniko, Terraform, Cosign,
# the security scanners, …); a new template is a new tool whose misconfigurations
# glsec may need a rule for. The check-gitlab-ci-templates workflow compares this
# output with the reviewed snapshot in .github/gitlab-ci-templates.txt.
#
#   gitlab-ci-templates.sh > .github/gitlab-ci-templates.txt
#
# Needs curl and jq. The API response is read only as data (jq does not execute it).
set -euo pipefail
export LC_ALL=C

api="https://gitlab.com/api/v4/projects/gitlab-org%2Fgitlab/repository/tree"
query="path=lib/gitlab/ci/templates&recursive=true&per_page=100&ref=master"

page=1
{
  while :; do
    resp=$(curl -fsSL --retry 3 "$api?$query&page=$page")
    [ "$(jq 'length' <<<"$resp")" -eq 0 ] && break
    jq -r '.[]
      | select(.type == "blob" and (.path | endswith(".gitlab-ci.yml")))
      | .path | sub("^lib/gitlab/ci/templates/"; "")' <<<"$resp"
    page=$((page + 1))
    [ "$page" -gt 20 ] && break # safety bound; ~2 pages today
  done
} | sort -u
