# Copyright The glsec Authors
# SPDX-License-Identifier: Apache-2.0

# Base images are pinned by digest; Dependabot (docker ecosystem, daily) moves
# the digest when upstream rebuilds the tag (#539).
FROM golang:1.27-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o glsec ./cmd/glsec

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
COPY --from=builder /build/glsec /usr/local/bin/glsec

# ARGs do not cross build stages, so re-declare them here for the LABELs
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
ARG GH=https://github.com/glsec/glsec
LABEL org.opencontainers.image.title="glsec" \
      org.opencontainers.image.description="Security linter for GitLab CI (.gitlab-ci.yml) files" \
      org.opencontainers.image.url="${GH}" \
      org.opencontainers.image.source="${GH}" \
      org.opencontainers.image.documentation="${GH}/blob/main/README.md" \
      org.opencontainers.image.vendor="glsec" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.created="${DATE}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}"
USER 65532:65532
ENTRYPOINT ["glsec"]
