FROM golang:1.27-alpine AS builder
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

FROM alpine:3.24
# alpine:3.24 has not been rebuilt since the openssl fix for CVE-2026-14456
# landed in v3.24/main; drop this once the base image ships 3.5.8-r0.
# hadolint ignore=DL3017
RUN apk --no-cache upgrade
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
