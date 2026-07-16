FROM dhi.io/golang:1.26-alpine3.24@sha256:1d0318638e26a7a22e3844c649718cfb7ad000860e0ec32b3daf73376c1a6921 AS builder
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o glsec ./cmd/glsec


FROM dhi.io/alpine-base:3.24-dev@sha256:74230b37711de2e5cbc42b8fbd0bb019417ce99b05e5792390d75cb6c948a560 AS certs
RUN apk add --no-cache ca-certificates


#checkov:skip=CKV_DOCKER_2:no healthcheck needed
FROM dhi.io/alpine-base:3.24@sha256:037a503be3d6f50f01bde0ef366e9b9c84060a2db5781b076df40cdd706e5119
COPY --from=certs /etc/ssl/certs/ /etc/ssl/certs/
COPY --from=builder /build/glsec /usr/local/bin/glsec

# Redeclare ARGs in this stage so they can be consumed by the LABEL instruction
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
ARG GH=https://github.com/glsec/glsec

# Standardized OpenContainer Labels (OCI Annotations)
LABEL org.opencontainers.image.title="glsec" \
      org.opencontainers.image.description="A security utility built in Go" \
      org.opencontainers.image.url="${GH}" \
      org.opencontainers.image.source="${GH}" \
      org.opencontainers.image.documentation="${GH}/blob/main/README.md" \
      org.opencontainers.image.vendor="glsec" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.created="${DATE}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.base.name="dhi.io/alpine-base:3.24" \
      org.opencontainers.image.base.digest="sha256:037a503be3d6f50f01bde0ef366e9b9c84060a2db5781b076df40cdd706e5119"

USER nonroot
ENTRYPOINT ["glsec"]
