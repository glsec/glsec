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


FROM dhi.io/alpine-base:3.24@sha256:037a503be3d6f50f01bde0ef366e9b9c84060a2db5781b076df40cdd706e5119
COPY --from=certs /etc/ssl/certs/ /etc/ssl/certs/
COPY --from=builder /build/glsec /usr/local/bin/glsec

USER nonroot
ENTRYPOINT ["glsec"]
