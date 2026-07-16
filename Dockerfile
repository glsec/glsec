FROM dhi.io/golang:1.26-alpine3.24@sha256:1d0318638e26a7a22e3844c649718cfb7ad000860e0ec32b3daf73376c1a6921 AS builder
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

FROM dhi.io/alpine:3.24@sha256:037a503be3d6f50f01bde0ef366e9b9c84060a2db5781b076df40cdd706e5119
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/glsec /usr/local/bin/glsec
USER nonroot
ENTRYPOINT ["glsec"]
