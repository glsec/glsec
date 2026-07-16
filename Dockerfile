FROM dhi.io/golang:1.26-alpine3.24 AS builder
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


FROM dhi.io/alpine-base:3.24-dev AS certs
RUN apk add --no-cache ca-certificates


FROM dhi.io/alpine-base:3.24
COPY --from=certs /etc/ssl/certs/ /etc/ssl/certs/
COPY --from=builder /build/glsec /usr/local/bin/glsec

USER nonroot
ENTRYPOINT ["glsec"]
