FROM golang:1.25-alpine AS builder
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

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/glsec /usr/local/bin/glsec
ENTRYPOINT ["glsec"]
