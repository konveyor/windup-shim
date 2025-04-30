ARG VERSION=latest

FROM golang:1.21 as builder
WORKDIR /windup-shim

COPY go.mod /windup-shim
COPY go.sum /windup-shim
COPY pkg /windup-shim/pkg
COPY main.go /windup-shim

RUN go build -o windup-shim main.go

FROM quay.io/konveyor/analyzer-lsp:release-0.7

FROM quay.io/konveyor/java-external-provider:${VERSION}

WORKDIR /windup-shim

COPY --from=builder /windup-shim/windup-shim /usr/bin/windup-shim
COPY --from=analyzer-lsp /usr/local/bin/konveyor-analyzer /usr/local/bin/konveyor-analyzer

ENTRYPOINT ["windup-shim"]
