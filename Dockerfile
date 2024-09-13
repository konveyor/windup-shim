ARG VERSION=latest

FROM golang:1.22 as builder
WORKDIR /windup-shim

COPY go.mod /windup-shim
COPY go.sum /windup-shim
COPY pkg /windup-shim/pkg
COPY main.go /windup-shim

RUN go build -o windup-shim main.go

FROM quay.io/konveyor/analyzer-lsp:${VERSION} as analyzer-lsp

# This is the container built from the Dockerfile in the analyzer-lsp project
FROM quay.io/konveyor/java-external-provider:${VERSION}

# TODO debug only
RUN microdnf install -y procps vim wget unzip git

RUN git clone https://github.com/konveyor-ecosystem/windup-rulesets.git -b konveyor /windup-rulesets

COPY --from=builder /windup-shim/windup-shim /usr/bin/windup-shim
COPY --from=analyzer-lsp /usr/local/bin/konveyor-analyzer /usr/local/bin/konveyor-analyzer

WORKDIR /windup-shim

# For debugging
COPY go.mod /windup-shim
COPY go.sum /windup-shim
COPY pkg /windup-shim/pkg
COPY main.go /windup-shim

ENTRYPOINT ["windup-shim"]
