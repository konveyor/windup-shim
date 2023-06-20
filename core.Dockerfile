FROM golang:1.18 as builder
WORKDIR /windup-shim

COPY go.mod /windup-shim
COPY go.sum /windup-shim
COPY pkg /windup-shim/pkg
COPY main.go /windup-shim

RUN go build -o windup-shim main.go

FROM quay.io/konveyor/analyzer-lsp

WORKDIR /windup-shim

COPY --from=builder /windup-shim/windup-shim /usr/bin/windup-shim

ENTRYPOINT ["windup-shim"]
