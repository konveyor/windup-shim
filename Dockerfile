FROM golang:1.18 as builder
WORKDIR /windup-shim
# TODO limit to prevent unnecessary rebuilds
COPY go.mod /windup-shim
COPY go.sum /windup-shim
COPY  pkg /windup-shim/pkg
COPY  main.go /windup-shim

RUN go build -o windup-shim main.go

# This is the container built from the Dockerfile in the analyzer-lsp project
FROM analyzer-lsp

RUN microdnf install git -y && git clone https://github.com/windup/windup-rulesets.git /windup-rulesets
COPY --from=builder /windup-shim/windup-shim /usr/bin/windup-shim

# TODO debug only
RUN microdnf install -y procps vim

# CMD ["windup-shim", "test", "/windup-rulesets/rules/"]
ENTRYPOINT ["windup-shim"]
