FROM golang:1.18 as builder
WORKDIR /windup-shim
# TODO limit to prevent unnecessary rebuilds
COPY  . /windup-shim
RUN go build -o windup-shim main.go

# This is the container built from the Dockerfile in the analyzer-lsp project
FROM analyzer-lsp

RUN microdnf install git -y && git clone https://github.com/windup/windup-rulesets.git /windup-rulesets
COPY --from=builder /windup-shim/windup-shim /usr/bin/windup-shim
COPY . /windup-shim

CMD ["windup-shim", "test", "/windup-rulesets/rules/"]
