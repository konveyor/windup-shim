FROM openjdk:11-slim as java-builder

FROM golang:1.18 as builder
WORKDIR /windup-shim

COPY go.mod /windup-shim
COPY go.sum /windup-shim
COPY  pkg /windup-shim/pkg
COPY  main.go /windup-shim

RUN go build -o windup-shim main.go

# This is the container built from the Dockerfile in the analyzer-lsp project
FROM analyzer-lsp

# TODO debug only
RUN microdnf install -y procps vim wget unzip git

ARG WINDUP=https://repo1.maven.org/maven2/org/jboss/windup/tackle-cli/6.2.4.Final/tackle-cli-6.2.4.Final-offline.zip
RUN wget -qO /tmp/windup.zip $WINDUP \
 && unzip /tmp/windup.zip -d /windup \
 && rm /tmp/windup.zip \
 && ln -s /windup/tackle-cli-*/bin/windup-cli /usr/bin/windup-cli

RUN git clone https://github.com/windup/windup-rulesets.git /windup-rulesets \
  && git clone https://github.com/konveyor/example-applications /example-applications

COPY --from=java-builder /usr/local/openjdk-11 /java-11-openjdk

COPY --from=builder /windup-shim/windup-shim /usr/bin/windup-shim

WORKDIR /windup-shim

# For debugging
COPY go.mod /windup-shim
COPY go.sum /windup-shim
COPY pkg /windup-shim/pkg
COPY main.go /windup-shim

RUN mkdir /rules/ && /usr/bin/windup-shim convert --outputdir=/rules/ /windup-rulesets/rules/rules-reviewed/

ENTRYPOINT ["windup-shim"]
