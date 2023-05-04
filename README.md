![](https://byob.yarr.is/konveyor/windup-shim/windup-pass-rate)

## Code of Conduct
Refer to Konveyor's Code of Conduct [here](https://github.com/konveyor/community/blob/main/CODE_OF_CONDUCT.md).

## Building the Base Image

The shim will use the analyzer-lsp as the base image. You will need to build the base by:

1. Clone [analyzer-lsp](https://github.com/konveyor/analyzer-lsp).

```git clone git@github.com:konveyor/analyzer-lsp.git```

2. Build the base image

```cd analyzer-lsp && podman build -f Dockerfile -t analyzer-lsp```

## Running the demo

1. Build the Image

```podman build -f Dockerfile -t windup-shim```

2. Run the image

```podman run -it windup-shim test /windup-rulesets/rules/rules-reviewed```
