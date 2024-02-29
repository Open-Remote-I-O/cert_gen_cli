# cert_gen_cli
CLI in order to generate keypairs in order to enable mTLS communication between device and gateway

## Installation instructions 

The cli can be easily installed by the `go install` command eg:
`go install github.com/Open-Remote-I-O/cert_gen_cli@v0.1.4`

Or you can directly download and install the compiled version from the release

## Usage

### Generate CA key pair 

`cert_gen_cli genCaKeys`

This command will generate a set of keypairs that will rappresent the self signed certificate

### Generate parent key pair from CA key pair

`cert_gen_cli genCaParentCert`

At the moment the CLI offers this two commands, more information about them can be viewed using the `--help` flag for each subcommand
