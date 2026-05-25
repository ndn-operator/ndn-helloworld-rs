# ndn-helloworld-rs

Certificate-aware NDN producer and consumer binaries for `ndn-operator`
examples. Both clients communicate through the Unix socket injected by the
operator. The producer signs Data with an operator-issued `ndnd` ECDSA key;
the consumer validates the certificate chain and the embedded Light VerSec
policy before accepting content.

The application pins experimental
[`Quarmire/ndn-rs`](https://github.com/Quarmire/ndn-rs) at commit
`991ab06233d0b7596eda30e70fe069659be50042`. Its `ndnd` interoperability
must be checked before publishing a release image.

## Runtime Inputs

The operator injects these values into the selected application container:

| Environment variable | Purpose |
| --- | --- |
| `NDN_CLIENT_TRANSPORT` | `unix://` URI of the attached `ndnd` application socket |
| `NDN_PREFIX` | Application namespace of the attached Network |
| `NDN_APP_SIGNING_KEY_FILE` | Producer-only `NDN KEY` PEM path |
| `NDN_APP_SIGNING_CERT_FILE` | Producer-only `NDN CERT` PEM path |
| `NDN_APP_TRUST_ANCHOR_DIR` | Consumer directory containing trusted root certificates |
| `NDN_APP_CERTIFICATE_CHAIN_DIR` | Consumer directory containing non-anchor chain certificates |

`consumer` embeds `schema/helloworld.tlv`, compiled from
`schema/helloworld.lvs`. It accepts only Data whose subnetwork component agrees
with its delegated application signing identity.

## Commands

```shell
producer --name /root-network/subnetwork1/helloworld/valid
consumer --name /root-network/subnetwork1/helloworld/valid
consumer --expect-reject --name /root-network/subnetwork1/helloworld/forged
```

Successful validation logs `VERIFIED data <name>:`. Expected policy rejection
logs `REJECTED data <name>:` and exits with status zero.

## Build And Test

```shell
cargo test --locked
docker build -t ghcr.io/ndn-operator/ndn-helloworld-rs:v0.1.0 .
```

`tests/ndnd-interop.sh` is the publication gate when an `ndnd` binary and a
Unix-face test setup are available; Kubernetes integration tests exercise the
same signed producer/validator path with operator-issued credentials.

After the gate passes against `ndnd` 1.5.2, dispatch the `Build application
image` workflow with `release_tag=v0.1.0` and confirm
`ndnd_interop_passed`. Tag pushes alone do not publish an unverified image.
