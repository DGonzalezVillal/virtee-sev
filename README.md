<!-- cargo-rdme start -->

The `sev` crate provides an implementation of the [AMD Secure Encrypted
Virtualization (SEV)][SEV] APIs and the [SEV Secure Nested Paging
Firmware (SNP)][SNP] ABIs.

[SEV]: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/programmer-references/55766_SEV-KM_API_Specification.pdf
[SNP]: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf

## SEV APIs

The linux kernel exposes two technically distinct AMD SEV APIs:

1. An API for managing the SEV platform itself
2. An API for managing SEV-enabled KVM virtual machines

This crate implements both of those APIs and offers them to client.
code through a flexible and type-safe high-level interface.

## SNP ABIs

Like SEV, the linux kernel exposes another two different AMD SEV-SNP ABIs:

1. An ABI for managing the SEV-SNP platform itself
2. An ABI for managing SEV-SNP enabled KVM virtual machines

These new ABIs work only for **SEV-SNP** enabled hosts and guests.

This crate implements APIs for both SEV and SEV-SNP management.

## SEV and SEV-SNP enablement

By default, only the SEV-SNP library is compiled. First-generation SEV
(pre-SNP) support — certificate and attestation report verification,
reference values, and session types — is available via the `sev` feature
flag. Host platform management (`/dev/sev`) requires the `platform` feature;
KVM guest launch requires `launch` (which enables `platform`). That legacy
stack is separate from SEV-SNP and is not needed for SNP-only consumers such
as remote attestation verifiers.
Because many modules provide support to both legacy SEV and SEV-SNP, they have
been split into individual sub-modules `sev.rs` and `snp.rs`, isolating
generation specific behavior.

For example, to include first-generation SEV support:  
`sev = { version = "1.2.1", default-features = false, features = ["sev"] }`  

To use SEV-SNP with the defaults (or explicitly):  
`sev = { version = "1.2.1", features = ["snp"] }`  

## SNP attestation

For SEV-SNP remote attestation, use the [`attestation`](https://docs.rs/sev/latest/sev/attestation/) module. It is organized around [IETF RATS](https://datatracker.ietf.org/doc/rfc9334/) roles. Enable the role features you need:

| Feature | Module | Role |
|---|---|---|
| `evidence` | `attestation::evidence::snp` | Evidence framing and parsing |
| `verifier` | `attestation::verifier` | Signature and chain verification |
| `endorser` | `attestation::endorser` | Endorsement material (VCEK/VLEK chains) |
| `attester` | `attestation::attester` | Guest evidence collection (`/dev/sev-guest`) |
| `reference` | `attestation::reference` | Reference values (launch digest, ID block) |

Defaults include `evidence`, `verifier`, `endorser`, and `reference` but not `attester` or `platform`.

Shared firmware ABI wire types live in [`types`](https://docs.rs/sev/latest/sev/types/), organized as `types::snp`, `types::sev`, and `types::shared` (OVMF, vCPU models, VMSA pages).

## Legacy SEV attestation

For first-generation SEV (`feature = "sev"`), the same [`attestation`](https://docs.rs/sev/latest/sev/attestation/) module provides legacy roles:

| Module | Role |
|---|---|
| `attestation::evidence::sev` | `LegacyAttestationReport` |
| `attestation::verifier::sev` | Certificate chain and report verification |
| `attestation::endorser::sev` | PEK/PDH/CEK chains and built-in ARK/ASK |
| `attestation::reference::sev` | Launch digest reference calculation |

## Platform Management

Enable the `platform` feature for host `/dev/sev` management. [`platform::Firmware`](https://docs.rs/sev/latest/sev/platform/struct.Firmware.html) is the shared device handle. Generation-specific APIs and types live in [`platform::sev`](https://docs.rs/sev/latest/sev/platform/sev/index.html) (legacy SEV) and [`platform::snp`](https://docs.rs/sev/latest/sev/platform/snp/index.html) (SEV-SNP). ABI wire types are under [`types`](https://docs.rs/sev/latest/sev/types/).

## Guest Management

Enable the `launch` feature for KVM guest bring-up (`launch` implies `platform`).
Refer to the [launch](https://docs.rs/sev/latest/sev/launch/) module for more information.

## Cryptographic Verification

`verifier`, `endorser`, and `reference` require a crypto backend: enable
`crypto-openssl` or `crypto-rust` (mutually exclusive). Defaults use
`crypto-openssl` with vendored OpenSSL.

Examples:

`sev = { version = "1.2.1", default-features = false, features = ["snp", "verifier", "crypto-openssl"] }`  
`sev = { version = "1.2.1", default-features = false, features = ["snp", "verifier", "crypto-rust"] }`

## Remarks

Note that the linux kernel provides access to these APIs through a set
of `ioctl`s that are meant to be called on device nodes (`/dev/kvm` and
`/dev/sev`, to be specific). As a result, these `ioctl`s form the substrate
of the `sev` crate. Binaries that result from consumers of this crate are
expected to run as a process with the necessary privileges to interact
with the device nodes.

## Using the C API

Projects in C can take advantage of the C API for the SEV [launch] ioctls.
Enable the `launch` feature and use `cargo-c` with the features you would
like to produce and install a `pkg-config` file, a static library, a dynamic
library, and a C header:

`cargo cinstall --prefix=/usr --libdir=/usr/lib64 --features launch`

[platform]: ./src/platform/
[launch]: ./src/launch/

<!-- cargo-rdme end -->
