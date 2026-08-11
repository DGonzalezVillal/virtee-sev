<!-- cargo-rdme start -->

Rust bindings for AMD Secure Encrypted Virtualization (SEV) and SEV-SNP.

The crate wraps Linux kernel interfaces to the AMD Secure Processor: host
platform management on `/dev/sev`, guest attestation on `/dev/sev-guest`, and
KVM guest launch ioctls. Wire-format types from the [SEV API][SEV] and
[SEV-SNP firmware ABI][SNP] live in [`types`](https://docs.rs/sev/latest/sev/types/);
higher-level attestation workflows are grouped under
[`attestation`](https://docs.rs/sev/latest/sev/attestation/) following
[IETF RATS][RATS] roles.

[SEV]: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/programmer-references/55766_SEV-KM_API_Specification.pdf
[SNP]: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf
[RATS]: https://datatracker.ietf.org/doc/rfc9334/

## Architecture

```text
 types          firmware (internal)     platform / attester
 ─────          ───────────────────     ─────────────────────
 wire values    ioctl C layouts    →    /dev/sev, /dev/sev-guest APIs
      │                │                        │
      └────────────────┴────────────────────────┘
                       │
             attestation (RATS roles)
             evidence · verifier · endorser · attester · reference
```

- [`types`](https://docs.rs/sev/latest/sev/types/) — firmware ABI **vocabulary** (TCB, guest policy, ID block, cert table entries, platform status fields)
- `firmware` (internal) — Linux ioctl transport layouts
- [`platform`](https://docs.rs/sev/latest/sev/platform/) — host `/dev/sev` management
- [`attestation::attester`](https://docs.rs/sev/latest/sev/attestation/attester/) — guest `/dev/sev-guest` evidence collection
- [`attestation::evidence`](https://docs.rs/sev/latest/sev/attestation/evidence/) — attestation report framing and parsing
- [`attestation::verifier`](https://docs.rs/sev/latest/sev/attestation/verifier/) — signature and chain verification
- [`attestation::endorser`](https://docs.rs/sev/latest/sev/attestation/endorser/) — endorsement material (VCEK/VLEK chains)
- [`attestation::reference`](https://docs.rs/sev/latest/sev/attestation/reference/) — launch digest and ID block reference values
- [`parser`](https://docs.rs/sev/latest/sev/parser/) — byte encoding/decoding traits for wire types

## Feature profiles

Defaults target **SNP remote attestation verifiers** — evidence parsing,
signature verification, and endorsement handling — without compiling host
platform or guest launch code:

```toml
sev = "7" # default-features = true
```

Common opt-in profiles:

| Goal | Features to enable |
|------|-------------------|
| Verify SNP reports (default) | `snp`, `evidence`, `verifier`, `endorser`, `crypto-openssl` |
| Collect guest evidence | add `attester` |
| Manage host platform (`/dev/sev`) | add `platform` |
| Launch KVM guests | add `launch` (implies `platform`) |
| First-generation SEV (pre-SNP) | add `sev`, usually with `crypto-openssl` |
| Pure-Rust crypto | replace `crypto-openssl` with `crypto-rust` |

Example — verifier with Rust crypto, no OpenSSL:

```toml
sev = { version = "7", default-features = false, features = ["snp", "verifier", "endorser", "evidence", "crypto-rust"] }
```

## Module guide

| Module | Feature gates | Purpose |
|--------|---------------|---------|
| [`types`](https://docs.rs/sev/latest/sev/types/) | `sev` and/or `snp` | Shared firmware ABI wire types |
| [`attestation`](https://docs.rs/sev/latest/sev/attestation/) | role features | RATS evidence, verification, endorsement, attestation, reference values |
| [`platform`](https://docs.rs/sev/latest/sev/platform/) | `platform` | Host `/dev/sev` platform management |
| [`launch`](https://docs.rs/sev/latest/sev/launch/) | `launch` | KVM guest bring-up (requires `platform`) |
| [`error`](https://docs.rs/sev/latest/sev/error/) | always | Error types for ioctl and parsing failures |
| [`parser`](https://docs.rs/sev/latest/sev/parser/) | always | Encoding/decoding traits for wire types |

Low-level ioctl layouts are internal (`firmware`); public host and guest
device APIs are [`platform::Firmware`](https://docs.rs/sev/latest/sev/platform/struct.Firmware.html) and [`attestation::attester::Firmware`](https://docs.rs/sev/latest/sev/attestation/attester/snp/struct.Firmware.html).

## Types layout

[`types::shared`](https://docs.rs/sev/latest/sev/types/shared/) holds ABI values used by both first-generation SEV and SEV-SNP:

- [`Generation`](https://docs.rs/sev/latest/sev/types/shared/enum.Generation.html) — EPYC product line (selects TCB layout, built-in certificate chains, and parsing behavior)
- [`FirmwareVersion`](https://docs.rs/sev/latest/sev/types/shared/struct.FirmwareVersion.html) — major/minor/build triple
- [`types::shared::launch`](https://docs.rs/sev/latest/sev/types/shared/launch/) — OVMF metadata, vCPU models, SEV-ES VMSA pages

Generation-specific modules:

- [`types::snp`](https://docs.rs/sev/latest/sev/types/snp/) — SNP wire types shared across roles: [`GuestPolicy`](https://docs.rs/sev/latest/sev/types/snp/struct.GuestPolicy.html), [`TcbVersion`](https://docs.rs/sev/latest/sev/types/snp/struct.TcbVersion.html), certificate tables, ID block, platform status/config, derived-key parameters, launch page types
- [`types::sev`](https://docs.rs/sev/latest/sev/types/sev/) — legacy SEV platform status and state (requires `sev`)

**Attestation reports** (`Report`, `ReportBody`, `Signature`) live in
[`attestation::evidence::snp`](https://docs.rs/sev/latest/sev/attestation/evidence/snp/), not in `types`. Evidence types compose wire atoms from `types` (for example `TcbVersion` and `GuestPolicy` inside `ReportBody`).

SNP platform wire types such as [`SnpPlatformStatus`](https://docs.rs/sev/latest/sev/types/snp/platform/struct.SnpPlatformStatus.html) and [`Config`](https://docs.rs/sev/latest/sev/types/snp/platform/struct.Config.html) are re-exported from [`platform::snp`](https://docs.rs/sev/latest/sev/platform/snp/) when the `platform` feature is enabled.

## SNP attestation (RATS)

| Feature | Module | Role |
|---------|--------|------|
| `evidence` | [`attestation::evidence::snp`](https://docs.rs/sev/latest/sev/attestation/evidence/snp/) | Parse attestation reports (untrusted framing + body fields) |
| `verifier` | [`attestation::verifier`](https://docs.rs/sev/latest/sev/attestation/verifier/) | Verify signatures and certificate chains |
| `endorser` | [`attestation::endorser`](https://docs.rs/sev/latest/sev/attestation/endorser/) | VCEK/VLEK chains and built-in CA material |
| `attester` | [`attestation::attester`](https://docs.rs/sev/latest/sev/attestation/attester/) | Guest evidence collection (`/dev/sev-guest`) |
| `reference` | [`attestation::reference`](https://docs.rs/sev/latest/sev/attestation/reference/) | Launch digest and ID block reference values |

Typical verifier flow:

```ignore
use sev::attestation::{
    evidence::snp::{Report, ReportBody},
    endorser::snp::Chain,
    verifier::Verifiable,
};

let report = Report::from_bytes(&raw)?;
let chain = Chain::from_pem(&ark_pem, &ask_pem, &vek_pem)?;
(chain, &report).verify()?;
let body = ReportBody::try_from((&report, &chain))?;
```

Parse evidence with [`attestation::evidence::snp`](https://docs.rs/sev/latest/sev/attestation/evidence/snp/), verify with [`attestation::verifier::snp`](https://docs.rs/sev/latest/sev/attestation/verifier/snp/), and resolve endorsement material with [`attestation::endorser::snp`](https://docs.rs/sev/latest/sev/attestation/endorser/snp/).

## Legacy SEV attestation

With `feature = "sev"`, the same [`attestation`](https://docs.rs/sev/latest/sev/attestation/) module provides legacy roles:

| Module | Role |
|--------|------|
| [`attestation::evidence::sev`](https://docs.rs/sev/latest/sev/attestation/evidence/sev/) | `LegacyAttestationReport` parsing |
| [`attestation::verifier::sev`](https://docs.rs/sev/latest/sev/attestation/verifier/sev/) | PEK/PDH/CEK chain and report verification |
| [`attestation::endorser::sev`](https://docs.rs/sev/latest/sev/attestation/endorser/sev/) | Built-in ARK/ASK and certificate chains |
| [`attestation::reference::sev`](https://docs.rs/sev/latest/sev/attestation/reference/sev/) | Launch digest reference calculation |

## Platform and launch

[`platform::Firmware`](https://docs.rs/sev/latest/sev/platform/struct.Firmware.html) opens `/dev/sev`. Shared ioctls (legacy SEV and SNP): platform status and CPU identifier export. SNP-specific ioctls (status, commit, config, VLEK load) live under [`platform::snp`](https://docs.rs/sev/latest/sev/platform/snp/) and require an explicit [`Generation`](https://docs.rs/sev/latest/sev/types/shared/enum.Generation.html) because TCB byte layout varies by CPU generation. Optional host CPUID detection is available via [`Generation::identify_host_generation`](https://docs.rs/sev/latest/sev/types/shared/enum.Generation.html#method.identify_host_generation) on Linux x86_64.

[`launch`](https://docs.rs/sev/latest/sev/launch/) adds KVM guest launch on top of `platform` (SEV and SNP launch flows). A C ABI for launch ioctls is available when `launch` is enabled (see below).

## Cryptographic backends

`verifier`, `endorser`, and `reference` require exactly one of `crypto-openssl` or `crypto-rust`. Defaults use vendored OpenSSL (`crypto-openssl`).

## Linux and privileges

Kernel access is through `ioctl`s on device nodes (`/dev/sev`, `/dev/sev-guest`, `/dev/kvm`). Processes using this crate typically need appropriate permissions for those nodes (often root or membership in a dedicated group).

## C API for launch

C projects can link against launch ioctls by enabling `launch` and installing with [cargo-c](https://github.com/lu-zero/cargo-c):

```text
cargo cinstall --prefix=/usr --libdir=/usr/lib64 --features launch
```

<!-- cargo-rdme end -->
