# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added

- Introduced the `snp::types` module for portable SNP ABI value types shared
  across attestation and platform code. `TcbVersion` is the first type moved
  there; `firmware::host::TcbVersion` remains available as a re-export.
- Moved `GuestPolicy` and `Version` into `snp::types`.
- Moved `CertType` and `MaskId` into `snp::types`; `firmware::host`
  re-exports them for compatibility.
- Moved `DerivedKey` and `GuestFieldSelect` into `snp::types::derived_key`.
- Introduced the `attestation` module with `attestation::evidence::snp` for
  SNP attestation report types (`Report`, `ReportBody`, `ReportVariant`,
  `KeyInfo`, `PlatformInfo`).
- Introduced `attestation::verifier::snp` for SNP report signature
  verification and the verified `ReportBody` conversion path.
- Introduced `attestation::endorser::snp` for SNP endorsement chains
  (`Certificate`, `Chain`, `ca`, `builtin`).
- Moved the SNP `Verifiable` trait and all verification impls into
  `attestation::verifier`.
- Moved SNP report signature wire types (`SignatureAlgorithm`, `Signature`)
  into `attestation::evidence::snp` and ECDSA verification into
  `attestation::verifier::snp`.
- Introduced `attestation::attester::snp` for the SNP guest attester role
  (`attestation::attester::snp::Firmware`).
- Introduced `attestation::reference::snp::idblock` and
  `attestation::reference::snp::measurement` for SNP ID block and launch
  digest reference calculation. Shared helpers (`sev_hashes`) live directly
  under `attestation::reference`.
- Moved guest launch types into `snp::types::launch` (OVMF metadata layouts,
  QEMU vCPU models, OVMF firmware parsing, and SEV-ES VMSA save-area pages).

### Changed

- Moved `PlatformInfo` and `KeyInfo` to `attestation::evidence::snp::fields`.
  These are grouped report-body parsing views, not standalone SNP ABI types.
- Grouped `Version` and `GuestPolicy` under `snp::types::primitives` and `MaskId`
  under `snp::types::platform_config`. `GuestPolicy` is shared across the
  attestation report, launch, and id-block paths, not report-only. Flat
  re-exports at `snp::types` are unchanged.
- Grouped `DerivedKey` and `GuestFieldSelect` under `snp::types::derived_key`
  for the `SNP_GET_DERIVED_KEY` guest ioctl ABI.
- Moved `Report`, `ReportBody`, and `ReportVariant` from the guest firmware
  path into `attestation::evidence::snp`, split across `report`, `body`, and
  `variant` submodules. Flat re-exports at `attestation` are unchanged.
- Moved SNP report verification (`Verifiable` impls and verified
  `ReportBody` `TryFrom` paths) from `attestation::evidence::snp::report` into
  `attestation::verifier::snp`. Evidence retains framing and parse-only APIs.
- Moved SNP certificate chain types (`Certificate`, `Chain`, `ca`, `builtin`)
  from `certs::snp` into `attestation::endorser::snp`.
- Moved the SNP `Verifiable` trait and verification impls (certificate,
  chain, report signature, and report appraisal) into
  `attestation::verifier`.
- Removed `certs::snp`. SNP attestation now lives entirely under
  `attestation`; `certs` is legacy SEV only (`feature = "sev"`).
- Removed the `firmware::guest::types` shim. Guest attestation device access
  moved to `attestation::attester::snp::Firmware`.
- Moved SNP guest firmware ioctl definitions from `firmware::linux::guest`
  into `firmware::guest`.
- Moved SNP launch digest and ID block wire types into `snp::types`
  (`SnpLaunchDigest`, `FamilyId`, `ImageId`, `IdBlock`, `IdAuth`, and related
  ECDSA wire layouts). OpenSSL conversions remain in
  `attestation::reference`.
- Moved QEMU vCPU model types (`CpuType`, `cpu_sig`) into
  `snp::types::launch::vcpu`. Removed `attestation::reference::vcpu_types`.
- Reorganized `attestation::reference::snp` into `reference::snp::idblock`
  and `reference::snp::measurement`. `IdMeasurements` lives in
  `reference::snp::idblock`; wire types remain in `snp::types`. Removed
  `reference::snp::idblock_types`.
- Reorganized `attestation::reference` into `reference::snp` and
  `reference::sev`. Shared helpers (`sev_hashes`, `digest`) live directly
  under `attestation::reference`.
- Removed the unused top-level `vmsa` module (superseded by
  `snp::types::launch::vmsa`).
- Removed legacy `sev` from the crate's default features. Defaults are now
  `snp` only, so SNP attestation and verification can be built on non-x86_64
  targets without pulling in first-generation SEV code. Enable the `sev`
  feature explicitly for the full pre-SNP stack: platform APIs, certificate and
  attestation report verification, launch, and session.
