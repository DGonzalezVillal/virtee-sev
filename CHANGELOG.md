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
- Removed the `firmware::guest::types` shim. `firmware::guest` now holds only
  the guest device API (`Firmware`) and re-exports `DerivedKey` and
  `GuestFieldSelect` for the Linux ioctl layer.
- Removed legacy `sev` from the crate's default features. Defaults are now
  `snp` only, so SNP attestation and verification can be built on non-x86_64
  targets without pulling in first-generation SEV code. Enable the `sev`
  feature explicitly for the full pre-SNP stack: platform APIs, certificate and
  attestation report verification, launch, and session.
