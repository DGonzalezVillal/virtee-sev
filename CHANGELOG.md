# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added

- Introduced the `snp::types` module for portable SNP ABI value types shared
  across attestation and platform code. `TcbVersion` is the first type moved
  there; `firmware::host::TcbVersion` remains available as a re-export.
- Moved `GuestPolicy`, `PlatformInfo`, `KeyInfo`, and `Version` into
  `snp::types`; `firmware::guest` re-exports them for compatibility.
- Moved `CertType` and `MaskId` into `snp::types`; `firmware::host`
  re-exports them for compatibility.
- Moved `DerivedKey` and `GuestFieldSelect` into `snp::types::derived_key`;
  `firmware::guest` re-exports them for compatibility.

### Changed

- Grouped attestation report field types under `snp::types::report`
  (`PlatformInfo`, `KeyInfo`). The flat `snp::types` re-exports are unchanged.
- Grouped `Version` and `GuestPolicy` under `snp::types::primitives` and `MaskId`
  under `snp::types::platform_config`. `GuestPolicy` is shared across the
  attestation report, launch, and id-block paths, not report-only. Flat
  re-exports at `snp::types` are unchanged.
- Grouped `DerivedKey` and `GuestFieldSelect` under `snp::types::derived_key`
  for the `SNP_GET_DERIVED_KEY` guest ioctl ABI.
- Removed legacy `sev` from the crate's default features. Defaults are now
  `snp` only, so SNP attestation and verification can be built on non-x86_64
  targets without pulling in first-generation SEV code. Enable the `sev`
  feature explicitly for the full pre-SNP stack: platform APIs, certificate and
  attestation report verification, launch, and session.
