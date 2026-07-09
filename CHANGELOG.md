# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Changed

- Removed legacy `sev` from the crate's default features. Defaults are now
  `snp` only, so SNP attestation and verification can be built on non-x86_64
  targets without pulling in first-generation SEV code. Enable the `sev`
  feature explicitly for the full pre-SNP stack: platform APIs, certificate and
  attestation report verification, launch, and session.
