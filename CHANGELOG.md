# Changelog

Keep a Changelog format; Semantic Versioning for tagged releases. Dates are Europe/Istanbul.

## [Unreleased]
### Changed
- Documents are now licensed under CC BY 4.0 (attribution required); software stays MIT in `LICENSE-CODE`. Added ATTRIBUTION.md. Earlier copies remain under MIT for those who received them.
### Added
- Restore drill evidence: `--evidence` writes a sealed JSON record (measured RTO, simulated RPO, targets from `examples/backup/recovery-objectives.json`, SHA-256 or HMAC-SHA256 seal); `tools/verify_evidence.py` verifies it; auditor mapping in `docs/backup-recovery.md`.
- CONTRIBUTING, SECURITY, FAQ and known limitations, MIT license file (where missing), CI workflow draft.
- scripts/check_redaction.py with tests: flags IPv4 addresses outside RFC 5737 ranges and e-mail addresses.
