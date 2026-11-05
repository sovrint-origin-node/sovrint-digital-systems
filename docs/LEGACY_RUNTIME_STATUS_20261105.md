# Legacy SOVRINT runtime hardening — review branch (2026-11-05)

**Historical repository:** `sovrint-origin-node/sovrint-digital-systems`. This is not the canonical deployment repository.
**Candidate branch:** `security/auditnode-fail-closed-20261105`. Do not auto-merge or deploy.
**Status:** Local verification candidate; default branch remains untouched.

## Evidence-based corrections
- `AuditNode.js` now verifies synthetic-only ONYX origin/witness Ed25519 signatures against independently pinned trust material. It never reports that facts or institutional claims have been verified, and never asserts `distortionNeutralized: true`.
- `RootCertManager.js`: a name string does not establish a signed certificate. `verified: false`.
- `TokenMint.js`: no signing authority; no token is minted and `verified: false`.
- `TokenValidator.js`: a `SOVRINT.` prefix is insufficient. `valid: false`.
- `OverrideClause.js`: generating override text is not execution. `injected: false`.
- `LineageTrace.js`: caller-supplied mappings are not a verifiable seal. `sealed: false`.
- `GraphRenderer.js`: returning a descriptor does not render. `rendered: false`.
- `CollapseMapper.js`: no live telemetry. Status `SIMULATED_NOT_LIVE`.
- `CorrectionLoop.js`: numerical scaling is explicitly `SIMULATION_ONLY`, `corrected: false`.
- `SignalPulse.js`: demonstrated score is not verified integrity; `integrity: null`.

## Test evidence
- `tests/AuditNode.test.mjs`: 21 adversarial cryptographic and fail-closed cases.
- `tests/legacy_fail_closed.test.mjs`: 13 unverified/simulation assertions.
- Both suites passed under Node.js 22 on 2026-11-05 in a local isolated test. Not evidence of active CI or deployed behavior.

## Scope and preservation
- Historical `main`, Git history, workflows, GitHub Pages and public endpoints remain unchanged pending a deliberate review.
- None of these wrappers can issue authority, create a valid certificate, validate token ownership, prove root identity, modify an institution, or authorize a legal correction.
- The native canonical destinations are private repositories under `SOVRINT-OG`; separately tested AuditNode candidate is proposed in `SOVRINT-OG/integrity-engine` draft PR #4.
- Do not copy the `1.35 MB SOVRINT GENESIS v1.0: Frequency Calibration (220/200)` artifact until its file type, rights, content and sensitivity are separately reviewed.
- Do not import untrusted placeholders or obsolete third-party CI workflows into production.

Copyright (c) Katrina Pietroniro. All rights reserved. Historical attribution preserved.
