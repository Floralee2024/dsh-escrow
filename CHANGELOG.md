# Changelog

## 0.3.26 - 2026-09-24

- CLI now accepts DSH_ESCROW_APPROVAL_TOKEN as the adapter token fallback, keeping WSL adapter and dsh Web authentication aligned.
- Added automatic local browser opening when a new approval request arrives and no approval page has been seen recently.
- Added duplicate-open suppression while the approval page is active, plus the --no-open flag for headless environments.
- Added regression coverage for automatic open requests and visible-page suppression.

## 0.3.25 - 2026-09-22

- Fixed local approval adapter requests for real dsh Web agents by removing runtime-only `agent` and `AbortSignal` objects from the JSON payload.
- Added a circular-agent regression test covering the production serialization failure mode.
- Updated public documentation for the adapter, structured approval cards, critical-red and never-learn policy, evidence boundaries, and reproducibility.

## 0.3.24

- Added the local structured approval adapter MVP.
- Added structured action details, external-side-effect classification, critical-red handling, and adapter integration tests.
- Extended the full test command to include host approval, side-effect audit, adapter integration, and adapter server tests.