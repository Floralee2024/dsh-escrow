# Changelog

## 0.3.25 - 2026-09-22

- Fixed local approval adapter requests for real dsh Web agents by removing runtime-only `agent` and `AbortSignal` objects from the JSON payload.
- Added a circular-agent regression test covering the production serialization failure mode.
- Updated public documentation for the adapter, structured approval cards, critical-red and never-learn policy, evidence boundaries, and reproducibility.

## 0.3.24

- Added the local structured approval adapter MVP.
- Added structured action details, external-side-effect classification, critical-red handling, and adapter integration tests.
- Extended the full test command to include host approval, side-effect audit, adapter integration, and adapter server tests.