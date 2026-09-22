# Security policy

## Scope

`dsh-escrow` is a pre-execution approval and audit component for DeepSeek Harness. It is not a complete sandbox, policy engine, or proof of agent security.

## Safe deployment notes

- Keep the local approval adapter bound to `127.0.0.1`; do not expose it to a LAN or the public Internet.
- Treat the adapter token as a secret. Prefer `DSH_ESCROW_APPROVAL_TOKEN` or a private profile overlay; do not commit tokens or runtime logs.
- Keep `timeoutPolicy: cancel` unless an explicit operational review justifies another policy.
- Review custom rules and `trustedToolEffects` as administrator-controlled security policy.
- Run `/escrow doctor` and inspect the ledger integrity report after migration or recovery.

## Reporting

For a non-sensitive reproducible bug, open a GitHub issue with the smallest safe reproduction and the exact version. Do not include secrets, tokens, private paths, or raw ledgers.

For a suspected vulnerability, use GitHub's private vulnerability reporting for this repository when available, or contact the maintainer through the GitHub profile before public disclosure.

## Claim boundary

The project tests implemented behavior and selected attack samples. It does not claim universal security, complete classification, resistance to every prompt-injection strategy, or safety of an unreviewed deployment configuration.