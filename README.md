# dsh-escrow

**Pre-execution escrow and fail-closed human approval for irreversible agent actions.**

`dsh-escrow` is a plugin for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness). It classifies tool calls before execution, places high-risk actions in an escrow window, and releases them only after an explicit decision. Silence, timeout, adapter failure, and unknown outcomes do not release an action.

> **Current release: v0.3.26.** This repository is a system/artifact prototype. Its tests document implemented invariants and exercised behaviors; they do not prove universal security, production-scale effectiveness, or safety against every attacker.

## What it provides

- Deterministic pre-execution classification for shell and trusted non-shell effects.
- `green` / `yellow` / `red` routing with built-in coverage for destructive, privileged, external-side-effect, shared-resource, and governance actions.
- Synchronous human approval for `host` or local `adapter` mode; asynchronous queueing with `escrow_result` for the default `queue` mode.
- One-shot replay tokens, same-signature deduplication, late-call protection, and fail-closed red-path handling.
- Structured approval details: operation, target, remote, branch/ref, URL, database/schema, resource, permission scope, tool, risk class, and learning policy.
- A dependency-free local approval adapter that renders a browser card on `127.0.0.1`.
- Append-only redacted ledger records with hash-chain and HMAC integrity checks, migration, replay, reporting, and doctor commands.
- Explicit never-learn handling for critical actions such as force push, recursive deletion, disk/system operations, external publishing, privilege elevation, shared-resource deletion, and dsh governance changes.

## Why escrow?

Permission presets and post-hoc rollback answer “what can be attempted” or “how can damage be repaired.” Escrow adds a decision point **before the side effect takes place**. A red action is not treated as successful merely because it was queued, and a missing human decision is not interpreted as consent.

## Install from GitHub

Prerequisites: Node.js 18+ and an installed DeepSeek Harness profile.

```powershell
git clone https://github.com/Floralee2024/dsh-escrow.git
cd dsh-escrow
dsh plugin --profile web add .
```

Restart the dsh profile after installing or changing the plugin. If you install from another directory on Windows, pass that directory as the plugin path instead of the example `.`.

## Quick start: local approval adapter

The adapter is an MVP replacement approval surface. It binds to loopback, keeps pending requests in memory, supports the two stable one-shot outcomes currently used by the host protocol (`allowed-once` and `rejected`), and automatically opens the local approval page when a new request arrives if no approval page is currently visible.

Start it from the repository root:

```powershell
node approval-adapter/bin/dsh-escrow-approval-adapter.mjs --port 3099
```

The adapter attempts to open the tokenized local URL automatically. If the environment is headless or the launcher is unavailable, open the printed local URL manually. Do not expose the adapter on a LAN or public interface.

Configure the dsh profile without committing the token:

```yaml
- id: escrow
  config:
    approvalMode: adapter
    approvalAdapterUrl: http://127.0.0.1:3099
    approvalAdapterTimeoutSec: 300
    mode: sync
    ttlSec: 300
    timeoutPolicy: cancel
    defaultAction: yellow
    builtinRules: true
```

Set the token in the process environment, or put it in a private profile overlay:

```powershell
$env:DSH_ESCROW_APPROVAL_TOKEN = '<token printed by the adapter>'
```

The end-to-end flow is:

```text
3081 Web session
  -> dsh tool call
  -> dsh-escrow tools/pre-execute
  -> POST 127.0.0.1:3099/v1/approvals
  -> structured approval card
  -> human clicks “允许一次” or “拒绝”
  -> the original tool call is released or denied
  -> result returns to the 3081 session
```

The adapter UI deliberately exposes only the MVP buttons. `approve-now` and explicit manual whitelist decisions remain available through the `/escrow` command surface; richer adapter buttons require a compatible host protocol extension.

## Approval card and policy

A card includes the tool, risk class, reason, approval id, and structured action fields where available. It also states the applicable learning policy.

- Normal learnable red actions: after two approvals, the default policy waits for a 24-hour cooling period before automatic allow. A configured immediate-allow learning choice is available in the protocol payload, but is not rendered as an adapter MVP button.
- Two decisions rejecting the same signature activate the learned deny path.
- `never-learn` actions never become automatically allowed, regardless of approval count. They can only be added by an explicit `/escrow allow` action, with the associated risk left to the administrator.
- `critical-red` is reserved for actions such as force push, production/shared-resource deletion, formal package publishing, privilege elevation, security-policy changes, and dsh governance changes. These require an explicit decision each time.
- Classification is based on the action representation, not on a claim such as `-WhatIf`; a dry-run command can still require review.

## Command surface

```text
/escrow pending
/escrow approve <id>
/escrow approve-now <id>
/escrow approve-and-allow <id>
/escrow deny <id>
/escrow allowlist
/escrow allow <signature>
/escrow deny <signature>
/escrow forget <signature>
/escrow approve all
/escrow deny all
/escrow export [path]
/escrow import <path>
/escrow reduce [--since 7d]
/escrow migrate
/escrow doctor
/escrow stats
```

`queue` mode is asynchronous and returns a synthetic foreground result while the action remains pending. `host` and `adapter` modes are synchronous and wait for the decision. Any unavailable approval path or timeout is fail-closed under `timeoutPolicy: cancel`.

## Configuration

The main configuration is applied through the profile's `cordis.patch.yml`:

```yaml
- id: escrow
  config:
    ttlSec: 300
    timeoutPolicy: cancel       # cancel | release | hold
    defaultAction: yellow       # green | yellow | red
    builtinRules: true
    mode: async                 # async | sync
    approvalMode: queue          # queue | host | adapter
    approvalAdapterUrl: http://127.0.0.1:3099
    approvalAdapterToken: ''     # prefer DSH_ESCROW_APPROVAL_TOKEN
    approvalAdapterTimeoutSec: 300
    learnWhitelist: true
    learnThreshold: 2
    autoBlacklist: true
    cooldownHours: 24
    approvalChoices:
      immediateAllow: true
      manualWhitelist: true
    selfModification:
      red: true
    trustedToolEffects:
      - tool: email.send
        effects: [external-write]
      - tool: browser.publish
        effects: [external-write, shared-resource-write]
```

User rules are deterministic and first-match-wins. A user `green` rule cannot suppress an internal red rule. Non-shell tools must receive trusted effects from the host or administrator; tool arguments and MCP annotations cannot self-declare that an action is safe.

## Ledger and integrity

Decisions are written to `$DSH_HOME/.dsh-escrow/ledger.jsonl` after secret redaction. The ledger records observations, queued actions, decisions, waiting time, tool identity, and session identity. Size limits rotate the active file to `ledger.jsonl.bak`.

Each current-format row carries a SHA-256 chain value and HMAC. `/escrow doctor` reports integrity, key mismatch, legacy rows, schema problems, and classifier performance. Legacy rows must be migrated before the ledger can provide the full current integrity guarantee.

The integrity design protects against accidental or unnoticed tampering and against an attacker who can rewrite the chain but does not possess the HMAC key. It does not protect against an attacker who can modify both the ledger and its key, nor does it establish that the surrounding runtime is trustworthy.

## Tests and reproduction

Run from the repository root:

```powershell
npm test
npm run test:taste
npm run test:integration
npm run test:host
npm run test:side-effects
npm run test:all
```

The current full suite covers 107 smoke assertions, 43 taste-state assertions, 76 plugin integration assertions, the visible host seam, external-side-effect classification, adapter integration, and adapter server behavior. The test suite is executable evidence for these cases, not a universal security proof.

The paper artifact is in [`paper/`](paper/):

- [`paper/manuscript.md`](paper/manuscript.md) — system/artifact paper draft;
- [`paper/experiment-card.json`](paper/experiment-card.json) — claim boundary and falsifiers;
- [`paper/reproduce.ps1`](paper/reproduce.ps1) — reproducibility entry point.

## Known limitations

- The local adapter is an in-memory MVP. Restarting it safely loses pending requests and causes the waiting call to fail closed.
- The adapter is loopback-only and has no multi-user identity, durable storage, TLS, or remote notification service.
- The current adapter card supports only `allowed-once` and `rejected`; richer learning choices remain command-based.
- The classifier is deterministic but not complete. A tool or effect not represented in the configured rules may be misclassified.
- The repository does not claim to prove security, eliminate prompt injection, or replace deployment-specific threat modeling and operational review.

## Related material

- [`approval-adapter/README.md`](approval-adapter/README.md)
- [`设计-v0.2.md`](设计-v0.2.md)
- [`红灯细分规则-v0.4.md`](红灯细分规则-v0.4.md)
- [`third-party-review/`](third-party-review/)
- [`paper/`](paper/)

## License

MIT. See [`LICENSE`](LICENSE).