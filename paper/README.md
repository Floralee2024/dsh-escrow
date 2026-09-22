# dsh-escrow paper package

This directory contains the GitHub-ready artifact paper for **dsh-escrow**.

The paper presents dsh-escrow as a pre-execution escrow mechanism for
irreversible agent actions. It makes a deliberately bounded claim: the
implementation and its tested invariants are documented and reproducible;
the package does **not** claim that agent safety is solved or that the system
is secure against every attacker or runtime.

## Contents

- [`manuscript.md`](manuscript.md) — complete system/artifact paper draft.
- [`experiment-card.json`](experiment-card.json) — formal research question,
  estimands, evidence boundary, and falsifiers.
- [`reproduce.ps1`](reproduce.ps1) — runs the current test suites and records
  the package metadata needed for a local artifact check.

## Current evidence boundary

The v0.3.25 repository currently contains:

The current regression baseline is 107 smoke assertions, 43 taste assertions, and 76 integration assertions, plus host-seam, external-side-effect, and adapter checks.

- unit, taste-state, and plugin integration tests;
- deterministic classifier and never-learn regression cases;
- replay, timeout, late-call, duplicate-call, ledger, HMAC, and migration
  checks;
- multiple independent review rounds and review probes;
- a headless-agent spike for the async placeholder result and `escrow_result`
  polling behavior.

These artifacts support implementation correctness and a bounded behavioral
demonstration. They do not establish a universal security guarantee,
production-scale effectiveness, or a causal reduction in real-world harm.

## Reproduction

From the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\paper\reproduce.ps1
```

The underlying test command is:

```powershell
npm run test:all
```

The paper should be read together with:

- [`../README.md`](../README.md)
- [`../设计-v0.2.md`](../设计-v0.2.md)
- [`../设计-v0.2-评审.md`](../设计-v0.2-评审.md)
- [`../third-party-review/findings-log.md`](../third-party-review/findings-log.md)

