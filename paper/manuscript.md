# Pre-Execution Escrow for Irreversible Agent Actions

## Fail-Closed Deferred Approval with Pattern-Scoped Never-Learn Invariants

**Artifact:** dsh-escrow v0.3.21
**License:** MIT  
**Status:** reproducible system/artifact paper draft

## Abstract

Agent systems can invoke tools whose effects are difficult or impossible to
undo: deleting a directory, force-pushing a branch, writing credentials, or
modifying the agent's own control files. Conventional permission levels and
post-hoc rollback do not provide a reliable window in which a human can stop
an action before it takes effect. This paper presents **dsh-escrow**, a plugin
for DeepSeek Harness that adds a pre-execution escrow state to the tool
execution lifecycle.

The system classifies tool calls with deterministic rules, places red actions
in a queue, returns a model-visible placeholder without blocking the agent
loop, and executes the original action only after a human decision. Timeout
defaults to denial. Approved actions are replayed through the normal execution
pipeline using a single-use call identifier that is never placed in tool
arguments. The system also introduces a human-decision-driven taste store and
a constitutional never-learn list for destructive, disk-level, and
self-modifying actions.

The artifact includes implementation, regression tests, integration tests,
ledger integrity checks, review probes, design records, and reproduction
instructions. The current evidence establishes tested implementation
invariants and a bounded headless-agent polling behavior. It does not claim
universal security, production-scale effectiveness, or protection against a
fully compromised host or runtime. This claim boundary is part of the design:
security mechanisms should expose what they have measured instead of
converting test completeness into a global safety guarantee.

## 1. Introduction

Tool-using agents create a control problem that is different from ordinary
application authorization. An agent may be allowed to read files and run
tests, yet the same execution surface can also delete data, publish code,
overwrite credentials, or change the instructions that govern future actions.
The problem is intensified in headless settings, where a conventional
interactive approval request can block the agent indefinitely or be
unavailable altogether.

Existing controls commonly occupy one of three states: allow, deny, or ask and
wait. Rollback systems operate after an action has already taken effect. The
missing state is **defer before effect**: preserve the exact proposed action,
show it to an authorized human, and make silence safe.

This paper describes dsh-escrow, a self-contained plugin that adds that state
to DeepSeek Harness without modifying the harness source. The plugin is
designed around five invariants:

1. Approval is a human command, never a model-visible tool.
2. The escrow store and its control files are themselves protected.
3. Destructive and self-modifying categories never enter automatic taste
   learning.
4. A replay exemption is single-use and never appears in model-visible
   arguments.
5. Once an action is classified red, downstream errors do not silently turn it
   into an execution.

The contribution is therefore not a claim that a regex classifier solves
agent safety. It is a concrete execution protocol, a set of explicit safety
invariants, and an artifact whose implementation and failure history can be
inspected and reproduced.

### Contributions

- A non-blocking pre-execution escrow protocol with polling-based result
  retrieval.
- A replay design that preserves the normal tool pipeline while preventing
  recursive re-escrow and duplicate execution.
- A conservative taste-learning design with cooldown and a never-learn
  category for irreversible or self-modifying actions.
- An append-only audit ledger with redaction, hash-chain integrity checks, and
  optional HMAC anchoring.
- An open implementation with tests, review probes, design decisions, and an
  explicit evidence boundary.

## 2. Problem Definition and Scope

Let a tool call be \(a=(n,\theta,s)\), where \(n\) is a tool name, \(\theta\) is its argument object, and \(s\) is session metadata. The escrow layer maps
the call to a deterministic classification:

\[
  c(a) \in \{\text{green},\text{yellow},\text{red}\}.
\]

Green calls are allowed. Yellow calls are allowed and recorded. Red calls are
held in an escrow queue. A human decision (d) then determines whether the
original call is denied, expires, or is replayed once.

The system addresses **unintended or unauthorized execution by an agent** in
the tool lifecycle. It does not attempt to defend against an attacker that
already controls the host, the JavaScript runtime, the plugin source, or both
the ledger and its key material. It also does not infer whether a command is
morally or operationally appropriate beyond the configured classification
rules.

## 3. Threat Model and Claim Boundary

### 3.1 In-scope failure modes

The artifact treats the following as security-relevant failures:

- a red action executes without the required decision;
- a timeout or abort accidentally releases a red action;
- a late duplicate call executes after the original escrow item settled;
- an approved action executes twice;
- the model reaches the approval command through its visible tool surface;
- repeated approval automatically whitelists a never-learn category;
- an agent edits escrow state, its own instructions, or profile configuration
  without the self-modification policy applying;
- an audit ledger silently loses integrity or leaks credentials.

### 3.2 Out-of-scope capabilities

The current artifact does not establish protection from:

- a fully compromised host or runtime;
- an attacker that can modify both ledger contents and HMAC keys;
- unrecognized shell semantics outside the tested command corpus;
- vulnerabilities in the underlying harness or operating system;
- a malicious plugin that bypasses the normal tool lifecycle;
- every possible prompt-injection strategy.

The distinction matters: passing a test proves the encoded behavior for that
test. It does not prove the specification is complete or that all tool paths
are covered.

## 4. System Design

### 4.1 Execution lifecycle

The main lifecycle is:

```text
model tool call
    |
    v
tools/pre-execute
    |-- replay exemption -> allow once
    |-- taste allow       -> allow when policy permits
    |-- green/yellow      -> allow (yellow is logged)
    `-- red              -> enqueue escrow item, then allow to execute hook
                                      |
                                      v
                               tools/execute
                                  |-- pending item -> synthetic result
                                  `-- approved replay -> real execution

human command /escrow approve <id>
    -> mint one-time replay callId
    -> execute through the normal pipeline
    -> consume exemption and store the real result

model-visible escrow_result(id)
    -> pending / executed / denied / expired
```

The pre-execute hook performs classification and queueing. In async mode the
agent receives a valid foreground-shaped synthetic result immediately; it can
continue unrelated work or poll `escrow_result`. The synthetic result does
not claim that the action executed.

### 4.2 Deterministic classification

The classifier uses explicit rules for dangerous commands and sensitive paths.
Examples include recursive deletion, forceful Git operations, disk formatting,
credential paths, private keys, and writes to the escrow or agent-control
directories. Matching is case-insensitive under the Windows-oriented policy.

User rules can make an action more restrictive or classify an otherwise
unmatched action, but a user green rule cannot suppress an intrinsic red match.
The classifier does not use an AI model for the security decision. The current normalization covers the tested Windows-oriented command forms, including quoted paths, simple glob markers, and simple shell-variable assignments; full shell parsing, command substitution, aliases, and encoded paths remain outside the claim boundary.

### 4.3 Non-blocking escrow and safe silence

The default mode is asynchronous. A red call is represented by an escrow ID,
not executed, and made queryable. The default timeout policy is `cancel`, so
no human decision is interpreted as a denial. `ttlSec: 0` provides an
immediate fail-closed posture for CI and headless environments. Synchronous
mode and per-tool synchronous escape hatches remain available for operations
whose later steps require the true result of a write.

### 4.4 Replay without recursion or duplication

Approval must eventually execute the exact action that the human saw, but a
normal replay would encounter the red classifier again. dsh-escrow therefore
mints a random call identifier at approval time and binds it to the queued
action. The identifier is checked in the pre-execute and execute paths,
consumed once, and never placed in the arguments visible to the model.

The queue retains settled identities long enough to reject late original
calls. This prevents a denied or already-approved original invocation from
falling through to an unguarded downstream executor.

### 4.5 Taste learning and never-learn categories

Taste learning is intended to reduce repeated human interruptions for stable,
low-risk signatures. It is deliberately not a general allowlist learner:

- repeated human approvals move a signature through learning and cooldown;
- repeated human denials can create a blacklist decision;
- timeouts and cancellations do not count as negative human decisions;
- dangerous and self-modifying categories never become automatically
  whitelisted;
- imported entries require review before activation;
- plugin identity changes invalidate active learned entries for review.

The never-learn policy covers destructive recursive operations, force flags,
disk operations, workspace-discard operations, and self-modification. A human
may still make an explicit manual exception, but that exception is not
silently inferred from repeated approvals.

### 4.6 Audit ledger

The ledger is append-only JSONL. Sensitive values are redacted before storage.
The current implementation supports hash chaining, HMAC authentication,
rotation, legacy detection, migration, session metadata, and report/reduce
views. A legacy-format ledger is read-only until an explicit /escrow migrate operation succeeds; user-supplied h and m fields are preserved under payload_h and payload_m so they cannot overwrite chain fields. The integrity model is intentionally stated narrowly: it detects unnoticed corruption and, with an available key, makes offline recomputation harder. It is not a defense against an attacker who controls both the ledger and the key.

## 5. Implementation Artifact

The implementation is a small ESM plugin with the following module split:

| Module | Responsibility |
|---|---|
| `lib/classify.mjs` | deterministic action and path classification |
| `lib/queue.mjs` | escrow state machine, deduplication, settlement |
| `lib/replay.mjs` | approved/timeout replay lifecycle |
| `lib/synth-result.mjs` | schema-shaped placeholder results |
| `lib/signature.mjs` | conservative signature extraction and never-learn rules |
| `lib/taste.mjs` | learning, cooldown, blacklist, import/export |
| `lib/ledger.mjs` | redacted append-only ledger and integrity checks |
| `lib/report.mjs` | statistics, integrity and human-attention report |
| `lib/reduce.mjs` | duplicate-action and SNR-lite analysis |
| `lib/index.mjs` | Cordis hook and tool integration |

The repository also includes the design review, spike decision, third-party
review prompts and probes, and regression suites. These records are part of
the artifact rather than informal background: they show how several
implementation failures were found, reproduced, and repaired.

## 6. Evaluation Evidence

### 6.1 Current repository verification

The v0.3.21 package exposes three test entry points through npm run test:all:

1. classifier, queue, ledger, M7, M8, M6, HMAC and migration smoke tests;
2. taste/signature state-machine tests;
3. plugin-level integration tests using a mock Cordis context and a complete
   pre-execute/execute replay path.

The current checked repository reports 107 smoke assertions, 43 taste
assertions, and 75 integration assertions, for 225 passing assertions. The
tests cover encoded invariants such as:

- red classification and sensitive-path detection;
- immediate timeout denial and abort handling;
- pending signature deduplication;
- one-time replay and late-call rejection;
- release and async replay behavior;
- never-learn coverage for recursive deletion and workspace discard;
- self-modification governance;
- ledger redaction, chain integrity, HMAC mismatch and migration;
- report and reduce accounting.

This is implementation evidence. The denominator is the repository test
suite, not the space of possible attacks.

### 6.2 Headless-agent spike

The project includes a headless-agent spike in which a red call received a
schema-valid synthetic result, did not repeatedly invoke the same command,
and polled `escrow_result` for the pending state. This supports the feasibility
of the async interaction under that specific harness and prompt context. It
does not estimate behavior across models, prompts, or workloads.

### 6.3 Independent review evidence

The third-party review rounds identified and checked issues involving:

- replay and late-call double execution;
- argument snapshot mutation;
- dangerous command coverage;
- self-modification and never-learn alignment;
- ledger rotation and chain verification;
- HMAC and migration guards.

The review records are valuable evidence of engineering process and concrete
failure handling. They are not equivalent to an independent security
certification. The reviewer had access to the repository and review probes,
and the remaining accepted limitations are documented in the findings log.

## 7. Evaluation Protocol for Stronger Claims

The artifact contains an experiment card for the next evidence level. A full
effectiveness evaluation should compare:

- unguarded execution;
- synchronous approval;
- async escrow without taste learning;
- async escrow with taste learning and never-learn rules.

The same deterministic workload should be replayed across conditions. The
workload should include destructive filesystem operations, forceful Git
operations, credential-path writes, self-modification, benign near misses,
timeouts, aborts, duplicate calls, late calls, replay reuse, and attempts to
reach approval through the model-visible tool surface.

Primary measurements should include unauthorized execution rate, replay
double-execution rate, self-approval rate, never-learn violations,
false-positive interception, task completion, approval latency, agent retry
rate, and pre-execute overhead. The workload should use a fake or isolated
executor; the experiment must not execute real destructive commands.

The strongest claim that this protocol could support is conditional:

> Under the stated harness, workload, and attacker model, dsh-escrow reduced
> the measured rate of unauthorized irreversible execution while preserving a
> stated task-completion and operator-cost profile.

Even that claim would remain conditional on the tested environment.

## 8. Limitations

The current artifact has five important limitations.

First, the classifier is deterministic but necessarily incomplete. The tested
normalization covers quoted paths, simple glob markers, and simple shell-variable
assignments, but unknown shell syntax, command substitution, aliases, encoded
paths, or a new tool can fall outside the rule corpus.

Second, the tests are primarily implementation and integration tests. They do
not provide a broad population estimate of attack success or false positives.

Third, the taste store is a usability mechanism with security constraints,
not an oracle of human intent. A human can still manually approve an unsafe
action, and fatigue or social engineering are not eliminated by a queue.

Fourth, async execution introduces a semantic hazard: the agent may continue
with work that depends on a result that has not arrived. The `syncTools` escape
hatch and polling interface reduce this hazard but do not prove that a model
will always use them correctly.

Fifth, the ledger integrity mechanism has a bounded threat model. It supports
auditability, not an external tamper-proof log or a trusted hardware root.
Legacy ledgers require explicit migration before new writes are accepted.
Rotation intentionally exposes main and backup generations together for review,
so cross-generation action IDs can make aggregate reports ambiguous.

## 9. Reproducibility and Responsible Use

The repository is MIT licensed. The paper package can be checked with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\paper\reproduce.ps1
```

When deploying the plugin, users should begin with `ttlSec: 0` in unattended
contexts, keep builtin rules enabled, review custom green rules carefully,
avoid automatic learning for destructive signatures, and treat the ledger as
an audit aid rather than a substitute for host isolation or backups.

## 10. Conclusion

dsh-escrow adds a practical fourth state to agent tool execution: neither
immediate allow, immediate deny, nor blocking ask, but a pre-execution escrow
window in which a human can approve or cancel an exact action. Its technical
value lies in the interaction between asynchronous control flow, replay
identity, deterministic classification, conservative learning, self-change
governance, and auditability.

The current artifact is sufficient for a reproducible system/artifact paper
with a bounded claim. A stronger security-effectiveness paper requires the
baseline and independent attack evaluation described above. Keeping that
distinction explicit is itself a safety property of the publication.

## References and project records

- [dsh-escrow README](../README.md)
- [v0.2 design](../设计-v0.2.md)
- [design review](../设计-v0.2-评审.md)
- [S0 spike conclusion](../S0-spike-结论.md)
- [third-party findings log](../third-party-review/findings-log.md)
- [third-party review package](../third-party-review/README.md)
- [Agent Inbox](https://github.com/Zijian-Ni/agent-inbox)
- [Agent Patterns Catalog: Approval Queue](https://agentpatternscatalog.github.io/patterns/patterns/approval-queue.html)
- [PydanticAI](https://github.com/pydantic/pydantic-ai)

