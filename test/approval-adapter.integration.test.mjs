import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startApprovalAdapter } from '../approval-adapter/src/server.mjs';
import * as plugin from '../lib/index.mjs';

function makeCtx() {
  const listeners = new Map();
  const commands = [];
  return {
    logger: { info() {}, warn() {} },
    on(event, fn) { listeners.set(event, fn); },
    get() { return undefined; },
    commands: { register(def) { commands.push(def); } },
    tools: { register() {}, execute() {} },
    _listeners: listeners,
    _commands: commands
  };
}

const ledgerDir = mkdtempSync(join(tmpdir(), 'escrow-adapter-intg-'));
const adapter = await startApprovalAdapter({ port: 0, token: 'integration-token', ttlMs: 5000 });
const headers = { authorization: 'Bearer integration-token', 'content-type': 'application/json' };

try {
  const ctx = makeCtx();
  plugin.apply(ctx, {
    approvalMode: 'adapter',
    approvalAdapterUrl: `http://127.0.0.1:${adapter.port}`,
    approvalAdapterToken: 'integration-token',
    approvalAdapterTimeoutSec: 5,
    ttlSec: 5,
    timeoutPolicy: 'cancel',
    defaultAction: 'yellow',
    builtinRules: true,
    rules: [],
    ledgerDir
  });
  const pre = ctx._listeners.get('tools/pre-execute');
  assert.equal(typeof pre, 'function');
  const circularAgent = { id: 'adapter-agent' };
  circularAgent.self = circularAgent;
  const approval = pre({
    name: 'bash',
    arguments: { command: 'git push origin main --force', remote: 'origin', branch: 'main' },
    callId: 'adapter-call-1',
    agent: circularAgent,
    signal: new AbortController().signal
  }, () => Promise.resolve({ kind: 'allow' }));

  let pending;
  for (let i = 0; i < 30; i += 1) {
    const response = await fetch(`http://127.0.0.1:${adapter.port}/v1/approvals`, { headers });
    pending = (await response.json()).approvals[0];
    if (pending) break;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.ok(pending, 'adapter should expose a pending approval');
  assert.equal(pending.details.remote, 'origin');
  assert.equal(pending.details.branch, 'main');
  assert.equal(pending.riskClass, 'critical-red');

  const decision = await fetch(`http://127.0.0.1:${adapter.port}/v1/approvals/${pending.approvalId}/decision`, {
    method: 'POST', headers, body: JSON.stringify({ outcome: 'allowed-once' })
  });
  assert.equal(decision.status, 200);
  const result = await approval;
  assert.equal(result.kind, 'allow');
  console.log('[approval-adapter] dsh-escrow adapter mode -> structured card -> allowed-once -> execution gate passed');
} finally {
  await adapter.close();
  rmSync(ledgerDir, { recursive: true, force: true });
}
