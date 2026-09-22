import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const plugin = await import('../lib/index.mjs');

const dir = mkdtempSync(join(tmpdir(), 'escrow-host-'));
try {
  const listeners = new Map();
  const requests = [];
  let realRuns = 0;
  const commands = [];
  const tools = {
    registered: [],
    register(def) { this.registered.push(def); },
    async execute(input) {
      const pre = listeners.get('tools/pre-execute');
      const preResult = await pre(input, async () => ({ kind: 'allow' }));
      if (preResult.kind === 'deny') return { isError: true, error: { message: preResult.reason } };
      const execute = listeners.get('tools/execute');
      return execute(input, async () => {
        realRuns += 1;
        return { isError: false, value: { stdout: { text: 'ESCROW_HOST_REAL_OUTPUT' } } };
      });
    }
  };
  const hostApproval = {
    request(req) {
      return new Promise((resolve) => requests.push({ req, resolve }));
    }
  };
  const ctx = {
    logger: { info() {}, warn() {} },
    get(name) { return name === 'approval' ? hostApproval : undefined; },
    on(name, fn) { listeners.set(name, fn); },
    commands: { register(def) { commands.push(def); } },
    tools
  };
  const api = plugin.apply(ctx, {
    approvalMode: 'host',
    mode: 'sync',
    ttlSec: 30,
    timeoutPolicy: 'cancel',
    defaultAction: 'yellow',
    builtinRules: true,
    rules: [],
    ledgerDir: dir,
    learnThreshold: 1,
    rules: [{ id: 'host-learnable-red', tools: ['bash'], args: [{ key: 'command', pattern: '^echo approval-test$' }], action: 'red' }]
  });

  const agent = { id: 'host-test-agent', session: { events: [] } };
  const input = {
    name: 'bash',
    arguments: { command: 'git push origin main' },
    callId: 'host-call-1',
    agent,
    signal: new AbortController().signal
  };
  const pending = tools.execute(input);
  await new Promise((resolve) => setTimeout(resolve, 25));
  assert.equal(requests.length, 1, 'host approval request should be created once');
  assert.equal(realRuns, 0, 'real execution must wait for host approval');
  assert.equal(requests[0].req.toolName, 'bash');
  assert.equal(requests[0].req.callId, 'host-call-1');
  assert.match(requests[0].req.reason, /托管编号 esc-/);
  assert.match(requests[0].req.reason, /允许一次；/);
  assert.match(requests[0].req.reason, /拒绝达到1次后/);
  assert.equal(requests[0].req.details.remote, 'origin');
  assert.equal(requests[0].req.details.branch, 'main');
  assert.equal(requests[0].req.riskClass, 'red');
  assert.ok(Array.isArray(requests[0].req.choices));
  assert.ok(requests[0].req.choices.some((choice) => choice.id === 'allowed-and-manual-whitelist'));

  requests[0].resolve('allowed-once');
  const result = await pending;
  assert.equal(result.isError, false);
  assert.equal(realRuns, 1, 'one host approval must produce exactly one real execution');

  const input2 = {
    name: 'bash',
    arguments: { command: 'echo approval-test' },
    callId: 'host-call-2',
    agent,
    signal: new AbortController().signal
  };
  const pending2 = tools.execute(input2);
  await new Promise((resolve) => setTimeout(resolve, 25));
  assert.equal(requests.length, 2, 'second red action should create a second host approval request');
  assert.ok(requests[1].req.choices.some((choice) => choice.id === 'allowed-now'));
  requests[1].resolve('allowed-now');
  const result2 = await pending2;
  assert.equal(result2.isError, false);
  assert.equal(realRuns, 2, 'allowed-now should still execute exactly once');
  assert.equal(api.taste.check('echo approval-test'), 'allow', 'threshold=1 + allowed-now should activate the signature');

  const text = await tools.registered.find((tool) => tool.name === 'escrow_result').execute({ id: 'missing' });
  assert.equal(text.status, 'expired');
  console.log('[host-approval] visible-seam contract passed: pending -> allowed-once -> one real execution');
} finally {
  rmSync(dir, { recursive: true, force: true });
}