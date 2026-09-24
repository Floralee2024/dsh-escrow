import assert from 'node:assert/strict';
import { openApprovalBrowser, startApprovalAdapter } from '../src/server.mjs';

const adapter = await startApprovalAdapter({ port: 0, ttlMs: 5000, token: 'test-token' });
const headers = { authorization: 'Bearer test-token', 'content-type': 'application/json' };
const request = {
  approvalId: 'esc-adapter-test',
  toolName: 'shell',
  reason: '测试审批',
  riskClass: 'red',
  details: { target: 'demo.txt', remote: 'origin', branch: 'main', url: 'https://example.test/repo' },
  approvalPlan: { threshold: 2, cooldownHours: 24, immediateAllow: true, manualWhitelist: true },
  choices: [{ id: 'allowed-once', label: '允许一次' }, { id: 'rejected', label: '拒绝' }]
};

try {
  const created = await fetch(`http://127.0.0.1:${adapter.port}/v1/approvals`, { method: 'POST', headers, body: JSON.stringify(request) });
  assert.equal(created.status, 201);
  const pending = await fetch(`http://127.0.0.1:${adapter.port}/v1/approvals`, { headers });
  const pendingBody = await pending.json();
  assert.equal(pendingBody.approvals[0].details.remote, 'origin');
  assert.equal(pendingBody.approvals[0].details.branch, 'main');

  const wait = fetch(`http://127.0.0.1:${adapter.port}/v1/approvals/${request.approvalId}/wait?waitMs=4000`, { headers });
  await new Promise((resolve) => setTimeout(resolve, 20));
  const decided = await fetch(`http://127.0.0.1:${adapter.port}/v1/approvals/${request.approvalId}/decision`, { method: 'POST', headers, body: JSON.stringify({ outcome: 'allowed-once' }) });
  assert.equal(decided.status, 200);
  assert.deepEqual(await wait.then((response) => response.json()), { outcome: 'allowed-once', source: 'human' });

  const unauthorized = await fetch(`http://127.0.0.1:${adapter.port}/v1/approvals`);
  assert.equal(unauthorized.status, 401);
  console.log('[approval-adapter] structured request -> human decision -> allowed-once passed');
} finally {
  await adapter.close();
}

const opened = [];
const autoOpenAdapter = await startApprovalAdapter({
  port: 0,
  ttlMs: 5000,
  token: 'auto-open-test-token',
  autoOpen: true,
  openBrowser: async (url) => { opened.push(url); }
});
const autoHeaders = { authorization: 'Bearer auto-open-test-token', 'content-type': 'application/json' };
const autoRequest = {
  approvalId: 'esc-auto-open-test',
  toolName: 'bash',
  reason: 'automatic browser-open probe',
  riskClass: 'red'
};
try {
  const autoCreated = await fetch('http://127.0.0.1:' + autoOpenAdapter.port + '/v1/approvals', {
    method: 'POST', headers: autoHeaders, body: JSON.stringify(autoRequest)
  });
  assert.equal(autoCreated.status, 201);
  assert.equal(opened.length, 1, 'first pending approval should request automatic browser open');
  assert.match(opened[0], /token=auto-open-test-token/);

  const seen = await fetch('http://127.0.0.1:' + autoOpenAdapter.port + '/v1/approvals', { headers: autoHeaders });
  assert.equal(seen.status, 200);
  const second = await fetch('http://127.0.0.1:' + autoOpenAdapter.port + '/v1/approvals', {
    method: 'POST', headers: autoHeaders, body: JSON.stringify({ ...autoRequest, approvalId: 'esc-auto-open-test-2' })
  });
  assert.equal(second.status, 201);
  assert.equal(opened.length, 1, 'a recently visible approval page should not be reopened');
  console.log('[approval-adapter] pending approval -> automatic browser-open request -> page presence suppresses duplicate passed');
} finally {
  await autoOpenAdapter.close();
}

const spawnCalls = [];
await openApprovalBrowser('http://127.0.0.1:3099/?token=test', {
  isWsl: true,
  spawnImpl: (command, args, options) => {
    spawnCalls.push({ command, args, options });
    return { unref() {}, once(event, listener) { if (event === 'spawn') queueMicrotask(listener); } };
  }
});
assert.equal(spawnCalls[0].command, 'cmd.exe');
assert.deepEqual(spawnCalls[0].args, ['/c', 'start', '', 'http://127.0.0.1:3099/?token=test']);
console.log('[approval-adapter] WSL browser launcher command passed');
