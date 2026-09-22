import assert from 'node:assert/strict';
import { startApprovalAdapter } from '../src/server.mjs';

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
