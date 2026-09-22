/**
 * 外部副作用与权限分类审计矩阵。
 *
 * 这不是执行测试：所有样本只调用纯分类器，不执行命令。
 * high-risk 样本代表必须进入内置 red 的动作；本命令纳入 test:all。
 */

import assert from 'node:assert/strict';
import { classifyExec } from '../lib/classify.mjs';
import { extractActionDetails, createApprovalPlan, formatApprovalPlan } from '../lib/approval-details.mjs';
import { neverLearnReason } from '../lib/signature.mjs';

const opts = { builtinRules: true, defaultAction: 'yellow', rules: [] };

const highRisk = [
  ['package publish', 'bash', 'npm publish'],
  ['container push', 'bash', 'docker push registry.example/app:latest'],
  ['cluster delete', 'bash', 'kubectl delete deployment app'],
  ['infrastructure apply', 'bash', 'terraform apply plan.tfplan'],
  ['HTTP POST', 'pwsh', 'Invoke-RestMethod https://example.test/api -Method Post -Body $body'],
  ['curl upload', 'bash', 'curl -X POST https://example.test/api -d payload'],
  ['service install', 'pwsh', 'New-Service -Name demo -BinaryPathName C:\\demo.exe'],
  ['privilege elevation', 'pwsh', 'Start-Process powershell -Verb RunAs'],
  ['sudo privilege elevation', 'bash', 'sudo apt-get install package'],
  ['database destruction', 'bash', 'psql -c "DROP DATABASE app"'],
  ['scheduled task creation', 'pwsh', 'schtasks /Create /TN demo /TR demo.exe'],
  ['registry mutation', 'pwsh', 'reg.exe add HKLM\\Software\\Demo /v Enabled /t REG_DWORD /d 1'],
  ['external message tool', 'email.send', null, ['external-write']]
];

const safe = [
  ['local status', 'bash', 'git status'],
  ['local diff', 'bash', 'git diff --stat'],
  ['local commit', 'bash', 'git commit -am update'],
  ['infrastructure plan', 'bash', 'terraform plan'],
  ['package publish preview', 'bash', 'npm publish --dry-run'],
  ['cluster read', 'bash', 'kubectl get pods'],
  ['cluster apply preview', 'bash', 'kubectl apply --dry-run=client -f app.yml'],
  ['helm upgrade preview', 'bash', 'helm upgrade demo chart --dry-run'],
  ['HTTP GET', 'pwsh', 'Invoke-RestMethod https://example.test/api -Method Get'],
  ['package test', 'bash', 'npm test'],
  ['container list', 'bash', 'docker ps'],
  ['source read', 'pwsh', 'Get-Content .\\src\\main.ts']
];

function classify(tool, command, trustedEffects = []) {
  return classifyExec({ name: tool, trustedEffects, arguments: command === null ? { to: 'user@example.test', body: 'message' } : { command } }, opts);
}

console.log('\n[external side-effects audit]');
let gaps = 0;

for (const [label, tool, command, trustedEffects = []] of highRisk) {
  const result = classify(tool, command, trustedEffects);
  const expected = 'red';
  const status = result.action === expected ? 'OK' : 'GAP';
  console.log(`${status}\thigh-risk\t${label}\t${tool}\t${result.action}\t${result.ruleId}`);
  if (status === 'GAP') gaps += 1;
  assert.ok(neverLearnReason(tool, command === null ? { to: 'user@example.test', body: 'message' } : { command }, { trustedEffects }), `high-risk action became learnable: ${label}`);
}

// 工具参数可以携带同名字段，但不能自行声明为可信权限标签。
const untrustedSelfLabel = classifyExec({ name: 'email.send', arguments: { to: 'user@example.test', effects: ['external-write'] } }, opts);
assert.notEqual(untrustedSelfLabel.action, 'red', 'arguments.effects must not become a trusted security decision');
assert.equal(neverLearnReason('email.send', { to: 'user@example.test', effects: ['external-write'] }), null);
const configuredMetadata = classifyExec({ name: 'email.send', arguments: { to: 'user@example.test' } }, {
  ...opts,
  trustedToolEffects: { 'email.send': ['external-write'] }
});
assert.equal(configuredMetadata.action, 'red', 'admin trustedToolEffects must classify non-shell external writes as red');

const criticalRed = [
  ['force push', 'bash', 'git push origin main --force'],
  ['production delete', 'bash', 'kubectl delete deployment prod-api'],
  ['shared delete', 'bash', 'kubectl delete deployment shared-api'],
  ['formal package publish', 'bash', 'npm publish'],
  ['privilege elevation', 'pwsh', 'Start-Process powershell -Verb RunAs'],
  ['security policy change', 'pwsh', 'Set-ExecutionPolicy Bypass -Scope LocalMachine'],
  ['dsh governance change', 'fs.write', null]
];

for (const [label, tool, command] of criticalRed) {
  const exec = command === null
    ? { name: tool, arguments: { path: 'C:/Users/me/.dsh/config.json', content: 'x' } }
    : { name: tool, arguments: { command } };
  const result = classifyExec(exec, opts);
  assert.equal(result.action, 'red', 'critical-red must remain red: ' + label);
  assert.equal(result.risk, 'critical-red', 'critical-red risk missing: ' + label);
  assert.ok(result.criticalReason, 'critical-red reason missing: ' + label);
  console.log('OK\tcritical-red\t' + label + '\t' + result.ruleId);
}

assert.ok(neverLearnReason('bash', { command: 'git push origin main' }), 'ordinary git push must be never-learn');

const customCritical = classifyExec(
  { name: 'bash', arguments: { command: 'deploy-production --delete' } },
  {
    ...opts,
    rules: [{
      id: 'user-production-delete',
      tools: ['bash'],
      args: [{ key: 'command', pattern: 'deploy-production --delete' }],
      action: 'red',
      risk: 'critical-red'
    }]
  }
);
assert.equal(customCritical.risk, 'critical-red', 'user rules must be able to add critical-red action content');
assert.equal(customCritical.source, 'user');

const detailSample = extractActionDetails(
  { name: 'bash' },
  { reason: 'push' },
  JSON.stringify({ command: 'git push origin main' })
);
assert.equal(detailSample.operation, 'git push');
assert.equal(detailSample.remote, 'origin');
assert.equal(detailSample.branch, 'main');
const policyText = formatApprovalPlan(createApprovalPlan({ threshold: 2, cooldownHours: 24, riskClass: 'red' }));
assert.match(policyText, /批准达到2次后，默认冷却期（24小时）结束才自动放行/);
assert.match(policyText, /拒绝达到2次后，后续相同签名直接拒绝/);
const criticalPolicyText = formatApprovalPlan(createApprovalPlan({ threshold: 2, cooldownHours: 24, riskClass: 'critical-red' }));
assert.match(criticalPolicyText, /每次默认需要人工审批/);
assert.match(criticalPolicyText, /拒绝达到2次后，后续相同签名直接拒绝/);
assert.doesNotMatch(criticalPolicyText, /批准达到2次后，默认冷却期/);
assert.doesNotMatch(criticalPolicyText, /立即放行/);
for (const [label, tool, command] of safe) {
  const result = classify(tool, command);
  assert.notEqual(result.action, 'red', `safe control unexpectedly red: ${label}`);
  console.log(`OK\tsafe-control\t${label}\t${tool}\t${result.action}\t${result.ruleId}`);
}

if (gaps > 0) {
  console.error(`\n审计发现 ${gaps} 个外部副作用/权限 red GAP。`);
  process.exitCode = 2;
} else {
  console.log('\n候选外部副作用与权限动作全部进入 red。');
}
