/**
 * dsh-escrow 纯模块冒烟测试（classify / queue / ledger，不依赖 dsh 运行时）。
 * 运行：node test/smoke.test.mjs
 *
 * v0.1.1：修复测试挂起（pendingList 用例残留 60s 定时器）；
 * 新增「安全回归」区——每条对应一个实测复现过的攻击样本或 bug。
 */

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, existsSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { classifyExec, globToRegExp } from '../lib/classify.mjs';
import { createQueue, signatureHash } from '../lib/queue.mjs';
import { createLedger } from '../lib/ledger.mjs';
import { synthForeground, placeholderText } from '../lib/synth-result.mjs';
import { computeReduce, readLedgerLines } from '../lib/reduce.mjs';
import { computeReport } from '../lib/report.mjs';

let passed = 0;
function ok(name, fn) {
  try {
    fn();
    passed += 1;
    console.log(`  ✓ ${name}`);
  } catch (e) {
    console.error(`  ✗ ${name}\n    ${e.message}`);
    process.exitCode = 1;
  }
}
async function okAsync(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  ✓ ${name}`);
  } catch (e) {
    console.error(`  ✗ ${name}\n    ${e.message}`);
    process.exitCode = 1;
  }
}
const ctx = { rules: [], builtinRules: true, defaultAction: 'yellow' };

console.log('\n[classify 基础]');
ok('globToRegExp 基础匹配', () => {
  assert.equal(globToRegExp('bash').test('bash'), true);
  assert.equal(globToRegExp('mcp__*').test('mcp__github'), true);
  assert.equal(globToRegExp('*').test('any-tool'), true);
  assert.equal(globToRegExp('**/.env*').test('C:/Users/me/proj/.env'), true);
  assert.equal(globToRegExp('**/.env*').test('src/index.js'), false);
  assert.equal(globToRegExp('**/.ssh/**').test('C:/Users/me/.ssh/id_rsa'), true);
});
ok('rm -rf 命中内置危险命令 → red', () => {
  const r = classifyExec({ name: 'bash', arguments: { command: 'rm -rf /tmp/foo' } }, ctx);
  assert.equal(r.action, 'red');
});
ok('git push → red', () => {
  const r = classifyExec({ name: 'bash', arguments: { command: 'git push origin main' } }, ctx);
  assert.equal(r.action, 'red');
});
ok('普通 ls 命令 → 默认 yellow', () => {
  const r = classifyExec({ name: 'bash', arguments: { command: 'ls -la' } }, ctx);
  assert.equal(r.action, 'yellow');
});
ok('.env 敏感路径写 → red', () => {
  const r = classifyExec({ name: 'fs.write', arguments: { path: 'C:/Users/me/proj/.env' } }, ctx);
  assert.equal(r.action, 'red');
});
ok('file_uri 键指向敏感路径 → red（M2 审查补充：路径键变体覆盖）', () => {
  const r = classifyExec({ name: 'fs.write', arguments: { file_uri: 'file:///C:/Users/me/proj/.env' } }, ctx);
  assert.equal(r.action, 'red');
});
ok('普通文件写 → 默认 yellow', () => {
  const r = classifyExec({ name: 'fs.write', arguments: { path: 'C:/Users/me/proj/src/index.js' } }, ctx);
  assert.equal(r.action, 'yellow');
});
ok('mcp 工具（未命中规则）→ 默认 yellow', () => {
  const r = classifyExec({ name: 'mcp__github.createIssue', arguments: {} }, ctx);
  assert.equal(r.action, 'yellow');
});
ok('用户规则 first-match-wins（无内置命中时 green 生效）', () => {
  const rules = [{ id: 'allow-ls', tools: ['bash'], args: [{ key: 'command', pattern: '^ls ' }], action: 'green' }];
  const r = classifyExec({ name: 'bash', arguments: { command: 'ls -la' } }, { rules, builtinRules: true, defaultAction: 'red' });
  assert.equal(r.action, 'green');
  const r2 = classifyExec({ name: 'bash', arguments: { command: 'rm -rf x' } }, { rules, builtinRules: true, defaultAction: 'red' });
  assert.equal(r2.action, 'red');
});
ok('builtinRules=false 时 rm -rf 走 defaultAction', () => {
  const r = classifyExec({ name: 'bash', arguments: { command: 'rm -rf x' } }, { rules: [], builtinRules: false, defaultAction: 'red' });
  assert.equal(r.action, 'red');
});
ok('正则语法错误不抛异常', () => {
  const rules = [{ tools: ['bash'], args: [{ key: 'command', pattern: '([' }], action: 'red' }];
  const r = classifyExec({ name: 'bash', arguments: { command: 'echo hi' } }, { rules, builtinRules: false, defaultAction: 'yellow' });
  assert.equal(r.action, 'yellow');
});

console.log('\n[安全回归 · 分类器绕过（v0.1.1，每条对应实测攻击样本）]');
const redCases = [
  ['RM -RF 大写绕过', { name: 'bash', arguments: { command: 'RM -RF /tmp/x' } }],
  ['rm -r -f 分离旗标', { name: 'bash', arguments: { command: 'rm -r -f /tmp/x' } }],
  ['rm -f -r 反向分离旗标', { name: 'bash', arguments: { command: 'rm -f -r /tmp/x' } }],
  ['rm --recursive --force 长旗标', { name: 'bash', arguments: { command: 'rm --recursive --force /tmp/x' } }],
  ['remove-item -recurse 小写', { name: 'pwsh', arguments: { command: 'remove-item -recurse C:\\x' } }],
  ['工具名 Bash 大写', { name: 'Bash', arguments: { command: 'rm -rf /tmp/x' } }],
  ['git -C repo push 全局选项穿插', { name: 'bash', arguments: { command: 'git -C /repo push origin main' } }],
  ['git.exe push', { name: 'bash', arguments: { command: 'git.exe push origin main' } }],
  ['shell 读 SSH 私钥（不经 path 参数）', { name: 'bash', arguments: { command: 'cat ~/.ssh/id_rsa' } }],
  ['shell 写 .env（重定向）', { name: 'bash', arguments: { command: 'echo KEY=1 >> .env' } }],
  ['写 .ENV 大写（Windows 不区分大小写）', { name: 'fs.write', arguments: { path: 'C:/proj/.ENV' } }],
  ['filePath 键指向敏感文件', { name: 'fs.write', arguments: { filePath: 'C:/proj/.env' } }],
  ['嵌套参数 opts.path 指向敏感文件', { name: 'fs.write', arguments: { opts: { path: 'C:/proj/.env' } } }]
];
for (const [label, exec] of redCases) {
  ok(`绕过样本 → red：${label}`, () => {
    assert.equal(classifyExec(exec, ctx).action, 'red');
  });
}
ok('不误报：git commit -m "fix push bug"', () => {
  const r = classifyExec({ name: 'bash', arguments: { command: 'git commit -m "fix push bug"' } }, ctx);
  assert.equal(r.action, 'yellow');
});
ok('rm -r ./dir-with-f → red（递归删除目录树；round-3 MEDIUM-2 翻转原"不误报"定位）', () => {
  const r = classifyExec({ name: 'bash', arguments: { command: 'rm -r ./dir-with-f' } }, ctx);
  assert.equal(r.action, 'red');
});
ok('不误报：rm ./foo-f（无递归旗标，路径内 -f 非旗标）→ yellow', () => {
  const r = classifyExec({ name: 'bash', arguments: { command: 'rm ./foo-f' } }, ctx);
  assert.equal(r.action, 'yellow');
});
ok('pwsh rm -Recurse（无 -Force）→ red（round-3 MEDIUM-2）', () => {
  const r = classifyExec({ name: 'pwsh', arguments: { command: 'rm -Recurse C:\\x' } }, ctx);
  assert.equal(r.action, 'red');
});
ok('git checkout -- <file> 丢弃工作区改动 → red（round-3 MEDIUM-2）', () => {
  const r = classifyExec({ name: 'bash', arguments: { command: 'git checkout -- src/main.ts' } }, ctx);
  assert.equal(r.action, 'red');
});
ok('git restore <file> → red（round-3 MEDIUM-2）', () => {
  const r = classifyExec({ name: 'bash', arguments: { command: 'git restore src/main.ts' } }, ctx);
  assert.equal(r.action, 'red');
});
ok('不误报：git checkout --help（-- 后非空白）→ yellow', () => {
  const r = classifyExec({ name: 'bash', arguments: { command: 'git checkout --help' } }, ctx);
  assert.equal(r.action, 'yellow');
});
ok('不误报：git checkout feature/x（正常切分支）→ yellow', () => {
  const r = classifyExec({ name: 'bash', arguments: { command: 'git checkout feature/x' } }, ctx);
  assert.equal(r.action, 'yellow');
});
ok('不误报：src/tokenizer.ts（token glob 已收窄）', () => {
  const r = classifyExec({ name: 'fs.write', arguments: { path: 'src/tokenizer.ts' } }, ctx);
  assert.equal(r.action, 'yellow');
});
ok('用户 green 不能压制内置红灯（^ls 前缀规则 + 复合命令）', () => {
  const rules = [{ id: 'allow-ls', tools: ['bash'], args: [{ key: 'command', pattern: '^ls ' }], action: 'green' }];
  const r = classifyExec({ name: 'bash', arguments: { command: 'ls -la; rm -rf /tmp/x' } }, { rules, builtinRules: true, defaultAction: 'yellow' });
  assert.equal(r.action, 'red');
});
ok('用户 yellow 仍可覆盖内置 red（白名单能力保留）', () => {
  const rules = [{ id: 'allow-push', tools: ['bash'], args: [{ key: 'command', pattern: '^git push' }], action: 'yellow' }];
  const r = classifyExec({ name: 'bash', arguments: { command: 'git push origin main' } }, { rules, builtinRules: true, defaultAction: 'yellow' });
  assert.equal(r.action, 'yellow');
  assert.equal(r.ruleId, 'allow-push');
});
ok('args.key 生效：key=query 命中 DROP TABLE', () => {
  const rules = [{ id: 'no-drop', tools: ['mytool'], args: [{ key: 'query', pattern: 'DROP TABLE' }], action: 'red' }];
  const r = classifyExec({ name: 'mytool', arguments: { query: 'DROP TABLE users' } }, { rules, builtinRules: false, defaultAction: 'yellow' });
  assert.equal(r.action, 'red');
  assert.equal(r.ruleId, 'no-drop');
});

console.log('\n[queue]');
await okAsync('批准 → approved 且 via=human', async () => {
  const q = createQueue({ ttlSec: 60, timeoutPolicy: 'cancel' });
  const { id, promise } = q.enqueue({ tool: 'bash', reason: 'test' });
  assert.equal(q.decide(id, 'approved'), true);
  const out = await promise;
  assert.equal(out.decision, 'approved');
  assert.equal(out.via, 'human');
  assert.equal(q.pendingList().length, 0);
});
await okAsync('超时（cancel 策略）→ denied 且 via=timeout', async () => {
  const q = createQueue({ ttlSec: 0.05, timeoutPolicy: 'cancel' });
  const { promise } = q.enqueue({ tool: 'bash' });
  const out = await promise;
  assert.equal(out.decision, 'denied');
  assert.equal(out.via, 'timeout');
});
await okAsync('超时（release 策略）→ approved', async () => {
  const q = createQueue({ ttlSec: 0.05, timeoutPolicy: 'release' });
  const { promise } = q.enqueue({ tool: 'bash' });
  const out = await promise;
  assert.equal(out.decision, 'approved');
  assert.equal(out.via, 'timeout');
});
await okAsync('ttl=0 → 立即 denied 且不残留幽灵条目', async () => {
  const q = createQueue({ ttlSec: 0, timeoutPolicy: 'cancel' });
  const { id, promise } = q.enqueue({ tool: 'bash' });
  const out = await promise;
  assert.equal(out.decision, 'denied');
  assert.equal(out.via, 'immediate');
  assert.equal(q.pendingList().length, 0); // 回归：旧版 settle 先于 pending.set，条目永久残留
  assert.equal(q.decide(id, 'approved'), false); // 回归：旧版对已 settle 条目误报成功
});
await okAsync('预中止信号入队 → cancelled 且不残留幽灵条目', async () => {
  const q = createQueue({ ttlSec: 60, timeoutPolicy: 'cancel' });
  const ac = new AbortController();
  ac.abort();
  const { id, promise } = q.enqueue({ tool: 'bash', signal: ac.signal });
  const out = await promise;
  assert.equal(out.decision, 'cancelled');
  assert.equal(q.pendingList().length, 0);
  assert.equal(q.decide(id, 'approved'), false);
});
await okAsync('运行中信号中止 → cancelled 且 via=abort', async () => {
  const q = createQueue({ ttlSec: 60, timeoutPolicy: 'cancel' });
  const ac = new AbortController();
  const { promise } = q.enqueue({ tool: 'bash', signal: ac.signal });
  ac.abort();
  const out = await promise;
  assert.equal(out.decision, 'cancelled');
  assert.equal(out.via, 'abort');
});
await okAsync('非标准 signal（无 addEventListener）不抛异常', async () => {
  const q = createQueue({ ttlSec: 0.05, timeoutPolicy: 'cancel' });
  const { promise } = q.enqueue({ tool: 'bash', signal: { aborted: false } });
  const out = await promise;
  assert.equal(out.decision, 'denied');
});
await okAsync('已过期条目 decide 返回 false', async () => {
  const q = createQueue({ ttlSec: 0.03, timeoutPolicy: 'cancel' });
  const { id, promise } = q.enqueue({ tool: 'bash' });
  await promise;
  assert.equal(q.decide(id, 'approved'), false);
});
ok('pendingList 快照包含工具、年龄与摘要', () => {
  const q = createQueue({ ttlSec: 60, timeoutPolicy: 'cancel' });
  q.enqueue({ tool: 'bash', reason: 'danger', summary: '{"command":"rm -rf /x"}' });
  const list = q.pendingList();
  assert.equal(list.length, 1);
  assert.equal(list[0].tool, 'bash');
  assert.equal(list[0].summary, '{"command":"rm -rf /x"}');
  assert.equal(typeof list[0].ageMs, 'number');
  q.cancelAll(); // 回归：旧版此处残留 60s 定时器导致测试进程挂起
});

console.log('\n[M1 signatureHash]');
ok('signatureHash：工具名大小写不敏感', () => {
  assert.equal(signatureHash('bash', { command: 'ls' }), signatureHash('Bash', { command: 'ls' }));
});
ok('signatureHash：参数键序无关（稳定 JSON）', () => {
  assert.equal(signatureHash('bash', { command: 'ls', b: 2, a: 1 }), signatureHash('bash', { a: 1, b: 2, command: 'ls' }));
});
ok('signatureHash：参数不同 → hash 不同', () => {
  assert.notEqual(signatureHash('bash', { command: 'ls' }), signatureHash('bash', { command: 'ls -la' }));
});
ok('signatureHash：非 shell 工具按完整参数区分', () => {
  assert.equal(signatureHash('fs.write', { path: '/a/.env' }), signatureHash('fs.write', { path: '/a/.env' }));
  assert.notEqual(signatureHash('fs.write', { path: '/a/.env' }), signatureHash('fs.write', { path: '/a/b.txt' }));
});

console.log('\n[M1 queue 状态机]');
ok('enqueue 带签名：entry.state=pending 且可查询', () => {
  const q = createQueue({ ttlSec: 60, timeoutPolicy: 'cancel' });
  const { id, promise } = q.enqueue({ tool: 'bash', reason: 'x', signatureHash: 'sig1', originalCallId: 'call1', summary: 's' });
  assert.equal(q.getEntry(id).state, 'pending');
  assert.equal(q.getEntry(id).originalCallId, 'call1');
  assert.equal(typeof promise.then, 'function');
  q.cancelAll();
});
ok('同签名去重：同 hash 不重复入队，返回既有 id', () => {
  const q = createQueue({ ttlSec: 60, timeoutPolicy: 'cancel' });
  const first = q.enqueue({ tool: 'bash', reason: 'x', signatureHash: 'sig1', originalCallId: 'call1' });
  const again = q.enqueue({ tool: 'bash', reason: 'x', signatureHash: 'sig1', originalCallId: 'call2' });
  assert.equal(again.id, first.id);
  assert.equal(q.pendingList().length, 1);
  q.cancelAll();
});
ok('不同签名可同时 pending', () => {
  const q = createQueue({ ttlSec: 60, timeoutPolicy: 'cancel' });
  q.enqueue({ tool: 'bash', reason: 'x', signatureHash: 'sigA' });
  q.enqueue({ tool: 'bash', reason: 'x', signatureHash: 'sigB' });
  assert.equal(q.pendingList().length, 2);
  q.cancelAll();
});
await okAsync('approve → state=approved 且从签名索引移除', async () => {
  const q = createQueue({ ttlSec: 60, timeoutPolicy: 'cancel' });
  const { id, promise } = q.enqueue({ tool: 'bash', reason: 'x', signatureHash: 'sig1', originalCallId: 'call1' });
  assert.equal(q.decide(id, 'approved'), true);
  const out = await promise;
  assert.equal(out.decision, 'approved');
  assert.equal(q.getEntry(id).state, 'approved');
  // 已 settle 的签名不再去重拦截 → 重新入队产生新条目
  const again = q.enqueue({ tool: 'bash', reason: 'x', signatureHash: 'sig1', originalCallId: 'call3' });
  assert.notEqual(again.id, id);
});
await okAsync('超时（cancel）→ state=expired', async () => {
  const q = createQueue({ ttlSec: 0.03, timeoutPolicy: 'cancel' });
  const { id, promise } = q.enqueue({ tool: 'bash', reason: 'x', signatureHash: 'sigT' });
  const out = await promise;
  assert.equal(out.decision, 'denied');
  assert.equal(out.via, 'timeout');
  assert.equal(q.getEntry(id).state, 'expired');
});
await okAsync('ttl=0 → 立即 denied（via=immediate，state=denied）', async () => {
  const q = createQueue({ ttlSec: 0, timeoutPolicy: 'cancel' });
  const { id, promise } = q.enqueue({ tool: 'bash', reason: 'x', signatureHash: 'sig0' });
  const out = await promise;
  assert.equal(out.via, 'immediate');
  assert.equal(q.getEntry(id).state, 'denied');
});
ok('settled 条目保留在 entries（供 escrow_result 查询）', () => {
  const q = createQueue({ ttlSec: 0, timeoutPolicy: 'cancel' });
  const { id } = q.enqueue({ tool: 'bash', reason: 'x', signatureHash: 'sigK' });
  assert.equal(q.getEntry(id).state, 'denied');
  assert.equal(q.pendingList().length, 0);
});

console.log('\n[M1 重放令牌]');
ok('mintToken：exemptions + replaying 双向登记，均单次消费', () => {
  const q = createQueue({ ttlSec: 60, timeoutPolicy: 'cancel' });
  const { id } = q.enqueue({ tool: 'bash', reason: 'x', signatureHash: 'sigR' });
  const token = q.mintToken(id);
  assert.equal(typeof token, 'string');
  assert.equal(q.isExempt(token), true);
  assert.equal(q.isReplaying(token), true);
  assert.equal(q.consumeExemption(token), true);
  assert.equal(q.consumeExemption(token), false); // 单次
  assert.equal(q.isExempt(token), false);
  q.finishReplay(token);
  assert.equal(q.isReplaying(token), false);
  q.cancelAll();
});
ok('markExecuted → state=executed + resultText', () => {
  const q = createQueue({ ttlSec: 60, timeoutPolicy: 'cancel' });
  const { id } = q.enqueue({ tool: 'bash', reason: 'x', signatureHash: 'sigE' });
  q.markExecuted(id, 'real output');
  assert.equal(q.getEntry(id).state, 'executed');
  assert.equal(q.getEntry(id).resultText, 'real output');
  q.cancelAll();
});
ok('未知条目查询返回 undefined', () => {
  const q = createQueue({ ttlSec: 60, timeoutPolicy: 'cancel' });
  assert.equal(q.getEntry('esc-999'), undefined);
});

console.log('\n[M1 synth-result]');
ok('synthForeground：合法前台结构 + 占位文本进 stdout.text', () => {
  const r = synthForeground('hello placeholder');
  assert.equal(r.isError, false);
  assert.equal(r.value.kind, 'foreground');
  assert.equal(r.value.exitCode, null);
  assert.equal(r.value.signal, null);
  assert.equal(r.value.timedOut, false);
  assert.equal(r.value.aborted, false);
  assert.equal(r.value.timeoutMs, 0);
  assert.equal(r.value.stdout.text, 'hello placeholder');
  assert.equal(r.value.stdout.truncated, false);
  assert.equal(r.value.stderr.text, '');
  assert.equal(r.value.stderr.truncated, false);
});
ok('placeholderText：首次含 escrow_result 指令', () => {
  const t = placeholderText('esc-1001', false);
  assert.equal(t.includes('esc-1001'), true);
  assert.equal(t.includes('escrow_result'), true);
  assert.equal(t.includes('不要重复发起'), true);
});
ok('placeholderText：重复发起含「已在审批队列」', () => {
  const t = placeholderText('esc-1001', true);
  assert.equal(t.includes('已在审批队列'), true);
  assert.equal(t.includes('escrow_result'), true);
});

console.log('\n[M7 自改治理]');
ok('写 $DSH_HOME 文件 → red（selfmod）', () => {
  const r = classifyExec({ name: 'fs.write', arguments: { path: 'C:/Users/me/.dsh/config.json' } }, ctx);
  assert.equal(r.action, 'red');
  assert.equal(r.ruleId, 'selfmod');
});
ok('写 AGENTS.md → red（selfmod）', () => {
  const r = classifyExec({ name: 'fs.write', arguments: { path: 'D:/proj/AGENTS.md' } }, ctx);
  assert.equal(r.action, 'red');
});
ok('写 cordis.patch.yml → red（selfmod）', () => {
  const r = classifyExec({ name: 'fs.write', arguments: { path: 'C:/Users/me/.dsh/profiles/tui/cordis.patch.yml' } }, ctx);
  assert.equal(r.action, 'red');
});
ok('写 profile package.json → red（selfmod）', () => {
  const r = classifyExec({ name: 'fs.write', arguments: { path: 'C:/Users/me/.dsh/profiles/tui/package.json' } }, ctx);
  assert.equal(r.action, 'red');
});
ok('写 .dsh-escrow 状态目录 → red（selfmod）', () => {
  const r = classifyExec({ name: 'fs.write', arguments: { path: 'C:/Users/me/.dsh/.dsh-escrow/allowlist.json' } }, ctx);
  assert.equal(r.action, 'red');
});
ok('命令串自改：echo x >> AGENTS.md → red（重定向目标）', () => {
  const r = classifyExec({ name: 'bash', arguments: { command: 'echo KEY=1 >> AGENTS.md' } }, ctx);
  assert.equal(r.action, 'red');
});
ok('命令串自改：写 .dsh 相对路径 → red（重定向目标）', () => {
  const r = classifyExec({ name: 'bash', arguments: { command: 'echo x >> .dsh/config.json' } }, ctx);
  assert.equal(r.action, 'red');
});
ok('保守：git commit -m 提及 AGENTS.md → 自改红（宽松命令串检测，托管一次批准即放行）', () => {
  const r = classifyExec({ name: 'bash', arguments: { command: 'git commit -m "update AGENTS.md"' } }, ctx);
  assert.equal(r.action, 'red');
  assert.equal(r.ruleId, 'selfmod');
});
ok('cp 复制到 AGENTS.md → red（二轮审查 HIGH：非重定向写工具）', () => {
  const r = classifyExec({ name: 'bash', arguments: { command: 'cp /tmp/evil.md AGENTS.md' } }, ctx);
  assert.equal(r.action, 'red');
});
ok('sed -i 编辑 AGENTS.md → red', () => {
  const r = classifyExec({ name: 'bash', arguments: { command: "sed -i 's/x/y/' AGENTS.md" } }, ctx);
  assert.equal(r.action, 'red');
});
ok('mv 改名到 AGENTS.md → red', () => {
  const r = classifyExec({ name: 'bash', arguments: { command: 'mv backup.md AGENTS.md' } }, ctx);
  assert.equal(r.action, 'red');
});
ok('命令串引号拼接绕过（AGENTS\'\'.md）→ red（R6-2 修复：去引号匹配）', () => {
  const r = classifyExec({ name: 'bash', arguments: { command: "echo x > AGENTS''.md" } }, ctx);
  assert.equal(r.action, 'red');
});
ok('命令串引号拼接绕过（"AGENTS".md）→ red（R6-2 修复）', () => {
  const r = classifyExec({ name: 'bash', arguments: { command: 'printf x > "AGENTS".md' } }, ctx);
  assert.equal(r.action, 'red');
});
ok('命令串 glob 自改目标（AGENTS.m?）→ red', () => {
  const r = classifyExec({ name: 'bash', arguments: { command: 'echo x > AGENTS.m?' } }, ctx);
  assert.equal(r.action, 'red');
  assert.equal(r.ruleId, 'selfmod');
});
ok('命令串简单变量展开自改目标（$F.md）→ red', () => {
  const r = classifyExec({ name: 'bash', arguments: { command: 'F=AGENTS; echo x > $F.md' } }, ctx);
  assert.equal(r.action, 'red');
  assert.equal(r.ruleId, 'selfmod');
});
ok('selfModification:false → 自改走正常分类（不红）', () => {
  const r = classifyExec({ name: 'fs.write', arguments: { path: 'D:/proj/AGENTS.md' } }, { rules: [], builtinRules: true, defaultAction: 'yellow', selfModification: false });
  assert.equal(r.action, 'yellow');
});
ok('普通文件写不误报 selfmod', () => {
  const r = classifyExec({ name: 'fs.write', arguments: { path: 'src/index.js' } }, ctx);
  assert.equal(r.action, 'yellow');
});

console.log('\n[M8 reduce]');
ok('computeReduce：同签名 ×12 → 重复 + SNR<1 + suggest=1', () => {
  const lines = [];
  for (let i = 0; i < 12; i++) lines.push({ t: '2026-08-29T00:00:00.000Z', kind: 'observe', tool: 'bash', args: '{"command":"git push origin main"}' });
  const r = computeReduce(lines, { threshold: 10 });
  assert.equal(r.total, 12);
  assert.equal(r.duplicates.length, 1);
  assert.equal(r.duplicates[0].count, 12);
  assert.equal(r.duplicates[0].signature, 'git push origin <BRANCH>');
  assert.equal(r.snr, 0);
  assert.equal(r.suggest, 1);
  assert.equal(r.projectedSnr, 1);
  assert.equal(r.denied, 0);
});
ok('computeReduce：不同签名 → 无重复 SNR=1', () => {
  const lines = [
    { t: '2026-08-29T00:00:00.000Z', kind: 'observe', tool: 'bash', args: '{"command":"npm test"}' },
    { t: '2026-08-29T00:00:00.000Z', kind: 'observe', tool: 'bash', args: '{"command":"ls -la"}' }
  ];
  const r = computeReduce(lines, { threshold: 10 });
  assert.equal(r.duplicates.length, 0);
  assert.equal(r.snr, 1);
});
ok('computeReduce：denied 统计（escrow.decided decision=denied）', () => {
  const lines = [
    { t: '2026-08-29T00:00:00.000Z', kind: 'observe', tool: 'bash', args: '{"command":"ls"}' },
    { t: '2026-08-29T00:00:00.000Z', kind: 'escrow.decided', decision: 'denied', via: 'timeout' },
    { t: '2026-08-29T00:00:00.000Z', kind: 'escrow.decided', decision: 'approved', via: 'human' }
  ];
  const r = computeReduce(lines, { threshold: 10 });
  assert.equal(r.denied, 1);
  assert.equal(r.total, 1); // 只有 observe 算执行；decided 本身不算
});
ok('computeReduce：since 过滤', () => {
  const now = Date.now();
  const old = new Date(now - 10 * 86400000).toISOString();
  const recent = new Date(now - 3600000).toISOString();
  const lines = [
    { t: old, kind: 'observe', tool: 'bash', args: '{"command":"git push origin main"}' },
    { t: recent, kind: 'observe', tool: 'bash', args: '{"command":"git push origin main"}' }
  ];
  const r = computeReduce(lines, { threshold: 10, sinceMs: now - 7 * 86400000 });
  assert.equal(r.total, 1);
});
ok('computeReduce：approved_executed 含 args 计入签名', () => {
  const lines = [
    { t: '2026-08-29T00:00:00.000Z', kind: 'observe', tool: 'bash', args: '{"command":"git push origin main"}' },
    { t: '2026-08-29T00:00:00.000Z', kind: 'escrow.approved_executed', tool: 'bash', args: '{"command":"git push origin main"}' }
  ];
  const r = computeReduce(lines, { threshold: 2 });
  assert.equal(r.total, 2);
  assert.equal(r.duplicates.length, 1);
});
ok('computeReduce：空/坏行容错', () => {
  const lines = [{ t: 'bad-date', kind: 'observe' }, null, 'not-json', { kind: 'observe', tool: 'bash' }];
  const r = computeReduce(lines, { threshold: 10 });
  assert.equal(typeof r.total, 'number');
  assert.equal(Array.isArray(r.duplicates), true);
});
ok('computeReduce：whitelisted 行带 signature 计入重复（M8 审查 HIGH）', () => {
  const lines = [];
  for (let i = 0; i < 12; i++) lines.push({ t: '2026-08-29T00:00:00.000Z', kind: 'escrow.whitelisted', tool: 'bash', signature: 'git push origin <BRANCH>' });
  const r = computeReduce(lines, { threshold: 10 });
  assert.equal(r.total, 12);
  assert.equal(r.duplicates.length, 1);
  assert.equal(r.duplicates[0].count, 12);
});
ok('computeReduce：blacklisted 计入拦下 + interruptRate 分母（M8 审查 MEDIUM/LOW）', () => {
  const lines = [
    { t: '2026-08-29T00:00:00.000Z', kind: 'observe', tool: 'bash', args: '{"command":"ls"}' },
    { t: '2026-08-29T00:00:00.000Z', kind: 'escrow.blacklisted', tool: 'bash', signature: 'npm install' }
  ];
  const r = computeReduce(lines, { threshold: 10 });
  assert.equal(r.denied, 1);
  assert.equal(r.interruptRate, 0.5); // denied / (total+denied) = 1/2，不超 100%
});

console.log('\n[M6 哈希链]');
ok('哈希链：连续写入的 h 链正确', () => {
  const dir = mkdtempSync(join(tmpdir(), 'escrow-h-'));
  try {
    const ledger = createLedger({ dir });
    ledger.write('observe', { tool: 'bash' });
    ledger.write('observe', { tool: 'pwsh' });
    const lines = readFileSync(join(dir, 'ledger.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    assert.equal(lines.length, 2);
    const sha = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
    const b1 = JSON.stringify({ t: lines[0].t, kind: lines[0].kind, tool: lines[0].tool });
    const b2 = JSON.stringify({ t: lines[1].t, kind: lines[1].kind, tool: lines[1].tool });
    assert.equal(lines[0].h, sha('genesis' + b1));
    assert.equal(lines[1].h, sha(lines[0].h + b2));
    assert.equal(ledger.integrity.tampered, false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
ok('哈希链：篡改中间行 → tampered', () => {
  const dir = mkdtempSync(join(tmpdir(), 'escrow-h-'));
  try {
    const ledger = createLedger({ dir });
    ledger.write('observe', { tool: 'bash' });
    ledger.write('observe', { tool: 'pwsh' });
    ledger.write('observe', { tool: 'cmd' });
    const file = join(dir, 'ledger.jsonl');
    const lines = readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    lines[1].tool = 'HACKED';
    writeFileSync(file, lines.map((l) => JSON.stringify(l)).join('\n') + '\n', 'utf8');
    const ledger2 = createLedger({ dir });
    assert.equal(ledger2.integrity.tampered, true);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
ok('哈希链：旧格式无 h 行 → legacy 且迁移前只读', () => {
  const dir = mkdtempSync(join(tmpdir(), 'escrow-h-'));
  try {
    writeFileSync(join(dir, 'ledger.jsonl'), JSON.stringify({ t: '2026-01-01T00:00:00.000Z', kind: 'observe', tool: 'old' }) + '\n', 'utf8');
    const ledger = createLedger({ dir });
    assert.equal(ledger.integrity.legacyDetected, true);
    assert.equal(ledger.integrity.tampered, false);
    assert.equal(ledger.write('observe', { tool: 'new' }), false);
    const lines = readFileSync(join(dir, 'ledger.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    assert.equal(lines.length, 1);
    assert.equal(ledger.migrate().migrated, 1);
    assert.equal(ledger.write('observe', { tool: 'new' }), true);
    const migrated = readFileSync(join(dir, 'ledger.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    assert.equal(typeof migrated[1].h, 'string'); // 迁移后新行带 h
    assert.equal(ledger.integrity.tampered, false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
ok('哈希链：轮转后链头重置 genesis', () => {
  const dir = mkdtempSync(join(tmpdir(), 'escrow-h-'));
  try {
    const ledger = createLedger({ dir, maxBytes: 200 });
    for (let i = 0; i < 10; i++) ledger.write('observe', { tool: 'x'.repeat(60) });
    ledger.write('observe', { tool: 'post-rotate' }); // 触发轮转后写入
    const lines = readFileSync(join(dir, 'ledger.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    assert.equal(lines[0].tool, 'post-rotate'); // 轮转后新文件第一行是链头
    const sha = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
    assert.equal(lines[0].h, sha('genesis' + JSON.stringify({ t: lines[0].t, kind: lines[0].kind, tool: lines[0].tool })));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
ok('哈希链：legacy 行 chainResets 计数（R8-1）', () => {
  const dir = mkdtempSync(join(tmpdir(), 'escrow-h-'));
  try {
    writeFileSync(join(dir, 'ledger.jsonl'), JSON.stringify({ t: '2026-01-01T00:00:00.000Z', kind: 'observe', tool: 'old' }) + '\n', 'utf8');
    const ledger = createLedger({ dir });
    assert.equal(ledger.integrity.chainResets, 1);
    assert.equal(ledger.integrity.legacyDetected, true);
    assert.equal(ledger.integrity.tampered, false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
ok('readLedgerLines：.bak 行带 _src 标记（R8-2）', () => {
  const dir = mkdtempSync(join(tmpdir(), 'escrow-h-'));
  try {
    writeFileSync(join(dir, 'ledger.jsonl'), JSON.stringify({ t: '2026-01-01T00:00:00.000Z', kind: 'observe', tool: 'main' }) + '\n', 'utf8');
    writeFileSync(join(dir, 'ledger.jsonl.bak'), JSON.stringify({ t: '2026-01-01T00:00:00.000Z', kind: 'observe', tool: 'old' }) + '\n', 'utf8');
    const lines = readLedgerLines(join(dir, 'ledger.jsonl'));
    assert.equal(lines.length, 2);
    assert.equal(lines.find((l) => l.tool === 'main')._src, undefined); // main 不加标记
    assert.equal(lines.find((l) => l.tool === 'old')._src, 'bak'); // .bak 标记来源
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

console.log('\n[M6+ HMAC 锚定]');
ok('账本 payload.h/m 冲突字段保留为命名空间', () => {
  const dir = mkdtempSync(join(tmpdir(), 'escrow-payload-'));
  try {
    const ledger = createLedger({ dir });
    ledger.write('observe', { tool: 'bash', h: 'USER_H', m: 'USER_M' });
    const rec = JSON.parse(readFileSync(join(dir, 'ledger.jsonl'), 'utf8').trim());
    assert.equal(rec.payload_h, 'USER_H');
    assert.equal(rec.payload_m, 'USER_M');
    assert.notEqual(rec.h, 'USER_H');
    assert.notEqual(rec.m, 'USER_M');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
ok('HMAC：写入行带 m 且重载验证通过', () => {
  const dir = mkdtempSync(join(tmpdir(), 'escrow-k-'));
  try {
    const ledger = createLedger({ dir });
    ledger.write('observe', { tool: 'bash' });
    const lines = readFileSync(join(dir, 'ledger.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    assert.equal(typeof lines[0].m, 'string');
    assert.equal(ledger.integrity.keyed, true);
    assert.equal(ledger.integrity.keyMismatch, false);
    const ledger2 = createLedger({ dir });
    assert.equal(ledger2.integrity.keyMismatch, false);
    assert.equal(ledger2.integrity.tampered, false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
ok('HMAC：只改 m → keyMismatch（h 链 OK）；改 body → tampered', () => {
  const dir = mkdtempSync(join(tmpdir(), 'escrow-k-'));
  try {
    const ledger = createLedger({ dir });
    ledger.write('observe', { tool: 'bash' });
    const f = join(dir, 'ledger.jsonl');
    const line1 = JSON.parse(readFileSync(f, 'utf8').trim());
    line1.m = 'f'.repeat(64);
    writeFileSync(f, JSON.stringify(line1) + '\n', 'utf8');
    const l2 = createLedger({ dir });
    assert.equal(l2.integrity.tampered, false);
    assert.equal(l2.integrity.keyMismatch, true);
    const line2 = JSON.parse(readFileSync(f, 'utf8').trim());
    line2.tool = 'HACK';
    writeFileSync(f, JSON.stringify(line2) + '\n', 'utf8');
    const l3 = createLedger({ dir });
    assert.equal(l3.integrity.tampered, true);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
ok('HMAC：密钥删除重生成 → keyMismatch（非篡改，区分处理）', () => {
  const dir = mkdtempSync(join(tmpdir(), 'escrow-k-'));
  try {
    const ledger = createLedger({ dir });
    ledger.write('observe', { tool: 'bash' });
    rmSync(join(dir, 'keys', 'hmac.key'), { force: true });
    const l2 = createLedger({ dir });
    assert.equal(l2.integrity.tampered, false);
    assert.equal(l2.integrity.keyMismatch, true);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
ok('migrate：legacy 账本 → 完整链 + chainResets 归零', () => {
  const dir = mkdtempSync(join(tmpdir(), 'escrow-k-'));
  try {
    writeFileSync(join(dir, 'ledger.jsonl'), [
      JSON.stringify({ t: '2026-01-01T00:00:00.000Z', kind: 'observe', tool: 'old1' }),
      JSON.stringify({ t: '2026-01-02T00:00:00.000Z', kind: 'observe', tool: 'old2' })
    ].join('\n') + '\n', 'utf8');
    const ledger = createLedger({ dir });
    assert.equal(ledger.integrity.legacyDetected, true);
    const r = ledger.migrate();
    assert.equal(r.migrated, 2);
    assert.equal(ledger.integrity.legacyDetected, false);
    assert.equal(ledger.integrity.chainResets, 0);
    const lines = readFileSync(join(dir, 'ledger.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    assert.equal(lines.length, 2);
    assert.equal(typeof lines[0].h, 'string');
    assert.equal(typeof lines[0].m, 'string');
    const ledger2 = createLedger({ dir });
    assert.equal(ledger2.integrity.tampered, false);
    assert.equal(ledger2.integrity.keyMismatch, false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
ok('migrate 守卫：tampered → 拒绝（不洗白篡改证据）', () => {
  const dir = mkdtempSync(join(tmpdir(), 'escrow-k-'));
  try {
    const ledger = createLedger({ dir });
    ledger.write('observe', { tool: 'bash' });
    const f = join(dir, 'ledger.jsonl');
    const line = JSON.parse(readFileSync(f, 'utf8').trim());
    line.tool = 'HACK';
    writeFileSync(f, JSON.stringify(line) + '\n', 'utf8');
    const l2 = createLedger({ dir });
    assert.equal(l2.integrity.tampered, true);
    const r = l2.migrate(false);
    assert.ok(r.error && r.error.includes('篡改'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
ok('migrate 守卫：keyMismatch 需 --force（防洗白）', () => {
  const dir = mkdtempSync(join(tmpdir(), 'escrow-k-'));
  try {
    const ledger = createLedger({ dir });
    ledger.write('observe', { tool: 'bash' });
    rmSync(join(dir, 'keys', 'hmac.key'), { force: true }); // 密钥更换 → keyMismatch
    const l2 = createLedger({ dir });
    assert.equal(l2.integrity.keyMismatch, true);
    const denied = l2.migrate(false);
    assert.ok(denied.error && denied.error.includes('密钥'));
    const forced = l2.migrate(true);
    assert.equal(forced.error, undefined);
    assert.equal(l2.integrity.keyMismatch, false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

console.log('\n[M6 report]');
ok('computeReport：统计/清单/ROI', () => {
  const lines = [
    { t: '2026-08-29T00:00:00.000Z', kind: 'observe', tool: 'bash', args: '{"command":"ls"}' },
    { t: '2026-08-29T00:00:00.000Z', kind: 'escrow.decided', id: 'esc-1', decision: 'denied', via: 'human', waitedMs: 5000 },
    { t: '2026-08-29T00:00:00.000Z', kind: 'escrow.decided', id: 'esc-2', decision: 'approved', via: 'human', waitedMs: 3000 },
    { t: '2026-08-29T00:00:00.000Z', kind: 'escrow.approved_executed', id: 'esc-2', tool: 'bash' },
    { t: '2026-08-29T00:00:00.000Z', kind: 'escrow.whitelisted', tool: 'bash', signature: 'git push origin <BRANCH>' },
    { t: '2026-08-29T00:00:00.000Z', kind: 'selfmod.decided', id: 'esc-3', decision: 'denied', via: 'human' }
  ];
  const r = computeReport(lines, {});
  assert.equal(r.total, 6);
  assert.equal(r.denied, 1);
  assert.equal(r.approved, 1); // 批准决策数（esc-2 decided approved）；approved_executed 计 executed
  assert.equal(r.executed, 1);
  assert.equal(r.roi.confirmCount, 2);
  assert.equal(r.roi.avgHumanWaitMs, 4000);
  assert.equal(r.redList.length, 1);
  assert.equal(r.tasteRec.length, 1);
  assert.equal(r.selfMod.length, 1);
});

console.log('\n[ledger]');
ok('写行并脱敏 API key', () => {
  const dir = mkdtempSync(join(tmpdir(), 'escrow-test-'));
  try {
    const ledger = createLedger({ dir });
    const ok1 = ledger.observe({ name: 'bash', callId: 'call-1', arguments: { command: 'KEY=sk-ABCDEFGH1234567890' } }, 'yellow');
    assert.equal(ok1, true);
    const text = readFileSync(join(dir, 'ledger.jsonl'), 'utf8');
    assert.equal(text.includes('sk-ABCDEFGH1234567890'), false);
    assert.equal(text.includes('REDACTED'), true);
    assert.equal(ledger.count, 1);
    ledger.observe({ name: 'bash' }, 'yellow');
    assert.equal(ledger.count, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
ok('redact 方法可复用', () => {
  const dir = mkdtempSync(join(tmpdir(), 'escrow-test-'));
  try {
    const ledger = createLedger({ dir });
    const out = ledger.redact({ api_key: 'AIzaSyAAAAAAAAAAAAAAAAAAAAA1' });
    assert.equal(out.includes('AIzaSyAAAA'), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
ok('回归：JSON 形态 password / token / secret 脱敏（旧版明文入账）', () => {
  const dir = mkdtempSync(join(tmpdir(), 'escrow-test-'));
  try {
    const ledger = createLedger({ dir });
    const out = ledger.redact({ password: 'hunter23456', token: 'abcdefgh12345', secret: 'topsecret99' });
    assert.equal(out.includes('hunter23456'), false);
    assert.equal(out.includes('abcdefgh12345'), false);
    assert.equal(out.includes('topsecret99'), false);
    assert.equal(out.includes('"password":"***REDACTED***"'), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
ok('回归：authorization 头与 PEM 私钥块脱敏', () => {
  const dir = mkdtempSync(join(tmpdir(), 'escrow-test-'));
  try {
    const ledger = createLedger({ dir });
    const out = ledger.redact({ authorization: 'Basic dXNlcjpwYXNzMTIz', pem: '-----BEGIN PRIVATE KEY-----ABCDEF123456-----END PRIVATE KEY-----' });
    assert.equal(out.includes('dXNlcjpwYXNzMTIz'), false);
    assert.equal(out.includes('ABCDEF123456'), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
ok('回归：空格分隔 flag 值（--token abc）与 URL 内嵌凭据脱敏（round-3 LOW-2）', () => {
  const dir = mkdtempSync(join(tmpdir(), 'escrow-test-'));
  try {
    const ledger = createLedger({ dir });
    const out = ledger.redact({ command: 'curl --token supersecret123 https://user:hunter2@api.example.com/x' });
    assert.equal(out.includes('supersecret123'), false);
    assert.equal(out.includes('hunter2'), false);
    assert.equal(out.includes('--token ***REDACTED***'), true);
    assert.equal(out.includes('https://***REDACTED***@'), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
ok('回归：账本超限轮转为 .bak 且计数重置（旧版无限增长）', () => {
  const dir = mkdtempSync(join(tmpdir(), 'escrow-test-'));
  try {
    const ledger = createLedger({ dir, maxBytes: 300 });
    for (let i = 0; i < 20; i++) ledger.write('observe', { tool: 'bash', args: 'x'.repeat(80) });
    assert.equal(existsSync(join(dir, 'ledger.jsonl.bak')), true);
    assert.equal(ledger.count < 20, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

console.log(`\n结果：${passed} 个断言全部通过\n`);
process.exit(process.exitCode ?? 0);
