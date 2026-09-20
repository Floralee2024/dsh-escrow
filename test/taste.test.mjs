/**
 * M2 品味习得单元测试（signature / taste store，纯模块，不依赖 dsh 运行时）。
 * 运行：node test/taste.test.mjs
 */

import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { commandSignature, extractSignature, neverLearnReason } from '../lib/signature.mjs';
import { createTasteStore } from '../lib/taste.mjs';

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

console.log('\n[signature 提取]');
ok('分支名归一：git push origin main → git push origin <BRANCH>', () => {
  assert.equal(commandSignature('git push origin main'), 'git push origin <BRANCH>');
  assert.equal(commandSignature('git push origin feature/x.y'), 'git push origin <BRANCH>');
});
ok('--force 保留原文，与普通 push 不同签名（P7）', () => {
  const a = commandSignature('git push origin --force');
  const b = commandSignature('git push origin main');
  assert.equal(a, 'git push origin --force');
  assert.notEqual(a, b);
});
ok('数字/哈希/HEAD 引用归一', () => {
  assert.equal(commandSignature('git log -n 5'), 'git log -n <N>');
  assert.equal(commandSignature('git show 1a2b3c4d'), 'git show <HASH>');
  assert.equal(commandSignature('git reset --hard HEAD~2'), 'git reset --hard <REF>');
});
ok('引号自由文本归一为 <STR>（commit message 不进签名）', () => {
  assert.equal(commandSignature('git commit -m "fix: whatever bug"'), 'git commit -m <STR>');
  assert.equal(commandSignature("git commit -m 'another'"), 'git commit -m <STR>');
});
ok('不认识的 token 一律原文（白名单式，宁窄勿宽）', () => {
  assert.equal(commandSignature('ls -la'), 'ls -la');
  assert.equal(commandSignature('rm -rf /tmp/x'), 'rm -rf /tmp/x');
});
ok('非 shell 工具签名 = 工具名 + 排序参数键（不含值）', () => {
  const s = extractSignature('fs.write', { path: '/a', content: 'x' });
  assert.equal(s.kind, 'tool');
  assert.equal(s.signature, 'fs.write(content,path)');
});
ok('shell 工具大小写不敏感地走命令签名', () => {
  const s = extractSignature('Bash', { command: 'git push origin main' });
  assert.equal(s.signature, 'git push origin <BRANCH>');
});

console.log('\n[不可学习名单]');
ok('rm -rf → 不可学习', () => {
  assert.ok(neverLearnReason('bash', { command: 'rm -rf /tmp/x' }));
});
ok('普通 git push → 可学习（品味习得要学得会它）', () => {
  assert.equal(neverLearnReason('bash', { command: 'git push origin main' }), null);
});
ok('git push --force → 不可学习（破坏性 + force）', () => {
  assert.ok(neverLearnReason('bash', { command: 'git push origin main --force' }));
});
ok('dd if= → 不可学习（磁盘类）', () => {
  assert.ok(neverLearnReason('bash', { command: 'dd if=/dev/zero of=/dev/sda' }));
});
ok('写 $DSH_HOME / .dsh-escrow → 不可学习（自改类）', () => {
  assert.ok(neverLearnReason('fs.write', { path: 'C:/Users/me/.dsh/config.json' }));
  assert.ok(neverLearnReason('fs.write', { path: 'C:/Users/me/.dsh/.dsh-escrow/allowlist.json' }));
});
ok('写 AGENTS.md / cordis.patch.yml → 不可学习（自改类）', () => {
  assert.ok(neverLearnReason('fs.write', { path: 'D:/proj/AGENTS.md' }));
  assert.ok(neverLearnReason('bash', { command: 'echo x >> cordis.patch.yml' }));
});
ok('普通文件写 / 普通命令 → 可学习', () => {
  assert.equal(neverLearnReason('fs.write', { path: 'src/index.js' }), null);
  assert.equal(neverLearnReason('bash', { command: 'npm test' }), null);
});
ok('git reset --hard → 不可学习（丢弃工作区/历史，force 判定漏检的破坏性形态）', () => {
  assert.ok(neverLearnReason('bash', { command: 'git reset --hard HEAD~2' }));
});
ok('git checkout -- 丢弃工作区 → 不可学习', () => {
  assert.ok(neverLearnReason('bash', { command: 'git checkout -- .' }));
});
ok('普通 git checkout <分支> 仍可学习', () => {
  assert.equal(neverLearnReason('bash', { command: 'git checkout feature/x' }), null);
});
// round-6 R6-1：never-learn 与 builtin 红按"绝对不可逆/不可恢复"口径对齐
ok('rm -r（无 -f）→ 不可学习（递归删目录树，无 -f 同样不可逆）', () => {
  assert.ok(neverLearnReason('bash', { command: 'rm -r /tmp/x' }));
  assert.ok(neverLearnReason('bash', { command: 'rm -R /tmp/x' }));
  assert.ok(neverLearnReason('bash', { command: 'rm --recursive /tmp/x' }));
});
ok('rm -rf 不受影响（回归：原断言不变）', () => {
  assert.ok(neverLearnReason('bash', { command: 'rm -rf /tmp/x' }));
});
ok('pwsh rm -Recurse → 不可学习（PowerShell 别名，与 Remove-Item -Recurse 同义）', () => {
  assert.ok(neverLearnReason('bash', { command: 'rm -Recurse /tmp/x' }));
  assert.ok(neverLearnReason('pwsh', { command: 'rm -Recurse /tmp/x' }));
});
ok('git restore → 不可学习（丢弃工作区/暂存改动的现代形态，与 reset --hard / checkout -- 同义）', () => {
  assert.ok(neverLearnReason('bash', { command: 'git restore .' }));
  assert.ok(neverLearnReason('bash', { command: 'git restore --staged x.js' }));
});
ok('git -C repo reset --hard → 不可学习（带全局选项的丢弃工作区形态）', () => {
  assert.ok(neverLearnReason('bash', { command: 'git -C my-repo reset --hard HEAD~1' }));
});
ok('git -C repo checkout -- → 不可学习（带全局选项的丢弃工作区形态）', () => {
  assert.ok(neverLearnReason('bash', { command: 'git -C my-repo checkout -- .' }));
});
ok('git checkout feature/x -f → 不可学习（分支切换 + force 旗标，破坏性 + force 组合）', () => {
  // 注意：扩展基座已加 restore，但 force 旗标仍走 RE_FORCE_FLAG；确保分支切换 + force 也命中。
  assert.ok(neverLearnReason('bash', { command: 'git checkout feature/x -f' }));
});
ok('命令串自改 echo x > AGENTS.md → 不可学习（M7 审查：裸文件名命令串）', () => {
  assert.ok(neverLearnReason('bash', { command: 'echo x > AGENTS.md' }));
});
ok('命令串自改 tee -a cordis.patch.yml → 不可学习（tee 带 flag）', () => {
  assert.ok(neverLearnReason('bash', { command: 'tee -a cordis.patch.yml < /dev/null' }));
});
ok('命令串自改 >AGENTS.md（零空格）→ 不可学习', () => {
  assert.ok(neverLearnReason('bash', { command: 'echo x >AGENTS.md' }));
});
ok('保守：git commit -m 提及 AGENTS.md → 不可学习（宽松命令串自改检测，自改永不学习）', () => {
  assert.ok(neverLearnReason('bash', { command: 'git commit -m "update AGENTS.md"' }));
});

console.log('\n[taste store 状态机]');
ok('批准 1 次 → learning，check 不命中', () => {
  const dir = mkdtempSync(join(tmpdir(), 'taste-'));
  try {
    const store = createTasteStore({ dir });
    const sig = 'git push origin <BRANCH>';
    const args = { command: 'git push origin main' };
    const r = store.recordDecision(sig, true, { toolName: 'bash', args });
    assert.equal(r.learned, true);
    assert.equal(r.status, 'learning');
    assert.equal(store.check(sig), null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
ok('批准 2 次 → cooling；冷却期内 check 仍不命中（P7 防疲劳固化）', () => {
  const dir = mkdtempSync(join(tmpdir(), 'taste-'));
  try {
    let t = 1000000;
    const store = createTasteStore({ dir, now: () => t });
    const sig = 'git push origin <BRANCH>';
    const args = { command: 'git push origin main' };
    store.recordDecision(sig, true, { toolName: 'bash', args });
    const r2 = store.recordDecision(sig, true, { toolName: 'bash', args });
    assert.equal(r2.status, 'cooling');
    t += 3600 * 1000; // +1h，冷却期内
    assert.equal(store.check(sig), null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
ok('冷却期满 → check 惰性晋升 active → allow', () => {
  const dir = mkdtempSync(join(tmpdir(), 'taste-'));
  try {
    let t = 1000000;
    const store = createTasteStore({ dir, now: () => t, cooldownHours: 24 });
    const sig = 'git push origin <BRANCH>';
    const args = { command: 'git push origin main' };
    store.recordDecision(sig, true, { toolName: 'bash', args });
    store.recordDecision(sig, true, { toolName: 'bash', args });
    t += 25 * 3600 * 1000; // +25h
    assert.equal(store.check(sig), 'allow');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
ok('拒绝 2 次 → 黑名单即时生效（无冷却期）', () => {
  const dir = mkdtempSync(join(tmpdir(), 'taste-'));
  try {
    const store = createTasteStore({ dir });
    const sig = 'npm publish <STR>';
    const args = { command: 'npm publish --dry-run' };
    store.recordDecision(sig, false, { toolName: 'bash', args });
    assert.equal(store.check(sig), null);
    store.recordDecision(sig, false, { toolName: 'bash', args });
    assert.equal(store.check(sig), 'deny');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
ok('never-learn 签名 recordDecision 被拒绝学习', () => {
  const dir = mkdtempSync(join(tmpdir(), 'taste-'));
  try {
    const store = createTasteStore({ dir });
    const r = store.recordDecision('rm -rf /tmp/x', true, { toolName: 'bash', args: { command: 'rm -rf /tmp/x' } });
    assert.equal(r.learned, false);
    assert.ok(r.reason);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
ok('手动 allow 可显式加入 never-learn 签名（source=manual，立即生效）', () => {
  const dir = mkdtempSync(join(tmpdir(), 'taste-'));
  try {
    const store = createTasteStore({ dir });
    const sig = 'rm -rf /tmp/x';
    const entry = store.allow(sig);
    assert.equal(entry.source, 'manual');
    assert.equal(store.check(sig), 'allow');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
ok('forget 删除名单条目', () => {
  const dir = mkdtempSync(join(tmpdir(), 'taste-'));
  try {
    const store = createTasteStore({ dir });
    store.allow('x y');
    assert.equal(store.check('x y'), 'allow');
    assert.equal(store.forget('x y'), 1);
    assert.equal(store.check('x y'), null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

console.log('\n[失效与复核]');
ok('插件树 hash 变化 → active 条目标记 pending-review，check 不命中', () => {
  const dir = mkdtempSync(join(tmpdir(), 'taste-'));
  try {
    const store = createTasteStore({ dir, pluginHash: 'hash-v1' });
    const sig = 'git push origin <BRANCH>';
    store.allow(sig);
    assert.equal(store.check(sig), 'allow');
    const marked = store.applyPluginHash('hash-v2');
    assert.equal(marked, 1);
    assert.equal(store.check(sig), null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
ok('confirmReview 恢复 active 并更新 hash', () => {
  const dir = mkdtempSync(join(tmpdir(), 'taste-'));
  try {
    let store = createTasteStore({ dir, pluginHash: 'hash-v1' });
    const sig = 'git push origin <BRANCH>';
    store.allow(sig);
    store.applyPluginHash('hash-v2');
    store = createTasteStore({ dir, pluginHash: 'hash-v2' });
    assert.equal(store.confirmReview(sig), true);
    assert.equal(store.check(sig), 'allow');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

console.log('\n[持久化与自检]');
ok('状态跨实例持久化', () => {
  const dir = mkdtempSync(join(tmpdir(), 'taste-'));
  try {
    createTasteStore({ dir }).allow('npm test');
    const store2 = createTasteStore({ dir });
    assert.equal(store2.check('npm test'), 'allow');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
ok('schema 损坏的 allowlist.json → 拒绝加载（空名单 + 告警）', () => {
  const dir = mkdtempSync(join(tmpdir(), 'taste-'));
  try {
    writeFileSync(join(dir, 'allowlist.json'), '{"broken":true}', 'utf8');
    const store = createTasteStore({ dir });
    assert.equal(store.snapshot().allowlist.length, 0);
    assert.equal(store.check('anything'), null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
ok('非 JSON 的 allowlist.json → 拒绝加载不抛异常', () => {
  const dir = mkdtempSync(join(tmpdir(), 'taste-'));
  try {
    writeFileSync(join(dir, 'allowlist.json'), 'not json at all', 'utf8');
    const store = createTasteStore({ dir });
    assert.equal(store.snapshot().allowlist.length, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

console.log('\n[品味包导出/导入]');
ok('导出 → 导入 roundtrip，导入条目为 pending-review', () => {
  const dirA = mkdtempSync(join(tmpdir(), 'taste-a-'));
  const dirB = mkdtempSync(join(tmpdir(), 'taste-b-'));
  try {
    const a = createTasteStore({ dir: dirA });
    a.allow('npm test');
    a.deny('npm publish');
    const pack = a.exportPack();
    const b = createTasteStore({ dir: dirB });
    const r = b.importPack(pack);
    assert.equal(r.ok, true);
    assert.equal(r.imported, 2);
    assert.equal(b.check('npm test'), null); // pending-review 不生效
    assert.equal(b.snapshot().allowlist[0].status, 'pending-review');
  } finally {
    rmSync(dirA, { recursive: true, force: true });
    rmSync(dirB, { recursive: true, force: true });
  }
});
ok('校验和被篡改 → 拒绝导入', () => {
  const dir = mkdtempSync(join(tmpdir(), 'taste-'));
  try {
    const a = createTasteStore({ dir });
    a.allow('npm test');
    const pack = JSON.parse(a.exportPack());
    pack.payload.allowlist[0].signature = 'rm -rf /';
    const r = a.importPack(JSON.stringify(pack));
    assert.equal(r.ok, false);
    assert.ok(r.error.includes('校验和'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
ok('meta 不符 → 拒绝导入', () => {
  const dir = mkdtempSync(join(tmpdir(), 'taste-'));
  try {
    const store = createTasteStore({ dir });
    assert.equal(store.importPack('{"hello":"world"}').ok, false);
    assert.equal(store.importPack('not json').ok, false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

console.log(`\n结果：${passed} 个断言全部通过\n`);
process.exit(process.exitCode ?? 0);
