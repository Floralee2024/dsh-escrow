/**
 * 第三方独立审查探针 round 6（M7 自改治理 + M8 减法审计复审）。
 * 运行：node D:/BigWorkspace/projects/dsh-escrow/third-party-review/probes/review-probe-r6.mjs
 *
 * C* = M7/M8 修复闭环补强验证（测试套件未覆盖的部分）
 * G* = round-6 新发现候选的确定性复现
 */
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const { classifyExec, extractRedirectTargets } = await import(new URL('../../lib/classify.mjs', import.meta.url).href);
const { neverLearnReason, extractSignature } = await import(new URL('../../lib/signature.mjs', import.meta.url).href);
const { createTasteStore } = await import(new URL('../../lib/taste.mjs', import.meta.url).href);
const { computeReduce, readLedgerLines } = await import(new URL('../../lib/reduce.mjs', import.meta.url).href);
const plugin = await import(new URL('../../lib/index.mjs', import.meta.url).href);

const AC = () => new AbortController();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const tmp = () => mkdtempSync(join(tmpdir(), 'escrow-probe-r6-'));
const out = (tag, name, detail) => console.log(`[${tag}] ${name}${detail ? ` —— ${detail}` : ''}`);
const cls = (name, command, extra = {}) =>
  classifyExec({ name, arguments: { command, ...extra } }, { rules: [], builtinRules: true, defaultAction: 'yellow' });

function makeCtx(ledgerDir) {
  const listeners = new Map();
  const commands = [];
  const tools = { registered: [], executed: [], register(d) { tools.registered.push(d); }, async execute() { return { isError: false, value: { stdout: { text: 'REAL', truncated: false }, stderr: { text: '', truncated: false } } }; } };
  return { logger: { info() {}, warn() {} }, on(e, f) { listeners.set(e, f); }, commands: { register(d) { commands.push(d); } }, tools, _listeners: listeners, _commands: commands, _tools: tools };
}

// ============ G1（HIGH 候选）：never-learn 与 v0.3.4 扩红口径脱节——破坏性命令可自动学习白名单化 ============
{
  const samples = [
    ['rm -r ./src（递归删除，v0.3.4 已红）', 'bash', 'rm -r ./src'],
    ['rm --recursive ./src（长旗标）', 'bash', 'rm --recursive ./src'],
    ['pwsh: rm -Recurse ./src', 'pwsh', 'rm -Recurse ./src'],
    ['git restore --worktree src/main.ts', 'bash', 'git restore --worktree src/main.ts'],
    ['git -C repo reset --hard（全局选项穿插）', 'bash', 'git -C repo reset --hard'],
    ['git -C repo checkout -- . （全局选项穿插）', 'bash', 'git -C repo checkout -- .']
  ];
  for (const [label, tool, command] of samples) {
    const nl = neverLearnReason(tool, { command });
    const c = cls(tool, command);
    out(nl === null && c.action === 'red' ? '缺陷确认' : 'OK',
      `G1 ${label}`, `classify=${c.action}/${c.ruleId} neverLearn=${nl === null ? '可学习!' : '不可学习'}`);
  }
  // 学习全链路：rm -r 两次人工批准 → 白名单可激活 → 第三次直接放行执行（hardRed 不挡 builtin-command）
  const dir = tmp();
  try {
    const store = createTasteStore({ dir, threshold: 2, cooldownHours: 0 });
    const sig = extractSignature('bash', { command: 'rm -r ./src' }).signature;
    const a1 = store.recordDecision(sig, true, { toolName: 'bash', args: { command: 'rm -r ./src' } });
    const a2 = store.recordDecision(sig, true, { toolName: 'bash', args: { command: 'rm -r ./src' } });
    const chk = store.check(sig);
    const c = cls('bash', 'rm -r ./src');
    const hardRed = c.action === 'red' && (
      c.ruleId === 'builtin-sensitive-path' || c.ruleId === 'builtin-command-sensitive'
      || (!c.ruleId.startsWith('builtin-') && !c.ruleId.startsWith('(default'))
    );
    out(chk === 'allow' && !hardRed ? '缺陷确认' : 'OK',
      'G1 全链路：rm -r 学习×2 → 白名单激活 → 品味放行（递归删除从此免托管）',
      `学习=${a1.learned}/${a2.learned} check=${chk} classify=${c.action}/${c.ruleId} hardRed=${hardRed}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ============ G2（MEDIUM 候选）：命令串自改检测的引号/glob/变量混淆绕过 ============
{
  const bypasses = [
    ['引号拆除：echo pwn > AGENTS\'\'.md（bash 拼接为 AGENTS.md）', 'echo pwn > AGENTS\'\'.md'],
    ['部分引号：printf x > "AGENTS".md', 'printf x > "AGENTS".md'],
    ['glob：echo x > AGENTS.m?（shell 展开为 AGENTS.md）', 'echo x > AGENTS.m?'],
    ['变量：F=AGENTS; echo x > $F.md', 'F=AGENTS; echo x > $F.md']
  ];
  for (const [label, command] of bypasses) {
    const c = cls('bash', command);
    const nl = neverLearnReason('bash', { command });
    out(c.action !== 'red' ? '缺陷确认' : 'OK', `G2 ${label}`, `classify=${c.action}/${c.ruleId} neverLearn=${nl === null ? '可学习' : '命中'}`);
  }
  // 对照：未混淆形态应红
  const ctrl = cls('bash', 'echo pwn > AGENTS.md');
  out(ctrl.action === 'red' && ctrl.ruleId === 'selfmod' ? 'OK' : '信息', 'G2 对照：echo pwn > AGENTS.md', `classify=${ctrl.action}/${ctrl.ruleId}`);
}

// ============ G3（LOW）：hardRed 前缀启发式——用户规则 id 以 builtin- 开头 → 失去"用户 red 不容品味覆盖"保护 ============
{
  const dir = tmp();
  try {
    const ctx = makeCtx(dir);
    const api = plugin.apply(ctx, {
      ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true,
      rules: [{ id: 'builtin-guard', tools: ['bash'], args: [{ key: 'command', pattern: 'deploy' }], action: 'red' }],
      ledgerDir: dir, mode: 'async'
    });
    api.taste.allow('deploy prod');
    const pre = ctx._listeners.get('tools/pre-execute');
    await pre({ name: 'bash', arguments: { command: 'deploy prod' }, callId: 'g3', signal: AC().signal }, () => Promise.resolve({ kind: 'allow' }));
    const queued = api.queue.pendingList().length;
    out(queued === 0 ? '缺陷确认' : 'OK', 'G3 用户 red 规则 id=builtin-guard 被品味 allow 绕过', `入队=${queued}（0=用户 red 失效）`);
    api.queue.cancelAll();
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ============ G4（LOW）：预中止信号的 async 自改条目 → selfmod.decided 漏记（settle 先于 entries.set）============
{
  const dir = tmp();
  try {
    const ctx = makeCtx(dir);
    const api = plugin.apply(ctx, { ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dir, mode: 'async' });
    const pre = ctx._listeners.get('tools/pre-execute');
    const ctl = new AbortController();
    ctl.abort(); // 信号在入队前已中止
    await pre({ name: 'fs.write', arguments: { path: join(dir, 'AGENTS.md'), content: 'x' }, callId: 'g4', signal: ctl.signal }, () => Promise.resolve({ kind: 'allow' }));
    const ledger = readFileSync(join(dir, 'ledger.jsonl'), 'utf8');
    const hasQueued = ledger.includes('selfmod.queued');
    const hasDecided = ledger.includes('selfmod.decided');
    const hasEscrowDecided = ledger.includes('escrow.decided');
    out(hasQueued && hasDecided && hasEscrowDecided ? '闭环' : '缺陷确认',
      'G4 预中止自改条目：selfmod.decided 落账', `selfmod.queued=${hasQueued} selfmod.decided=${hasDecided} escrow.decided=${hasEscrowDecided}`);
    api.queue.cancelAll();
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ============ C-M7-3（闭环补强）：async 自改条目超时 → selfmod.decided via timeout 落账 ============
{
  const dir = tmp();
  try {
    const ctx = makeCtx(dir);
    plugin.apply(ctx, { ttlSec: 1, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dir, mode: 'async' });
    const pre = ctx._listeners.get('tools/pre-execute');
    await pre({ name: 'fs.write', arguments: { path: join(dir, 'AGENTS.md'), content: 'x' }, callId: 'cm7', signal: AC().signal }, () => Promise.resolve({ kind: 'allow' }));
    await sleep(1300);
    const ledger = readFileSync(join(dir, 'ledger.jsonl'), 'utf8');
    out(ledger.includes('selfmod.decided') && ledger.includes('"via":"timeout"') ? '闭环' : '缺陷确认',
      'C-M7-3 自改条目超时 → selfmod.decided 落账', `selfmod.decided=${ledger.includes('selfmod.decided')}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ============ C-M8（闭环补强）：whitelisted 用落账 signature 统计 / .bak 合并 / interruptRate 上限 ============
{
  const dir = tmp();
  try {
    // 白名单行（无 args，只有 signature）×10 → 应被 signatureOf 计入重复
    const wl = JSON.stringify({ t: new Date().toISOString(), kind: 'escrow.whitelisted', tool: 'bash', signature: 'git push origin <BRANCH>' });
    writeFileSync(join(dir, 'ledger.jsonl'), Array(10).fill(wl).join('\n') + '\n', 'utf8');
    // .bak 里放 5 条 denied → 合并读应计入
    const dn = JSON.stringify({ t: new Date().toISOString(), kind: 'escrow.decided', decision: 'denied', via: 'timeout' });
    writeFileSync(join(dir, 'ledger.jsonl.bak'), Array(5).fill(dn).join('\n') + '\n', 'utf8');
    const r = computeReduce(readLedgerLines(join(dir, 'ledger.jsonl')), { threshold: 10, sinceMs: 0 });
    out(r.duplicates.length === 1 && r.duplicates[0].signature === 'git push origin <BRANCH>' && r.duplicates[0].count === 10 ? '闭环' : '缺陷确认',
      'C-M8-1 白名单行按落账 signature 统计重复', `duplicates=${JSON.stringify(r.duplicates)}`);
    out(r.denied === 5 && r.interruptRate <= 1 ? '闭环' : '缺陷确认',
      'C-M8-2 .bak 合并计入 + interruptRate ≤ 100%', `denied=${r.denied} interruptRate=${r.interruptRate.toFixed(3)} total=${r.total}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ============ C-M7-1（闭环）：重定向变体目标提取 + never-learn（tee -a / 零空格 / 1> / 2> / &> / tee --长选项）============
{
  const cases = [
    ['echo x >AGENTS.md（零空格）', 'echo x >AGENTS.md', 'AGENTS.md'],
    ['echo x >> AGENTS.md', 'echo x >> AGENTS.md', 'AGENTS.md'],
    ['echo x 1> AGENTS.md', 'echo x 1> AGENTS.md', 'AGENTS.md'],
    ['echo x 2> AGENTS.md', 'echo x 2> AGENTS.md', 'AGENTS.md'],
    ['echo x &> AGENTS.md', 'echo x &> AGENTS.md', 'AGENTS.md'],
    ['tee -a cordis.patch.yml', 'tee -a cordis.patch.yml < /dev/null', 'cordis.patch.yml'],
    ['tee --ignore-interrupts -a AGENTS.md（长选项）', 'tee --ignore-interrupts -a AGENTS.md', 'AGENTS.md'],
    ['双引号目标 echo x > "AGENTS.md"', 'echo x > "AGENTS.md"', 'AGENTS.md']
  ];
  for (const [label, command, want] of cases) {
    const targets = extractRedirectTargets(command);
    const nl = neverLearnReason('bash', { command });
    const hit = targets.includes(want) && nl !== null;
    out(hit ? '闭环' : '缺陷确认', `C-M7-1 ${label}`, `targets=${JSON.stringify(targets)} neverLearn=${nl ? '不可学习' : '可学习!'}`);
  }
}

// ============ C-M7-2（闭环）：命令串自改的 before 快照（重定向目标可读路径）============
{
  const dir = tmp();
  try {
    const target = join(dir, 'AGENTS.md');
    writeFileSync(target, 'before-content', 'utf8');
    const ctx = makeCtx(dir);
    const api = plugin.apply(ctx, { ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dir, mode: 'async' });
    const pre = ctx._listeners.get('tools/pre-execute');
    await pre({ name: 'bash', arguments: { command: `echo pwn > ${target}` }, callId: 'cm72', signal: AC().signal }, () => Promise.resolve({ kind: 'allow' }));
    const ledger = readFileSync(join(dir, 'ledger.jsonl'), 'utf8');
    const queued = ledger.split('\n').find((l) => l.includes('selfmod.queued'));
    const hasSnap = queued ? queued.includes('snapshots') && queued.includes('AGENTS.md') && queued.includes('hash') : false;
    out(hasSnap ? '闭环' : '缺陷确认', 'C-M7-2 命令串自改记录 before 快照 hash', hasSnap ? JSON.parse(queued).snapshots : `selfmod.queued=${!!queued}`);
    api.queue.cancelAll();
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ============ C-M8-3（闭环）：--since=7 等号形式 + escrow.blacklisted 计入"拦下" ============
{
  const dir = tmp();
  try {
    const now = Date.now();
    const line = (kind, extra = {}) => JSON.stringify({ t: new Date(now).toISOString(), kind, ...extra });
    writeFileSync(join(dir, 'ledger.jsonl'), [
      line('escrow.blacklisted', { tool: 'bash', signature: 'npm install' }),
      line('escrow.decided', { decision: 'denied', via: 'human' }),
      line('observe', { tool: 'bash', args: '{"command":"ls"}' }),
      JSON.stringify({ t: new Date(now - 30 * 86400000).toISOString(), kind: 'observe', tool: 'bash', args: '{"command":"old command"}' })
    ].join('\n') + '\n', 'utf8');
    const lines = readLedgerLines(join(dir, 'ledger.jsonl'));
    const all = computeReduce(lines, { threshold: 2, sinceMs: 0 });
    const since7 = computeReduce(lines, { threshold: 2, sinceMs: now - 7 * 86400000 });
    out(all.denied === 2 && all.total === 2 ? '闭环' : '缺陷确认',
      'C-M8-3 blacklisted 计入拦下', `denied=${all.denied}（blacklisted + decided）total=${all.total}`);
    out(since7.total === 1 ? '闭环' : '缺陷确认',
      'C-M8-4 --since 过滤生效（30 天前记录应被剔除）', `全部 total=${all.total} since7d total=${since7.total}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

console.log('\n==== round-6 探针结束 ====');
