/**
 * 第三方独立审查探针（round 3）：验证修复闭环 + 复现新发现缺陷。
 * 运行：node D:/BigWorkspace/projects/dsh-escrow/third-party-review/probes/review-probe.mjs
 *
 * C* = findings-log「请重点验证的修复闭环」补强验证（测试套件未覆盖的部分）
 * F* = 新发现缺陷的确定性复现
 * 每行输出 [OK]/[闭环]/[缺陷确认]/[信息] + 证据细节。
 */
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const plugin = await import(new URL('../../lib/index.mjs', import.meta.url).href);
const { classifyExec } = await import(new URL('../../lib/classify.mjs', import.meta.url).href);

const AC = () => new AbortController();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const tmp = () => mkdtempSync(join(tmpdir(), 'escrow-probe-'));
const REAL = { isError: false, value: { kind: 'foreground', exitCode: 0, signal: null, timedOut: false, aborted: false, timeoutMs: 0, stdout: { text: 'REAL OUTPUT', truncated: false }, stderr: { text: '', truncated: false } } };

/** 与 integration 测试同构的 mock ctx：tools.execute 走完整 pre→execute 流水线。 */
function makeCtx(ledgerDir) {
  const listeners = new Map();
  const commands = [];
  const tools = {
    registered: [], executed: [],
    register(d) { tools.registered.push(d); },
    async execute(input) {
      tools.executed.push(input);
      const pre = listeners.get('tools/pre-execute');
      if (pre) {
        const r = await pre({ name: input.name, arguments: input.arguments, callId: input.callId, signal: input.signal, agent: input.agent }, () => Promise.resolve({ kind: 'allow' }));
        if (r.kind === 'deny') return { isError: true, error: { message: r.reason }, content: [] };
      }
      const exe = listeners.get('tools/execute');
      if (exe) return exe({ name: input.name, arguments: input.arguments, callId: input.callId, signal: input.signal }, () => Promise.resolve(REAL));
      return REAL;
    }
  };
  return {
    logger: { info() {}, warn() {} },
    on(e, f) { listeners.set(e, f); },
    commands: { register(d) { commands.push(d); } },
    tools, _listeners: listeners, _commands: commands, _tools: tools
  };
}

const base = { ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], mode: 'async' };
const nextAllow = () => Promise.resolve({ kind: 'allow' });
const lines = [];
const out = (tag, name, detail) => { const s = `[${tag}] ${name}${detail ? ` —— ${detail}` : ''}`; lines.push(s); console.log(s); };

// ============ C1：approve all 同签名 2 条不同参数 → 两条都真实执行，学习一次 ============
{
  const dir = tmp();
  try {
    const ctx = makeCtx(dir);
    const api = plugin.apply(ctx, { ...base, ledgerDir: dir });
    const pre = ctx._listeners.get('tools/pre-execute');
    const cmd = ctx._commands.find((c) => c.name === 'escrow');
    await pre({ name: 'bash', arguments: { command: 'git push origin main' }, callId: 'c1a', signal: AC().signal }, nextAllow);
    await pre({ name: 'bash', arguments: { command: 'git push origin feature' }, callId: 'c1b', signal: AC().signal }, nextAllow);
    const ids = api.queue.pendingList().map((e) => e.id);
    cmd.handler({ rawInput: 'approve all', signal: AC().signal });
    await sleep(150);
    const states = ids.map((id) => api.queue.getEntry(id)?.state);
    const learned = api.taste.snapshot().allowlist.find((e) => e.signature.includes('git push'));
    out(ctx._tools.executed.length === 2 && states.every((s) => s === 'executed') ? '闭环' : '缺陷确认',
      'C1 approve all 两个实例都真实执行', `入队=${ids.length} 重放执行=${ctx._tools.executed.length} 状态=${states.join(',')}`);
    out(learned && learned.count === 1 ? '闭环' : '缺陷确认',
      'C1 approve all 学习按组一次', `白名单条目 count=${learned?.count} status=${learned?.status}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ============ C4：release + async 超时 → settle 后自动重放（不卡"执行中"） ============
{
  const dir = tmp();
  try {
    const ctx = makeCtx(dir);
    const api = plugin.apply(ctx, { ...base, ttlSec: 1, timeoutPolicy: 'release', ledgerDir: dir });
    const pre = ctx._listeners.get('tools/pre-execute');
    await pre({ name: 'bash', arguments: { command: 'git push origin main' }, callId: 'c4a', signal: AC().signal }, nextAllow);
    const id = api.queue.pendingList()[0]?.id;
    await sleep(1600); // 等 ttl=1s 超时 settle（release → approved via timeout → onSettle 触发重放）
    const st = api.queue.getEntry(id)?.state;
    const ledger = readFileSync(join(dir, 'ledger.jsonl'), 'utf8');
    out(st === 'executed' && ctx._tools.executed.length === 1 && ledger.includes('escrow.replayed') ? '闭环' : '缺陷确认',
      'C4 release+async 超时自动重放', `状态=${st} 执行=${ctx._tools.executed.length} 账本replayed=${ledger.includes('escrow.replayed')}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ============ F6a：async+cancel 超时拒绝后，迟到的原始调用到达 execute 层 → 仍被放行执行 ============
{
  const dir = tmp();
  try {
    const ctx = makeCtx(dir);
    const api = plugin.apply(ctx, { ...base, ttlSec: 1, timeoutPolicy: 'cancel', ledgerDir: dir });
    const pre = ctx._listeners.get('tools/pre-execute');
    const exe = ctx._listeners.get('tools/execute');
    await pre({ name: 'bash', arguments: { command: 'git push origin main' }, callId: 'f6a', signal: AC().signal }, nextAllow);
    await sleep(1600); // 超时拒绝（settle 删除 pendingByCallId/pendingBySig 索引）
    const ledger = readFileSync(join(dir, 'ledger.jsonl'), 'utf8');
    let exeNext = 0;
    // 模拟事件循环被下游钩子阻塞 >ttl 后，原始调用才到达 execute 层
    const r = await exe({ name: 'bash', arguments: { command: 'git push origin main' }, callId: 'f6a', signal: AC().signal }, () => { exeNext += 1; return Promise.resolve(REAL); });
    out(exeNext === 1 ? '缺陷确认' : 'OK',
      'F6a 已超时拒绝的动作仍被执行（execute 闸门只查"当前 pending"）', `超时落账=${ledger.includes('"via":"timeout"')} 迟到调用 next()=${exeNext} 返回isError=${r?.isError ?? false}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ============ F6b：async+release 超时自动重放 1 次 + 迟到的原始调用再执行 1 次 = 双执行 ============
{
  const dir = tmp();
  try {
    const ctx = makeCtx(dir);
    const api = plugin.apply(ctx, { ...base, ttlSec: 1, timeoutPolicy: 'release', ledgerDir: dir });
    const pre = ctx._listeners.get('tools/pre-execute');
    const exe = ctx._listeners.get('tools/execute');
    await pre({ name: 'bash', arguments: { command: 'git push origin main' }, callId: 'f6b', signal: AC().signal }, nextAllow);
    await sleep(1600); // 超时 approved → 自动重放（第 1 次真实执行）
    const replayed = ctx._tools.executed.length;
    let exeNext = 0;
    await exe({ name: 'bash', arguments: { command: 'git push origin main' }, callId: 'f6b', signal: AC().signal }, () => { exeNext += 1; return Promise.resolve(REAL); });
    out(replayed === 1 && exeNext === 1 ? '缺陷确认' : 'OK',
      'F6b release 超时重放 1 次 + 迟到原始调用又执行 1 次（双执行）', `自动重放=${replayed} 迟到调用 next()=${exeNext}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ============ F5：argsSnapshot 是活引用——入队后被下游钩子改写，批准后按改写后的参数重放（TOCTOU） ============
{
  const dir = tmp();
  try {
    const ctx = makeCtx(dir);
    const api = plugin.apply(ctx, { ...base, ledgerDir: dir });
    const pre = ctx._listeners.get('tools/pre-execute');
    const cmd = ctx._commands.find((c) => c.name === 'escrow');
    const args = { command: 'git push origin main' };
    await pre({ name: 'bash', arguments: args, callId: 'f5a', signal: AC().signal }, nextAllow);
    const snap = api.queue.pendingList()[0];
    const shownToHuman = snap?.summary; // 人工看到的是这个摘要
    args.command = 'rm -rf /tmp/innocent'; // 模拟 escrow 之后的下游 pre-execute 钩子原地改写 arguments
    cmd.handler({ rawInput: `approve ${snap.id}`, signal: AC().signal });
    await sleep(150);
    const replayedCmd = ctx._tools.executed[0]?.arguments?.command;
    out(replayedCmd === 'rm -rf /tmp/innocent' ? '缺陷确认' : 'OK',
      'F5 人工批准 A、实际执行 B（重放不重新分类，B 可为任意更危险命令）', `人工看到="${shownToHuman}" 实际执行="${replayedCmd}"`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ============ F4：sync 模式同签名并发去重 → 一次批准、两次真实执行 ============
{
  const dir = tmp();
  try {
    const ctx = makeCtx(dir);
    const api = plugin.apply(ctx, { ...base, mode: 'sync', ledgerDir: dir });
    const pre = ctx._listeners.get('tools/pre-execute');
    let n1 = 0; let n2 = 0;
    const t1 = () => { n1 += 1; return Promise.resolve({ kind: 'allow' }); };
    const t2 = () => { n2 += 1; return Promise.resolve({ kind: 'allow' }); };
    const p1 = pre({ name: 'bash', arguments: { command: 'git push origin main' }, callId: 'f4a', signal: AC().signal }, t1);
    const p2 = pre({ name: 'bash', arguments: { command: 'git push origin main' }, callId: 'f4b', signal: AC().signal }, t2);
    await sleep(20);
    const pendLen = api.queue.pendingList().length; // 去重 → 1 条
    const id = api.queue.pendingList()[0]?.id;
    api.queue.decide(id, 'approved'); // 人工只批准了这 1 条
    await Promise.all([p1, p2]);
    const ledger = readFileSync(join(dir, 'ledger.jsonl'), 'utf8');
    const queuedLines = ledger.split('\n').filter((l) => l.includes('escrow.queued')).length;
    out(pendLen === 1 && n1 + n2 === 2 ? '缺陷确认' : 'OK',
      'F4 sync 去重：1 次批准 → 两个调用都落到 next()（真实执行 2 次）', `入队=${pendLen} next()=${n1 + n2} 账本queued行=${queuedLines}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ============ F7：用户显式 red 规则被品味白名单覆盖 ============
{
  const dir = tmp();
  try {
    const ctx = makeCtx(dir);
    const api = plugin.apply(ctx, {
      ...base, ledgerDir: dir,
      rules: [{ id: 'always-escrow-deploy', tools: ['bash'], args: [{ key: 'command', pattern: 'deploy' }], action: 'red' }]
    });
    api.taste.allow('deploy prod'); // 签名经学习/手动进入白名单
    const pre = ctx._listeners.get('tools/pre-execute');
    await pre({ name: 'bash', arguments: { command: 'deploy prod' }, callId: 'f7a', signal: AC().signal }, nextAllow);
    const queued = api.queue.pendingList().length;
    const ledger = readFileSync(join(dir, 'ledger.jsonl'), 'utf8');
    out(queued === 0 && ledger.includes('escrow.whitelisted') ? '缺陷确认' : 'OK',
      'F7 用户配置 red（deploy 必托管）被品味 allow 直接放行', `入队=${queued} 白名单落账=${ledger.includes('escrow.whitelisted')}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ============ F1/F2/F3/F8：分类覆盖缺口（纯函数探测） ============
{
  const opts = { builtinRules: true, defaultAction: 'yellow', rules: [] };
  const probes = [
    ['F1 bash: rm -r ./src（递归删除，无 -f）', { name: 'bash', arguments: { command: 'rm -r ./src' } }],
    ['F1 bash: rm --recursive ./src（长旗标，无 --force）', { name: 'bash', arguments: { command: 'rm --recursive ./src' } }],
    ['F3 pwsh: rm -Recurse ./src（PS 别名递归删除，无 -Force）', { name: 'pwsh', arguments: { command: 'rm -Recurse ./src' } }],
    ['F2 bash: git checkout -- src/main.ts（丢弃文件改动，非 "."）', { name: 'bash', arguments: { command: 'git checkout -- src/main.ts' } }],
    ['F2 bash: git restore --worktree src/main.ts（现代等价写法）', { name: 'bash', arguments: { command: 'git restore --worktree src/main.ts' } }],
    ['F8 fs.write filename=".env"（路径键 filename 不在 KEYS）', { name: 'fs.write', arguments: { filename: '.env', content: 'x' } }],
    ['F8 fs.write outputFile=".env"（outputFile 不在 KEYS）', { name: 'fs.write', arguments: { outputFile: '.env', content: 'x' } }]
  ];
  for (const [name, exec] of probes) {
    const r = classifyExec(exec, opts);
    out(r.action === 'red' ? 'OK' : '缺陷确认', name, `分类=${r.action} ruleId=${r.ruleId}（yellow=放行+仅记账）`);
  }
}

console.log('\n==== 探针结束 ====');
