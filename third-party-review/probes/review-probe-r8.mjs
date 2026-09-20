/**
 * dsh-escrow round-8 第三方独立审查探针（M6-lite：账本哈希链 + report）
 * 运行：node D:/BigWorkspace/projects/dsh-escrow/third-party-review/probes/review-probe-r8.mjs
 *
 *  C*  = M6-lite 修复闭环验证（报告双计数/.bak 链验证/legacyDetected）
 *  G*  = round-8 新发现候选的确定性复现
 */
import { mkdtempSync, rmSync, writeFileSync, readFileSync, appendFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const { createLedger } = await import(new URL('../../lib/ledger.mjs', import.meta.url).href);
const { readLedgerLines } = await import(new URL('../../lib/reduce.mjs', import.meta.url).href);
const { computeReport } = await import(new URL('../../lib/report.mjs', import.meta.url).href);
const { computeReduce } = await import(new URL('../../lib/reduce.mjs', import.meta.url).href);
const plugin = await import(new URL('../../lib/index.mjs', import.meta.url).href);

const AC = () => new AbortController();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const tmp = () => mkdtempSync(join(tmpdir(), 'escrow-probe-r8-'));
const out = (tag, name, detail) => console.log(`[${tag}] ${name}${detail ? ' —— ' + detail : ''}`);

function makeCtx(ledgerDir) {
  const listeners = new Map();
  const commands = [];
  const tools = {
    registered: [], executed: [],
    register(d) { tools.registered.push(d); },
    async execute({ name, arguments: args }) {
      tools.executed.push({ name, args });
      return { isError: false, value: { stdout: { text: 'OK', truncated: false }, stderr: { text: '', truncated: false } } };
    }
  };
  return { logger: { info() {}, warn() {} }, on(e, f) { listeners.set(e, f); }, commands: { register(d) { commands.push(d); } }, tools, _listeners: listeners, _commands: commands, _tools: tools };
}

// ============ C-M6-1（闭环）：approved 双计数修复（async 一次批准 = 1 approved + 1 executed） ============
{
  const dir = tmp();
  try {
    const ctx = makeCtx(dir);
    plugin.apply(ctx, { ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dir, mode: 'async', syncTools: [] });
    const pre = ctx._listeners.get('tools/pre-execute');
    const next = async () => 'OK';
    // 入队一个 red → 人工批准
    const callId = 'm6-c1';
    await pre({ name: 'bash', arguments: { command: 'rm -rf /tmp/probe-m6-1' }, callId, signal: AC().signal }, next);
    const cmd = ctx._commands.find((c) => c.name === 'escrow');
    const id = cmd.handler({ rawInput: 'pending', signal: AC().signal }).text.match(/esc-\d+-\d+/)[0];
    cmd.handler({ rawInput: `approve ${id}`, signal: AC().signal });
    await sleep(300); // 等 replay 完成 + 异步落账
    const lines = readLedgerLines(join(dir, 'ledger.jsonl'));
    const rep = computeReport(lines);
    const decidedApproved = lines.filter((l) => l.kind === 'escrow.decided' && l.decision === 'approved').length;
    const executed = lines.filter((l) => l.kind === 'escrow.approved_executed').length;
    const repApproved = rep.approved;
    const repExecuted = rep.executed;
    out(decidedApproved === 1 && repApproved === 1 && executed === 1 && repExecuted === 1 ? '闭环' : '缺陷确认',
      'C-M6-1 async 一次批准：decided(approved)=1 + approved_executed=1 + report.approved=1 + report.executed=1（无双计数）',
      `decidedApproved=${decidedApproved} repApproved=${repApproved} executed=${executed} repExecuted=${repExecuted}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ============ C-M6-2（闭环）：.bak 链验证（篡改 .bak 报 tampered） ============
{
  const dir = tmp();
  try {
    const ledger = createLedger({ dir, maxBytes: 10 * 1024 * 1024 });
    ledger.write('observe', { session: 'test', tool: 'bash', callId: 'a1', cls: 'yellow', args: '{}' });
    ledger.write('observe', { session: 'test', tool: 'bash', callId: 'a2', cls: 'yellow', args: '{}' });
    // 手工造一个 ledger.jsonl.bak，里面有合法哈希链
    const bakFile = `${ledger.path}.bak`;
    const ledgerFile = ledger.path;
    const oldContent = readFileSync(ledgerFile, 'utf8').trim().split('\n');
    // 把第一条搬到 .bak 作为历史，构造链连续性
    writeFileSync(bakFile, oldContent[0] + '\n', 'utf8');
    // 然后篡改 .bak 第二字节内容并重算 h（确保 h 不匹配）
    const tampered = JSON.parse(oldContent[0]);
    tampered.tool = 'EVIL';
    const badH = 'deadbeef'.repeat(8);
    appendFileSync(bakFile, JSON.stringify({ ...tampered, h: badH }) + '\n', 'utf8');
    // 新建一个 ledger 实例重新 scanChain
    const ledger2 = createLedger({ dir, maxBytes: 10 * 1024 * 1024 });
    out(ledger2.integrity.tampered === true ? '闭环' : '缺陷确认',
      'C-M6-2 篡改 .bak 哈希链 → integrity.tampered=true',
      `tampered=${ledger2.integrity.tampered} legacyDetected=${ledger2.integrity.legacyDetected}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ============ C-M6-3（闭环）：legacyDetected 旧格式（无 h 行）→ 链重置 + 报告 ============
{
  const dir = tmp();
  try {
    const ledger = createLedger({ dir, maxBytes: 10 * 1024 * 1024 });
    // 写入旧格式（无 h）行：手动绕过 ledger.write 直接 append
    appendFileSync(ledger.path, JSON.stringify({ t: new Date().toISOString(), kind: 'observe', session: 'old', tool: 'bash', callId: 'old1', cls: 'yellow', args: '{}' }) + '\n', 'utf8');
    appendFileSync(ledger.path, JSON.stringify({ t: new Date().toISOString(), kind: 'observe', session: 'old', tool: 'bash', callId: 'old2', cls: 'yellow', args: '{}' }) + '\n', 'utf8');
    // 新建实例重新 scanChain
    const ledger2 = createLedger({ dir, maxBytes: 10 * 1024 * 1024 });
    out(ledger2.integrity.legacyDetected === true && ledger2.integrity.tampered === false ? '闭环' : '缺陷确认',
      'C-M6-3 旧格式（无 h）行 → legacyDetected=true 且 tampered=false',
      `tampered=${ledger2.integrity.tampered} legacyDetected=${ledger2.integrity.legacyDetected}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ============ G1（HIGH 候选）：legacy 行作为链重置点可被攻击者利用 ============
{
  const dir = tmp();
  try {
    const ledger = createLedger({ dir, maxBytes: 10 * 1024 * 1024 });
    // 先正常写 3 行（合法链）
    for (let i = 0; i < 3; i++) ledger.write('observe', { session: 'good', tool: 'bash', callId: `g-${i}`, cls: 'yellow', args: '{}' });
    const before = ledger.integrity.chainHead;
    // 在合法链中间追加一行无 h 的"旧格式"行（模拟攻击者植入重置点）
    const line4 = JSON.stringify({ t: new Date().toISOString(), kind: 'observe', session: 'attacker', tool: 'EVIL', callId: 'att-1', cls: 'yellow', args: '{"payload":"malicious"}' });
    appendFileSync(ledger.path, line4 + '\n', 'utf8');
    // 之后攻击者可以再追加"伪造链"——基于 genesis 重算 h
    // 我们验证：scanChain 后 chainHead 应当等于"被攻击污染的链头"还是原链头？
    const ledger2 = createLedger({ dir, maxBytes: 10 * 1024 * 1024 });
    const after = ledger2.integrity.chainHead;
    const legacyDetectedBefore = ledger2.integrity.legacyDetected;
    const blocked = ledger2.write('observe', { session: 'after-legacy', tool: 'bash' });
    const migrated = ledger2.migrate();
    out(legacyDetectedBefore === true && ledger2.integrity.legacyDetected === false && blocked === false && migrated.migrated >= 1 ? '闭环' : '缺陷确认',
      'G1 legacy 行：迁移前只读，显式 migrate 后恢复写入',
      `before=${before.slice(0,12)} after=${after.slice(0,12)} tampered=${ledger2.integrity.tampered} legacyBefore=${legacyDetectedBefore} legacyAfter=${ledger2.integrity.legacyDetected} blocked=${blocked} migrated=${migrated.migrated}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ============ G2（MEDIUM 候选）：payload 键名 `h` 静默丢失 ============
{
  const dir = tmp();
  try {
    const ledger = createLedger({ dir, maxBytes: 10 * 1024 * 1024 });
    // 用户写一行故意 payload 自带 h 字段（语义冲突）
    ledger.write('observe', { session: 'test', tool: 'bash', callId: 'h-conflict', cls: 'yellow', args: '{}', h: 'USER_OVERRIDE', m: 'USER_M_OVERRIDE' });
    const lines = readLedgerLines(ledger.path);
    const rec = lines.find((l) => l.callId === 'h-conflict');
    // 用户字段应被命名空间保留，链字段仍由 ledger 生成
    const payloadH = rec?.payload_h;
    const payloadM = rec?.payload_m;
    out(payloadH === 'USER_OVERRIDE' && payloadM === 'USER_M_OVERRIDE' ? '闭环' : '缺陷确认',
      'G2 payload.h/m 冲突字段：命名空间保留，链字段不被用户覆盖',
      `rec.h=${payloadH ? payloadH.slice(0, 16) + '...' : 'null'} rec.t=${rec?.t}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ============ G3（MEDIUM 候选）：report.avgWaitMs 与 roi.avgHumanWaitMs 字段冗余 ============
{
  const dir = tmp();
  try {
    const ledger = createLedger({ dir, maxBytes: 10 * 1024 * 1024 });
    ledger.write('escrow.decided', { session: 's', id: 'esc-1-1', tool: 'bash', decision: 'approved', via: 'human', waitedMs: 1500 });
    const lines = readLedgerLines(ledger.path);
    const rep = computeReport(lines);
    out(rep.avgWaitMs === undefined && rep.roi.avgHumanWaitMs === 1500 ? '闭环' : '缺陷确认',
      'G3 report 仅暴露 roi.avgHumanWaitMs（无重复顶层字段）',
      `rep.avgWaitMs=${rep.avgWaitMs} rep.roi.avgHumanWaitMs=${rep.roi.avgHumanWaitMs} rep.roi.confirmCount=${rep.roi.confirmCount}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ============ G4（MEDIUM 候选）：approveRate 与 interruptRate 分母口径不一致 ============
{
  const dir = tmp();
  try {
    const ledger = createLedger({ dir, maxBytes: 10 * 1024 * 1024 });
    // 模拟：3 观察（observe）+ 2 拒绝（decided denied）+ 1 批准（decided approved）+ 1 黑名单 + 1 白名单放行
    for (let i = 0; i < 3; i++) ledger.write('observe', { session: 's', tool: 'bash', callId: `obs-${i}`, cls: 'yellow', args: '{"command":"ls"}' });
    ledger.write('escrow.decided', { session: 's', id: 'esc-1-1', tool: 'bash', decision: 'denied', via: 'human', waitedMs: 1000 });
    ledger.write('escrow.decided', { session: 's', id: 'esc-2-1', tool: 'bash', decision: 'denied', via: 'timeout', waitedMs: 5000 });
    ledger.write('escrow.decided', { session: 's', id: 'esc-3-1', tool: 'bash', decision: 'approved', via: 'human', waitedMs: 1000 });
    ledger.write('escrow.blacklisted', { session: 's', id: 'esc-4-1', tool: 'bash', signature: 'git push origin <BRANCH>', reason: 'auto' });
    ledger.write('escrow.whitelisted', { session: 's', tool: 'bash', callId: 'wh-1', signature: 'npm install', reason: 'learned' });
    const lines = readLedgerLines(ledger.path);
    const rep = computeReport(lines);
    const red = computeReduce(lines);
    // report.approveRate = approved/(approved+denied)
    // reduce.interruptRate = denied/(total+denied)
    out(rep.approveRate.toFixed(2) !== (red.interruptRate).toFixed(2) ? '信息' : 'OK',
      'G4 approveRate 与 interruptRate 分母口径不同（同一账本）',
      `rep.approveRate=${rep.approveRate.toFixed(2)} (approved=${rep.approved} denied=${rep.denied}) | reduce.interruptRate=${red.interruptRate.toFixed(2)} (total=${red.total} denied=${red.denied})`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ============ G5（MEDIUM 候选）：readLedgerLines 把 .bak 行纳入统计，轮转后跨代重复 ============
{
  const dir = tmp();
  try {
    const ledger = createLedger({ dir, maxBytes: 10 * 1024 * 1024 });
    // 写 5 行作为 .bak 历史
    for (let i = 0; i < 5; i++) ledger.write('observe', { session: 's', tool: 'bash', callId: `bak-${i}`, cls: 'yellow', args: '{}' });
    // 手动把当前 ledger 内容搬到 .bak，然后新写
    const bakFile = `${ledger.path}.bak`;
    writeFileSync(bakFile, readFileSync(ledger.path, 'utf8'), 'utf8');
    // 在新 ledger 写 3 行
    for (let i = 0; i < 3; i++) ledger.write('observe', { session: 's', tool: 'bash', callId: `new-${i}`, cls: 'yellow', args: '{}' });
    const lines = readLedgerLines(ledger.path);
    out(lines.length === 13 ? '信息' : '缺陷确认',
      'G5 readLedgerLines main + .bak 跨代合并（已知统计限制）',
      `lines=${lines.length}（main + .bak 跨代合并）`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

console.log('\n==== round-8 探针结束 ====');
