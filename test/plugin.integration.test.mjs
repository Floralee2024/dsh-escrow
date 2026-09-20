/**
 * dsh-escrow 插件级集成测试（mock Cordis ctx，不需要真实 dsh 进程）。
 * 运行方式（必须在 escrowtest profile 目录内，让 bare import 解析到已安装的包）：
 *   cd C:/Users/flora/.dsh/profiles/escrowtest
 *   node --input-type=module D:/BigWorkspace/projects/dsh-escrow/test/plugin.integration.test.mjs
 *
 * v0.1.1：
 * - ttl=0 用例新增时延断言（<1500ms），旧版只查最终 deny，掩盖了 0 被改成 30 的 bug；
 * - 新增 next() 单调回归：下游同步抛错时，green 与「批准后 red」路径的 next()
 *   都只能被调用一次（旧版 catch 会再次调用 next，单次批准可能执行两次）。
 *
 * v0.2 M1：
 * - mock ctx 补 tools{register, execute}——execute 模拟完整流水线（pre-execute → execute），
 *   使 approve 重放能真实走豁免 + 放行链路；
 * - 「批准后 red next 单调」回归改用 sync 模式（v0.1.1 同步语义；M1 async 下 red 路径
 *   next 抛错为 fail-closed deny，不再外传）；
 * - 新增 M1 区：async 非阻塞、execute 合成结果、同签名去重、approve 重放、escrow_result 全链路。
 */

import { mkdtempSync, rmSync, existsSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// 默认测源码副本；设置 DSH_ESCROW_ENTRY 可指向 profile 里已安装的副本（验证真实安装）。
const entry = process.env.DSH_ESCROW_ENTRY || new URL('../lib/index.mjs', import.meta.url).href;
const plugin = await import(entry);

let passed = 0;
const results = [];
function record(name, ok, detail = '') {
  results.push({ name, ok, detail });
  if (ok) passed += 1;
}

// ---- mock ctx ----
// tools.execute 模拟 dsh 完整流水线：先走 tools/pre-execute（豁免/分类），再走 tools/execute。
// 这样 approve 的重放能真实经过 escrow 的豁免与放行逻辑。
const REAL_RESULT = (name) => ({
  isError: false,
  value: {
    kind: 'foreground', exitCode: 0, signal: null, timedOut: false, aborted: false, timeoutMs: 0,
    stdout: { text: `REAL OUTPUT: ${name}`, truncated: false },
    stderr: { text: '', truncated: false }
  }
});

function makeCtx(ledgerDir) {
  const listeners = new Map();
  const commands = [];
  const tools = {
    registered: [],
    executed: [],
    register(def) {
      tools.registered.push(def);
    },
    async execute(input) {
      tools.executed.push(input);
      const pre = listeners.get('tools/pre-execute');
      if (pre) {
        const preResult = await pre(
          { name: input.name, arguments: input.arguments, callId: input.callId, signal: input.signal, agent: input.agent },
          () => Promise.resolve({ kind: 'allow' })
        );
        if (preResult.kind === 'deny') return { isError: true, error: { message: preResult.reason }, content: [] };
      }
      const exe = listeners.get('tools/execute');
      if (exe) {
        return exe(
          { name: input.name, arguments: input.arguments, callId: input.callId, signal: input.signal },
          () => Promise.resolve(REAL_RESULT(input.name))
        );
      }
      return REAL_RESULT(input.name);
    }
  };
  return {
    logger: { info() {}, warn() {} },
    on(evt, fn) {
      listeners.set(evt, fn);
    },
    commands: {
      register(def) {
        commands.push(def);
      }
    },
    tools,
    _listeners: listeners,
    _commands: commands,
    _tools: tools
  };
}

const AC = () => new AbortController();

// ---- 用例 ----
async function run() {
  const dir = mkdtempSync(join(tmpdir(), 'escrow-intg-'));
  try {
    // 1. apply() 注册监听与命令
    const ctx = makeCtx(dir);
    plugin.apply(ctx, {
      ttlSec: 0, timeoutPolicy: 'cancel', defaultAction: 'yellow',
      builtinRules: true, rules: [], ledgerDir: dir
    });
    record('apply() 注册 tools/pre-execute 监听', ctx._listeners.has('tools/pre-execute'));
    record('apply() 注册 /escrow 命令', ctx._commands.some((c) => c.name === 'escrow'));

    const pre = ctx._listeners.get('tools/pre-execute');
    const next = () => Promise.resolve({ kind: 'allow' });

    // 2. 绿灯规则放行（无内置命中时 green 生效）
    const ctx2 = makeCtx(dir);
    plugin.apply(ctx2, {
      ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true,
      rules: [{ id: 'allow-ls', tools: ['bash'], args: [{ key: 'command', pattern: '^ls ' }], action: 'green' }],
      ledgerDir: dir
    });
    const pre2 = ctx2._listeners.get('tools/pre-execute');
    const allow = await pre2({ name: 'bash', arguments: { command: 'ls -la' }, callId: 'c1', signal: AC().signal }, next);
    record('绿灯规则 → allow', allow.kind === 'allow');

    // 3. red 且 ttl=0 → 立即 deny（fail-closed）。v0.1.1：必须真的"立即"（<1500ms）
    const t0 = Date.now();
    const deny = await pre({ name: 'bash', arguments: { command: 'rm -rf /tmp/x' }, callId: 'c2', signal: AC().signal }, next);
    const elapsed = Date.now() - t0;
    record('红灯 ttl=0 → deny 且含理由', deny.kind === 'deny' && deny.reason.includes('escrow'));
    record('红灯 ttl=0 → 立即返回（<1500ms，回归 0 被改成 30 的 bug）', elapsed < 1500, `${elapsed}ms`);

    // 4. yellow 默认 → allow 且记账
    const y = await pre({ name: 'bash', arguments: { command: 'ls -la' }, callId: 'c3', signal: AC().signal }, next);
    record('黄灯 → allow（记账放行）', y.kind === 'allow');

    // 5. 账本有 escrow.queued / escrow.decided / observe 记录
    const { readFileSync } = await import('node:fs');
    const text = readFileSync(join(dir, 'ledger.jsonl'), 'utf8');
    record('账本含 queued 记录', text.includes('escrow.queued'));
    record('账本含 decided 记录', text.includes('escrow.decided'));
    record('账本含 observe 记录', text.includes('observe'));

    // 6. async 红灯入队 → allow（非阻塞，不再同步等待）
    const ctxA = makeCtx(dir);
    plugin.apply(ctxA, {
      ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dir
    });
    const preA = ctxA._listeners.get('tools/pre-execute');
    const exeA = ctxA._listeners.get('tools/execute');
    const cmdA = ctxA._commands.find((c) => c.name === 'escrow');
    const escrowResultA = ctxA._tools.registered.find((t) => t.name === 'escrow_result');
    record('M1 apply() 注册 tools/execute 监听', typeof exeA === 'function');
    record('M1 apply() 注册 escrow_result 工具', !!escrowResultA);

    const exec1 = { name: 'bash', arguments: { command: 'rm -rf /tmp/x' }, callId: 'm1', signal: AC().signal, agent: 'agent-a' };
    const d1 = await preA(exec1, next);
    record('M1 async 红灯入队 → allow（非阻塞）', d1.kind === 'allow');

    // 7. execute 层对 pending 返回合成结果（stdout.text 含 esc-id）
    const synth1 = await exeA(exec1, () => Promise.resolve(REAL_RESULT('bash')));
    record('execute 层对 pending 返回合成结果（Success/foreground）', synth1.isError === false && synth1.value.kind === 'foreground' && synth1.value.stdout.text.includes('esc-'));
    const idMatch = synth1.value.stdout.text.match(/esc-\d+-\d+/);

    // 8. 同签名去重：第二次发起同签名 → 不重复入队，占位文本标注"已在审批队列"
    const exec1b = { name: 'bash', arguments: { command: 'rm -rf /tmp/x' }, callId: 'm1b', signal: AC().signal };
    const d2 = await preA(exec1b, next);
    record('同签名 pending 去重：返回 allow 且不重复入队', d2.kind === 'allow');
    const synth2 = await exeA(exec1b, () => Promise.resolve(REAL_RESULT('bash')));
    record('去重调用占位文本含「已在审批队列」', synth2.value.stdout.text.includes('已在审批队列'));
    record('去重后 pending 仍只有 1 条', cmdA.handler({ rawInput: 'pending', signal: AC().signal }).text.includes('1 个待决'));

    // 9. escrow_result：pending → approve 重放 → executed 取回真实结果
    record('escrow_result pending 状态', (await escrowResultA.execute({ id: idMatch[0] })).status === 'pending');
    const approveRes = cmdA.handler({ rawInput: `approve ${idMatch[0]}`, signal: AC().signal });
    record('approve 返回成功且触发重放', approveRes.kind === 'success');
    await new Promise((r) => setTimeout(r, 80)); // 等 mock 重放完成
    const executed = await escrowResultA.execute({ id: idMatch[0] });
    record('重放后 escrow_result → executed + 真实结果', executed.status === 'executed' && executed.result.includes('REAL OUTPUT: bash'));
    record('账本含 approved_executed / replayed', readFileSync(join(dir, 'ledger.jsonl'), 'utf8').includes('escrow.approved_executed') && readFileSync(join(dir, 'ledger.jsonl'), 'utf8').includes('escrow.replayed'));

    // 9b. async 超时 → escrow.decided via timeout 落账（M1 安全语义：超时拒绝必须可审计）
    const ctxX = makeCtx(dir);
    plugin.apply(ctxX, {
      ttlSec: 1, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dir, mode: 'async'
    });
    const preX = ctxX._listeners.get('tools/pre-execute');
    await preX({ name: 'bash', arguments: { command: 'rm -rf /tmp/x' }, callId: 'x1', signal: AC().signal }, next);
    await new Promise((r) => setTimeout(r, 1200)); // 等超时 settle + onSettle 落账
    record('async 超时 → escrow.decided via timeout 落账', readFileSync(join(dir, 'ledger.jsonl'), 'utf8').includes('"via":"timeout"'));

    // 10. sync 模式回归：red 同步等待，批准后 allow
    const ctxS = makeCtx(dir);
    plugin.apply(ctxS, {
      ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dir, mode: 'sync'
    });
    const preS = ctxS._listeners.get('tools/pre-execute');
    const cmdS = ctxS._commands.find((c) => c.name === 'escrow');
    const pS = preS({ name: 'bash', arguments: { command: 'git push origin main' }, callId: 's1', signal: AC().signal }, next);
    const pendingS = cmdS.handler({ rawInput: 'pending', signal: AC().signal });
    const idS = pendingS.text.match(/esc-\d+-\d+/);
    record('sync 模式：red 入队等待（approve 前未 settle）', typeof pS.then === 'function');
    const approveS = idS ? cmdS.handler({ rawInput: `approve ${idS[0]}`, signal: AC().signal }) : null;
    const finalS = await pS;
    record('sync 模式：批准后 allow', approveS?.kind === 'success' && finalS.kind === 'allow');
    record('sync 模式：pending 展示动作摘要（审批内容绑定）', pendingS.text.includes('git push origin main'));

    // 11. syncTools：async 模式下指定工具走同步
    const ctxT = makeCtx(dir);
    plugin.apply(ctxT, {
      ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dir, mode: 'async', syncTools: ['bash']
    });
    const preT = ctxT._listeners.get('tools/pre-execute');
    const cmdT = ctxT._commands.find((c) => c.name === 'escrow');
    const pT = preT({ name: 'bash', arguments: { command: 'git push origin main' }, callId: 't1', signal: AC().signal }, next);
    const idT = cmdT.handler({ rawInput: 'pending', signal: AC().signal }).text.match(/esc-\d+-\d+/);
    const approveT = idT ? cmdT.handler({ rawInput: `approve ${idT[0]}`, signal: AC().signal }) : null;
    const finalT = await pT;
    record('syncTools：命中工具走同步（批准后 allow）', approveT?.kind === 'success' && finalT.kind === 'allow');

    // 12. next() 单调回归：green 路径，下游同步抛错 → 拒绝外传且 next 只调一次
    {
      const ctxG = makeCtx(dir);
      plugin.apply(ctxG, {
        ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'green', builtinRules: true, rules: [], ledgerDir: dir
      });
      const preG = ctxG._listeners.get('tools/pre-execute');
      let calls = 0;
      const throwingNext = () => { calls += 1; throw new Error('downstream sync boom'); };
      let rejected = false;
      try {
        await preG({ name: 'bash', arguments: { command: 'ls' }, callId: 'g1', signal: AC().signal }, throwingNext);
      } catch {
        rejected = true;
      }
      record('green 路径 next() 同步抛错：只调用一次且异常外传', rejected && calls === 1, `calls=${calls}`);
    }

    // 13. next() 单调回归（sync 模式）：red 批准路径，下游同步抛错 → 单次批准不得执行两次
    {
      const ctxR = makeCtx(dir);
      plugin.apply(ctxR, {
        ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dir, mode: 'sync'
      });
      const preR = ctxR._listeners.get('tools/pre-execute');
      const cmdR = ctxR._commands.find((c) => c.name === 'escrow');
      let calls = 0;
      const throwingNext = () => { calls += 1; throw new Error('downstream sync boom'); };
      const pr = preR({ name: 'bash', arguments: { command: 'git push origin main' }, callId: 'r1', signal: AC().signal }, throwingNext);
      await new Promise((r) => setTimeout(r, 50));
      const list = cmdR.handler({ rawInput: 'pending', signal: AC().signal });
      const id = list.text.match(/esc-\d+-\d+/)[0];
      cmdR.handler({ rawInput: `approve ${id}`, signal: AC().signal });
      let rejected = false;
      try {
        await pr;
      } catch {
        rejected = true;
      }
      record('red 批准路径 next() 同步抛错：只调用一次且异常外传', rejected && calls === 1, `calls=${calls}`);
    }

    // 14. fail-closed 回归：red 已分类后托管链路异常 → deny 而不是放行
    {
      const ctxF = makeCtx(dir);
      plugin.apply(ctxF, {
        ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dir
      });
      const preF = ctxF._listeners.get('tools/pre-execute');
      let reads = 0;
      const exec = {
        name: 'bash', callId: 'f1', signal: AC().signal,
        get arguments() {
          reads += 1;
          // 读取顺序：M2 品味 extractSignature(1) → classify(2) → redact(3)。第三次（redact）抛错，模拟"red 分类后链路异常"。
          if (reads > 2) throw new Error('arguments getter boom');
          return { command: 'rm -rf /tmp/x' };
        }
      };
      let nextCalls = 0;
      const r = await preF(exec, () => { nextCalls += 1; return Promise.resolve({ kind: 'allow' }); });
      record('red 分类后链路异常 → fail-closed deny（不静默放行）', r.kind === 'deny' && nextCalls === 0, `nextCalls=${nextCalls}`);
    }

    // ===== M2 品味习得接线 =====
    {
      const ctxM2 = makeCtx(dir);
      const apiM2 = plugin.apply(ctxM2, {
        ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dir
      });
      const preM2 = ctxM2._listeners.get('tools/pre-execute');
      const cmdM2 = ctxM2._commands.find((c) => c.name === 'escrow');
      const m2Taste = apiM2.taste;

      // 15. 手动 allow 白名单 → 放行不托管
      const allowCmd = cmdM2.handler({ rawInput: 'allow git push origin <BRANCH>', signal: AC().signal });
      record('M2 手动 allow 加入白名单（立即生效）', allowCmd.kind === 'success' && m2Taste.check('git push origin <BRANCH>') === 'allow');
      const wl = await preM2({ name: 'bash', arguments: { command: 'git push origin main' }, callId: 'm2wl', signal: AC().signal }, next);
      record('M2 白名单签名 → 放行且不托管', wl.kind === 'allow' && cmdM2.handler({ rawInput: 'pending', signal: AC().signal }).text.includes('没有待决'));

      // 16. 手动 deny 黑名单 → 拒绝
      cmdM2.handler({ rawInput: 'deny npm install', signal: AC().signal });
      const bl = await preM2({ name: 'bash', arguments: { command: 'npm install' }, callId: 'm2bl', signal: AC().signal }, next);
      record('M2 黑名单签名 → deny', bl.kind === 'deny' && bl.reason.includes('黑名单'));

      // 17. 学习：forget 白名单后 approve 同签名 ×2 → 白名单冷却中
      cmdM2.handler({ rawInput: 'forget git push origin <BRANCH>', signal: AC().signal });
      await preM2({ name: 'bash', arguments: { command: 'git push origin main' }, callId: 'm2l1', signal: AC().signal }, next);
      const idL1 = cmdM2.handler({ rawInput: 'pending', signal: AC().signal }).text.match(/esc-\d+-\d+/)[0];
      cmdM2.handler({ rawInput: `approve ${idL1}`, signal: AC().signal });
      await preM2({ name: 'bash', arguments: { command: 'git push origin main' }, callId: 'm2l2', signal: AC().signal }, next);
      const idL2 = cmdM2.handler({ rawInput: 'pending', signal: AC().signal }).text.match(/esc-\d+-\d+/)[0];
      cmdM2.handler({ rawInput: `approve ${idL2}`, signal: AC().signal });
      const alText = cmdM2.handler({ rawInput: 'allowlist', signal: AC().signal }).text;
      record('M2 批准×2 → 白名单条目冷却中', alText.includes('git push origin <BRANCH>') && alText.includes('cooling'));

      // 18. never-learn 签名不被学习
      await preM2({ name: 'bash', arguments: { command: 'rm -rf /tmp/x' }, callId: 'm2nl', signal: AC().signal }, next);
      const idNL = cmdM2.handler({ rawInput: 'pending', signal: AC().signal }).text.match(/esc-\d+-\d+/)[0];
      cmdM2.handler({ rawInput: `approve ${idNL}`, signal: AC().signal });
      record('M2 never-learn 签名不被学习', !cmdM2.handler({ rawInput: 'allowlist', signal: AC().signal }).text.includes('rm -rf /tmp/x'));

      // 18b. round-6 R6-1：never-learn 与 builtin 红按"绝对不可逆/不可恢复"口径对齐
      // 五条曾因扩红而漏的形态，批准两次后白名单绝不能出现对应签名。
      const neverLearnCases = [
        { tag: 'm2-r-noforce', cmd: 'rm -r /tmp/x', sigNeedle: 'rm -r /tmp/x' },
        { tag: 'm2-r-rec', cmd: 'rm -Recurse /tmp/x', sigNeedle: 'rm -Recurse /tmp/x' },
        { tag: 'm2-g-restore', cmd: 'git restore .', sigNeedle: 'git restore <STR>' },
        { tag: 'm2-g-creset', cmd: 'git -C my-repo reset --hard HEAD~1', sigNeedle: 'git -C my-repo reset --hard <REF>' },
        { tag: 'm2-g-cchk', cmd: 'git -C my-repo checkout -- .', sigNeedle: 'git -C my-repo checkout -- <STR>' }
      ];
      for (const c of neverLearnCases) {
        await preM2({ name: 'bash', arguments: { command: c.cmd }, callId: `${c.tag}-1`, signal: AC().signal }, next);
        const id1 = cmdM2.handler({ rawInput: 'pending', signal: AC().signal }).text.match(/esc-\d+-\d+/)[0];
        cmdM2.handler({ rawInput: `approve ${id1}`, signal: AC().signal });
        await preM2({ name: 'bash', arguments: { command: c.cmd }, callId: `${c.tag}-2`, signal: AC().signal }, next);
        const id2 = cmdM2.handler({ rawInput: 'pending', signal: AC().signal }).text.match(/esc-\d+-\d+/)[0];
        cmdM2.handler({ rawInput: `approve ${id2}`, signal: AC().signal });
      }
      const alR6Text = cmdM2.handler({ rawInput: 'allowlist', signal: AC().signal }).text;
      for (const c of neverLearnCases) {
        record(`R6-1 never-learn ${c.cmd} 批准×2 不入白名单`,
          !alR6Text.includes(c.sigNeedle));
      }

      // 19. approve all 按签名组去重（同 M2 签名不同参数 → 一组）
      await preM2({ name: 'bash', arguments: { command: 'git push origin main' }, callId: 'm2d1', signal: AC().signal }, next);
      await preM2({ name: 'bash', arguments: { command: 'git push origin feature' }, callId: 'm2d2', signal: AC().signal }, next);
      const aa = cmdM2.handler({ rawInput: 'approve all', signal: AC().signal });
      record('M2 approve all 同签名 2 条合并为 1 组', aa.text.includes('1 组') && aa.text.includes('2 条'));
      record('M2 approve all 后队列清空', cmdM2.handler({ rawInput: 'pending', signal: AC().signal }).text.includes('没有待决'));

      // 20. 超时不学黑名单（独立短 ttl ctx + 独立目录）
      const dirT = mkdtempSync(join(tmpdir(), 'escrow-intg-t-'));
      try {
        const ctxT = makeCtx(dirT);
        const apiT = plugin.apply(ctxT, {
          ttlSec: 1, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dirT
        });
        const preT = ctxT._listeners.get('tools/pre-execute');
        await preT({ name: 'bash', arguments: { command: 'git push origin main' }, callId: 'm2t', signal: AC().signal }, next);
        await new Promise((r) => setTimeout(r, 1300)); // 等超时 settle
        record('M2 超时不学黑名单', apiT.taste.check('git push origin <BRANCH>') !== 'deny');
      } finally {
        rmSync(dirT, { recursive: true, force: true });
      }

      // 21. export → import 品味包
      const exp = cmdM2.handler({ rawInput: 'export', signal: AC().signal });
      const packPath = join(dir, 'escrow-taste-pack.yaml');
      record('M2 export 生成品味包文件', exp.kind === 'success' && existsSync(packPath));
      const ctxImp = makeCtx(dir);
      const apiImp = plugin.apply(ctxImp, {
        ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dir
      });
      const cmdImp = ctxImp._commands.find((c) => c.name === 'escrow');
      const imp = cmdImp.handler({ rawInput: `import ${packPath}`, signal: AC().signal });
      record('M2 import 品味包成功', imp.kind === 'success' && imp.text.includes('已导入'));
      record('M2 导入条目为 pending-review（不立即生效）', apiImp.taste.snapshot().allowlist.some((e) => e.signature === 'git push origin <BRANCH>' && e.status === 'pending-review'));

      // 22. 安全：品味 allow 不覆盖内置敏感路径（签名粒度无法区分具体敏感形态 → 写 .env 仍托管）
      cmdM2.handler({ rawInput: 'allow fs.write(content,path)', signal: AC().signal });
      await preM2({ name: 'fs.write', arguments: { path: 'C:/proj/.env', content: 'x' }, callId: 'm2sens', signal: AC().signal }, next);
      record('M2 品味 allow 不覆盖内置敏感路径（写 .env 仍托管）', cmdM2.handler({ rawInput: 'pending', signal: AC().signal }).text.includes('待决'));

      // 23a. LOW-1：用户显式 red 规则不容品味 allow 覆盖（显式配置 > 隐式习得，冲突时保守拒绝）
      const ctxUR = makeCtx(dir);
      plugin.apply(ctxUR, {
        ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true,
        rules: [{ id: 'block-npm', tools: ['bash'], args: [{ key: 'command', pattern: '^npm ' }], action: 'red' }],
        ledgerDir: dir
      });
      const preUR = ctxUR._listeners.get('tools/pre-execute');
      const cmdUR = ctxUR._commands.find((c) => c.name === 'escrow');
      cmdUR.handler({ rawInput: 'allow npm install', signal: AC().signal });
      await preUR({ name: 'bash', arguments: { command: 'npm install' }, callId: 'r3low1', signal: AC().signal }, next);
      record('LOW-1 用户显式 red 规则不容品味 allow 覆盖（仍托管）', cmdUR.handler({ rawInput: 'pending', signal: AC().signal }).text.includes('待决'));

      // 23b. R6 LOW 修复：用户规则 id 伪装 builtin-* 前缀，品味 allow 仍不覆盖（hardRed 改用 source 判定）
      const ctxBG = makeCtx(dir);
      plugin.apply(ctxBG, {
        ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true,
        rules: [{ id: 'builtin-guard', tools: ['bash'], args: [{ key: 'command', pattern: '^npm ' }], action: 'red' }],
        ledgerDir: dir
      });
      const preBG = ctxBG._listeners.get('tools/pre-execute');
      const cmdBG = ctxBG._commands.find((c) => c.name === 'escrow');
      cmdBG.handler({ rawInput: 'allow npm install', signal: AC().signal });
      await preBG({ name: 'bash', arguments: { command: 'npm install' }, callId: 'r6bg', signal: AC().signal }, next);
      record('R6 LOW 修复：用户 red id 伪装 builtin-* 前缀仍不容品味覆盖', cmdBG.handler({ rawInput: 'pending', signal: AC().signal }).text.includes('待决'));
    }

    // ===== round-3 回归（第三方独立审查修复固化，见 third-party-review/review-report-r3-2026-08-29.md）=====

    // 23. C1 闭环补强：approve all 同品味签名 2 实例 → 两个都真实重放执行（旧版只断言回执文本）
    {
      const ctxC1 = makeCtx(dir);
      plugin.apply(ctxC1, { ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dir });
      const preC1 = ctxC1._listeners.get('tools/pre-execute');
      const cmdC1 = ctxC1._commands.find((c) => c.name === 'escrow');
      await preC1({ name: 'bash', arguments: { command: 'git push origin main' }, callId: 'c1a', signal: AC().signal }, next);
      await preC1({ name: 'bash', arguments: { command: 'git push origin feature' }, callId: 'c1b', signal: AC().signal }, next);
      cmdC1.handler({ rawInput: 'approve all', signal: AC().signal });
      await new Promise((r) => setTimeout(r, 100));
      record('round3 C1：approve all 两个实例都真实重放执行', ctxC1._tools.executed.length === 2, `executed=${ctxC1._tools.executed.length}`);
    }

    // 24. C4 闭环补强：release + async 超时 → 自动重放，条目不卡"执行中"（旧版无用例）
    {
      const ctxC4 = makeCtx(dir);
      const apiC4 = plugin.apply(ctxC4, { ttlSec: 1, timeoutPolicy: 'release', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dir });
      const preC4 = ctxC4._listeners.get('tools/pre-execute');
      await preC4({ name: 'bash', arguments: { command: 'git push origin main' }, callId: 'c4a', signal: AC().signal }, next);
      const idC4 = apiC4.queue.pendingList()[0]?.id;
      await new Promise((r) => setTimeout(r, 1300)); // ttl=1s 超时 settle → onSettle 触发重放
      const st = apiC4.queue.getEntry(idC4)?.state;
      record('round3 C4：release+async 超时自动重放', st === 'executed' && ctxC4._tools.executed.length === 1, `state=${st} executed=${ctxC4._tools.executed.length}`);
    }

    // 25. HIGH-1a：已拒绝（settle）的条目，迟到的原始调用到达 execute 层不得裸执行
    {
      const ctxH1 = makeCtx(dir);
      const apiH1 = plugin.apply(ctxH1, { ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dir });
      const preH1 = ctxH1._listeners.get('tools/pre-execute');
      const exeH1 = ctxH1._listeners.get('tools/execute');
      const execH1 = { name: 'bash', arguments: { command: 'git push origin main' }, callId: 'h1a', signal: AC().signal };
      await preH1(execH1, next);
      const idH1 = apiH1.queue.pendingList()[0]?.id;
      apiH1.queue.decide(idH1, 'denied'); // 模拟超时/人工拒绝 settle（身份搬到 handled 索引）
      let lateNext = 0;
      const late = await exeH1(execH1, () => { lateNext += 1; return Promise.resolve(REAL_RESULT('bash')); });
      record('round3 HIGH-1a：已拒绝的迟到调用被拦截（不裸执行）', lateNext === 0 && late.isError === false && late.value.stdout.text.includes('不会执行'), `next=${lateNext}`);
    }

    // 26. HIGH-1b：async 批准重放后，迟到的原始调用不得再执行（防双执行）
    {
      const ctxH2 = makeCtx(dir);
      const apiH2 = plugin.apply(ctxH2, { ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dir });
      const preH2 = ctxH2._listeners.get('tools/pre-execute');
      const exeH2 = ctxH2._listeners.get('tools/execute');
      const cmdH2 = ctxH2._commands.find((c) => c.name === 'escrow');
      const execH2 = { name: 'bash', arguments: { command: 'git push origin main' }, callId: 'h2a', signal: AC().signal };
      await preH2(execH2, next);
      const idH2 = apiH2.queue.pendingList()[0]?.id;
      cmdH2.handler({ rawInput: `approve ${idH2}`, signal: AC().signal });
      await new Promise((r) => setTimeout(r, 100)); // 重放完成（执行恰好 1 次）
      let lateNext = 0;
      await exeH2(execH2, () => { lateNext += 1; return Promise.resolve(REAL_RESULT('bash')); });
      record('round3 HIGH-1b：批准重放后迟到原始调用不双执行', ctxH2._tools.executed.length === 1 && lateNext === 0, `executed=${ctxH2._tools.executed.length} lateNext=${lateNext}`);
    }

    // 27. HIGH-2：argsSnapshot 深拷贝——入队后下游改写 arguments，重放仍按审批时快照执行
    {
      const ctxH3 = makeCtx(dir);
      const apiH3 = plugin.apply(ctxH3, { ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dir });
      const preH3 = ctxH3._listeners.get('tools/pre-execute');
      const cmdH3 = ctxH3._commands.find((c) => c.name === 'escrow');
      const argsH3 = { command: 'git push origin main' };
      await preH3({ name: 'bash', arguments: argsH3, callId: 'h3a', signal: AC().signal }, next);
      const idH3 = apiH3.queue.pendingList()[0]?.id;
      argsH3.command = 'rm -rf /tmp/innocent'; // 模拟 escrow 之后的下游钩子原地改写
      cmdH3.handler({ rawInput: `approve ${idH3}`, signal: AC().signal });
      await new Promise((r) => setTimeout(r, 100));
      record('round3 HIGH-2：重放按审批时快照执行（不受入队后改写影响）', ctxH3._tools.executed[0]?.arguments?.command === 'git push origin main', `replayed="${ctxH3._tools.executed[0]?.arguments?.command}"`);
    }

    // 28. MEDIUM-1：sync 模式同签名并发去重——一次批准只执行一次，去重调用 deny 且不重复记账
    {
      const ctxM1 = makeCtx(dir);
      const apiM1 = plugin.apply(ctxM1, { ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dir, mode: 'sync' });
      const preM1 = ctxM1._listeners.get('tools/pre-execute');
      let n1 = 0; let n2 = 0;
      const p1 = preM1({ name: 'bash', arguments: { command: 'git push origin main' }, callId: 'm1s1', signal: AC().signal }, () => { n1 += 1; return Promise.resolve({ kind: 'allow' }); });
      const p2 = preM1({ name: 'bash', arguments: { command: 'git push origin main' }, callId: 'm1s2', signal: AC().signal }, () => { n2 += 1; return Promise.resolve({ kind: 'allow' }); });
      await new Promise((r) => setTimeout(r, 20));
      const pendM1 = apiM1.queue.pendingList().length;
      const idM1 = apiM1.queue.pendingList()[0]?.id;
      apiM1.queue.decide(idM1, 'approved');
      const [r1, r2] = await Promise.all([p1, p2]);
      record('round3 MEDIUM-1：sync 去重一次批准只执行一次', pendM1 === 1 && n1 === 1 && n2 === 0 && r1.kind === 'allow' && r2.kind === 'deny' && r2.reason.includes('不重复执行'), `pending=${pendM1} n1=${n1} n2=${n2} dup=${r2.kind}`);
    }

    // ===== M7 自改治理（独立目录隔离品味状态，避免与 M2 手动 allow 的 fs.write 冲突）=====
    {
      const dirM7 = mkdtempSync(join(tmpdir(), 'escrow-intg-m7-'));
      try {
        const selfFile = join(dirM7, 'AGENTS.md');
        writeFileSync(selfFile, 'before-content', 'utf8');
        const ctxM7 = makeCtx(dirM7);
        plugin.apply(ctxM7, {
          ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dirM7
        });
        const preM7 = ctxM7._listeners.get('tools/pre-execute');
        const exeM7 = ctxM7._listeners.get('tools/execute');
        const cmdM7 = ctxM7._commands.find((c) => c.name === 'escrow');

        // 24. 写 AGENTS.md → red 托管 + selfmod.queued 落账
        const selfExec = { name: 'fs.write', arguments: { path: selfFile, content: 'x' }, callId: 'm7s1', signal: AC().signal };
        const dSelf = await preM7(selfExec, next);
        record('M7 写 AGENTS.md → 入队托管', dSelf.kind === 'allow');
        const synthSelf = await exeM7(selfExec, () => Promise.resolve(REAL_RESULT('fs.write')));
        const idSelf = synthSelf.value.stdout.text.match(/esc-\d+-\d+/)?.[0];
        record('M7 execute 层对被托管自改返回合成结果', !!idSelf && synthSelf.value.stdout.text.includes('escrow_result'));
        record('M7 selfmod.queued 落账', readFileSync(join(dirM7, 'ledger.jsonl'), 'utf8').includes('selfmod.queued'));

        // 25. approve 自改 → selfmod.decided 落账 + 批准后不进品味白名单（never-learn）
        cmdM7.handler({ rawInput: `approve ${idSelf}`, signal: AC().signal });
        await new Promise((r) => setTimeout(r, 80));
        record('M7 approve 自改 → selfmod.decided 落账', readFileSync(join(dirM7, 'ledger.jsonl'), 'utf8').includes('selfmod.decided'));
        record('M7 自改批准后不进白名单', !cmdM7.handler({ rawInput: 'allowlist', signal: AC().signal }).text.includes('fs.write'));

        // 26. selfModification:false → 写 AGENTS.md 不托管（yellow 放行）
        const ctxOff = makeCtx(dirM7);
        plugin.apply(ctxOff, {
          ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dirM7,
          selfModification: { red: false }
        });
        const preOff = ctxOff._listeners.get('tools/pre-execute');
        const dOff = await preOff({ name: 'fs.write', arguments: { path: selfFile, content: 'x' }, callId: 'm7off', signal: AC().signal }, next);
        const cmdOff = ctxOff._commands.find((c) => c.name === 'escrow');
        record('M7 selfMod:false → 写 AGENTS.md 走正常分类（yellow 放行不托管）', dOff.kind === 'allow' && cmdOff.handler({ rawInput: 'pending', signal: AC().signal }).text.includes('没有待决'));
      } finally {
        rmSync(dirM7, { recursive: true, force: true });
      }
    }

    // ===== M8 reduce 减法审计 =====
    {
      const dirR = mkdtempSync(join(tmpdir(), 'escrow-intg-r-'));
      try {
        // 造账本：同签名 git push ×12（≥10 阈值）→ reduce 应报告重复
        const ledgerPath = join(dirR, 'ledger.jsonl');
        const rows = [];
        for (let i = 0; i < 12; i++) rows.push(JSON.stringify({ t: new Date().toISOString(), kind: 'observe', tool: 'bash', args: '{"command":"git push origin main"}' }));
        writeFileSync(ledgerPath, rows.join('\n') + '\n', 'utf8');
        const ctxR = makeCtx(dirR);
        plugin.apply(ctxR, { ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dirR });
        const cmdR = ctxR._commands.find((c) => c.name === 'escrow');
        const red = cmdR.handler({ rawInput: 'reduce', signal: AC().signal });
        record('M8 reduce 报告重复签名', red.kind === 'success' && red.text.includes('git push origin <BRANCH>') && red.text.includes('建议缓存/合并'));
        record('M8 reduce 含署名尾注', red.text.includes('Reduced by dsh-escrow') && red.text.includes('SNR'));
      } finally {
        rmSync(dirR, { recursive: true, force: true });
      }
      // 无重复场景
      const dirR2 = mkdtempSync(join(tmpdir(), 'escrow-intg-r2-'));
      try {
        const p2 = join(dirR2, 'ledger.jsonl');
        writeFileSync(p2, JSON.stringify({ t: new Date().toISOString(), kind: 'observe', tool: 'bash', args: '{"command":"npm test"}' }) + '\n', 'utf8');
        const ctxR2 = makeCtx(dirR2);
        plugin.apply(ctxR2, { ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dirR2 });
        const cmdR2 = ctxR2._commands.find((c) => c.name === 'escrow');
        const red2 = cmdR2.handler({ rawInput: 'reduce', signal: AC().signal });
        record('M8 reduce 无重复时如实报告', red2.text.includes('无（无签名达到阈值）'));
      } finally {
        rmSync(dirR2, { recursive: true, force: true });
      }
    }

    // ===== M6 report 命令 + 哈希链 =====
    {
      const dirM6 = mkdtempSync(join(tmpdir(), 'escrow-intg-m6-'));
      try {
        const ctxM6 = makeCtx(dirM6);
        const apiM6 = plugin.apply(ctxM6, { ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dirM6 });
        const cmdM6 = ctxM6._commands.find((c) => c.name === 'escrow');
        const preM6 = ctxM6._listeners.get('tools/pre-execute');
        await preM6({ name: 'bash', arguments: { command: 'ls' }, callId: 'm6o1', agent: 'agent-m6', signal: AC().signal }, next); // yellow observe
        await preM6({ name: 'bash', arguments: { command: 'git push origin main' }, callId: 'm6r1', agent: 'agent-m6', signal: AC().signal }, next); // red 入队
        const pendM6 = cmdM6.handler({ rawInput: 'pending', signal: AC().signal }).text.match(/esc-\d+-\d+/)?.[0];
        cmdM6.handler({ rawInput: `deny ${pendM6}`, signal: AC().signal });
        await new Promise((r) => setTimeout(r, 50));
        const rep = cmdM6.handler({ rawInput: 'report', signal: AC().signal });
        record('M6 report 含统计与署名', rep.kind === 'success' && rep.text.includes('总行数') && rep.text.includes('Reduced by dsh-escrow'));
        record('M6 report 含红灯清单（denied 明细 id）', rep.text.includes('esc-'));
        const repJson = cmdM6.handler({ rawInput: 'report --json', signal: AC().signal });
        try {
          const parsed = JSON.parse(repJson.text);
          record('M6 report --json 合法', typeof parsed.total === 'number' && parsed.denied >= 1 && typeof parsed.integrity === 'object');
        } catch {
          record('M6 report --json 合法', false);
        }
        record('M6 账本记录含 session（P10，= exec.agent）', readFileSync(join(dirM6, 'ledger.jsonl'), 'utf8').includes('"session":"agent-m6"'));
      } finally {
        rmSync(dirM6, { recursive: true, force: true });
      }
      // 哈希链篡改检测：apply 写入（带 h）→ 篡改账本 → 重载后 integrity.tampered
      const dirH = mkdtempSync(join(tmpdir(), 'escrow-intg-h-'));
      try {
        const ctxH1 = makeCtx(dirH);
        plugin.apply(ctxH1, { ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dirH });
        const preH = ctxH1._listeners.get('tools/pre-execute');
        await preH({ name: 'bash', arguments: { command: 'ls' }, callId: 'm6h1', signal: AC().signal }, next);
        const fileH = join(dirH, 'ledger.jsonl');
        const linesH = readFileSync(fileH, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
        linesH[0].tool = 'HACKED';
        writeFileSync(fileH, linesH.map((l) => JSON.stringify(l)).join('\n') + '\n', 'utf8');
        const ctxH2 = makeCtx(dirH);
        const apiH2 = plugin.apply(ctxH2, { ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dirH });
        record('M6 哈希链篡改检测（重载后 integrity.tampered）', apiH2.ledger?.integrity?.tampered === true);
      } finally {
        rmSync(dirH, { recursive: true, force: true });
      }
      // M6+ migrate：legacy 账本 → 完整链（R8-1 方案 B）
      const dirMg = mkdtempSync(join(tmpdir(), 'escrow-intg-mg-'));
      try {
        writeFileSync(join(dirMg, 'ledger.jsonl'), JSON.stringify({ t: '2026-01-01T00:00:00.000Z', kind: 'observe', tool: 'old' }) + '\n', 'utf8');
        const ctxMg = makeCtx(dirMg);
        const apiMg = plugin.apply(ctxMg, { ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dirMg });
        const cmdMg = ctxMg._commands.find((c) => c.name === 'escrow');
        record('M6+ migrate 前 legacyDetected', apiMg.ledger.integrity.legacyDetected === true);
        const mig = cmdMg.handler({ rawInput: 'migrate', signal: AC().signal });
        record('M6+ migrate 命令成功', mig.kind === 'success' && mig.text.includes('迁移 1 行'));
        record('M6+ migrate 后 legacy 清除且带 h', apiMg.ledger.integrity.legacyDetected === false && readFileSync(join(dirMg, 'ledger.jsonl'), 'utf8').includes('"h"'));
        const repMg = cmdMg.handler({ rawInput: 'report', signal: AC().signal });
        record('M6+ migrate 后 report 无 legacy 警告', !repMg.text.includes('chainResets'));
      } finally {
        rmSync(dirMg, { recursive: true, force: true });
      }
      // M9 doctor 自检
      const dirD = mkdtempSync(join(tmpdir(), 'escrow-intg-d-'));
      try {
        const ctxD = makeCtx(dirD);
        plugin.apply(ctxD, { ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dirD });
        const cmdD = ctxD._commands.find((c) => c.name === 'escrow');
        const doc = cmdD.handler({ rawInput: 'doctor', signal: AC().signal });
        record('M9 doctor 健康账本全绿', doc.kind === 'success' && doc.text.includes('结论：全绿'));
        record('M9 doctor 含哈希链与性能检查', doc.text.includes('账本哈希链') && doc.text.includes('分类器性能'));
        // 篡改账本 → doctor 账本项 ✗
        const preD = ctxD._listeners.get('tools/pre-execute');
        await preD({ name: 'bash', arguments: { command: 'ls' }, callId: 'm9d1', signal: AC().signal }, next); // 写入账本
        const fD = join(dirD, 'ledger.jsonl');
        const linesD = readFileSync(fD, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
        linesD[0].tool = 'HACK';
        writeFileSync(fD, linesD.map((l) => JSON.stringify(l)).join('\n') + '\n', 'utf8');
        const ctxD2 = makeCtx(dirD);
        plugin.apply(ctxD2, { ttlSec: 30, timeoutPolicy: 'cancel', defaultAction: 'yellow', builtinRules: true, rules: [], ledgerDir: dirD });
        const cmdD2 = ctxD2._commands.find((c) => c.name === 'escrow');
        const doc2 = cmdD2.handler({ rawInput: 'doctor', signal: AC().signal });
        record('M9 doctor 篡改账本 → 账本项 ✗', doc2.text.includes('✗ 账本哈希链'));
      } finally {
        rmSync(dirD, { recursive: true, force: true });
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

await run();
console.log('\n[plugin.integration]');
for (const r of results) {
  console.log(`  ${r.ok ? '✓' : '✗'} ${r.name}${r.detail ? `  (${r.detail})` : ''}`);
}
console.log(`\n结果：${passed}/${results.length} 通过`);
process.exit(results.every((r) => r.ok) ? 0 : 1);
