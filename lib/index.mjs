/**
 * dsh-escrow 插件入口：延迟执行窗口（不可逆动作进托管，批准才交割，超时默认拒绝）。
 *
 * v0.2 M1 架构（轮询式非阻塞）：
 * - tools/pre-execute（分类层）：分类 → green/yellow 放行 / red 托管（入队即放行，不再同步等待）。
 * - tools/execute（拦截层，新增）：查"托管中"签名 → 不调 next() 返回合成结果（S0 定案
 *   Success/foreground 形态，占位文本含行为指令）；重放调用（令牌 callId）→ next() 真实执行。
 * - escrow_result 模型可见工具：模型轮询托管动作状态（pending/executed/denied/expired）。
 * - 重放令牌 = 随机 callId（S0 定案）：批准时铸令牌，pre-execute 豁免 + execute 层放行，单次即删。
 * - 同签名 pending 去重：完全相同参数的重复发起不重复入队，返回既有条目 id。
 * - mode: async（默认，非阻塞）| sync（v0.1.1 行为，pre-execute await）；syncTools 工具级逃生门。
 * - ttl=0 语义保持：立即拒绝（fail-closed，不入队、不产生合成结果）。
 *
 * 安全不变式（v0.1.1 继承 + M1 扩展）：
 *   1. 已判 red 的托管链路任何异常 → fail-closed（deny 或合成"拒绝"结果），绝不静默放行；
 *   2. tools/execute wrapper 在任何路径上绝不抛异常（wrapper 抛错会终结当前 turn）；
 *   3. 豁免检查在 pre-execute 最前，防止重放调用被重新分类入队。
 *
 * v0.3.3 修复（第三方独立审查 round 3，见 third-party-review/review-report-r3-2026-08-29.md）：
 *   - HIGH-1：settle 后保留调用身份终态索引（queue.handledByCallId），execute 层拦截"已处置"
 *     的迟到裸调用——防"超时拒绝后迟到调用被静默执行"与"release 重放 + 原调用双执行"；
 *     sync 批准路径除外（其原调用即执行体）。
 *   - HIGH-2：argsSnapshot 深拷贝（cloneArgs），审批内容绑定不可被下游钩子原地改写。
 *   - MEDIUM-1：sync 模式同签名去重调用，一次批准只执行一次，且不重复记账。
 */

import z from '@deepseek-ai/schemastery';
import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveDshHome } from '@deepseek-ai/dsh-home-paths';
import { classifyExec, normalizeAction, collectPathCandidates, extractRedirectTargets, getTrustedEffects } from './classify.mjs';
import { extractActionDetails, createApprovalPlan, formatActionDetails, formatApprovalPlan } from './approval-details.mjs';
import { createLedger } from './ledger.mjs';
import { createQueue, signatureHash, normalizeTimeoutPolicy } from './queue.mjs';
import { registerEscrowCommands, learnDecision } from './commands.mjs';
import { synthForeground, placeholderText } from './synth-result.mjs';
import { replayEntry } from './replay.mjs';
import { extractSignature, neverLearnReason } from './signature.mjs';
import { createTasteStore } from './taste.mjs';
import { createApprovalAdapterClient } from './approval-adapter-client.mjs';

export const name = 'escrow';
export const inject = ['tools', 'commands'];

export const Config = z.object({
  /** 托管窗口（秒）。0 = 立即拒绝（fail-closed / CI，无论 async/sync）。 */
  ttlSec: z.number().default(300),
  /** 超时处置：cancel（默认拒绝）| release（放行）| hold（无限等）。 */
  timeoutPolicy: z.string().default('cancel'),
  /** 规则未命中时的默认处置。 */
  defaultAction: z.string().default('yellow'),
  /** 是否启用内置危险命令 / 敏感路径规则。 */
  builtinRules: z.boolean().default(true),
  /** 用户规则（first match wins，但 green 不能压制内置红灯）：{id?, tools[], args[{key,pattern}], paths[], action, risk?: critical-red} */
  rules: z.array(z.object({
    id: z.string().default(''),
    tools: z.array(z.string()).default([]),
    args: z.array(z.object({ key: z.string(), pattern: z.string() })).default([]),
    paths: z.array(z.string()).default([]),
    action: z.string(),
    risk: z.string().default('')
  })).default([]),
  /** 账本目录（默认 $DSH_HOME/.dsh-escrow）。 */
  ledgerDir: z.string().default(''),
  /** 账本单文件上限（MB），超限轮转为 ledger.jsonl.bak（只保留一代）。 */
  ledgerMaxMb: z.number().default(32),
  /** M1：async（默认，非阻塞轮询）| sync（v0.1.1 同步等待）。 */
  mode: z.string().default('async'),
  /** M1：工具级同步逃生门——命中这些工具的红灯动作保持同步等待（典型：写后读强依赖结果）。 */
  syncTools: z.array(z.string()).default([]),
  /** 宿主审批通道：queue（兼容旧命令队列）| host（使用 ctx.approval）| adapter（本地结构化审批宿主）。 */
  approvalMode: z.string().default('queue'),
  /** 本地 approval adapter 地址（approvalMode=adapter 时使用）。 */
  approvalAdapterUrl: z.string().default('http://127.0.0.1:3099'),
  /** 本地 approval adapter token；建议通过 profile 配置注入，不要提交到仓库。 */
  approvalAdapterToken: z.string().default(''),
  /** adapter 等待人工决定的最长时间（秒）。超时 fail-closed。 */
  approvalAdapterTimeoutSec: z.number().default(300),
  /** M2：人工批准学习白名单（同签名批准达 learnThreshold 后经冷却期放行）。 */
  learnWhitelist: z.boolean().default(true),
  /** M2：学习阈值（同签名人工批准次数）。 */
  learnThreshold: z.number().default(2),
  /** M2：人工拒绝学习黑名单（即时生效，不再打扰）。 */
  autoBlacklist: z.boolean().default(true),
  /** M2：白名单冷却期（小时），防疲劳误批准即时固化。 */
  cooldownHours: z.number().default(24),
  /** 审批卡可选学习策略；critical-red/never-learn 禁止自动立即学习，但保留显式手动白名单。 */
  approvalChoices: z.object({
    immediateAllow: z.boolean().default(true),
    manualWhitelist: z.boolean().default(true)
  }).default({ immediateAllow: true, manualWhitelist: true }),
  /** M7：自改动作治理——写 $DSH_HOME/AGENTS.md/配置/插件状态目录恒 red，永不进品味习得。 */
  selfModification: z.object({ red: z.boolean().default(true) }).default({ red: true }),
  /** 非 shell 工具的可信副作用标签；只允许宿主/管理员配置，不能由工具参数自报。 */
  trustedToolEffects: z.array(z.object({ tool: z.string(), effects: z.array(z.string()).default([]) })).default([]),
  /** M8：减法审计阈值（同一签名执行 ≥ 此数 → 建议缓存/合并）。 */
  reduce: z.object({ repeatThreshold: z.number().default(10) }).default({ repeatThreshold: 10 })
});

/** 从脱敏后的参数串生成审批摘要（截断，避免刷屏）。 */
function summarize(safeArgs, max = 180) {
  const s = typeof safeArgs === 'string' ? safeArgs : String(safeArgs ?? '');
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

/** ttlSec 归一化：0 是合法值（立即拒绝），不得被默认值吞掉；非数字回落 30。 */
function normalizeTtl(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return 30;
  return Math.max(0, Math.floor(n));
}

/**
 * 参数快照必须深拷贝（round-3 HIGH-2 修复）：存引用会被 escrow 之后的下游钩子原地改写——
 * 人工在 /escrow pending 看到 A、approve 后重放执行 B，且重放凭令牌豁免分类，B 可为任意命令。
 * structuredClone → JSON 深拷贝 → 浅拷贝，逐级容错（含函数/循环引用时不抛）。
 */
function cloneArgs(v) {
  if (v === null || typeof v !== 'object') return v ?? {};
  try { return structuredClone(v); } catch { /* 含函数等不可克隆结构 → 回落 */ }
  try { return JSON.parse(JSON.stringify(v)); } catch { /* 循环引用等 → 再回落浅拷贝 */ }
  return { ...v };
}

/**
 * 插件树 hash（M2 失效机制）：dsh 无现成 API，从合成插件树（ctx.loader.entries）或
 * profile 配置文件（ctx.baseUrl 下 package.json + cordis.patch.yml）近似计算。
 * 拿不到 → 空串（不触发 pending-review 失效）。任何异常容错返回空。
 */
function computePluginHash(ctx) {
  try {
    if (ctx?.loader?.entries) {
      // 只取稳定身份 id/name（不含 config——config 可能含运行时态，会导致 hash 漂移、白名单反复失效）。
      // entries 顺序排序后拼接，防 loader 迭代序不稳定造成 hash 漂移。
      const entries = ctx.loader.entries();
      const body = entries.map((e) => {
        const o = e?.options ?? {};
        return JSON.stringify([o.id, o.name]);
      }).sort().join('|');
      if (body) return createHash('sha256').update(body).digest('hex');
    }
    if (ctx?.baseUrl) {
      const dir = typeof ctx.baseUrl === 'string' ? ctx.baseUrl : fileURLToPath(ctx.baseUrl);
      const pkg = readFileSync(join(dir, 'package.json'), 'utf8');
      const patch = existsSync(join(dir, 'cordis.patch.yml')) ? readFileSync(join(dir, 'cordis.patch.yml'), 'utf8') : '';
      return createHash('sha256').update(pkg + patch).digest('hex');
    }
  } catch { /* 容错：无 hash 则不触发失效机制 */ }
  return '';
}

/**
 * M7：自改动作 before 快照标记——对路径候选计算文件内容 sha256（尽力：不存在/不可读跳过）。
 * v0.2.2 只记 hash 指针；快照本体与 /escrow undo 随 M4（v0.3）落地。
 */
function computeSnapshotHashes(paths) {
  if (!Array.isArray(paths)) return [];
  const out = [];
  for (const p of paths) {
    if (typeof p !== 'string' || !p) continue;
    try {
      const buf = readFileSync(p);
      out.push({ path: p, hash: createHash('sha256').update(buf).digest('hex') });
    } catch { /* 文件不存在/不可读 → 跳过 */ }
  }
  return out;
}

export function apply(ctx, config) {
  const ttlSec = normalizeTtl(config.ttlSec);
  const policy = normalizeTimeoutPolicy(config.timeoutPolicy);
  const defaultAction = normalizeAction(config.defaultAction, 'yellow');
  const mode = config.mode === 'sync' ? 'sync' : 'async';
  const approvalMode = config.approvalMode === 'host' || config.approvalMode === 'adapter' ? config.approvalMode : 'queue';
  const hostApproval = approvalMode === 'host' ? (ctx.get?.('approval') ?? ctx.approval) : null;
  const adapterApproval = approvalMode === 'adapter'
    ? createApprovalAdapterClient({
      baseUrl: config.approvalAdapterUrl,
      token: config.approvalAdapterToken || process.env.DSH_ESCROW_APPROVAL_TOKEN || '',
      timeoutMs: Math.max(1000, Math.floor((Number(config.approvalAdapterTimeoutSec) || 300) * 1000))
    })
    : null;
  const effectiveMode = approvalMode === 'host' || approvalMode === 'adapter' ? 'sync' : mode;
  const syncTools = Array.isArray(config.syncTools) ? config.syncTools : [];
  const learnWhitelist = config.learnWhitelist !== false;
  const learnThreshold = Math.max(1, Math.floor(Number(config.learnThreshold) || 2));
  const autoBlacklist = config.autoBlacklist !== false;
  const cdInput = Number(config.cooldownHours);
  const cooldownHours = Number.isFinite(cdInput) ? Math.max(0, cdInput) : 24; // 0 是合法值（无冷却期），不得被默认值吞掉
  const approvalChoices = {
    immediateAllow: config.approvalChoices?.immediateAllow !== false,
    manualWhitelist: config.approvalChoices?.manualWhitelist !== false
  };
  const selfModRed = config.selfModification?.red !== false;
  if (!selfModRed) ctx.logger?.warn('[escrow] 自改治理已关闭（selfModification.red=false）——写 $DSH_HOME/AGENTS.md/配置不再托管');
  const repeatThreshold = Math.max(2, Math.floor(Number(config.reduce?.repeatThreshold) || 10));
  const sep = process.platform === 'win32' ? '\\' : '/';
  const ledgerDir = config.ledgerDir || `${resolveDshHome()}${sep}.dsh-escrow`;
  const maxMb = Number.isFinite(Number(config.ledgerMaxMb)) ? Number(config.ledgerMaxMb) : 32;
  const ledger = createLedger({ dir: ledgerDir, maxBytes: Math.max(1, maxMb) * 1024 * 1024 });
  const queue = createQueue({ ttlSec, timeoutPolicy: policy });
  const builtinRules = config.builtinRules !== false;
  const rules = Array.isArray(config.rules) ? config.rules : [];
  const trustedToolEffects = Object.fromEntries(
    (Array.isArray(config.trustedToolEffects) ? config.trustedToolEffects : [])
      .filter((entry) => entry && typeof entry.tool === 'string')
      .map((entry) => [entry.tool, entry.effects])
  );
  const classifyOptions = { rules, builtinRules, defaultAction, selfModification: selfModRed, trustedToolEffects };

  // M2：品味习得存储。pluginHash 用于失效机制（插件树变化 → 条目待复核）。
  const pluginHash = computePluginHash(ctx);
  const taste = createTasteStore({ dir: ledgerDir, threshold: learnThreshold, cooldownHours, pluginHash });
  taste.applyPluginHash(pluginHash);

  ctx.logger?.info(`[escrow] ttl=${ttlSec}s policy=${policy} default=${defaultAction} mode=${effectiveMode} approval=${approvalMode} syncTools=${syncTools.length ? syncTools.join(',') : '-'} taste=${learnWhitelist ? `on(th=${learnThreshold})` : 'off'} blacklist=${autoBlacklist ? 'on' : 'off'} ledger=${ledger.path}`);

  ctx.on('tools/pre-execute', async (exec, next) => {
    // 豁免检查必须最前：重放调用（令牌 callId）跳过 escrow 分类，否则会被重新入队。
    const callId = exec?.callId ? String(exec.callId) : undefined;
    // M6 P10：会话上下文（从 exec.agent 派生，字符串或 {id/name} 都取到标识），注入本轮全部账本记录。
    const agent = exec?.agent;
    const session = typeof agent === 'string' ? agent : (agent?.id || agent?.name || undefined);
    if (callId && queue.isExempt(callId)) {
      queue.consumeExemption(callId);
      return { kind: 'allow' };
    }

    // M2 品味 check：白名单放行（不再托管）/ 黑名单拒绝。品味异常 fail-open（不因品味 bug 阻断主链路）。
    let m2Sig = '';
    try {
      const m2 = extractSignature(exec?.name, exec?.arguments);
      m2Sig = m2.signature;
      const t = taste.check(m2Sig);
      if (t === 'deny') {
        ledger.write('escrow.blacklisted', { session, tool: exec?.name, callId, signature: m2Sig, reason: `blacklisted (${m2.kind})` });
        return { kind: 'deny', reason: `[escrow] 该签名已在黑名单（曾人工拒绝 ≥${learnThreshold} 次），拒绝执行` };
      }
      if (t === 'allow') {
        // 安全：不容品味 allow 覆盖的 red——内置敏感路径/涉敏命令串/自改（签名粒度无法区分具体敏感形态）
        // + 用户显式 red 规则（显式配置 > 隐式习得，冲突保守拒绝；用 source 而非 ruleId 前缀判定，防用户 id 伪装 builtin-*）。
        // 内置普通命令红（如 git push，source:'builtin'）仍可被品味覆盖（学习本意）。
        const cls = classifyExec(exec, classifyOptions);
        const manualAllow = taste.allowSource?.(m2Sig) === 'manual';
        const neverLearn = neverLearnReason(exec?.name, exec?.arguments, { trustedEffects: getTrustedEffects(exec, classifyOptions) });
        const hardRed = cls.action === 'red' && !manualAllow && (
          cls.risk === 'critical-red'
          || !!neverLearn
          || cls.source === 'user'
          || cls.ruleId === 'builtin-sensitive-path' || cls.ruleId === 'builtin-command-sensitive'
          || cls.ruleId === 'builtin-external-effect' || cls.ruleId === 'builtin-trusted-effect' || cls.ruleId === 'selfmod'
        );
        if (!hardRed) {
          ledger.write('escrow.whitelisted', { session, tool: exec?.name, callId, signature: m2Sig, reason: `whitelisted (${m2.kind})` });
          return next();
        }
        // hard red：落到底部正常分类（托管）
      }
    } catch (err) {
      ctx.logger?.warn(`[escrow] taste check 异常: ${err instanceof Error ? err.message : String(err)}`);
    }

    let stage = 'classify';
    let cls = null;   // 分类结果；null = 分类未完成
    let reason = '';
    let queuedId = null;
    try {
      const classified = classifyExec(exec, classifyOptions);
      cls = classified.action;
      reason = classified.reason || `rule:${classified.ruleId}`;

      if (cls === 'yellow') {
        stage = 'observe';
        ledger.write('observe', { session, tool: exec?.name, callId, cls, args: ledger.redact(exec?.arguments) });
      } else if (cls === 'red') {
        stage = 'queue';
        const safeArgs = ledger.redact(exec?.arguments);
        const sig = signatureHash(exec?.name, exec?.arguments);
        const isSyncTool = effectiveMode === 'sync' || syncTools.includes(exec?.name);
        const argsSnapshot = cloneArgs(exec?.arguments);
        const trustedEffects = getTrustedEffects(exec, classifyOptions);
        const actionDetails = extractActionDetails(exec, classified, safeArgs);
        const learnBlockReason = neverLearnReason(exec?.name, exec?.arguments, { trustedEffects });
        const riskClass = classified.risk === 'critical-red' ? 'critical-red' : 'red';
        const approvalPlan = createApprovalPlan({
          threshold: learnThreshold,
          cooldownHours,
          riskClass,
          neverLearnReason: learnBlockReason,
          immediateAllow: approvalChoices.immediateAllow,
          manualWhitelist: approvalChoices.manualWhitelist
        });
        // M7：自改动作强制留 before 快照标记（文件内容 hash；快照本体随 M4 v0.3 落地）。
        const isSelfMod = classified.ruleId === 'selfmod';
        const cmdText = typeof exec?.arguments?.command === 'string' ? exec.arguments.command : '';
        const snapTargets = isSelfMod ? [...collectPathCandidates(exec?.arguments), ...extractRedirectTargets(cmdText)] : [];
        const snapshots = isSelfMod ? computeSnapshotHashes(snapTargets) : [];

        if (ttlSec === 0) {
          // 立即拒绝：fail-closed（无头/CI），不入队、不产生合成结果。
          ledger.write('escrow.queued', { session, id: null, tool: exec?.name, callId, reason, args: safeArgs });
          ledger.write('escrow.decided', { session, id: null, tool: exec?.name, decision: 'denied', via: 'immediate', waitedMs: 0 });
          if (isSelfMod) ledger.write('selfmod.decided', { session, id: null, decision: 'denied', via: 'immediate', snapshots });
          return { kind: 'deny', reason: `[escrow] 立即拒绝（ttl=0, fail-closed） (${reason})` };
        }

        if (isSyncTool) {
          // sync 逃生门：v0.1.1 行为——入队等待人工决策。
          if (approvalMode === 'host' && (typeof hostApproval?.request !== 'function' || !exec?.agent)) {
            ledger.write('escrow.queued', { session, id: null, tool: exec?.name, callId, reason, args: safeArgs, via: 'host-unavailable' });
            ledger.write('escrow.decided', { session, id: null, tool: exec?.name, decision: 'denied', via: 'host-unavailable', waitedMs: 0 });
            return { kind: 'deny', reason: '[escrow] 无法提供宿主人工审批界面，已安全拒绝（' + reason + '）' };
          }
          const { id, promise, dedup } = queue.enqueue({
            tool: exec?.name, reason, signal: exec?.signal, summary: summarize(safeArgs),
            signatureHash: sig, originalCallId: callId, argsSnapshot, agent: exec?.agent,
            tasteSignature: m2Sig, sync: true, snapshots, selfmod: isSelfMod, trustedEffects,
            neverLearnReason: learnBlockReason, riskClass, actionDetails, approvalPlan
          });
          queuedId = id;
          // 去重调用不重复记账（round-3 MEDIUM-1：旧版同 id 双写 queued/decided）。
          if (!dedup) ledger.write('escrow.queued', { session, id, tool: exec?.name, callId, reason, args: safeArgs });
          if (!dedup && isSelfMod) ledger.write('selfmod.queued', { session, id, tool: exec?.name, callId, reason, snapshots });
          let outcome;
          if ((approvalMode === 'host' || approvalMode === 'adapter') && !dedup) {
            const startedAt = Date.now();
            const approvalAbort = new AbortController();
            const forwardAbort = () => approvalAbort.abort();
            exec?.signal?.addEventListener('abort', forwardAbort, { once: true });
            const hostReason = [
              reason,
              '托管编号 ' + id + '；有效期 ' + ttlSec + 's。',
              '风险等级：' + riskClass,
              '【动作详情】',
              formatActionDetails(actionDetails) || '（未提取到额外结构化字段）',
              '【审批与学习】',
              formatApprovalPlan(approvalPlan),
              '【本次选择】允许一次；或选择学习策略后批准；也可以拒绝。'
            ].join('\n');
            let hostResult;
            try {
              const approvalRequest = {
                agent: exec.agent,
                toolName: exec.name,
                callId,
                approvalId: id,
                reason: hostReason,
                signal: approvalAbort.signal,
                details: actionDetails,
                riskClass,
                approvalPlan,
                choices: [
                  { id: 'allowed-once', label: '允许一次' },
                  ...(approvalPlan.immediateAllow ? [{ id: 'allowed-now', label: '批准达到' + approvalPlan.threshold + '次后，立即放行' }] : []),
                  ...(approvalPlan.manualWhitelist ? [{ id: 'allowed-and-manual-whitelist', label: '批准并加入白名单', warning: '如添加，用户需考虑清楚风险' }] : []),
                  { id: 'rejected', label: '拒绝' }
                ]
              };
              const requestApproval = approvalMode === 'adapter'
                ? adapterApproval.request(approvalRequest)
                : hostApproval.request(approvalRequest);
              hostResult = await Promise.race([
                requestApproval.then((result) => ({ source: approvalMode, result })),
                promise.then((result) => ({ source: 'queue', result }))
              ]);            } catch (err) {
              ctx.logger?.warn('[escrow] 宿主审批请求失败：' + (err instanceof Error ? err.message : String(err)));
              hostResult = { source: approvalMode, result: 'unavailable' };
            } finally {
              exec?.signal?.removeEventListener?.('abort', forwardAbort);
            }
            if (hostResult.source === 'host' || hostResult.source === 'adapter') {
              const hostOutcome = typeof hostResult.result === 'string' ? hostResult.result : hostResult.result?.outcome;
              const approved = ['allowed-once', 'allowed-now', 'allowed-and-whitelisted', 'allowed-and-manual-whitelist'].includes(hostOutcome);
              const learningMode = hostOutcome === 'allowed-now'
                ? 'immediate'
                : hostOutcome === 'allowed-and-whitelisted' || hostOutcome === 'allowed-and-manual-whitelist'
                  ? 'manual-allow'
                  : 'threshold';
              const via = hostOutcome === 'unavailable'
                ? 'host-unavailable'
                : approved || hostOutcome === 'rejected'
                  ? 'host'
                  : 'cancelled';
              queue.decide(id, approved ? 'approved' : 'denied', via);
              outcome = await promise;
              const settledEntry = queue.getEntry(id);
              if (settledEntry && hostOutcome === 'rejected') learnDecision(taste, settledEntry, false, { learnWhitelist, autoBlacklist });
              else if (settledEntry && approved) learnDecision(taste, settledEntry, true, { learnWhitelist, autoBlacklist }, learningMode);
              ctx.logger?.info('[escrow] host approval ' + id + ' outcome=' + hostOutcome + ' waitedMs=' + (Date.now() - startedAt));
            } else {
              approvalAbort.abort();
              outcome = hostResult.result;
            }
          } else {
            outcome = await promise;
          }
          if (!dedup) ledger.write('escrow.decided', { session, id, tool: exec?.name, decision: outcome.decision, via: outcome.via, waitedMs: outcome.waitedMs });
          if (!dedup) {
            const enSync = queue.getEntry(id);
            if (enSync?.selfmod) ledger.write('selfmod.decided', { session, id, decision: outcome.decision, via: outcome.via, snapshots: enSync.snapshots ?? [] });
          }
          if (outcome.decision !== 'approved') {
            const why = outcome.decision === 'cancelled'
              ? '已取消'
              : outcome.via === 'human' || outcome.via === 'host'
                ? '已被人工拒绝'
                : outcome.via === 'host-unavailable'
                  ? '宿主审批不可用，已安全拒绝'
                  : '未在窗口内获批，默认拒绝';
            return { kind: 'deny', reason: `[escrow:${id}] ${why} (${reason})` };
          }
          if (dedup) {
            // 同签名去重调用：由首个调用统一审批并执行，本调用不重复执行（round-3 MEDIUM-1）。
            return { kind: 'deny', reason: `[escrow:${id}] 与在审调用同签名，已统一审批并由该调用执行，本次不重复执行 (${reason})` };
          }
          // approved → 落到底部 next()（execute 层查签名无 pending → 真实执行）
        } else {
          // async 托管：入队不等待，放行到 execute 层返回合成结果。
          const { id, dedup } = queue.enqueue({
            tool: exec?.name, reason, signal: exec?.signal, summary: summarize(safeArgs),
            signatureHash: sig, originalCallId: callId, argsSnapshot, agent: exec?.agent,
            tasteSignature: m2Sig, sync: false, snapshots, selfmod: isSelfMod, trustedEffects,
            neverLearnReason: learnBlockReason, riskClass, actionDetails, approvalPlan,
            onSettle: (entryId, decision, via, waitedMs) => {
              // settle 可能发生在入队后的任意时刻（超时/人工决策/取消），在此落账。
              ledger.write('escrow.decided', { session, id: entryId, tool: exec?.name, decision, via, waitedMs });
              // M7：自改动作任何决策（含超时 deny / release 放行）都留 selfmod 审计。
              const en = queue.getEntry(entryId);
              if (en?.selfmod) ledger.write('selfmod.decided', { session, id: entryId, decision, via, snapshots: en.snapshots ?? [] });
              // release 策略超时放行：async 模式无命令通道（approve 才触发重放），settle 时自行
              // 触发真实执行，否则动作"已批准但永不执行"（escrow_result 永远报执行中）。
              if (decision === 'approved' && via === 'timeout') {
                replayEntry(ctx, queue, ledger, entryId);
              }
            }
          });
          queuedId = id;
          if (!dedup) ledger.write('escrow.queued', { session, id, tool: exec?.name, callId, reason, args: safeArgs });
          if (!dedup && isSelfMod) ledger.write('selfmod.queued', { session, id, tool: exec?.name, callId, reason, snapshots });
          return next();
        }
      }
      // green / yellow / sync-approved → 落到底部唯一 next()
    } catch (err) {
      // 安全不变式：已分类 red → fail-closed；分类未完成 / green / yellow 链路异常 → fail-open 一次
      ctx.logger?.warn(`[escrow] error at ${stage}: ${err instanceof Error ? err.message : String(err)}`);
      if (cls === 'red') {
        return { kind: 'deny', reason: `[escrow${queuedId ? `:${queuedId}` : ''}] 托管内部错误（${stage} 阶段），fail-closed 拒绝 (${reason})` };
      }
    }
    // 唯一 next() 调用点：在 try 之外，全函数至多执行一次（async-red 分支在 try 内 return next() 并返回）。
    return next();
  });

  // M1：tools/execute 拦截层。pending 签名 → 合成结果；重放令牌 → 真实执行。
  ctx.on('tools/execute', async (exec, next) => {
    try {
      const callId = exec?.callId ? String(exec.callId) : undefined;
      // 重放调用：令牌 callId 在 replaying 集 → 放行真实执行（单次）。
      if (callId && queue.isReplaying(callId)) {
        queue.finishReplay(callId);
        return next();
      }
      const sig = signatureHash(exec?.name, exec?.arguments);
      // 主匹配用调用身份（callId，跨钩子不变量）；签名 hash 兜底覆盖同签名重复调用（callId 不同）。
      const entryId = queue.findPendingByCallId(callId) ?? queue.findPendingBySig(sig);
      if (entryId) {
        const entry = queue.getEntry(entryId);
        if (entry && entry.state === 'pending') {
          const isRepeat = callId !== undefined && entry.originalCallId !== undefined && callId !== entry.originalCallId;
          return synthForeground(placeholderText(entry.id, isRepeat));
        }
      }
      // round-3 HIGH-1：调用身份已 settle（拒绝/超时/批准）——除 sync 批准路径（原调用即执行体）
      // 外一律不裸放行：防"超时拒绝后迟到调用被静默执行"与"release 重放 + 原调用双执行"。
      const handled = queue.findHandledByCallId(callId);
      if (handled) {
        const syncApproved = handled.sync && (handled.state === 'approved' || handled.state === 'executed');
        if (!syncApproved) {
          const why = handled.state === 'approved' || handled.state === 'executed'
            ? '该动作已由审批通道负责执行，本次不重复执行'
            : '该动作已被拒绝或已超时，不会执行';
          return synthForeground(`[dsh-escrow] ${why}（${handled.id}）；请调用 escrow_result("${handled.id}") 查询状态。`);
        }
      }
      return next();
    } catch (err) {
      // 绝不抛异常（wrapper 抛错终结 turn）；fail-closed 合成"拒绝"结果。
      ctx.logger?.warn(`[escrow] execute 拦截异常: ${err instanceof Error ? err.message : String(err)}`);
      return synthForeground('[dsh-escrow] 托管内部错误，动作未被放行；请稍后重试。');
    }
  });

  // M1：escrow_result 模型可见只读工具（模型轮询托管状态；审批通道仍只走 human command）。
  try {
    ctx.tools.register({
      name: 'escrow_result',
      description: '查询 dsh-escrow 托管动作（编号 esc-xxxx）的执行状态与结果。参数 id 为托管动作编号。',
      parameters: {
        type: 'object',
        properties: {
          id: { type: 'string', description: '托管动作编号，形如 esc-12345-1' }
        },
        required: ['id'],
        additionalProperties: false
      },
      output: {
        schema: {
          type: 'object',
          properties: {
            status: { type: 'string', enum: ['pending', 'executed', 'denied', 'expired'] },
            id: { type: 'string' },
            result: { type: 'string' }
          },
          required: ['status', 'id']
        },
        render(args, value) {
          const id = value?.id ?? '';
          const status = value?.status ?? 'unknown';
          let text;
          switch (status) {
            case 'executed': text = `托管动作 ${id} 已执行。结果：${value?.result ?? ''}`; break;
            case 'pending': text = `托管动作 ${id} 仍在审批中；批准后才可查询真实结果。`; break;
            case 'denied': text = `托管动作 ${id} 已被拒绝，未执行。`; break;
            case 'expired': text = `托管动作 ${id} 未在窗口内获批，超时拒绝，未执行。`; break;
            default: text = `托管动作 ${id} 状态未知或已过期。`;
          }
          return [{ type: 'text', text }];
        }
      },
      timeoutMs: 5000,
      async execute(args) {
        const id = typeof args?.id === 'string' ? args.id : '';
        const entry = id ? queue.getEntry(id) : undefined;
        if (!entry) return { status: 'expired', id, result: '未找到该托管动作。' };
        switch (entry.state) {
          case 'executed': return { status: 'executed', id, result: entry.resultText ?? '' };
          case 'pending': return { status: 'pending', id, result: '尚未批准；请稍后重试或等待人工审批。' };
          case 'approved': return { status: 'pending', id, result: '已批准，正在执行；请稍后重试。' };
          case 'expired': return { status: 'expired', id, result: '未在窗口内获批，超时拒绝。' };
          default: return { status: 'denied', id, result: '已拒绝，未执行。' };
        }
      }
    });
  } catch (err) {
    ctx.logger?.warn(`[escrow] escrow_result 注册失败: ${err instanceof Error ? err.message : String(err)}`);
  }

  registerEscrowCommands(ctx, queue, ledger, taste, {
    learnWhitelist, autoBlacklist, learnThreshold, repeatThreshold, pluginHash, rules,
    allowImmediate: approvalChoices.immediateAllow,
    allowManualWhitelist: approvalChoices.manualWhitelist
  });

  // 返回内部接口（dsh 运行时忽略；供集成测试与运维自检访问）。
  return { queue, taste, ledger };

  // Cordis 在插件卸载时自动撤销 ctx.on 与命令注册（可逆副作用），无需手动 dispose。
}
