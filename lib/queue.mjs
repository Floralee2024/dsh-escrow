/**
 * 托管队列（纯 Node，无 dsh 依赖，可单测）。
 *
 * 语义（Agent Inbox 原则：silence means no）：
 * - 入队后等待人工决策（/escrow approve <id> / deny <id>）。
 * - ttlSec > 0：超过窗口未决策 → 按 timeoutPolicy：
 *     cancel  → 拒绝（默认，超时即拒绝）
 *     release → 放行（显式配置才用，且会记录）
 *     hold    → 无限等待
 * - ttlSec === 0：不等待，立即拒绝（无头/CI 的 fail-closed 姿态）。
 * - 调用方信号中止 → cancelled（按拒绝处理）。
 *
 * v0.1.1 修正：
 * - 立即拒绝 / 预中止的条目不再进入 pending Map（旧版先入队幻影常驻、且 decide 会
 *   对已消失条目误报成功）。
 * - 决策结果带 via 字段（human / timeout / immediate / abort），调用方可区分
 *   「人工拒绝」与「超时默认拒绝」。
 * - 条目携带 summary（脱敏后的动作摘要），供 /escrow pending 展示给审批者。
 * - signal 非标准 AbortSignal（无 addEventListener）时跳过监听而不是抛 TypeError。
 *
 * v0.2 M1 扩展（非阻塞轮询式托管，保持 v0.1.1 enqueue/decide/pendingList 兼容）：
 * - entry.state：pending | approved | executed | denied | expired | cancelled。
 *   settled 后条目仍保留在 entries（供 escrow_result 查询历史），但 pending 索引移除。
 * - signatureHash + pendingBySig：同签名 pending 去重（完全相同参数才去重，严格）。
 * - 重放令牌（S0 定案：随机 callId，模型无法铸造）：
 *     mintToken() 同时登记 exemptions（pre-execute 豁免，单次）与 replaying
 *     （execute 层重放识别，单次）；consumeExemption / finishReplay 各消费一次。
 * - markExecuted(id, resultText)：批准重放完成后写回真实结果（供 escrow_result 返回）。
 */

import { createHash } from 'node:crypto';

export const TIMEOUT_POLICIES = new Set(['cancel', 'release', 'hold']);

export function normalizeTimeoutPolicy(policy) {
  return TIMEOUT_POLICIES.has(policy) ? policy : 'cancel';
}

/** 稳定 JSON 序列化：递归键排序，容错（undefined/函数/循环引用不抛）。 */
export function stableStringify(value) {
  if (value === undefined) return 'undefined';
  if (value === null) return 'null';
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : 'NaN';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'boolean') return String(value);
  if (typeof value === 'bigint') return String(value);
  if (typeof value === 'function' || typeof value === 'symbol') return String(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;
  }
  return String(value);
}

/**
 * M1 同签名去重用的严格 hash：sha256(工具名小写 + 稳定 JSON 参数)。
 * 仅完全相同参数才同 hash（与 M2 白名单式泛化签名目的不同——M1 宁可去重不足，不可过度拦截）。
 */
export function signatureHash(toolName, args) {
  const s = stableStringify({ tool: (toolName || '').toLowerCase(), args: args ?? {} });
  return createHash('sha256').update(s).digest('hex');
}

/** settle(decision, via) → entry.state 映射。 */
function stateFromSettle(decision, via) {
  if (decision === 'approved') return 'approved';
  if (decision === 'cancelled') return 'cancelled';
  return via === 'timeout' ? 'expired' : 'denied';
}

export function createQueue({ ttlSec = 30, timeoutPolicy = 'cancel', now = () => Date.now() } = {}) {
  const policy = normalizeTimeoutPolicy(timeoutPolicy);
  const MAX_ENTRIES = 1000;
  const pending = new Map();       // id → entry（仅 pending 中）
  const entries = new Map();       // id → entry（含 settled，供 escrow_result 查询；超限剪裁最旧 settled）
  const pendingBySig = new Map();  // signatureHash → entryId（仅 pending，settled 即删）
  const pendingByCallId = new Map(); // originalCallId → entryId（仅 pending；execute 层用身份匹配，不依赖跨钩子参数一致性）
  const handledByCallId = new Map(); // originalCallId → entry（settle 后保留终态身份；execute 层拦"迟到裸执行"，round-3 HIGH-1 修复）
  const exemptions = new Map();    // tokenCallId → entryId（pre-execute 豁免，单次）
  const replaying = new Set();     // tokenCallId（execute 层重放识别，单次）
  let seq = 0;

  const mintId = () => `esc-${process.pid}-${++seq}`;

  /** 剪裁最旧 settled 条目，防 entries 无限增长（仅删 settled，绝不删 pending）。 */
  function pruneSettled() {
    if (entries.size <= MAX_ENTRIES) return;
    for (const [eid, e] of entries) {
      if (!e.settled) continue;
      entries.delete(eid);
      if (e.originalCallId) handledByCallId.delete(e.originalCallId);
      if (entries.size <= MAX_ENTRIES) break;
    }
  }

  function snapshot(id) {
    const entry = entries.get(id);
    if (!entry || entry.settled) return undefined;
    return {
      id,
      tool: entry.tool,
      reason: entry.reason,
      summary: entry.summary,
      tasteSignature: entry.tasteSignature,
      createdAt: entry.createdAt,
      ageMs: now() - entry.createdAt
    };
  }

  /**
   * 入队（同步返回 id 与等待 promise，便于调用方先记账再等待）。
   * @param {object} opts - { tool, reason, signal, summary, signatureHash?, originalCallId? }
   * @returns {{ id: string, promise: Promise<{decision:'approved'|'denied'|'cancelled', id:string, waitedMs:number, via:string}> }}
   *   同签名 pending 去重时返回既有条目（不重复入队）。
   */
  function enqueue({ tool, reason, signal, summary, signatureHash: sig, originalCallId, argsSnapshot, agent, onSettle, tasteSignature, sync, snapshots, selfmod } = {}) {
    // M1 去重：同签名已有 pending 条目 → 不重复入队，返回既有条目。
    if (sig && pendingBySig.has(sig)) {
      const existingId = pendingBySig.get(sig);
      const existing = pending.get(existingId);
      if (existing) return { id: existingId, promise: existing.promise, dedup: true };
    }

    const id = mintId();
    const createdAt = now();
    let resolveSettle;
    const promise = new Promise((resolve) => {
      resolveSettle = resolve;
    });
    const entry = {
      id, tool, reason, summary, createdAt, settled: false, timer: null, settle: null,
      promise,
      signatureHash: sig,
      tasteSignature,
      originalCallId,
      argsSnapshot,
      agent,
      sync: !!sync, // sync 批准路径的原调用即执行体（execute 层对它放行）；async 条目 settle 后原调用一律拦截
      snapshots,    // M7：自改动作 before 快照 hash（[{path, hash}]，供 selfmod.decided 落账）
      selfmod: !!selfmod, // M7：自改动作标记（恒托管 + 永不学习；决策时写 selfmod.decided）
      state: 'pending'
    };
    const settle = (decision, via) => {
      if (entry.settled) return;
      entry.settled = true;
      entry.state = stateFromSettle(decision, via);
      if (entry.timer) clearTimeout(entry.timer);
      pending.delete(id);
      if (entry.signatureHash) pendingBySig.delete(entry.signatureHash);
      if (entry.originalCallId) {
        pendingByCallId.delete(entry.originalCallId);
        // settle 不是删除身份，而是搬到终态索引：execute 层据此拦截"已处置"的迟到原始调用（round-3 HIGH-1）。
        handledByCallId.set(entry.originalCallId, entry);
      }
      const waitedMs = now() - createdAt;
      resolveSettle({ decision, id, waitedMs, via });
      // M1：非阻塞模式下 escrow 用 onSettle 落 decided 账本（settle 可能发生在入队之后的任意时刻）。
      // id 作为参数传入（不用外部闭包变量），避免 enqueue 同步 settle 时外部尚未赋值的 TDZ 问题。
      if (typeof onSettle === 'function') {
        try {
          onSettle(id, decision, via, waitedMs);
        } catch { /* 记账失败不阻断主链路 */ }
      }
      pruneSettled();
    };
    entry.settle = settle;

    // 立即拒绝 / 预中止：先登记历史条目，再 settle，不进入 pending（不会产生幽灵条目）。
    // 先写入 entries 也保证同步 onSettle 回调能读取 selfmod 等审计元数据。
    if (ttlSec === 0) {
      entries.set(id, entry);
      settle('denied', 'immediate');
      return { id, promise };
    }
    if (signal && signal.aborted) {
      entries.set(id, entry);
      settle('cancelled', 'abort');
      return { id, promise };
    }

    pending.set(id, entry);
    entries.set(id, entry);
    if (sig) pendingBySig.set(sig, id);
    if (originalCallId) pendingByCallId.set(originalCallId, id);
    if (policy !== 'hold') {
      entry.timer = setTimeout(() => settle(policy === 'release' ? 'approved' : 'denied', 'timeout'), ttlSec * 1000);
    }
    if (signal && typeof signal.addEventListener === 'function') {
      signal.addEventListener('abort', () => settle('cancelled', 'abort'), { once: true });
    }
    return { id, promise };
  }

  /**
   * 人工/外部决策。
   * @returns {boolean} 是否成功（条目不存在、已超时或已 settle 均返回 false）
   */
  function decide(id, decision) {
    const entry = entries.get(id);
    if (!entry || entry.settled) return false;
    entry.settle(decision === 'approved' ? 'approved' : 'denied', 'human');
    return true;
  }

  function cancelAll() {
    for (const id of [...pending.keys()]) decide(id, 'denied');
    return pending.size === 0;
  }

  /** M1：铸一次性重放令牌（随机 callId，模型无法铸造），同时登记豁免与重放识别。 */
  function mintToken(entryId) {
    const token = `esc-replay-${process.pid}-${++seq}-${Math.random().toString(36).slice(2, 10)}`;
    exemptions.set(token, entryId);
    replaying.add(token);
    return token;
  }

  function isExempt(tokenCallId) {
    return exemptions.has(tokenCallId);
  }

  /** pre-execute 豁免：验证后删除（单次豁免）。 */
  function consumeExemption(tokenCallId) {
    return exemptions.delete(tokenCallId);
  }

  function isReplaying(tokenCallId) {
    return replaying.has(tokenCallId);
  }

  /** execute 层重放执行后清理（单次识别）。同时清 exemptions 双保险（pre-execute 豁免可能未被消费）。 */
  function finishReplay(tokenCallId) {
    replaying.delete(tokenCallId);
    exemptions.delete(tokenCallId);
  }

  /** M1：批准重放完成后写回真实结果。 */
  function markExecuted(id, resultText) {
    const entry = entries.get(id);
    if (!entry) return false;
    entry.state = 'executed';
    entry.resultText = resultText;
    return true;
  }

  return {
    get policy() {
      return policy;
    },
    get ttlSec() {
      return ttlSec;
    },
    pendingList() {
      return [...pending.keys()].map(snapshot).filter(Boolean);
    },
    /** M1：查任意条目（含 settled），供 escrow_result。 */
    getEntry(id) {
      return entries.get(id);
    },
    /** M1：查 pending 签名的条目 id。 */
    findPendingBySig(sig) {
      return pendingBySig.get(sig);
    },
    /** M1：按原始调用身份（callId）查 pending 条目 id——execute 层主匹配路径，不依赖跨钩子参数一致性。 */
    findPendingByCallId(callId) {
      return callId ? pendingByCallId.get(callId) : undefined;
    },
    /** round-3 HIGH-1：查已 settle 的调用身份（execute 层拦"已处置"的迟到裸调用；sync 批准路径除外）。 */
    findHandledByCallId(callId) {
      return callId ? handledByCallId.get(callId) : undefined;
    },
    enqueue,
    decide,
    cancelAll,
    mintToken,
    isExempt,
    consumeExemption,
    isReplaying,
    finishReplay,
    markExecuted
  };
}
