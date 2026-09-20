/**
 * M8-lite 减法审计（纯 Node + 复用 M2 extractSignature，可单测）。
 * 数据源 = 账本（append-only，唯一事实源）。永不自动卸载——只输出建议，创作者拍板（宪法级）。
 *
 * 统计口径：
 * - 执行动作（total）：observe（yellow 放行）+ escrow.approved_executed（批准执行）+ escrow.whitelisted（白名单放行）。
 *   ⚠️ green 放行未单独记账 → 可能低估 green（默认 yellow 居多，接受）。
 * - 拦下（denied）：escrow.decided 的 decision ∈ {denied, cancelled}（含 ttl=0 immediate / timeout / human 拒绝）。
 * - 静默（silent）：observe + whitelisted（放行不打扰）。
 * - 签名：extractSignature(rec.tool, rec.args)，args 为 redact 后 JSON 字符串（parse 容错）。
 */
import { readFileSync } from 'node:fs';
import { extractSignature } from './signature.mjs';

const EXEC_KINDS = new Set(['observe', 'escrow.approved_executed', 'escrow.whitelisted']);

/** 读 ledger.jsonl（含轮转的 .bak，若存在），逐行 parse JSON，跳过空行/坏行；读失败 → []。
 * 来自 .bak 的行附加 `_src: 'bak'`（R8-2：轮转后 esc seq 重置，跨代合并时 id 可能重复，展示方据此区分来源）。 */
export function readLedgerLines(file) {
  if (typeof file !== 'string') return [];
  const out = [];
  for (const [f, src] of [[file, 'main'], [`${file}.bak`, 'bak']]) {
    try {
      for (const line of readFileSync(f, 'utf8').split('\n')) {
        const s = line.trim();
        if (!s) continue;
        try {
          const rec = JSON.parse(s);
          if (rec && typeof rec === 'object' && src === 'bak') rec._src = 'bak';
          out.push(rec);
        } catch { /* 坏行跳过 */ }
      }
    } catch { /* 主文件或 .bak 不存在/读失败 → 跳过 */ }
  }
  return out;
}

function parseArgs(args) {
  if (typeof args !== 'string') return args;
  try {
    return JSON.parse(args);
  } catch {
    return {};
  }
}

function signatureOf(rec) {
  try {
    // 落账已带签名的行（如 escrow.whitelisted 的 m2Sig）直接用；否则从 tool+args 重算。
    if (typeof rec?.signature === 'string' && rec.signature) return rec.signature;
    if (!rec?.tool) return null;
    const args = parseArgs(rec.args);
    if (!args || typeof args !== 'object') return null;
    return extractSignature(rec.tool, args).signature;
  } catch {
    return null;
  }
}

/**
 * 从账本行统计减法指标。
 * @param {object[]} lines - 已 parse 的账本行
 * @param {object} opts - { threshold, sinceMs }
 */
export function computeReduce(lines, { threshold = 10, sinceMs = 0 } = {}) {
  let total = 0;
  let denied = 0;
  let silent = 0;
  const bySig = new Map();

  for (const rec of lines) {
    if (!rec || typeof rec !== 'object') continue;
    const t = typeof rec.t === 'string' ? new Date(rec.t).getTime() : NaN;
    if (!Number.isFinite(t) || t < sinceMs) continue;

    if (rec.kind === 'escrow.decided') {
      if (rec.decision === 'denied' || rec.decision === 'cancelled') denied += 1;
      continue;
    }
    if (rec.kind === 'escrow.blacklisted') {
      // 黑名单自动拒绝也属"拦下"（阻止了执行；不打扰但阻止）。
      denied += 1;
      continue;
    }
    if (!EXEC_KINDS.has(rec.kind)) continue;

    total += 1;
    if (rec.kind !== 'escrow.approved_executed') silent += 1;
    const sig = signatureOf(rec);
    if (sig) bySig.set(sig, (bySig.get(sig) || 0) + 1);
  }

  const duplicates = [...bySig.entries()]
    .filter(([, c]) => c >= threshold)
    .map(([signature, count]) => ({ signature, count }))
    .sort((a, b) => b.count - a.count);
  const dupCount = duplicates.reduce((s, d) => s + d.count, 0);
  const snr = total > 0 ? (total - dupCount) / total : 1;

  return {
    total,
    denied,
    silent,
    duplicates,
    dupCount,
    snr,
    repeatRate: total > 0 ? dupCount / total : 0,
    interruptRate: total + denied > 0 ? denied / (total + denied) : 0,
    suggest: duplicates.length,
    // 去掉重复执行后 SNR 提升至 1（假设去重后剩余动作均有效）
    projectedSnr: dupCount > 0 ? 1 : snr
  };
}
