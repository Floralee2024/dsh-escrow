/**
 * M6-lite 最小报告（纯函数，复用 readLedgerLines 与 reduce 口径）。
 * 统计（总数/分布/拦下/批准率/平均等待）+ 红灯清单 + 品味习得记录 + 自改记录
 * + 注意力 ROI（确认次数/平均人工耗时）。署名尾注由 commands 拼接。
 */

export function computeReport(lines, { sinceMs = 0, redLimit = 20, recLimit = 20 } = {}) {
  let total = 0;
  let denied = 0;
  let approved = 0;
  let executed = 0;
  const byKind = {};
  const humanWaits = [];
  const redList = [];
  const tasteRec = [];
  const selfMod = [];

  for (const rec of lines) {
    if (!rec || typeof rec !== 'object') continue;
    const t = typeof rec.t === 'string' ? new Date(rec.t).getTime() : NaN;
    if (!Number.isFinite(t) || t < sinceMs) continue;
    total += 1;
    byKind[rec.kind] = (byKind[rec.kind] || 0) + 1;

    if (rec.kind === 'escrow.blacklisted') {
      // 黑名单自动拒绝：拦下 + 品味记录
      denied += 1;
      redList.push({ id: rec.id, tool: rec.tool, reason: 'blacklisted', via: 'blacklist', t: rec.t, src: rec._src });
      tasteRec.push({ kind: 'blacklisted', signature: rec.signature, t: rec.t, src: rec._src });
    } else if (rec.kind === 'escrow.decided') {
      if (rec.decision === 'denied' || rec.decision === 'cancelled') {
        denied += 1;
        redList.push({ id: rec.id, tool: rec.tool, reason: rec.reason, via: rec.via, t: rec.t, src: rec._src });
      } else if (rec.decision === 'approved') {
        // 批准决策数（async/sync 都落 decided(approved)；approved_executed 是执行记录，另行统计避免双重计数）
        approved += 1;
      }
      // 注意力 ROI：人工决策（via=human）的确认次数与平均耗时
      if (rec.via === 'human' && typeof rec.waitedMs === 'number') humanWaits.push(rec.waitedMs);
    } else if (rec.kind === 'escrow.approved_executed') {
      executed += 1;
    } else if (rec.kind === 'escrow.whitelisted') {
      tasteRec.push({ kind: 'whitelisted', signature: rec.signature, t: rec.t, src: rec._src });
    } else if (rec.kind === 'selfmod.decided') {
      selfMod.push({ id: rec.id, decision: rec.decision, via: rec.via, snapshots: rec.snapshots, src: rec._src });
    }
  }

  const approveRate = approved + denied > 0 ? approved / (approved + denied) : 0;
  const avgHumanWaitMs = humanWaits.length ? humanWaits.reduce((a, b) => a + b, 0) / humanWaits.length : 0;

  return {
    total,
    byKind,
    denied,
    approved,
    executed,
    approveRate,
    redList: redList.slice(-redLimit),
    tasteRec: tasteRec.slice(-recLimit),
    selfMod: selfMod.slice(-recLimit),
    roi: { confirmCount: humanWaits.length, avgHumanWaitMs }
  };
}
