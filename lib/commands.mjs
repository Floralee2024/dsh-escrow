/**
 * /escrow 命令（纯函数构造器：传入 ctx、queue、ledger、taste、opts，返回注册函数）。
 *
 * v0.1.1：pending 与 approve/deny 回显动作摘要（summary，已脱敏）。
 * v0.2 M1：approve 批准后异步重放执行（结果存队列条目，模型经 escrow_result 查询）。
 * v0.2 M2：品味习得命令——approve/deny 人工决策触发学习（超时/取消不学）；新增
 *   allowlist / allow <sig> / deny <sig> / forget <sig> / export / import / approve all / deny all。
 *
 * 命令语义：
 * - `/escrow deny <id>`：arg 匹配条目 id（esc-\d+-\d+）→ 拒绝托管条目；否则视为黑名单签名。
 * - `/escrow approve all` / `deny all`：按签名组去重批（同签名多实例合并一次决策 + 学一次）。
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { replayEntry } from './replay.mjs';
import { computeReduce, readLedgerLines } from './reduce.mjs';
import { computeReport } from './report.mjs';
import { classifyExec } from './classify.mjs';
import { formatActionDetails, formatApprovalPlan } from './approval-details.mjs';

const HELP = `escrow 用法：
  队列：
  /escrow pending             列出待决的托管动作（含动作摘要）
  /escrow approve <id>        批准单个托管动作（按默认阈值/冷却策略）
  /escrow approve-now <id>    批准并选择“达到阈值后立即放行”
  /escrow approve-and-allow <id>  批准并将相同签名立即加入白名单（高风险）
  /escrow deny <id>           拒绝单个托管动作
  /escrow approve all         按签名组去重批准（同签名多实例合并为一次决策）
  /escrow deny all            按签名组去重拒绝
  品味（M2）：
  /escrow allowlist           查看白名单/黑名单
  /escrow allow <sig>         手动加入白名单（立即生效）
  /escrow deny <sig>          手动加入黑名单（立即生效）
  /escrow forget <sig>        从名单移除
  /escrow export [path]       导出品味包（默认 ledgerDir/escrow-taste-pack.yaml）
  /escrow import <path>       导入品味包（校验和/schema 不符拒绝；导入条目待复核）
  其他：
  /escrow stats               统计（策略 / 待决 / 账本行数）
  /escrow reduce [--since N]  减法审计（重复动作 / SNR / 署名尾注；N 单位 d/h，默认全部历史）
  /escrow report [--json|--md] [--since N]  最小报告（统计 / 红灯清单 / ROI / 署名；哈希链完整性附注）
  /escrow migrate            迁移 legacy 账本为完整哈希链（h + HMAC；旧文件备份为 .premigrate）
  /escrow doctor             自检报告（哈希链 / 名单 schema / 密钥 / 规则数 / 分类器性能）
  /escrow help                本帮助`;

/** 条目 id 形态（queue.mintId: esc-<pid>-<seq>），用于区分 deny <id> 与 deny <sig>。 */
const ENTRY_ID_RE = /^esc-\d+-\d+$/;

/** M9 doctor：分类器热路径性能基准（N4 预算 < 1ms）。用代表性命令跑 N 次取平均。 */
function measureClassifyPerf(rules) {
  const N = 100;
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < N; i++) {
    classifyExec({ name: 'bash', arguments: { command: 'git push origin main' } }, { rules, builtinRules: true, defaultAction: 'yellow', selfModification: true });
  }
  return Number(process.hrtime.bigint() - t0) / 1e6 / N;
}

/**
 * M2：人工决策触发学习（仅人工 approve/deny 调用；超时/取消天然不学）。
 * never-learn 签名由 recordDecision 内部拒绝（返回 {learned:false, reason}）。
 */
export function learnDecision(taste, entry, approved, { learnWhitelist, autoBlacklist }, learnMode = 'threshold') {
  if (!taste || !entry?.tasteSignature) return null;
  if (!approved && !autoBlacklist) return null;
  if (approved && learnMode === 'manual-allow') {
    const result = taste.allow(entry.tasteSignature);
    return { learned: true, status: result.status, source: 'manual', warning: '显式手动白名单；请确认远端、分支、权限和资源范围' };
  }
  if (approved && !learnWhitelist) return null;
  return taste.recordDecision(entry.tasteSignature, approved, {
    toolName: entry.tool,
    args: entry.argsSnapshot ?? {},
    trustedEffects: entry.trustedEffects ?? [],
    immediate: approved && learnMode === 'immediate'
  });
}

export function registerEscrowCommands(ctx, queue, ledger, taste = null, opts = {}) {
  const {
    learnWhitelist = true,
    autoBlacklist = true,
    repeatThreshold = 10,
    pluginHash = '',
    rules = [],
    allowImmediate = true,
    allowManualWhitelist = true
  } = opts;
  const success = (text) => ({ kind: 'success', text });
  const error = (text) => ({ kind: 'error', text });

  /** 按签名组去重批：同签名多实例合并为一次决策 + 学一次；approved 时重放每组第一个实例。 */
  function decideGroup(decision) {
    const pending = queue.pendingList();
    if (pending.length === 0) return null;
    const groups = new Map(); // key → ids[]
    for (const e of pending) {
      const key = e.tasteSignature || `${e.tool}|${e.summary}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(e.id);
    }
    let decisions = 0;
    for (const [, ids] of groups) {
      // 只处理成功 settle 的条目：pendingList 快照与 decide 之间可能已超时（decide 返回 false），
      // 已超时的绝不重放执行（超时默认拒绝语义）。
      const decided = ids.filter((id) => queue.decide(id, decision === 'approved' ? 'approved' : 'denied'));
      if (decided.length === 0) continue;
      const first = queue.getEntry(decided[0]);
      if (decision === 'approved') {
        // 「去重批」指学习按组一次；执行各自进行——队内同品味签名但不同参数的实例（M1 严格 hash 未去重）
        // 必须逐个真实执行，不能只跑第一个（否则副作用丢失）。selfmod.decided 由 settle 统一落账。
        if (first) learnDecision(taste, first, true, opts);
        for (const id of decided) replayEntry(ctx, queue, ledger, id);
      } else if (first) {
        learnDecision(taste, first, false, opts);
      }
      decisions += 1;
    }
    return { decisions, total: pending.length };
  }

  ctx.commands.register({
    name: 'escrow',
    description: '托管队列：查看/批准/拒绝 agent 的不可逆动作 + 品味习得',
    input: { hint: 'pending | approve <id|all> | approve-now <id> | approve-and-allow <id> | deny <id|sig|all> | allowlist | allow <sig> | export | import <path> | stats | help' },
    recordInput: true,
    handler(invocation) {
      const parts = invocation.rawInput.trim().split(/\s+/);
      const cmd = parts[0] || '';
      const arg = parts.slice(1).join(' ');

      switch (cmd) {
        case 'pending': {
          const list = queue.pendingList();
          if (list.length === 0) return success('[escrow] 当前没有待决托管动作');
          const lines = list.map((e) => {
            const age = e.ageMs < 1000 ? `${e.ageMs}ms` : `${(e.ageMs / 1000).toFixed(1)}s`;
            const head = `  ${e.id}  ${e.tool}  (${age})  ${e.reason || ''}`;
            return e.summary ? `${head}\n      ↳ ${e.summary}` : head;
          });
          return success(`[escrow] ${list.length} 个待决动作：\n${lines.join('\n')}\n\n批准: /escrow approve <id|all>\n拒绝: /escrow deny <id|all>`);
        }
        case 'approve': {
          if (arg === 'all') {
            const r = decideGroup('approved');
            if (!r) return success('[escrow] 当前没有待决动作');
            return success(`[escrow] 已按签名组批准 ${r.decisions} 组（覆盖 ${r.total} 条待决动作），正在执行…`);
          }
          if (!arg) return error('[escrow] 用法：/escrow approve <id> 或 approve all');
          const snap = queue.pendingList().find((e) => e.id === arg);
          if (!queue.decide(arg, 'approved')) return error(`[escrow] ${arg} 不存在或已过期（可能已超时拒绝）`);
          const entryA = queue.getEntry(arg);
          learnDecision(taste, entryA, true, opts);
          replayEntry(ctx, queue, ledger, arg);
          return success(`[escrow] 已批准 ${arg}（${snap?.tool ?? '?'}${snap?.summary ? `: ${snap.summary}` : ''}），正在执行…`);
        }
        case 'approve-now': {
          if (!allowImmediate) return error('[escrow] 当前配置未启用“达到阈值后立即放行”选项');
          if (!arg) return error('[escrow] 用法：/escrow approve-now <id>');
          const snap = queue.pendingList().find((e) => e.id === arg);
          if (!queue.decide(arg, 'approved')) return error('[escrow] ' + arg + ' 不存在或已过期（可能已超时拒绝）');
          const entry = queue.getEntry(arg);
          const learned = learnDecision(taste, entry, true, opts, 'immediate');
          replayEntry(ctx, queue, ledger, arg);
          const note = learned?.learned ? '；已选择达到阈值后立即放行' : '；本次仅批准一次，未改变自动学习策略（该动作可能 never-learn/critical-red）';
          return success('[escrow] 已批准 ' + arg + '（' + (snap?.tool ?? '?') + '），正在执行…' + note);
        }
        case 'approve-and-allow': {
          if (!allowManualWhitelist) return error('[escrow] 当前配置未启用手动白名单选项');
          if (!arg) return error('[escrow] 用法：/escrow approve-and-allow <id>');
          const snap = queue.pendingList().find((e) => e.id === arg);
          if (!queue.decide(arg, 'approved')) return error('[escrow] ' + arg + ' 不存在或已过期（可能已超时拒绝）');
          const entry = queue.getEntry(arg);
          learnDecision(taste, entry, true, opts, 'manual-allow');
          replayEntry(ctx, queue, ledger, arg);
          return success('[escrow] 已批准并手动加入白名单 ' + arg + '（' + (snap?.tool ?? '?') + '）。这是显式高风险选择，请确认远端、权限和资源范围；正在执行…');
        }
        case 'deny': {
          if (arg === 'all') {
            const r = decideGroup('denied');
            if (!r) return success('[escrow] 当前没有待决动作');
            return success(`[escrow] 已按签名组拒绝 ${r.decisions} 组（覆盖 ${r.total} 条待决动作）`);
          }
          if (!arg) return error('[escrow] 用法：/escrow deny <id|all> 或 deny <签名>（加入黑名单）');
          if (ENTRY_ID_RE.test(arg)) {
            // 拒绝托管条目
            const snap = queue.pendingList().find((e) => e.id === arg);
            if (!queue.decide(arg, 'denied')) return error(`[escrow] ${arg} 不存在或已过期（可能已超时拒绝）`);
            const entryD = queue.getEntry(arg);
            learnDecision(taste, entryD, false, opts);
            return success(`[escrow] 已拒绝 ${arg}（${snap?.tool ?? '?'}${snap?.summary ? `: ${snap.summary}` : ''}）`);
          }
          // 否则视为黑名单签名
          if (!taste) return error('[escrow] 品味习得未启用');
          taste.deny(arg);
          return success(`[escrow] 已手动加入黑名单（立即生效）：${arg}`);
        }
        case 'allowlist': {
          if (!taste) return error('[escrow] 品味习得未启用');
          const snap = taste.snapshot();
          const fmt = (list, label) => list.length
            ? list.map((e) => `  ${e.signature}  [${e.status}] ×${e.count} (${e.source})`).join('\n')
            : `  （空）`;
          return success(`[escrow] 白名单：\n${fmt(snap.allowlist, 'allow')}\n黑名单：\n${fmt(snap.denylist, 'deny')}`);
        }
        case 'allow': {
          if (!arg) return error('[escrow] 用法：/escrow allow <签名>');
          if (!taste) return error('[escrow] 品味习得未启用');
          taste.allow(arg);
          return success('[escrow] 已手动加入白名单（立即生效）：' + arg + '。这是显式高风险选择，请确认远端、权限和资源范围。');
        }
        case 'forget': {
          if (!arg) return error('[escrow] 用法：/escrow forget <签名>');
          if (!taste) return error('[escrow] 品味习得未启用');
          const n = taste.forget(arg);
          return n > 0 ? success(`[escrow] 已从名单移除 ${n} 条：${arg}`) : error(`[escrow] 名单中无 ${arg}`);
        }
        case 'export': {
          if (!taste) return error('[escrow] 品味习得未启用');
          const path = arg || join(dirname(ledger.path), 'escrow-taste-pack.yaml');
          try {
            writeFileSync(path, taste.exportPack(), 'utf8');
            return success(`[escrow] 已导出品味包：${path}`);
          } catch (e) {
            return error(`[escrow] 导出失败：${e instanceof Error ? e.message : String(e)}`);
          }
        }
        case 'import': {
          if (!arg) return error('[escrow] 用法：/escrow import <路径>');
          if (!taste) return error('[escrow] 品味习得未启用');
          try {
            const r = taste.importPack(readFileSync(arg, 'utf8'));
            return r.ok
              ? success(`[escrow] 已导入 ${r.imported} 条品味包（全部待复核，经 /escrow allow 确认）`)
              : error(`[escrow] 导入失败：${r.error}`);
          } catch (e) {
            return error(`[escrow] 读取失败：${e instanceof Error ? e.message : String(e)}`);
          }
        }
        case 'reduce': {
          // M8 减法审计：重复动作 + SNR + 署名尾注。永不自动卸载——只输出建议（宪法级）。
          let sinceMs = 0;
          let sinceLabel = '全部历史';
          const sm = arg.match(/--since[=\s]+(\d+)([dh])?/);
          if (sm) {
            const n = Number(sm[1]);
            const unit = sm[2] || 'd';
            sinceMs = Date.now() - n * (unit === 'd' ? 86400000 : 3600000);
            sinceLabel = `since ${n}${unit}`;
          }
          const r = computeReduce(readLedgerLines(ledger.path), { threshold: repeatThreshold, sinceMs });
          const fmt = (x) => Number(x).toLocaleString('en-US');
          const pct = (x) => `${(x * 100).toFixed(1)}%`;
          const dupLines = r.duplicates.length
            ? r.duplicates.map((d) => `    ${d.signature}  ×${fmt(d.count)}  → 重复 ${fmt(d.count)} 次，建议缓存/合并`).join('\n')
            : '    无（无签名达到阈值）';
          const sign = `── Reduced by dsh-escrow ── 本月：拦下 ${fmt(r.denied)} · 静默 ${fmt(r.silent)} · 建议减去 ${r.suggest} · SNR ${r.snr.toFixed(2)} → ${r.projectedSnr.toFixed(2)}`;
          return success(
            `[escrow] reduce 成绩单（${sinceLabel}，重复阈值 ≥${repeatThreshold} 次）\n` +
            `─ 重复动作：\n${dupLines}\n` +
            `─ 信噪比：总动作 ${fmt(r.total)} · 拦下 ${fmt(r.denied)} · 静默 ${fmt(r.silent)} · 重复率 ${pct(r.repeatRate)} · 打扰率 ${pct(r.interruptRate)}\n` +
            `  SNR ${r.snr.toFixed(2)} → ${r.projectedSnr.toFixed(2)}（若执行以上建议）\n` +
            `${sign}`
          );
        }
        case 'report': {
          // M6 最小报告：统计 + 红灯清单 + 品味/自改 + ROI + 署名尾注（账本哈希链完整性附注）。
          let sinceMs = 0;
          let sinceLabel = '全部历史';
          const sm = arg.match(/--since[=\s]+(\d+)([dh])?/);
          if (sm) {
            const n = Number(sm[1]);
            const unit = sm[2] || 'd';
            sinceMs = Date.now() - n * (unit === 'd' ? 86400000 : 3600000);
            sinceLabel = `since ${n}${unit}`;
          }
          const wantJson = /(^|\s)--json\b/.test(arg);
          const wantMd = /(^|\s)--md\b/.test(arg);
          const lines = readLedgerLines(ledger.path);
          const r = computeReport(lines, { sinceMs });
          // 署名尾注复用 reduce 口径（与 /escrow reduce 完全一致，避免两命令"静默/SNR"报告矛盾）
          const rd = computeReduce(lines, { threshold: repeatThreshold, sinceMs });
          const fmt = (x) => Number(x).toLocaleString('en-US');
          const pct = (x) => `${(x * 100).toFixed(1)}%`;

          if (wantJson) {
            return success(JSON.stringify({
              ...r,
              reduce: { denied: rd.denied, silent: rd.silent, suggest: rd.suggest, snr: rd.snr, projectedSnr: rd.projectedSnr },
              since: sinceLabel, integrity: ledger.integrity
            }, null, 2));
          }

          const kinds = Object.entries(r.byKind).map(([k, c]) => `${k}=${c}`).join(' ');
          const head = `[escrow] report（${sinceLabel}）`;
          let body;
          if (wantMd) {
            body = [
              '| 指标 | 值 |', '|---|---|',
              `| 总行数 | ${fmt(r.total)} |`,
              `| 拦下 | ${fmt(r.denied)} |`,
              `| 批准 | ${fmt(r.approved)}（${pct(r.approveRate)}） |`,
              `| 平均人工等待 | ${r.roi.avgHumanWaitMs.toFixed(0)}ms |`,
              `| 注意力 ROI | 确认 ${r.roi.confirmCount} 次 · 平均 ${r.roi.avgHumanWaitMs.toFixed(0)}ms |`,
              `| 红灯清单 | ${r.redList.length} 条 |`,
              `| 品味记录 | ${r.tasteRec.length} 条 |`,
              `| 自改记录 | ${r.selfMod.length} 条 |`,
              `| 分布 | ${kinds} |`
            ].join('\n');
          } else {
            const redShow = r.redList.map((x) => `${x.id || x.tool || x.reason}${x.src === 'bak' ? '(bak)' : ''}`).join(', ') || '无';
            body = [
              `  总行数 ${fmt(r.total)} · 拦下 ${fmt(r.denied)} · 批准 ${fmt(r.approved)}（${pct(r.approveRate)}）· 平均等待 ${r.roi.avgHumanWaitMs.toFixed(0)}ms`,
              `  注意力 ROI：确认 ${r.roi.confirmCount} 次 · 平均人工耗时 ${r.roi.avgHumanWaitMs.toFixed(0)}ms`,
              `  红灯清单（最近 ${r.redList.length}）：${redShow}`,
              `  品味习得 ${r.tasteRec.length} 条 · 自改记录 ${r.selfMod.length} 条`,
              `  分布：${kinds}`
            ].join('\n');
          }
          const integrityNote = [
            ledger.integrity?.tampered ? '\n  ⚠️ 账本哈希链校验失败（可能被篡改或截断）' : '',
            ledger.integrity?.keyMismatch ? '\n  ⚠️ 哈希链完整但 HMAC 密钥不匹配（可能密钥被更换）；确认更换则 /escrow migrate --force 重锚定，怀疑篡改请勿执行' : '',
            ledger.integrity?.keyError ? '\n  ⚠️ HMAC 密钥不可用（空或读取失败），账本已降级为无锚定链；请检查 keys/hmac.key' : '',
            ledger.integrity?.chainResets ? `\n  ⚠️ 账本含 ${ledger.integrity.chainResets} 处链外历史（legacy），防篡改能力受限；建议 /escrow migrate 迁移到完整链` : ''
          ].join('');
          const sign = `── Reduced by dsh-escrow ── 本月：拦下 ${fmt(rd.denied)} · 静默 ${fmt(rd.silent)} · 建议减去 ${rd.suggest} · SNR ${rd.snr.toFixed(2)} → ${rd.projectedSnr.toFixed(2)}`;
          return success(`${head}\n${body}${integrityNote}\n${sign}`);
        }
        case 'migrate': {
          // M6+（R8-1 方案 B）：legacy 账本 → 完整链（h + m 逐行重算，当前密钥统一锚定）。
          // 安全守卫：tampered 拒绝；keyMismatch 需 --force 显式确认（防洗白篡改证据）。
          const force = /(^|\s)--force\b/.test(arg);
          const r = ledger.migrate(force);
          if (r.error) return error(`[escrow] migrate 失败：${r.error}`);
          const i = ledger.integrity;
          const bakNote = existsSync(`${ledger.path}.bak`) ? '；.bak 为历史归档，若含 legacy 不影响当前链' : '';
          return success(`[escrow] 已迁移 ${r.migrated} 行${r.skipped ? `（跳过 ${r.skipped} 行坏数据）` : ''}为完整链（h + HMAC）；链头 ${(i.chainHead || 'genesis').slice(0, 12)}…${bakNote}`);
        }
        case 'doctor': {
          // M9 最小自检：聚合账本哈希链 / 名单 schema / 密钥 / 插件树 hash / 规则数 / 分类器性能。
          const lines = [];
          let bad = 0;
          // 1. 账本哈希链
          const i = ledger.integrity || {};
          if (i.tampered) { bad += 1; lines.push('✗ 账本哈希链：校验失败（可能被篡改或截断）'); }
          else if (i.keyMismatch || i.keyError) { bad += 1; lines.push(`✗ 账本哈希链：HMAC 密钥不可用（${i.keyMismatch ? '不匹配' : '读取失败'}）`); }
          else { lines.push(`✓ 账本哈希链：${i.keyed ? 'HMAC 锚定' : '无密钥'}（tampered=false${i.legacyDetected ? `，legacy=${i.chainResets || 1}（建议 migrate）` : ''}）`); }
          // 2. 名单 schema
          const snap = taste?.snapshot ? taste.snapshot() : null;
          if (snap && Array.isArray(snap.allowlist) && Array.isArray(snap.denylist)) {
            const malformed = [...snap.allowlist, ...snap.denylist].find((e) => !e || typeof e.signature !== 'string' || typeof e.status !== 'string');
            if (malformed) { bad += 1; lines.push('✗ 名单 schema：存在结构异常条目'); }
            else lines.push(`✓ 名单 schema：allowlist ${snap.allowlist.length} / denylist ${snap.denylist.length}，结构有效`);
          } else { bad += 1; lines.push('✗ 名单 schema：无法读取（taste 未启用或状态文件损坏）'); }
          // 3. 密钥文件
          const keyFile = join(dirname(ledger.path), 'keys', 'hmac.key');
          if (i.keyError) { bad += 1; lines.push('✗ 密钥文件：存在但不可用（空或读取失败，HMAC 锚定失效）'); }
          else if (existsSync(keyFile) || i.keyed) lines.push('✓ 密钥文件：存在（HMAC 锚定就绪）');
          else { bad += 1; lines.push('✗ 密钥文件：缺失（HMAC 锚定未启用）'); }
          // 4. 插件树 hash
          lines.push(pluginHash ? '✓ 插件树 hash：可用（品味失效机制就绪）' : '⚠ 插件树 hash：不可用（无 ctx/loader，失效机制不触发）');
          // 5. 规则数上限（N4 预算）
          const rc = Array.isArray(rules) ? rules.length : 0;
          if (rc <= 256) lines.push(`✓ 规则数：${rc} / 256`);
          else { bad += 1; lines.push(`✗ 规则数：${rc} / 256（超预算）`); }
          // 6. 分类器性能（N4 预算 < 1ms）
          const perfMs = measureClassifyPerf(rules);
          if (perfMs < 1) lines.push(`✓ 分类器性能：${perfMs.toFixed(2)}ms < 1ms 预算`);
          else { bad += 1; lines.push(`✗ 分类器性能：${perfMs.toFixed(2)}ms ≥ 1ms 预算`); }
          return success(`[escrow] doctor 自检报告\n${lines.join('\n')}\n结论：${bad === 0 ? '全绿' : `${bad} 项异常（× 用 /escrow report|migrate|allow 手动修复）`}`);
        }
        case 'stats': {
          return success(`[escrow] 策略: ttl=${queue.ttlSec}s policy=${queue.policy}；待决=${queue.pendingList().length}；账本行数=${ledger.count}（${ledger.path}）`);
        }
        case 'help':
        case '':
          return success(HELP);
        default:
          return error(`[escrow] 未知子命令 "${cmd}"\n${HELP}`);
      }
    }
  });
}
