/**
 * 重放执行（M1 共享模块）：批准后异步重放被托管的动作。
 *
 * 触发点：
 * - commands.mjs：/escrow approve <id> 与 approve all（人工批准）。
 * - index.mjs：release 策略超时放行（settle approved via timeout）时——async 模式无命令通道，
 *   必须在 settle 时自行触发，否则动作"已批准但永不执行"。
 *
 * 机制：铸一次性重放令牌（随机 callId），加入 exemptions（pre-execute 豁免）+ replaying
 * （execute 层放行），经 ctx.tools.execute 走完整流水线真实执行；结果存回条目供 escrow_result 查询。
 */
import { resultToText } from './synth-result.mjs';

export function replayEntry(ctx, queue, ledger, entryId) {
  const entry = queue.getEntry(entryId);
  if (!entry) return;
  const agent = entry.agent;
  const session = typeof agent === 'string' ? agent : (agent?.id || agent?.name || undefined); // M6 P10
  if (!ctx.tools?.execute) {
    // 无工具执行环境（如纯命令上下文）：不卡 approved，标记失败供 escrow_result 查询。
    queue.markExecuted(entryId, '已批准，但无工具执行环境（无法重放）。');
    ledger.write('escrow.replayed', { id: entryId, ok: false, session, reason: 'no tools.execute' });
    return;
  }
  const token = queue.mintToken(entryId);
  const controller = new AbortController();
  ctx.tools.execute({
    callId: token,
    name: entry.tool,
    arguments: entry.argsSnapshot ?? {},
    agent: entry.agent,
    signal: controller.signal
  }).then((result) => {
    queue.finishReplay(token);
    queue.markExecuted(entryId, resultToText(result));
    ledger.write('escrow.approved_executed', { id: entryId, tool: entry.tool, via: 'replay', args: ledger.redact(entry.argsSnapshot ?? {}), session });
    ledger.write('escrow.replayed', { id: entryId, token, ok: true, session });
  }).catch((err) => {
    queue.finishReplay(token);
    queue.markExecuted(entryId, `执行失败: ${err instanceof Error ? err.message : String(err)}`);
    ledger.write('escrow.replayed', { id: entryId, ok: false, session, reason: err instanceof Error ? err.message : String(err) });
  });
}
