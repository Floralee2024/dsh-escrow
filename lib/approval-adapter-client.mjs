/**
 * dsh-escrow 的本地 approval adapter HTTP 客户端。
 *
 * MVP 只使用宿主当前支持的两种最终决定：allowed-once / rejected。
 * 更丰富的学习策略仍由 /escrow approve-now 等插件命令处理。
 */

function normalizeBaseUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) throw new TypeError('approvalAdapterUrl is required');
  return raw.replace(/\/+$/, '');
}

function normalizeTimeout(value, fallback = 300000) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(1000, Math.floor(n));
}

async function readJson(response) {
  let body = null;
  try { body = await response.json(); } catch { /* below turns it into a useful error */ }
  if (!response.ok) {
    const detail = body?.error ? `: ${body.error}` : '';
    throw new Error(`approval adapter HTTP ${response.status}${detail}`);
  }
  return body;
}

/**
 * Keep runtime-only objects out of the wire payload. In a live dsh agent,
 * `agent` and `signal` are process objects (and may be circular); the adapter
 * only needs the approval card fields below.
 */
function adapterPayload(req, approvalId) {
  return {
    approvalId,
    ...(req.toolName !== undefined ? { toolName: String(req.toolName) } : {}),
    ...(req.callId !== undefined ? { callId: String(req.callId) } : {}),
    ...(req.reason !== undefined ? { reason: String(req.reason) } : {}),
    ...(req.details !== undefined ? { details: req.details } : {}),
    ...(req.riskClass !== undefined ? { riskClass: String(req.riskClass) } : {}),
    ...(req.approvalPlan !== undefined ? { approvalPlan: req.approvalPlan } : {}),
    ...(req.choices !== undefined ? { choices: req.choices } : {})
  };
}
/**
 * @param {{baseUrl?: string, token?: string, timeoutMs?: number, fetchImpl?: typeof fetch}} opts
 */
export function createApprovalAdapterClient(opts = {}) {
  const baseUrl = normalizeBaseUrl(opts.baseUrl || 'http://127.0.0.1:3099');
  const token = String(opts.token || '').trim();
  const timeoutMs = normalizeTimeout(opts.timeoutMs);
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== 'function') throw new TypeError('global fetch is unavailable');

  const headers = () => ({
    'content-type': 'application/json',
    ...(token ? { authorization: `Bearer ${token}` } : {})
  });

  return {
    baseUrl,
    timeoutMs,
    async request(req = {}) {
      const approvalId = String(req.approvalId || '').trim();
      if (!approvalId) throw new TypeError('approvalId is required');
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs + 1500);
      try {
        await readJson(await fetchImpl(`${baseUrl}/v1/approvals`, {
          method: 'POST',
          headers: headers(),
          body: JSON.stringify(adapterPayload(req, approvalId)),
          signal: controller.signal
        }));
        const waitUrl = `${baseUrl}/v1/approvals/${encodeURIComponent(approvalId)}/wait?waitMs=${timeoutMs}`;
        const result = await readJson(await fetchImpl(waitUrl, {
          method: 'GET',
          headers: headers(),
          signal: controller.signal
        }));
        return result?.outcome || 'unavailable';
      } catch (err) {
        if (err?.name === 'AbortError') return 'unavailable';
        throw err;
      } finally {
        clearTimeout(timer);
      }
    }
  };
}
