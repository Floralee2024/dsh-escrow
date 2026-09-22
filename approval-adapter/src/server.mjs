import http from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';

const DEFAULT_HOST = '127.0.0.1';
const DEFAULT_PORT = 3099;
const DEFAULT_TTL_MS = 300000;
const MAX_BODY_BYTES = 256 * 1024;
const OUTCOMES = new Set(['allowed-once', 'rejected']);
const DETAIL_KEYS = ['operation', 'target', 'remote', 'branch', 'url', 'database', 'resource', 'permissionScope', 'tool'];

function text(value, limit = 500) {
  if (typeof value !== 'string') return '';
  const valueTrimmed = value.trim();
  return valueTrimmed.length > limit ? `${valueTrimmed.slice(0, limit)}…` : valueTrimmed;
}

function cloneDetails(value) {
  if (!value || typeof value !== 'object') return {};
  return Object.fromEntries(DETAIL_KEYS
    .filter((key) => text(value[key]))
    .map((key) => [key, text(value[key])]));
}

function clonePlan(value) {
  if (!value || typeof value !== 'object') return {};
  return {
    riskClass: text(value.riskClass, 40),
    threshold: Number.isFinite(Number(value.threshold)) ? Number(value.threshold) : 2,
    cooldownHours: Number.isFinite(Number(value.cooldownHours)) ? Number(value.cooldownHours) : 24,
    immediateAllow: value.immediateAllow === true,
    manualWhitelist: value.manualWhitelist !== false,
    neverLearnReason: text(value.neverLearnReason, 300) || null
  };
}

function cloneChoices(value) {
  if (!Array.isArray(value)) return [];
  return value
    .filter((choice) => choice && typeof choice === 'object' && OUTCOMES.has(choice.id))
    .map((choice) => ({
      id: choice.id,
      label: text(choice.label, 160) || choice.id,
      warning: text(choice.warning, 300) || undefined
    }));
}

function normalizeRequest(input = {}) {
  const approvalId = text(input.approvalId, 120);
  if (!approvalId) throw new Error('approvalId is required');
  const choices = cloneChoices(input.choices);
  return {
    approvalId,
    toolName: text(input.toolName, 160) || 'unknown-tool',
    callId: text(input.callId, 160),
    reason: text(input.reason, 4000),
    details: cloneDetails(input.details),
    riskClass: text(input.riskClass, 40) || 'red',
    approvalPlan: clonePlan(input.approvalPlan),
    choices: choices.length > 0 ? choices : [
      { id: 'allowed-once', label: '允许一次' },
      { id: 'rejected', label: '拒绝' }
    ],
    createdAt: new Date().toISOString()
  };
}

function json(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(body)
  });
  res.end(body);
}

function html(res, body) {
  res.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(body)
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); }
      catch { reject(new Error('invalid JSON body')); }
    });
    req.on('error', reject);
  });
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && timingSafeEqual(left, right);
}

function page() {
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>dsh-escrow approval</title>
<style>
:root{color-scheme:dark;font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;background:#111827;color:#e5e7eb}
body{margin:0;background:linear-gradient(135deg,#111827,#1f2937);min-height:100vh}.wrap{max-width:900px;margin:0 auto;padding:28px 18px 60px}
h1{font-size:22px;margin:0 0 6px}.sub{color:#9ca3af;margin-bottom:22px}.empty{padding:32px;border:1px dashed #4b5563;border-radius:14px;color:#9ca3af;text-align:center}
.card{background:#1f2937;border:1px solid #4b5563;border-left:5px solid #ef4444;border-radius:14px;padding:18px;margin:16px 0;box-shadow:0 12px 32px #0004}.card.critical{border-left-color:#f97316}
.head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}.tool{font-weight:700;font-size:17px}.id{font:12px ui-monospace,monospace;color:#9ca3af}.risk{display:inline-block;margin-top:7px;padding:3px 8px;border-radius:999px;background:#7f1d1d;color:#fecaca;font-size:12px}.critical .risk{background:#7c2d12;color:#fed7aa}
.reason{white-space:pre-wrap;color:#d1d5db;margin:14px 0}.details{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px;margin:14px 0}.field{background:#111827;border-radius:9px;padding:9px 11px}.label{display:block;color:#9ca3af;font-size:12px;margin-bottom:3px}.value{word-break:break-word}
.policy{white-space:pre-wrap;background:#111827;border-radius:9px;padding:11px;color:#c4b5fd;font-size:13px;line-height:1.55}.buttons{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}button{border:0;border-radius:9px;padding:10px 16px;font-weight:700;cursor:pointer}button.allow{background:#16a34a;color:white}button.deny{background:#991b1b;color:white}button:disabled{opacity:.5;cursor:wait}.warning{color:#fbbf24;font-size:12px;margin-top:8px}
@media(max-width:560px){.wrap{padding:18px 10px}.head{display:block}.id{display:block;margin-top:8px}}
</style></head><body><main class="wrap"><h1>dsh-escrow 人工审批</h1><div class="sub">本地 adapter · 只显示待审批动作 · 断线和超时默认拒绝</div><section id="list"></section></main>
<script>
const params=new URLSearchParams(location.search);const token=params.get('token')||'';if(token){history.replaceState(null,'',location.pathname)}
const labels={operation:'动作',target:'目标对象',remote:'远端',branch:'分支/引用',url:'URL',database:'数据库/架构',resource:'资源',permissionScope:'权限范围',tool:'工具'};
async function api(path,init={}){const headers={'authorization':'Bearer '+token,...(init.headers||{})};const r=await fetch(path,{...init,headers});if(!r.ok)throw new Error((await r.text())||r.statusText);return r.json()}
function el(tag,textValue,cls){const n=document.createElement(tag);if(cls)n.className=cls;if(textValue!==undefined)n.textContent=textValue;return n}
function card(item){const c=el('article',undefined,'card '+(item.riskClass==='critical-red'?'critical':''));const h=el('div',undefined,'head');const left=el('div');left.append(el('div',item.toolName,'tool'));left.append(el('span',item.riskClass,'risk'));const right=el('div',item.approvalId,'id');h.append(left,right);c.append(h);if(item.reason)c.append(el('div',item.reason,'reason'));const ds=el('div',undefined,'details');for(const [key,label] of Object.entries(labels)){if(item.details&&item.details[key]){const f=el('div',undefined,'field');f.append(el('span',label,'label'),el('span',item.details[key],'value'));ds.append(f)}}if(ds.children.length)c.append(ds);const p=item.approvalPlan||{};let lines=[];if(item.riskClass==='critical-red')lines.push('critical-red：每次都需要人工审批，不会因批准次数达到阈值而自动放行。');else if(p.neverLearnReason)lines.push('该动作即使人工批准很多次，也不会自动进入白名单。');else{lines.push('批准达到'+(p.threshold||2)+'次后，默认冷却期（'+(p.cooldownHours??24)+'小时）结束才自动放行。');}lines.push('拒绝达到'+(p.threshold||2)+'次后，后续相同签名直接拒绝，不再请求人工审批。');c.append(el('div',lines.join('\\n'),'policy'));const bs=el('div',undefined,'buttons');for(const choice of item.choices||[]){if(!['allowed-once','rejected'].includes(choice.id))continue;const b=el('button',choice.label,choice.id==='rejected'?'deny':'allow');if(choice.warning)b.title=choice.warning;b.onclick=async()=>{b.disabled=true;try{await api('/v1/approvals/'+encodeURIComponent(item.approvalId)+'/decision',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({outcome:choice.id})});await load()}catch(e){b.disabled=false;alert(e.message)}};bs.append(b)}c.append(bs);return c}
async function load(){const root=document.getElementById('list');try{const data=await api('/v1/approvals');root.replaceChildren();if(!data.approvals.length)root.append(el('div','当前没有待审批动作。','empty'));else data.approvals.forEach(item=>root.append(card(item)))}catch(e){root.replaceChildren(el('div','adapter 连接失败：'+e.message,'empty'))}}
load();setInterval(load,1000);
</script></body></html>`;
}

function createRecord(request, ttlMs, onRemove) {
  let resolveDecision;
  const decisionPromise = new Promise((resolve) => { resolveDecision = resolve; });
  const record = {
    request,
    state: 'pending',
    outcome: null,
    source: null,
    createdAt: Date.now(),
    decide(outcome, source) {
      if (record.state !== 'pending') return false;
      record.state = outcome === 'allowed-once' ? 'approved' : 'rejected';
      record.outcome = outcome;
      record.source = source;
      clearTimeout(record.timer);
      resolveDecision({ outcome, source });
      const cleanupTimer = setTimeout(() => onRemove(request.approvalId, record), 60000);
      cleanupTimer.unref?.();
      return true;
    },
    wait(waitMs) {
      if (record.state !== 'pending') return Promise.resolve({ outcome: record.outcome, source: record.source });
      const timeout = Math.max(1000, Math.min(Number(waitMs) || ttlMs, ttlMs));
      return Promise.race([
        decisionPromise,
        new Promise((resolve) => setTimeout(() => {
          record.decide('rejected', 'wait-timeout');
          resolve({ outcome: 'rejected', source: 'wait-timeout' });
        }, timeout))
      ]);
    },
    timer: setTimeout(() => record.decide('rejected', 'expired'), ttlMs)
  };
  return record;
}

function publicRecord(record) {
  return {
    ...record.request,
    state: record.state,
    outcome: record.outcome,
    source: record.source,
    createdAt: new Date(record.createdAt).toISOString()
  };
}

/** Start the local approval adapter. No external dependencies are required. */
export function startApprovalAdapter(options = {}) {
  const host = options.host || DEFAULT_HOST;
  const port = Number.isFinite(Number(options.port)) ? Number(options.port) : DEFAULT_PORT;
  const ttlMs = Math.max(1000, Number(options.ttlMs) || DEFAULT_TTL_MS);
  const token = String(options.token || randomBytes(24).toString('hex'));
  const records = new Map();
  const remove = (id, record) => { if (records.get(id) === record) records.delete(id); };
  const auth = (req) => {
    const header = req.headers.authorization || '';
    return header.startsWith('Bearer ') && safeEqual(header.slice(7), token);
  };
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url || '/', `http://${req.headers.host || host}`);
    if (req.method === 'GET' && url.pathname === '/') return html(res, page());
    if (req.method === 'GET' && url.pathname === '/healthz') return json(res, 200, { ok: true });
    if (!auth(req)) return json(res, 401, { error: 'unauthorized' });
    try {
      if (req.method === 'GET' && url.pathname === '/v1/approvals') {
        return json(res, 200, { approvals: [...records.values()].filter((record) => record.state === 'pending').map(publicRecord) });
      }
      if (req.method === 'POST' && url.pathname === '/v1/approvals') {
        const request = normalizeRequest(await readBody(req));
        const existing = records.get(request.approvalId);
        if (existing) return json(res, 200, publicRecord(existing));
        const record = createRecord(request, ttlMs, remove);
        records.set(request.approvalId, record);
        return json(res, 201, publicRecord(record));
      }
      const match = url.pathname.match(/^\/v1\/approvals\/([^/]+)(?:\/(wait|decision))?$/);
      if (!match) return json(res, 404, { error: 'not found' });
      const id = decodeURIComponent(match[1]);
      const record = records.get(id);
      if (!record) return json(res, 404, { error: 'approval not found' });
      if (match[2] === 'wait' && req.method === 'GET') {
        const result = await record.wait(url.searchParams.get('waitMs'));
        return json(res, 200, result);
      }
      if (match[2] === 'decision' && req.method === 'POST') {
        const body = await readBody(req);
        const outcome = text(body.outcome, 40);
        if (!OUTCOMES.has(outcome)) return json(res, 400, { error: 'MVP adapter accepts allowed-once or rejected only' });
        if (!record.decide(outcome, 'human')) return json(res, 409, { error: 'approval already settled' });
        return json(res, 200, publicRecord(record));
      }
      return json(res, 405, { error: 'method not allowed' });
    } catch (err) {
      return json(res, 400, { error: err instanceof Error ? err.message : String(err) });
    }
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.removeListener('error', reject);
      const address = server.address();
      const actualPort = typeof address === 'object' && address ? address.port : port;
      resolve({
        server,
        host,
        port: actualPort,
        token,
        url: `http://${host}:${actualPort}/?token=${encodeURIComponent(token)}`,
        close: () => new Promise((done) => server.close(() => done()))
      });
    });
  });
}
