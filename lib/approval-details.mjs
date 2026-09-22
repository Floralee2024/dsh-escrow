/**
 * 从已分类的工具调用提取审批卡需要的低敏结构化字段。
 * 这里不改变安全判定；它只生成展示/审计信息，并且输入应优先使用 ledger.redact 后的参数。
 */

const DISPLAY_LIMIT = 180;

function text(value) {
  if (typeof value !== 'string') return '';
  const trimmed = value.trim();
  return trimmed.length > DISPLAY_LIMIT ? `${trimmed.slice(0, DISPLAY_LIMIT)}…` : trimmed;
}

function firstString(args, keys) {
  for (const key of keys) {
    const value = text(args?.[key]);
    if (value) return value;
  }
  return '';
}

function safeUrl(value) {
  const raw = text(value);
  if (!raw) return '';
  try {
    const url = new URL(raw);
    url.username = '';
    url.password = '';
    if (url.search) url.search = '?…';
    if (url.hash) url.hash = '#…';
    return text(url.toString());
  } catch {
    return raw.replace(/([?&](?:token|key|secret|password|sig)=)[^&\s]+/gi, '$1…');
  }
}

function commandTokens(command) {
  return command
    .replace(/"[^"\n]*"|'[^'\n]*'/g, (m) => m.slice(1, -1))
    .split(/\s+/)
    .filter(Boolean);
}

function afterVerb(command, verbPattern) {
  const match = command.match(verbPattern);
  return match ? text(match[1]) : '';
}

/**
 * @param {object} exec - 原始工具调用
 * @param {object} classification - classifyExec 返回值
 * @param {object} safeArgs - 已脱敏参数（可选）
 * @returns {Record<string, string>}
 */
export function extractActionDetails(exec, classification = {}, safeArgs = exec?.arguments ?? {}) {
  let args = {};
  if (safeArgs && typeof safeArgs === 'object') {
    args = safeArgs;
  } else if (typeof safeArgs === 'string') {
    try {
      const parsed = JSON.parse(safeArgs);
      if (parsed && typeof parsed === 'object') args = parsed;
    } catch {
      // 脱敏摘要可能不是 JSON；展示字段保持为空，不回读原始参数。
    }
  }
  const command = typeof args.command === 'string' ? args.command : '';
  const name = text(exec?.name);
  const details = {};
  const put = (key, value) => {
    const v = text(value);
    if (v) details[key] = v;
  };

  put('operation', classification.criticalReason || classification.reason || name);
  put('tool', name);

  const url = safeUrl(firstString(args, ['url', 'uri', 'endpoint', 'href']) || (command.match(/https?:\/\/[^\s'"<>]+/i)?.[0] ?? ''));
  put('url', url);
  put('target', firstString(args, ['target', 'path', 'file', 'resource', 'name', 'to', 'recipient']));
  put('remote', firstString(args, ['remote', 'repository', 'repo']));
  put('branch', firstString(args, ['branch', 'ref']));
  put('database', firstString(args, ['database', 'db', 'schema']));
  put('permissionScope', firstString(args, ['permissionScope', 'scope', 'role']));

  if (command) {
    if (/\bgit(?:\.exe)?\b[^\n]*\bpush\b/i.test(command)) {
      const pushIndex = commandTokens(command).findIndex((token) => /^push$/i.test(token));
      const operands = pushIndex >= 0
        ? commandTokens(command).slice(pushIndex + 1).filter((token) => !token.startsWith('-'))
        : [];
      put('operation', 'git push');
      put('remote', details.remote || operands[0]);
      put('branch', details.branch || operands[1]);
    }
    if (/\b(?:npm|pnpm|yarn|cargo|gem)\s+publish\b/i.test(command)) put('operation', '正式发布包/制品');
    if (/\b(?:docker|podman|nerdctl)\s+push\b/i.test(command)) put('operation', '推送容器制品');
    put('resource', afterVerb(command, /\bkubectl\s+(?:delete|apply|replace|patch|scale)\b\s+(.+)/i));
    put('resource', details.resource || afterVerb(command, /\b(?:terraform|pulumi|helm)\s+(?:apply|destroy|import|up|install|upgrade|uninstall|rollback)\b\s+(.+)/i));
    const db = command.match(/\b(?:DROP|TRUNCATE|ALTER|DELETE|UPDATE|INSERT|GRANT|REVOKE)\s+(?:DATABASE|SCHEMA|TABLE|ROLE|USER)?\s*([A-Za-z0-9_.-]+)/i);
    put('database', details.database || db?.[1]);
    if (/\b(?:sudo|doas|runas)\b/i.test(command) || /\bStart-Process\b[^\n]*\s-Verb\s+RunAs\b/i.test(command)) {
      put('permissionScope', details.permissionScope || '系统级/提升后的进程权限');
    }
    if (/\b(?:Set-ExecutionPolicy|icacls|reg(?:\.exe)?\s+(?:add|delete|import))\b/i.test(command)) {
      put('permissionScope', details.permissionScope || '系统安全策略/访问控制');
    }
  }

  return details;
}

export function createApprovalPlan({ threshold = 2, cooldownHours = 24, riskClass = 'red', neverLearnReason = null, immediateAllow = true, manualWhitelist = true } = {}) {
  const critical = riskClass === 'critical-red';
  return {
    riskClass,
    threshold: Math.max(1, Number(threshold) || 2),
    cooldownHours: Math.max(0, Number(cooldownHours) || 0),
    immediateAllow: !!immediateAllow && !critical && !neverLearnReason,
    manualWhitelist: !!manualWhitelist,
    neverLearnReason: neverLearnReason || null
  };
}

export function formatApprovalPlan(plan = {}) {
  const threshold = Math.max(1, Number(plan.threshold) || 2);
  const cooldownHours = Math.max(0, Number(plan.cooldownHours) || 0);
  const lines = [];
  if (plan.riskClass === 'critical-red') {
    lines.push('风险等级：critical-red；每次默认需要人工审批，不因批准次数达到阈值而自动放行。');
  } else if (plan.neverLearnReason) {
    lines.push('该动作即使人工批准很多次，也不会自动进入白名单。');
    lines.push('如需放行同一签名，可使用“批准并加入白名单”；如添加，用户需考虑清楚风险。');
  } else {
    lines.push('批准达到' + threshold + '次后，默认冷却期（' + cooldownHours + '小时）结束才自动放行。');
    if (plan.immediateAllow) lines.push('可选：“批准达到' + threshold + '次后，立即放行”（跳过冷却期）。');
  }
  lines.push('拒绝达到' + threshold + '次后，后续相同签名直接拒绝，不再请求人工审批。');
  return lines.join('\n');
}

export function formatActionDetails(details = {}) {
  const labels = [
    ['operation', '动作'],
    ['target', '目标对象'],
    ['remote', '远端'],
    ['branch', '分支/引用'],
    ['url', 'URL'],
    ['database', '数据库/架构'],
    ['resource', '资源'],
    ['permissionScope', '权限范围'],
    ['tool', '工具']
  ];
  return labels
    .filter(([key]) => details[key])
    .map(([key, label]) => `${label}: ${details[key]}`)
    .join('\n');
}
