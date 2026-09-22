/**
 * 分类引擎（纯函数，无 dsh 依赖，可单测）。
 *
 * 设计原则：确定性规则优先（绝不用 AI 分类器做安全决策）。
 *
 * 优先级（v0.1.1 修正）：
 *   1. 用户规则 first-match-wins；但命中 green 时不立即生效，先让内置红灯裁决——
 *      用户 green 不能压制内置 red（防 `^ls ` 前缀规则放行 `ls -la; rm -rf x`），
 *      用户 yellow / red 可以覆盖内置结果（白名单/升级能力保留）；
 *   2. 内置规则（危险命令 / 命令串涉敏 / 敏感路径）命中一律 red；
 *   3. 用户 green 在内置未命中时生效；
 *   4. 皆未命中 → defaultAction。
 *
 * 所有匹配一律大小写不敏感（Windows 的 shell 与文件系统均不区分大小写）。
 * 任何分类过程不抛异常——分类器失败按 defaultAction 处理（fail open to default），
 * 但绝不把 red 静默降级。
 */

/** 将 glob 串转成正则（大小写不敏感）。`**` 跨任意层目录（含零层），`*`/`?` 不跨路径分隔符。 */
export function globToRegExp(glob) {
  let out = '';
  let i = 0;
  while (i < glob.length) {
    const ch = glob[i];
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        out += '.*';
        i += 2;
        if (glob[i] === '/' || glob[i] === '\\') i += 1; // **/ 吞掉一个分隔符
      } else {
        out += '[^/\\\\]*';
        i += 1;
      }
    } else if (ch === '?') {
      out += '[^/\\\\]';
      i += 1;
    } else {
      out += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
      i += 1;
    }
  }
  return new RegExp(`^${out}$`, 'i');
}

/** 工具名 glob 列表匹配（`*` 通配，含 `mcp__*` 这类前缀通配；大小写不敏感）。 */
export function matchTools(tools, name) {
  return tools.some((g) => globToRegExp(g).test(name));
}

/**
 * 从参数对象里提取可能携带路径的值。
 * 按常见键名（大小写不敏感），递归遍历嵌套对象（深度上限 4，防环），
 * 兼容 filePath / file_path / outputPath 等变体。
 */
export function collectPathCandidates(args) {
  const out = [];
  const KEYS = new Set([
    'path', 'paths', 'pathname', 'file', 'files', 'filepath', 'file_path', 'filename', 'file_name',
    'target', 'targetpath', 'target_path', 'target_file', 'targetfile',
    'src', 'source', 'source_path', 'source_file', 'sourcefile',
    'dst', 'dest', 'destination', 'dest_path', 'dest_file', 'destfile', 'dst_file', 'dstfile',
    'uri', 'file_uri', 'directory', 'dir', 'cwd', 'root',
    'out', 'output', 'outfile', 'out_file', 'outputpath', 'output_path', 'output_file', 'outputfile',
    'input', 'inputfile', 'input_file', 'in_file', 'infile'
  ]);
  const seen = new Set();
  const walk = (obj, depth) => {
    if (!obj || typeof obj !== 'object' || depth > 4 || seen.has(obj)) return;
    seen.add(obj);
    for (const [k, v] of Object.entries(obj)) {
      if (KEYS.has(k.toLowerCase())) {
        if (typeof v === 'string') out.push(v);
        else if (Array.isArray(v)) out.push(...v.filter((x) => typeof x === 'string'));
        else if (v && typeof v === 'object') walk(v, depth + 1);
      } else if (v && typeof v === 'object') {
        walk(v, depth + 1);
      }
    }
  };
  walk(args, 0);
  return out;
}

/**
 * 内置危险 shell 命令正则（全部大小写不敏感）。
 * 覆盖：旗标任意分组/顺序（rm -r -f、rm -fr）、长旗标（--recursive --force）、
 * git 全局选项穿插（git -C repo push）、.exe 后缀（git.exe / shutdown.exe）。
 */
const GIT_OPT = String.raw`(?:\s+(?:-[a-zA-Z](?:\s+\S+)?|--[\w-]+(?:=\S+)?))*`;
const git = (sub) => new RegExp(String.raw`\bgit(?:\.exe)?\b${GIT_OPT}\s+${sub}`, 'i');
/** 导出给 signature.mjs 复用——never-learn 必须与 builtin 红灯共享 GIT_OPT，
 * 否则 `git -C repo reset --hard` 这种带全局选项的形态会被漏判。 */
export const GIT_GLOBAL_OPT = GIT_OPT;

export const BUILTIN_COMMAND_PATTERNS = [
  // rm 带递归旗标（-r/-R，任意长短/分组）→ 递归删除目录树（无论是否 -f），红。
  // 只认空白引导的 -r 旗标，路径内 '-f' 字样不构成旗标（rm ./foo-f 不红）。
  /\brm\b(?=[^\n]*\s-{1,2}[a-zA-Z-]*r)/i,
  git(String.raw`clean\b(?=[^\n]*-[a-zA-Z]*f)(?=[^\n]*-[a-zA-Z]*[dx])`),
  git(String.raw`push\b`),
  git(String.raw`reset\s+--hard`),
  git(String.raw`checkout\s+--(?:\s|$)`), // 丢弃任意路径工作区改动（原仅 `-- .`；-- 后须空白/结束，避免 --help 误报）
  git(String.raw`restore\b`),            // 丢弃工作区/暂存改动（git restore 现代形态）
  /\bRemove-Item\b[^\n]*-\s*Recurse/i,
  /\brm\b[^\n]*-\s*Recurse/i,            // PowerShell 别名 rm -Recurse（无 -Force 也递归）
  /\b(del|rd|rmdir)\b[^\n]*\/s/i,
  /\bmkfs(?:\.[\w-]+)?\b/i,
  /\bformat(?:\.exe)?\b[^\n]*[a-z]:/i,
  /\b(?:shutdown|reboot)(?:\.exe)?\b/i,
  /\bdd\s+if=/i,
  /curl[^\n|]*\|\s*(ba)?sh\b/i,
  /wget[^\n|]*\|\s*(ba)?sh\b/i,
  /:\s*\(\)\s*\{\s*:\|:&\s*\}\s*;/,
  /\bchmod\s+-R\s+777\s+\/+/i,
  /\bchown\s+-R\s+[^ ]+\s+\/+/i,
  />>?\s*\/dev\/sd/
];

/**
 * 外部副作用/权限变化命令：动作本身未必不可逆，但会把影响带出当前工作区，
 * 或改变系统/共享资源状态，因此统一进入 red。只收录高置信度的完整命令形态，
 * 避免把 plan、get、test 等只读/预演动作误判为红灯。
 */
export const BUILTIN_EXTERNAL_COMMAND_PATTERNS = [
  { re: /\b(?:npm|pnpm|yarn|cargo|gem)\s+publish\b(?![^\n]*--dry-run(?:[=\s]|$))/i, label: '发布包/制品' },
  { re: /\b(?:docker|podman|nerdctl)\s+push\b/i, label: '推送容器制品' },
  { re: /\bkubectl\s+(?:delete|apply|replace|patch|scale)\b(?![^\n]*--dry-run(?:[=\s]|$))/i, label: '修改集群资源' },
  { re: /\bterraform\s+(?:apply|destroy|import)\b/i, label: '修改基础设施' },
  { re: /\bpulumi\s+(?:up|destroy|import)\b/i, label: '修改基础设施' },
  { re: /\bhelm\s+(?:install|upgrade|uninstall|rollback)\b(?![^\n]*--dry-run(?:[=\s]|$))/i, label: '修改集群发布' },
  { re: /\bInvoke-(?:RestMethod|WebRequest)\b[^\n]*\s-Method\s+(?:Post|Put|Patch|Delete)\b/i, label: 'HTTP 外部写入' },
  { re: /\b(?:curl|wget)\b[^\n]*(?:\s-X\s*(?:POST|PUT|PATCH|DELETE)\b|\s--request(?:=|\s+)(?:POST|PUT|PATCH|DELETE)\b|\s(?:-d|--data(?:=|\s)|--upload-file|--form|-[T])\b)/i, label: 'HTTP 外部写入' },
  { re: /\bNew-Service\b/i, label: '安装系统服务' },
  { re: /\bStart-Process\b[^\n]*\s-Verb\s+RunAs\b/i, label: '请求权限提升' },
  { re: /\b(?:sudo|doas|runas)\b/i, label: '请求权限提升' },
  { re: /\b(?:sc|sc\.exe)\s+(?:create|config|delete)\b/i, label: '修改系统服务' },
  { re: /\bschtasks(?:\.exe)?\s+\/(?:create|delete|change)\b/i, label: '修改计划任务' },
  { re: /\breg(?:\.exe)?\s+(?:add|delete|import)\b/i, label: '修改系统注册表' },
  { re: /\bSet-ExecutionPolicy\b/i, label: '修改脚本执行策略' },
  { re: /\b(?:psql|mysql|mariadb|sqlite3|sqlcmd)\b[^\n]*\b(?:DROP|TRUNCATE|ALTER|DELETE|UPDATE|INSERT|GRANT|REVOKE)\b/i, label: '修改数据库/权限' }
];

/**
 * critical-red：高影响动作不因“熟悉”而自动学习。
 * 保持 action=red 兼容旧调用方；risk 用于审批卡和更细的治理策略。
 */
export const BUILTIN_CRITICAL_COMMAND_PATTERNS = [
  { re: git(String.raw`push\b[^\n]*(?:--force\b|--force-with-lease\b|\s-[a-zA-Z]*f[a-zA-Z]*(?:\s|$))`), label: '强制推送', reason: '强制推送会改写远端历史' },
  { re: /\b(?:npm|pnpm|yarn|cargo|gem)\s+publish\b(?![^\n]*--dry-run(?:[=\s]|$))/i, label: '发布正式包', reason: '正式包/制品发布' },
  { re: /\b(?:docker|podman|nerdctl)\s+push\b/i, label: '发布容器制品', reason: '正式制品发布' },
  { re: /\b(?:Start-Process\b[^\n]*\s-Verb\s+RunAs|sudo|doas|runas)\b/i, label: '提升系统权限', reason: '权限提升' },
  { re: /\b(?:Set-ExecutionPolicy|icacls|reg(?:\.exe)?\s+(?:add|delete|import))\b/i, label: '修改安全策略', reason: '系统安全策略/访问控制变更' },
  { re: /\b(?:sc|sc\.exe)\s+(?:create|config|delete)\b|\bschtasks(?:\.exe)?\s+\/(?:create|delete|change)\b/i, label: '修改安全策略', reason: '系统服务/计划任务安全策略变更' },
  { re: /\b(?:chmod|chown)\b[^\n]*(?:-R|777|root)\b/i, label: '修改安全策略', reason: '文件权限/所有权策略变更' },
  { re: /\b(?:rm|Remove-Item|del|rd|rmdir)\b[^\n]*(?:prod(?:uction)?|shared)\b/i, label: '删除生产/共享资源', reason: '生产/共享资源删除' },
  { re: /\bkubectl\s+delete\b[^\n]*(?:prod(?:uction)?|shared|--all)\b/i, label: '删除生产/共享资源', reason: '生产/共享资源删除' },
  { re: /\b(?:terraform|pulumi)\s+destroy\b[^\n]*(?:prod(?:uction)?|shared)\b/i, label: '删除生产/共享资源', reason: '生产/共享基础设施删除' },
  { re: /\b(?:psql|mysql|mariadb|sqlite3|sqlcmd)\b[^\n]*\b(?:DROP|TRUNCATE|DELETE)\b[^\n]*(?:prod(?:uction)?|shared)\b/i, label: '删除生产/共享数据', reason: '生产/共享数据库删除' }
];

/**
 * 可信工具副作用标签。它们只能来自宿主注入的顶层字段或管理员配置，
 * 不能从 exec.arguments / MCP 工具参数读取；命中后用户 green 和品味白名单均不可压制。
 */
export const TRUSTED_EFFECTS = new Set([
  'external-write',
  'privileged',
  'destructive',
  'shared-resource-write',
  'secret-read',
  'governance'
]);

function normalizeEffects(value) {
  if (typeof value === 'string') return TRUSTED_EFFECTS.has(value) ? [value] : [];
  if (!Array.isArray(value)) return [];
  return [...new Set(value.filter((effect) => typeof effect === 'string' && TRUSTED_EFFECTS.has(effect)))];
}

/** 读取宿主/管理员可信标签；刻意不读取 arguments 内的同名字段。 */
export function getTrustedEffects(exec, opts = {}) {
  const configured = opts?.trustedToolEffects?.[exec?.name];
  return [...new Set([
    ...normalizeEffects(exec?.trustedEffects),
    ...normalizeEffects(configured)
  ])];
}

function trustedEffectLabel(effect) {
  return {
    'external-write': '外部写入',
    privileged: '权限提升/系统管理',
    destructive: '破坏性副作用',
    'shared-resource-write': '共享资源写入',
    'secret-read': '敏感信息读取',
    governance: '安全治理配置变更'
  }[effect] || effect;
}

/**
 * shell 命令串中的敏感路径字样（命令不经过 path 参数，必须扫命令文本本身）。
 * 例：`cat ~/.ssh/id_rsa`、`echo x >> .env`。
 */
export const BUILTIN_COMMAND_SENSITIVE = [
  { re: /\.env(\b|[\/\\])/i, label: '.env' },
  { re: /\.ssh[\/\\]/i, label: '.ssh/' },
  { re: /\bid_(rsa|ed25519|ecdsa|dsa)\b/i, label: 'SSH 私钥' },
  { re: /\.aws[\/\\]/i, label: '.aws/' },
  { re: /\.npmrc\b/i, label: '.npmrc' },
  { re: /\.pem\b/i, label: '.pem' },
  { re: /\bcredentials(\b|[\/\\])/i, label: 'credentials' },
  { re: /secrets[\/\\]/i, label: 'secrets/' },
  { re: /\.gnupg[\/\\]/i, label: '.gnupg/' },
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/, label: 'PEM 私钥块' }
];

/** 内置敏感路径 glob（大小写不敏感；token 类收窄为真实密钥文件形态，避免 tokenizer.ts 误报）。 */
export const BUILTIN_SENSITIVE_PATHS = [
  '**/.env*',
  '**/.ssh/**',
  '**/id_rsa*',
  '**/id_ed25519*',
  '**/id_ecdsa*',
  '**/*.pem',
  '**/credentials*',
  '**/secrets/**',
  '**/*.key',
  '**/auth.json',
  '**/.npmrc',
  '**/.aws/**',
  '**/.gnupg/**',
  '**/.kube/**',
  '**/.docker/config.json',
  '**/*.token',
  '**/token.json',
  '**/tokens.json',
  '**/.tokens'
];

/** shell 类工具名（命令串检查只对这些工具生效；大小写不敏感）。 */
export const SHELL_TOOLS = ['bash', 'sh', 'shell', 'pwsh', 'powershell', 'cmd', 'terminal'];

/**
 * 自改类路径模式（M7 宪法第 3 条 + M2 不可学习名单共用）：
 * 写这些路径 → 恒 red（托管）；签名永不自动学习。
 * 要求路径分隔符边界（精确，避免文件名含字样误报）。
 */
export const SELFMOD_PATTERNS = [
  { re: /(^|[\/\\])\.dsh-escrow([\/\\]|$)/i, label: '.dsh-escrow 自身目录' },
  { re: /(^|[\/\\])\.dsh([\/\\]|$)/i, label: '$DSH_HOME' },
  { re: /(^|[\/\\])AGENTS\.md$/i, label: 'AGENTS.md' },
  { re: /cordis\.patch\.yml$/i, label: 'profile cordis.patch.yml' },
  { re: /profiles[\/\\][^\/\\]+[\/\\]package\.json$/i, label: 'profile package.json' }
];

/**
 * 命令串重定向目标的自改检测（宽松：目标含自改字样即红）。
 * 与 SELFMOD_PATTERNS 分离：命令串里目标常为裸文件名（`>> AGENTS.md`，无路径分隔符），
 * 精确模式不匹配；这里只对"重定向/tee 的目标"检测，避免 `git commit -m "提及 AGENTS.md"` 误报。
 */
export const SELFMOD_TARGET_MARKERS = [
  /\bAGENTS\.md\b/i,
  /\bAGENTS\.m[?*](?=\s|$|[;&|])/i,
  /(?:^|[\s\/\\])\.dsh(?:-escrow)?\b/i,
  /\bcordis\.patch\.yml\b/i,
  /profiles[\/\\][^\/\\]+[\/\\]package\.json\b/i
];

/**
 * 重定向/tee 目标提取正则：支持 >> > 1> 2> &>（零或多空格）、tee 后跟可选 flag。
 * 捕获组 1/2/3 = 双引号内容 / 单引号内容 / 裸 token。
 */
const REDIRECT_RE = /(?:(?:>>|>|1>|2>|&>)\s*|(?:tee\s+(?:--?[a-zA-Z][\w-]*(?:=[^\s]+)?\s+)*))(?:"([^"]*)"|'([^']*)'|(\S+))/gi;

/** 提取命令串的重定向/tee 目标（供 classify 自改判定与 M7 快照）。 */
export function extractRedirectTargets(command) {
  if (typeof command !== 'string') return [];
  const out = [];
  for (const m of command.matchAll(REDIRECT_RE)) {
    const t = m[1] ?? m[2] ?? m[3] ?? '';
    if (t) out.push(t);
  }
  return out;
}

/** 命令串是否含自改目标（供 classify 与 never-learn 共用——宪法第 3 条：自改永不学习）。
 * 宽松：命令串任何位置出现自改字样即红——覆盖 cp/mv/sed -i/python 等非重定向写工具
 * （重定向检测有盲区）。保守：自改相关命令罕见且敏感，托管一次批准即放行；
 * `git commit -m "提及 AGENTS.md"` 也会被托管（可接受）。 */
export function findCommandSelfMod(command) {
  if (typeof command !== 'string') return null;
  // 先去引号（'' / "" 拼接绕过，如 AGENTS''.md 或 "AGENTS".md），再测自改字样。
  const stripped = command.replace(/["']/g, '');
  // 对简单的 shell 变量赋值做保守展开：F=AGENTS; echo x > $F.md。
  // 不尝试实现完整 shell 解释器；无法静态确定的命令仍属于已知限制。
  const assignments = new Map();
  const assignmentRe = /(?:^|[;&\n])\s*([A-Za-z_]\w*)\s*=\s*([^\s;&|]+)/g;
  for (const match of stripped.matchAll(assignmentRe)) assignments.set(match[1], match[2]);
  let expanded = stripped;
  for (let pass = 0; pass < 3; pass += 1) {
    let next = expanded;
    for (const [name, value] of assignments) {
      const variableRe = new RegExp(`\\$\\{${name}\\}|\\${name}(?=$|[^A-Za-z0-9_])`, 'g');
      next = next.replace(variableRe, value);
    }
    if (next === expanded) break;
    expanded = next;
  }
  const hit = SELFMOD_TARGET_MARKERS.find((re) => re.test(expanded));
  return hit ? '命令串含自改目标' : null;
}

const VALID_ACTIONS = new Set(['green', 'yellow', 'red']);

export function normalizeAction(action, fallback) {
  return VALID_ACTIONS.has(action) ? action : fallback;
}

/**
 * 把扁平规则转成内部结构。每条规则：
 * { id, tools: string[], args: {key,pattern}[], paths: string[], action, risk? }
 */
export function normalizeRules(rules) {
  if (!Array.isArray(rules)) return [];
  return rules
    .filter((r) => r && typeof r === 'object' && VALID_ACTIONS.has(r.action))
    .map((r) => ({
      id: r.id || '',
      tools: Array.isArray(r.tools) ? r.tools : [],
      args: Array.isArray(r.args) ? r.args.filter((a) => a && typeof a.key === 'string' && typeof a.pattern === 'string') : [],
      paths: Array.isArray(r.paths) ? r.paths : [],
      action: r.action,
      risk: r.risk === 'critical-red' ? 'critical-red' : ''
    }));
}

function safeJson(v) {
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

/**
 * 分类一次工具调用。
 * @param {object} exec - { name, arguments }
 * @param {object} opts - { rules, builtinRules, defaultAction }
 * @returns {{ action: 'green'|'yellow'|'red', ruleId: string, reason: string }}
 */
export function classifyExec(exec, opts = {}) {
  const builtinRules = opts.builtinRules !== false;
  const selfModRed = opts.selfModification !== false;
  const defaultAction = normalizeAction(opts.defaultAction, 'yellow');
  const rules = normalizeRules(opts.rules);
  const fallback = defaultAction;
  const name = exec?.name || '';
  const args = exec?.arguments ?? {};
  const command = typeof args?.command === 'string' ? args.command : '';
  const trustedEffects = getTrustedEffects(exec, opts);

  // 可信元数据是硬 red，必须在用户规则和品味白名单之前裁决。
  if (builtinRules && trustedEffects.length > 0) {
    const labels = trustedEffects.map(trustedEffectLabel).join('、');
    const criticalEffect = trustedEffects.find((effect) => ['privileged', 'destructive', 'shared-resource-write', 'governance'].includes(effect));
    return {
      action: 'red',
      risk: criticalEffect ? 'critical-red' : 'red',
      criticalReason: criticalEffect ? `可信标签对应高风险动作: ${trustedEffectLabel(criticalEffect)}` : undefined,
      ruleId: 'builtin-trusted-effect',
      source: 'builtin',
      reason: `可信副作用标签: ${labels}`
    };
  }

  const checkRule = (rule) => {
    // 规则内所有约束为 AND：tools 命中 && 所有声明的 args 模式命中各自 key && 任一 paths 命中。
    // 任一约束声明但未命中 → 整条规则不适用。
    if (rule.tools.length > 0 && !matchTools(rule.tools, name)) return null;
    if (rule.args.length > 0) {
      let hit = false;
      for (const a of rule.args) {
        const re = safeRegExp(a.pattern);
        if (!re) continue;
        // v0.1.1：按 key 取参数字段，不再一律只测 command。
        const v = args?.[a.key];
        const text = typeof v === 'string' ? v : v === undefined || v === null ? '' : safeJson(v);
        if (text && re.test(text)) {
          hit = true;
          break;
        }
      }
      if (!hit) return null;
    }
    if (rule.paths.length > 0) {
      const cands = collectPathCandidates(args);
      const hit = rule.paths.some((p) => cands.some((c) => globToRegExp(p).test(c)));
      if (!hit) return null;
    }
    return rule;
  };

  // 1. 用户规则 first-match-wins；首个命中是 green 时挂起，等内置红灯裁决。
  let userGreen = null;
  for (const rule of rules) {
    const hit = checkRule(rule);
    if (!hit) continue;
    if (hit.action === 'green') {
      userGreen = hit;
      break;
    }
    const userRisk = hit.action === 'red' && hit.risk === 'critical-red' ? 'critical-red' : undefined;
    return {
      action: hit.action,
      risk: userRisk,
      criticalReason: userRisk ? (hit.reason || '用户自定义 critical-red 动作') : undefined,
      ruleId: hit.id || '(user)',
      source: 'user',
      reason: ruleReason(hit, name, command, args)
    };
  }

  // 2. 内置规则：命中一律 red，用户 green 不可压制。
  if (builtinRules) {
    if (command && SHELL_TOOLS.some((t) => globToRegExp(t).test(name))) {
      const critical = BUILTIN_CRITICAL_COMMAND_PATTERNS.find((p) => p.re.test(command));
      if (critical) {
        return { action: 'red', risk: 'critical-red', criticalReason: critical.reason, ruleId: 'builtin-critical-red', source: 'builtin', reason: `critical-red: ${critical.label}` };
      }
      const hit = BUILTIN_COMMAND_PATTERNS.find((r) => r.test(command));
      if (hit) return { action: 'red', ruleId: 'builtin-command', source: 'builtin', reason: `危险命令模式: ${hit.source}` };
      const external = BUILTIN_EXTERNAL_COMMAND_PATTERNS.find((p) => p.re.test(command));
      if (external) return { action: 'red', ruleId: 'builtin-external-effect', source: 'builtin', reason: `外部副作用/权限动作: ${external.label}` };
      const sens = BUILTIN_COMMAND_SENSITIVE.find((s) => s.re.test(command));
      if (sens) return { action: 'red', ruleId: 'builtin-command-sensitive', source: 'builtin', reason: `命令串涉敏: ${sens.label}` };
    }
    const cands = collectPathCandidates(args);
    if (cands.length > 0) {
      const pathHit = BUILTIN_SENSITIVE_PATHS.find((p) => cands.some((c) => globToRegExp(p).test(c)));
      if (pathHit) return { action: 'red', ruleId: 'builtin-sensitive-path', source: 'builtin', reason: `敏感路径: ${pathHit}` };
    }
    // M7 自改：写 $DSH_HOME/AGENTS.md/配置/插件状态目录恒 red（宪法第 3 条；config selfModification.red 可关）。
    if (selfModRed) {
      const smPath = cands.length > 0 && SELFMOD_PATTERNS.find((p) => cands.some((c) => p.re.test(c)));
      if (smPath) return { action: 'red', risk: 'critical-red', criticalReason: 'dsh 治理配置变更', ruleId: 'selfmod', source: 'builtin', reason: `critical-red: 自改路径: ${smPath.label}` };
      if (command) {
        const smCmd = findCommandSelfMod(command);
        if (smCmd) return { action: 'red', risk: 'critical-red', criticalReason: 'dsh 治理配置变更', ruleId: 'selfmod', source: 'builtin', reason: `critical-red: 命令串写入自改目标: ${smCmd}` };
      }
    }
  }

  // 3. 内置未命中，用户 green 生效。
  if (userGreen) return { action: 'green', ruleId: userGreen.id || '(user)', source: 'user', reason: ruleReason(userGreen, name, command, args) };

  // 4. 默认处置。
  return { action: fallback, ruleId: '(default)', source: 'default', reason: `default:${fallback}` };
}

function ruleReason(rule, name, command) {
  if (rule.args.length > 0 && command) return `规则 ${rule.id} 命中参数模式`;
  if (rule.paths.length > 0) return `规则 ${rule.id} 命中敏感路径`;
  return `规则 ${rule.id} 命中工具 ${name}`;
}

function safeRegExp(pattern) {
  try {
    if (Array.isArray(pattern)) return new RegExp(pattern.map((p) => `(?:${p})`).join('|'), 'i');
    return new RegExp(pattern, 'i');
  } catch {
    return null;
  }
}
