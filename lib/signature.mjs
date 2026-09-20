/**
 * 稳定签名提取（M2 品味习得的核心，纯函数，无 dsh 依赖）。
 *
 * 白名单式规范化（设计 P7）：只有匹配已知安全形态的 token 才替换为通配符——
 *   数字 → <N>    哈希 → <HASH>    远程名后的分支 → <BRANCH>    HEAD~n → <REF>
 * `--`/`-` 开头的 flag 一律保留原文：`git push origin --force` 与普通 push 不同签名。
 * 引号包裹的片段归一为 <STR>（commit message 等自由文本不进入签名）。
 * 其余一律保留原文——宁可签名过窄（多学几次），不可过宽（误放行）。
 *
 * 非 shell 工具：`tool(key1,key2)`（排序后的参数键），不含参数值。
 */

import { SHELL_TOOLS, collectPathCandidates, SELFMOD_PATTERNS, findCommandSelfMod, GIT_GLOBAL_OPT } from './classify.mjs';

const RE_NUMBER = /^\d+$/;
const RE_HASH = /^[0-9a-f]{7,40}$/i;
const RE_BRANCH = /^[A-Za-z][\w./-]{0,99}$/;
const RE_HEAD_REF = /^HEAD(~\d+|\^\d*)?$/;
const REMOTE_NAMES = new Set(['origin', 'upstream']);

/** 破坏性命令基座（带 force 旗标时进不可学习名单）。
 * 注意：用 GIT_GLOBAL_OPT 让 `git -C repo` 这种全局选项也命中。 */
const RE_DESTRUCTIVE_BASE = new RegExp(String.raw`\b(rm|git(?:\.exe)?\s+(?:push|clean|reset|checkout|restore)|Remove-Item|del|rd|rmdir)\b${GIT_GLOBAL_OPT}`, 'i');
const RE_FORCE_FLAG = /\s--force\b|\s-[a-zA-Z]*f[a-zA-Z]*(\s|$)/;

/** 引号片段归一，再按空白切 token。 */
function tokenize(command) {
  const masked = command.replace(/"[^"\n]*"|'[^'\n]*'/g, '<STR>');
  return masked.split(/\s+/).filter(Boolean);
}

/** shell 命令 → 稳定签名。 */
export function commandSignature(command) {
  const tokens = tokenize(command);
  const out = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === '<STR>' || t.startsWith('-')) {
      out.push(t); // flag 与自由文本槽位原文保留
    } else if (RE_HEAD_REF.test(t)) {
      out.push('<REF>');
    } else if (RE_NUMBER.test(t)) {
      out.push('<N>');
    } else if (RE_HASH.test(t)) {
      out.push('<HASH>');
    } else if (REMOTE_NAMES.has(tokens[i - 1]) && RE_BRANCH.test(t)) {
      out.push('<BRANCH>');
    } else {
      out.push(t); // 白名单式：不认识的一律原文
    }
  }
  return out.join(' ');
}

/**
 * 提取一次工具调用的稳定签名。
 * @returns {{ signature: string, kind: 'command'|'tool' }}
 */
export function extractSignature(toolName, args) {
  const name = toolName || '';
  const command = typeof args?.command === 'string' ? args.command : '';
  if (command && SHELL_TOOLS.some((t) => t === name.toLowerCase())) {
    return { signature: commandSignature(command), kind: 'command' };
  }
  const keys = args && typeof args === 'object' ? Object.keys(args).sort() : [];
  return { signature: `${name}(${keys.join(',')})`, kind: 'tool' };
}

/**
 * 不可学习名单（设计 P7 + 宪法第 3 条）。
 * 与 builtin 红灯按"绝对不可逆/不可恢复"口径对齐——round-6 R6-1 修复：
 *   rm -r（无 -f）/ pwsh rm -Recurse / git restore / git -C repo reset --hard /
 *   git -C repo checkout -- 均必须永不自动学习。
 * 设计 P7 保留：`git push` `git clean -fd` 等可学习（否则品味习得锁死）。
 * @returns {string|null} 命中原因；null = 可学习。
 */
const NEVER_LEARN_COMMAND_PATTERNS = [
  // rm 任意递归形态（-r/-R/--recursive，旗标任意分组/顺序；不再限定 -f——rm -r 与 rm -rf 同样不可逆）
  /\brm\b(?=[^\n]*\s-{1,2}[a-zA-Z-]*r)/i,
  // PowerShell 别名（rm -Recurse / Remove-Item -Recurse）
  /\bRemove-Item\b[^\n]*-\s*Recurse/i,
  /\brm\b[^\n]*-\s*Recurse/i,
  // cmd 递归删除（del / rd / rmdir 带 /s）
  /\b(del|rd|rmdir)\b[^\n]*\/s/i,
  // 磁盘/系统级
  /\bdd\s+if=/i,
  /\bmkfs(?:\.[\w-]+)?\b/i,
  /\bformat(?:\.exe)?\b[^\n]*[a-z]:/i,
  /\b(?:shutdown|reboot)(?:\.exe)?\b/i,
  /:\s*\(\)\s*\{\s*:\|:&\s*\}\s*;/,
  />>?\s*\/dev\/sd/,
  /\bchmod\s+-R\s+777\s+\/+/i,
  /\bchown\s+-R\s+[^ ]+\s+\/+/i,
  // 丢弃工作区/暂存改动（不可恢复）：reset --hard / checkout -- / restore（git restore 现代形态）
  // 用 GIT_GLOBAL_OPT 让 `git -C repo reset --hard` 等带全局选项形态也命中。
  new RegExp(String.raw`\bgit(?:\.exe)?${GIT_GLOBAL_OPT}\s+reset\s+--hard`, 'i'),
  new RegExp(String.raw`\bgit(?:\.exe)?${GIT_GLOBAL_OPT}\s+checkout\s+--`, 'i'),
  new RegExp(String.raw`\bgit(?:\.exe)?${GIT_GLOBAL_OPT}\s+restore\b`, 'i')
];

/**
 * 不可学习名单（设计 P7 + 宪法第 3 条）。
 * @returns {string|null} 命中原因；null = 可学习。
 */
export function neverLearnReason(toolName, args) {
  const command = typeof args?.command === 'string' ? args.command : '';
  if (command) {
    if (NEVER_LEARN_COMMAND_PATTERNS.some((r) => r.test(command))) {
      return '递归删除/磁盘/系统级命令永不自动学习';
    }
    if (RE_DESTRUCTIVE_BASE.test(command) && RE_FORCE_FLAG.test(command)) {
      return '破坏性命令带 force 旗标永不自动学习';
    }
    if (findCommandSelfMod(command) || SELFMOD_PATTERNS.some((p) => p.re.test(command))) {
      return '自改类命令永不自动学习';
    }
  }
  const paths = collectPathCandidates(args);
  const hit = SELFMOD_PATTERNS.find((p) => paths.some((c) => p.re.test(c)));
  if (hit) return `自改类路径（${hit.label}）永不自动学习`;
  return null;
}
