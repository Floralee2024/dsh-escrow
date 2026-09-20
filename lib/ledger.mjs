/**
 * append-only 账本（纯 Node，无 dsh 依赖）。
 * 每次写入一行 JSON，永不修改、永不删除。写失败不抛异常（记录到 stderr），
 * 因为账本不应成为 agent 主链路的故障点。
 *
 * v0.1.1 修正：
 * - 脱敏正则兼容 JSON 形态：{"password":"..."} 键名后的引号不再导致漏脱敏；
 *   新增 authorization 头与 PEM 私钥块。
 * - 轮转：文件超过 maxBytes 时轮转为 ledger.jsonl.bak（只保留一代），避免无限增长。
 * - 启动行数统计改为分块读取，不再把整个账本一次性读入内存。
 */

import { appendFileSync, mkdirSync, existsSync, statSync, renameSync, rmSync, openSync, readSync, closeSync, readFileSync, writeFileSync, copyFileSync } from 'node:fs';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { join } from 'node:path';

function sha256(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/** 常见密钥形态的脱敏正则。整段即密钥的模式直接打码；键名=值模式保留键名（键名两侧引号可选，兼容 JSON）。 */
const SECRET_PATTERNS = [
  { re: /sk-[A-Za-z0-9_-]{8,}/g, keepPrefix: false },
  { re: /Bearer\s+[A-Za-z0-9._~+/=-]{12,}/gi, keepPrefix: false },
  { re: /AIza[0-9A-Za-z_-]{20,}/g, keepPrefix: false },
  { re: /AKIA[0-9A-Z]{16}/g, keepPrefix: false },
  { re: /gh[pousr]_[A-Za-z0-9]{20,}/g, keepPrefix: false },
  { re: /xox[baprs]-[A-Za-z0-9-]{10,}/g, keepPrefix: false },
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[^-]*(-----END [A-Z ]*PRIVATE KEY-----)?/g, keepPrefix: false },
  { re: /("?api[_-]?key"?\s*[:=]\s*"?)[^",}\s]{8,}/gi, keepPrefix: true },
  { re: /("?(?:password|passwd|secret|token)"?\s*[:=]\s*"?)[^",}\s]{8,}/gi, keepPrefix: true },
  { re: /("?authorization"?\s*[:=]\s*"?)(?:[A-Za-z]{3,10}\s+)?[^",}\s]{8,}/gi, keepPrefix: true },
  // 空格分隔的 flag 值：--token abc、--access-token abc、--api-key sk-xxx（round-3 LOW-2）
  { re: /(--?(?:[a-z_-]+-)?(?:token|secret|password|passwd|api[_-]?key)\b\s+)[^\s]{4,}/gi, keepPrefix: true },
  // URL 内嵌凭据：scheme://user:pass@host → 保留 scheme 与 @，打码 user:pass（round-3 LOW-2）
  { re: /([a-z][a-z0-9+.-]*:\/\/)[^:\/\s]+:[^@\s]+@/gi, keepPrefix: true, suffix: '@' }
];

function redact(value) {
  let text = typeof value === 'string' ? value : safeStringify(value);
  for (const { re, keepPrefix, suffix = '' } of SECRET_PATTERNS) {
    text = text.replace(re, (m, g1) => {
      if (keepPrefix && g1) return `${g1}***REDACTED***${suffix}`;
      return '***REDACTED***';
    });
  }
  return text;
}

function safeStringify(value) {
  if (value === undefined) return 'undefined';
  if (value === null) return 'null';
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

/** 分块统计行数（内存恒定，不整文件读入）。 */
function countLines(file) {
  let fd;
  try {
    fd = openSync(file, 'r');
  } catch {
    return 0;
  }
  try {
    const buf = Buffer.alloc(1 << 20);
    let n = 0;
    let bytes;
    while ((bytes = readSync(fd, buf, 0, buf.length, null)) > 0) {
      for (let i = 0; i < bytes; i++) if (buf[i] === 10) n += 1;
    }
    return n;
  } finally {
    closeSync(fd);
  }
}

export function createLedger({ dir, maxBytes = 32 * 1024 * 1024 } = {}) {
  const root = dir || join(process.env.DSH_HOME || join(process.env.USERPROFILE || process.env.HOME || '.', '.dsh'), '.dsh-escrow');
  const file = join(root, 'ledger.jsonl');
  const bak = `${file}.bak`;
  if (!existsSync(root)) {
    try {
      mkdirSync(root, { recursive: true });
    } catch (e) {
      process.stderr.write(`[dsh-escrow] ledger mkdir failed: ${e.message}\n`);
    }
  }

  // HMAC 锚定密钥（keys/hmac.key）：防"知道算法但无密钥"的攻击者重算链。不存在 → 生成。
  const keysDir = join(root, 'keys');
  const hmacKeyFile = join(keysDir, 'hmac.key');
  let hmacKey = '';
  let keyError = false; // 密钥存在但读失败/为空 → 锚定降级（告警，不静默）
  function ensureKey() {
    try {
      if (existsSync(hmacKeyFile)) {
        hmacKey = readFileSync(hmacKeyFile, 'utf8').trim();
        if (!hmacKey) {
          keyError = true;
          process.stderr.write('[dsh-escrow] HMAC 密钥文件为空，锚定失效（keyMismatch 检测将跳过）\n');
        }
      } else {
        mkdirSync(keysDir, { recursive: true });
        const k = randomBytes(32).toString('hex');
        writeFileSync(hmacKeyFile, `${k}\n`, { encoding: 'utf8', mode: 0o600 });
        hmacKey = k;
      }
    } catch (e) {
      hmacKey = '';
      keyError = true;
      process.stderr.write(`[dsh-escrow] HMAC 密钥读取失败，锚定降级：${e.message}\n`);
    }
  }
  ensureKey();
  const hmacOf = (h) => (hmacKey ? createHmac('sha256', hmacKey).update(h).digest('hex') : '');

  let lineCount = 0;
  if (existsSync(file)) {
    try {
      lineCount = countLines(file);
    } catch { /* ignore */ }
  }

  // M6 哈希链：每行 `h = sha256(prevH + 行内容 sans h)` + HMAC `m = hmac(key, h)`；
  // 启动扫描当前文件 + .bak 验证链 + 定位链头。keyMismatch 与 tampered 分开（密钥更换 ≠ 篡改）。
  let prevH = 'genesis';
  let tampered = false;
  let legacyDetected = false;
  let chainResets = 0;
  let keyMismatch = false;

  /**
   * 验证单个文件哈希链。返回 { prev, tampered, keyMismatch, legacy, resets }。
   * 旧格式（无 h）行 → 链重置 + legacy + resets 计数。legacy 当前链会在显式
   * /escrow migrate 前只读，避免继续追加数据把链重置点误当作可信边界。
   */
  function verifyFile(path) {
    let prev = 'genesis';
    let bad = false;
    let keyBad = false;
    let legacy = false;
    let resets = 0;
    for (const raw of readFileSync(path, 'utf8').split('\n')) {
      const s = raw.trim();
      if (!s) continue;
      let rec;
      try {
        rec = JSON.parse(s);
      } catch { continue; }
      if (typeof rec.h !== 'string') {
        prev = 'genesis'; // 旧格式：链外历史，链重置
        legacy = true;
        resets += 1;
        continue;
      }
      const { h, m, ...rest } = rec;
      if (h !== sha256(prev + JSON.stringify(rest))) {
        bad = true;
      } else if (typeof m === 'string') {
        // h 链 OK 但 m 不匹配：密钥被更换或知情攻击者无密钥篡改（非普通篡改）。
        const em = hmacOf(h);
        if (em && m !== em) keyBad = true;
      }
      prev = h;
    }
    return { prev, tampered: bad, keyMismatch: keyBad, legacy, resets };
  }

  function scanChain() {
    try {
      if (existsSync(file)) {
        const f = verifyFile(file);
        prevH = f.prev; // 写用当前文件链头
        if (f.tampered) tampered = true;
        if (f.keyMismatch) keyMismatch = true;
        if (f.legacy) legacyDetected = true;
        chainResets += f.resets;
      }
      if (existsSync(bak)) {
        // .bak 只计入 tampered（防篡改 .bak 污染统计不告警）；legacy/keyMismatch/chainResets
        // 只对 live 当前链报告——否则 migrate 后 .bak 的 legacy 会让"当前链已迁移"误报未迁移。
        const b = verifyFile(bak);
        if (b.tampered) tampered = true;
      }
      if (tampered) process.stderr.write('[dsh-escrow] ledger 哈希链校验失败：账本可能被篡改或截断\n');
      if (keyMismatch) process.stderr.write('[dsh-escrow] ledger 哈希链完整但 HMAC 密钥不匹配（可能密钥被更换）；建议 /escrow migrate 重锚定\n');
      if (legacyDetected) process.stderr.write('[dsh-escrow] ledger 含链外历史（legacy）行，哈希链防篡改能力受限；建议 /escrow migrate 迁移到完整链\n');
    } catch (e) {
      process.stderr.write(`[dsh-escrow] ledger scanChain failed: ${e.message}\n`);
    }
  }
  scanChain();

  /** 超限轮转：ledger.jsonl → ledger.jsonl.bak（只保留一代）。 */
  function rotateIfNeeded(incomingBytes) {
    try {
      if (!existsSync(file)) return;
      if (statSync(file).size + incomingBytes <= maxBytes) return;
      rmSync(bak, { force: true });
      renameSync(file, bak);
      lineCount = 0;
      prevH = 'genesis'; // 新文件链头
      const human = maxBytes >= 1024 * 1024 ? `${Math.round(maxBytes / 1024 / 1024)}MB` : maxBytes >= 1024 ? `${Math.round(maxBytes / 1024)}KB` : `${maxBytes}B`;
      process.stderr.write(`[dsh-escrow] ledger rotated (> ${human}) → ${bak}\n`);
    } catch (e) {
      process.stderr.write(`[dsh-escrow] ledger rotate failed: ${e.message}\n`);
    }
  }

  return {
    get path() {
      return file;
    },
    get count() {
      return lineCount;
    },
    get integrity() {
      return { tampered, keyMismatch, keyError, legacyDetected, chainResets, keyed: !!hmacKey, chainHead: prevH };
    },
    get maxBytes() {
      return maxBytes;
    },
    /** 追加一行（M6+ 哈希链 + HMAC：h = sha256(prevH + 行内容 sans h)，m = hmac(key, h)）。返回是否成功。 */
    write(kind, payload = {}) {
      if (legacyDetected) {
        process.stderr.write('[dsh-escrow] ledger 含 legacy 行，迁移前只读；请先执行 /escrow migrate\n');
        return false;
      }
      const safePayload = payload && typeof payload === 'object' ? payload : {};
      const { h: payloadH, m: payloadM, ...payloadRest } = safePayload;
      const record = {
        t: new Date().toISOString(),
        kind,
        ...payloadRest,
        ...(payloadH !== undefined ? { payload_h: payloadH } : {}),
        ...(payloadM !== undefined ? { payload_m: payloadM } : {})
      };
      try {
        const recordJson = JSON.stringify(record);
        // 先轮转（可能重置 prevH），再基于新 prevH 计算链 h——顺序关键：h 必须反映轮转后的链头。
        rotateIfNeeded(Buffer.byteLength(recordJson) + 150); // +150 近似 h(64)+m(64)+字段名+换行（实际 ~141）
        const h = sha256(prevH + recordJson);
        const m = hmacOf(h);
        const line = JSON.stringify(m ? { ...record, h, m } : { ...record, h });
        appendFileSync(file, `${line}\n`, 'utf8');
        prevH = h;
        lineCount += 1;
        return true;
      } catch (e) {
        process.stderr.write(`[dsh-escrow] ledger append failed: ${e.message}\n`);
        return false;
      }
    },
    /**
     * M6+ migrate（R8-1 方案 B）：把当前账本（含 legacy 无 h 行）重写为完整链（每行带 h + m），
     * 原子替换（copyFile 备份 + 单次 rename），旧文件备份为 ledger.jsonl.premigrate。
     * 用当前密钥统一锚定（解决密钥更换后旧 m 不匹配）。
     *
     * 安全守卫（审查 HIGH）：migrate 会按当前内容重算 h+m——若账本已被篡改/密钥不匹配，执行会
     * 把篡改内容"重锚定"为干净链（抹除证据）。故：
     * - tampered → 拒绝（绝不重锚定篡改内容）；
     * - keyMismatch → 需 force=true 显式确认（仅当确认是密钥被更换时，重锚定才是正确解药）。
     * @param {boolean} force - 密钥不匹配时是否强制重锚定
     * @returns {{ migrated:number, skipped:number, error?:string }}
     */
    migrate(force = false) {
      if (!existsSync(file)) return { migrated: 0, skipped: 0 };
      // 防 TOCTOU：不用启动快照（scanChain 只在 createLedger 时跑一次），对当前文件重新校验——
      // 否则进程启动后、migrate 前被篡改并重算 h 的账本，会因快照 tampered=false 被重锚定洗白。
      let curTampered = false;
      let curKeyBad = false;
      if (existsSync(file)) {
        const cur = verifyFile(file);
        curTampered = cur.tampered;
        curKeyBad = cur.keyMismatch;
      }
      if (curTampered) return { migrated: 0, skipped: 0, error: '账本哈希链校验失败（可能被篡改）——migrate 会重算并抹除篡改证据，拒绝执行' };
      if ((curKeyBad || keyError) && !force) return { migrated: 0, skipped: 0, error: 'HMAC 密钥不可用（不匹配或读取失败）——migrate 会重新锚定/剥除 m；确认是密钥问题请用 /escrow migrate --force，怀疑被篡改请勿执行' };
      try {
        const out = [];
        let skipped = 0;
        let prev = 'genesis';
        for (const raw of readFileSync(file, 'utf8').split('\n')) {
          const s = raw.trim();
          if (!s) continue;
          let rec;
          try {
            rec = JSON.parse(s);
          } catch { skipped += 1; continue; }
          const { h, m, ...rest } = rec;
          const body = JSON.stringify(rest);
          const nh = sha256(prev + body);
          const nm = hmacOf(nh);
          out.push(nm ? { ...rest, h: nh, m: nm } : { ...rest, h: nh });
          prev = nh;
        }
        if (out.length === 0) return { migrated: 0, skipped };
        const tmp = `${file}.tmp-${process.pid}`;
        writeFileSync(tmp, out.map((x) => JSON.stringify(x)).join('\n') + '\n', 'utf8');
        // 原子替换：先复制备份（不动原文件），再单次 rename(tmp→file)；即使 rename 失败原文件仍在。
        // .premigrate 已存在则不覆盖（保留首次迁移前的原始 legacy 备份）。
        try {
          if (!existsSync(`${file}.premigrate`)) copyFileSync(file, `${file}.premigrate`);
        } catch { /* 备份失败不阻断主迁移 */ }
        renameSync(tmp, file);
        // 重扫确认迁移结果（仅 file；.bak 是历史归档，可能仍含 legacy）
        prevH = 'genesis'; tampered = false; keyMismatch = false; legacyDetected = false; chainResets = 0;
        scanChain();
        return { migrated: out.length, skipped };
      } catch (e) {
        process.stderr.write(`[dsh-escrow] ledger migrate failed: ${e.message}\n`);
        return { migrated: 0, skipped: 0, error: e.message };
      }
    },
    /** 追加一条工具观察记录（自动脱敏）。 */
    observe(exec, cls) {
      return this.write('observe', {
        tool: exec?.name,
        callId: exec?.callId ? String(exec.callId) : undefined,
        cls,
        args: redact(exec?.arguments)
      });
    },
    redact
  };
}
