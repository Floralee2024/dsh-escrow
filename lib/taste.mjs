/**
 * 品味存储（M2 核心，纯 Node，无 dsh 依赖，可单测）。
 *
 * 状态机（白名单条目）：
 *   learning（批准计数 < threshold）
 *     → cooling（达标，冷却期内不生效，防疲劳误批准即时固化）
 *     → active（冷却期满，check 时惰性晋升）
 *   pending-review（插件树 hash 变化 / 品味包导入 → 待人工复核，check 不命中）
 * 黑名单条目：learning（拒绝 < 2 次）→ active（直接 deny）。
 *
 * 硬规则：
 * - never-learn 签名不进入自动学习（手动 /escrow allow 可加入，标 source:'manual'）；
 * - 文件加载时 schema 校验，失败拒绝加载并告警（v0.2.2 保留自 M9 的自检项）；
 * - 写盘原子化（tmp + rename），账本之外的状态文件不允许半截写入。
 */

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import { neverLearnReason } from './signature.mjs';

const FILE_VERSION = 1;

function sha256(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function atomicWriteJson(file, obj) {
  const tmp = `${file}.tmp-${process.pid}`;
  writeFileSync(tmp, `${JSON.stringify(obj, null, 2)}\n`, 'utf8');
  renameSync(tmp, file);
}

/** 加载并 schema 校验名单文件。失败 → 告警 + 返回空名单（拒绝加载）。 */
function loadListFile(file, label) {
  if (!existsSync(file)) return [];
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(file, 'utf8'));
  } catch (e) {
    process.stderr.write(`[dsh-escrow] ${label} 解析失败，拒绝加载（${e.message}）: ${file}\n`);
    return [];
  }
  if (!parsed || parsed.version !== FILE_VERSION || !Array.isArray(parsed.entries)) {
    process.stderr.write(`[dsh-escrow] ${label} schema 校验失败（version/entries），拒绝加载: ${file}\n`);
    return [];
  }
  const valid = parsed.entries.filter((e) =>
    e && typeof e.signature === 'string' && typeof e.count === 'number' &&
    typeof e.lastAt === 'number' && typeof e.status === 'string'
  );
  if (valid.length !== parsed.entries.length) {
    process.stderr.write(`[dsh-escrow] ${label} 有 ${parsed.entries.length - valid.length} 条 schema 不符，已丢弃: ${file}\n`);
  }
  return valid;
}

export function createTasteStore({ dir, threshold = 2, cooldownHours = 24, now = () => Date.now(), pluginHash = '' } = {}) {
  if (!dir) throw new Error('createTasteStore: dir 必填');
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const allowFile = join(dir, 'allowlist.json');
  const denyFile = join(dir, 'denylist.json');

  let allowlist = loadListFile(allowFile, 'allowlist');
  let denylist = loadListFile(denyFile, 'denylist');

  const save = () => {
    try {
      atomicWriteJson(allowFile, { version: FILE_VERSION, entries: allowlist });
      atomicWriteJson(denyFile, { version: FILE_VERSION, entries: denylist });
      return true;
    } catch (e) {
      process.stderr.write(`[dsh-escrow] taste store 写盘失败: ${e.message}\n`);
      return false;
    }
  };

  const findAllow = (sig) => allowlist.find((e) => e.signature === sig);
  const findDeny = (sig) => denylist.find((e) => e.signature === sig);
  const forgetEntry = (sig) => {
    const before = allowlist.length + denylist.length;
    allowlist = allowlist.filter((e) => e.signature !== sig);
    denylist = denylist.filter((e) => e.signature !== sig);
    return before - (allowlist.length + denylist.length);
  };

  /** 惰性晋升：冷却期满的条目转 active。 */
  function promote(entry) {
    if (entry.status === 'cooling' && now() >= entry.cooldownUntil) {
      entry.status = 'active';
      save();
    }
    return entry.status;
  }

  return {
    /**
     * 记录一次人工决策。never-learn 签名直接跳过（除非调用方已自行判定并声明）。
     * @param {object} opts - { toolName, args, trustedEffects } 原始工具调用（never-learn 判定依据）
     * @returns {{learned:boolean, reason?:string, status?:string}}
     */
    recordDecision(signature, approved, { toolName = '', args = {}, trustedEffects = [], assumeLearnable = false, immediate = false } = {}) {
      if (!assumeLearnable) {
        const nl = neverLearnReason(toolName, args, { trustedEffects });
        if (nl) return { learned: false, reason: nl };
      }
      const list = approved ? allowlist : denylist;
      const find = approved ? findAllow : findDeny;
      let entry = find(signature);
      if (!entry) {
        entry = {
          signature, count: 0, lastAt: 0, source: 'learned',
          status: 'learning', cooldownUntil: 0, pluginHash
        };
        list.push(entry);
      }
      entry.count += 1;
      entry.lastAt = now();
      if (entry.status === 'learning' && entry.count >= threshold) {
        if (approved) {
          entry.status = immediate ? 'active' : 'cooling';
          entry.cooldownUntil = immediate ? 0 : now() + cooldownHours * 3600 * 1000;
        } else {
          entry.status = 'active'; // 黑名单无冷却期：拒绝即时生效
        }
      }
      save();
      return { learned: true, status: entry.status };
    },

    /**
     * 查询签名当前处置。
     * @returns {'allow'|'deny'|null} null = 不干预（走正常托管流程）
     */
    check(signature) {
      const deny = findDeny(signature);
      if (deny && deny.status === 'active') return 'deny';
      const allow = findAllow(signature);
      if (allow && promote(allow) === 'active') return 'allow';
      return null;
    },

    /** 返回白名单来源，供安全硬红区分自动学习与用户显式 /escrow allow。 */
    allowSource(signature) {
      return findAllow(signature)?.source || null;
    },

    /** 手动显式加入（/escrow allow|deny <sig>；never-learn 也只能走这条路，立即生效）。 */
    allow(signature) {
      let entry = findAllow(signature);
      if (!entry) {
        entry = { signature, count: 0, lastAt: 0, source: 'manual', status: 'active', cooldownUntil: 0, pluginHash };
        allowlist.push(entry);
      }
      entry.status = 'active';
      entry.source = 'manual';
      entry.lastAt = now();
      save();
      return entry;
    },
    deny(signature) {
      let entry = findDeny(signature);
      if (!entry) {
        entry = { signature, count: 0, lastAt: 0, source: 'manual', status: 'active', cooldownUntil: 0, pluginHash };
        denylist.push(entry);
      }
      entry.status = 'active';
      entry.source = 'manual';
      entry.lastAt = now();
      save();
      return entry;
    },
    forget(signature) {
      const removed = forgetEntry(signature);
      save();
      return removed;
    },

    /** 插件树 hash 变化 → 携带旧 hash 的条目转待复核（M2 失效机制）。 */
    applyPluginHash(hash) {
      let marked = 0;
      for (const entry of [...allowlist, ...denylist]) {
        if (entry.pluginHash && entry.pluginHash !== hash && entry.status === 'active') {
          entry.status = 'pending-review';
          marked += 1;
        }
      }
      if (marked > 0) save();
      return marked;
    },

    /** 待复核条目人工确认后恢复 active。 */
    confirmReview(signature) {
      const entry = findAllow(signature) || findDeny(signature);
      if (!entry || entry.status !== 'pending-review') return false;
      entry.status = 'active';
      entry.pluginHash = pluginHash;
      save();
      return true;
    },

    /**
     * 导出品味包（文件名 escrow-taste-pack.yaml，内容为 JSON——JSON 是合法 YAML 1.2，
     * 任何 YAML 解析器可读；校验和覆盖 payload 的规范串）。
     */
    exportPack() {
      const payload = {
        version: FILE_VERSION,
        createdAt: new Date(now()).toISOString(),
        allowlist,
        denylist
      };
      const body = JSON.stringify(payload);
      return JSON.stringify({
        meta: { format: 'escrow-taste-pack', version: FILE_VERSION, checksum: sha256(body) },
        payload
      }, null, 2);
    },

    /**
     * 导入品味包：校验和 / schema 不符 → 拒绝；通过 → 全部条目 pending-review。
     * @returns {{ok:boolean, imported?:number, error?:string}}
     */
    importPack(content) {
      let pack;
      try {
        pack = JSON.parse(content);
      } catch (e) {
        return { ok: false, error: `解析失败: ${e.message}` };
      }
      if (!pack?.meta || pack.meta.format !== 'escrow-taste-pack' || typeof pack.meta.checksum !== 'string' || !pack.payload) {
        return { ok: false, error: 'schema 不符（meta.format/checksum/payload）' };
      }
      if (sha256(JSON.stringify(pack.payload)) !== pack.meta.checksum) {
        return { ok: false, error: '校验和不符，拒绝加载' };
      }
      const { allowlist: al, denylist: dl } = pack.payload;
      if (!Array.isArray(al) || !Array.isArray(dl)) {
        return { ok: false, error: 'payload.allowlist/denylist 必须是数组' };
      };
      let imported = 0;
      for (const e of [...al, ...dl]) {
        if (!e || typeof e.signature !== 'string') continue;
        forgetEntry(e.signature);
        const target = dl.includes(e) ? denylist : allowlist;
        target.push({
          signature: e.signature, count: 0, lastAt: now(), source: 'imported',
          status: 'pending-review', cooldownUntil: 0, pluginHash: ''
        });
        imported += 1;
      }
      save();
      return { ok: true, imported };
    },

    /** 快照（供 /escrow allowlist 与报告）。 */
    snapshot() {
      return {
        allowlist: allowlist.map((e) => ({ ...e })),
        denylist: denylist.map((e) => ({ ...e }))
      };
    },

    /** 测试/运维用：直接读取磁盘文件路径。 */
    get files() {
      return { allowFile, denyFile };
    }
  };
}
