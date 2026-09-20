# dsh-escrow 第三方独立复审报告（round 8：M6-lite 账本哈希链 + report）

- 审查者：独立第三方（无开发上下文；round-3/round-6 同一方，本轮聚焦 v0.3.10→v0.3.14 新增的 M6-lite）
- 日期：2026-08-30　对象：dsh-escrow **v0.3.14**（`D:\BigWorkspace\projects\dsh-escrow`）
- 方法：通读 ledger.mjs / report.mjs / commands.mjs / index.mjs 的 M6 改动 + reduce.mjs 的相依性 → 跑基线 → 8 组确定性探针
- 基线：`npm run test:all` **206 断言全绿**（smoke 96 + taste 43 + integration 67）✓
- 复现脚本：`third-party-review/probes/review-probe-r8.mjs`（本轮新增）
- 回归抽查：复跑 `probes/review-probe-r6.mjs`（round-6 旧探针，所有 [OK]/[闭环] 保留；本轮未触及 R6-1 修复路径）

---

## 一、M6-lite 修复闭环验证（findings-log 第八轮）

| 条目 | 验证结论 | 证据 |
|---|---|---|
| MEDIUM：`/escrow report` approved 双重计数（async 一次批准计 2 次：decided + approved_executed） | ✓ 闭环 | 探针 C-M6-1：async approve 后 `decidedApproved=1, repApproved=1, executed=1, repExecuted=1`，无双计 |
| MEDIUM：`.bak` 链外却被 report/reduce 读取——篡改 .bak 污染统计不告警 | ✓ 闭环 | 探针 C-M6-2：篡改 `.bak` 第二字节 + 改 h → `integrity.tampered=true` 启动告警 |
| MEDIUM：现有旧格式账本（无 h）向后兼容 | ✓ 闭环 | 探针 C-M6-3：手动 append 两行无 h → `legacyDetected=true, tampered=false`，不误报 |
| LOW：`String(exec.agent)` 塌缩 `[object Object]` | ✓ 闭环（代码复核） | `index.mjs:187` 提取 `agent.id/name`；ledger 全部 record 注入 session 字段 |
| LOW：payload 含 `h` 键误报 | 接受项（已知限制） | findings-log 第八轮明确"潜在脆弱，落账键名若用 h 需保留前缀" |

**结论：第八轮 5 条修复中 4 条闭环成立，1 条（payload.h 限制）按已知风险接受。**

---

## 二、round-8 新发现（独立审查抓到的，按风险排序）

### 🔴 HIGH R8-1：legacy 行作为链重置点绕过篡改检测

**现象**：在合法账本中间追加一行无 `h` 字段的数据，扫描链后 `integrity.chainHead` 从原链头（如 `efc2ad66...`）重置为 `genesis`，**`tampered=false, legacyDetected=true`**。这意味着：
- 该行之后的"合法写入"使用新链头（genesis）继续算 h → 单看后续行，链是合法的
- 攻击者可在重置点之后任意篡改内容（修改 args、tool、时间戳），重算链 → `tampered` 仍 false
- "重置点之前的合法链"也连带失效（chainHead 突变 → 后续审计无法回溯）

**触发路径**（探针 G1 实证）：
1. 正常 append 3 行（chainHead = efc2ad66）
2. 用 `appendFileSync` 直接追加一行无 h 数据（绕过 ledger.write）
3. 重新 `createLedger` → scanChain → chainHead = `genesis`，`tampered=false`

**威胁模型**：v0.3 README 承认"防无意篡改、不防知情攻击者"——但**legacy 重置让非知情攻击者也具备绕过能力**：
- 自动备份恢复脚本可能写出无 h 的中间行
- 第三方运维工具（如 logrotate、外部监控、归档同步）的 file rewrite 可能遗留无 h 行
- 磁盘错误/部分写入也可能产生无 h 残行

**建议修法**（按取舍排列）：
- **方案 A（最稳）**：`verifyFile` 检测到无 h 行 → 视为 `tampered=true`（而非 legacy 软告警）。语义：链一旦断裂，整个账本不再可信。优点：杜绝重置点；缺点：破坏向后兼容（旧账本启动即报错）
- **方案 B（向后兼容）**：`legacyDetected=true` 时禁止 append 新行（read-only mode），要求用户显式 `/escrow migrate` 重写账本。优点：保留历史；缺点：需要新命令
- **方案 C（最小变更）**：scanChain 报告 `legacyDetected=true` 时 stderr 升级为 error 级别，且 `integrity` 增 `chainResets: <count>` 字段，便于审计检测。优点：低风险；缺点：不阻断写入
- 折中：方案 C 立即落地 + 方案 B 在下个版本提供 migrate 命令

**验证**：修复后跑探针 G1，预期 `tampered=true`（方案 A）或 `chainResets>=1 + 写新行被拒`（方案 B）。

---

### 🟡 MEDIUM R8-2：readLedgerLines 把 .bak 全读入，跨代统计合并（含 seq 重置风险）

**现象**：`readLedgerLines(file)` 按 `[file, file.bak]` 顺序读取，跨代全合并。轮转后 main 是新链头（genesis）但保留旧 seq；.bak 是上一代全部历史。两代合并：
- reduce/report 的 `total`/`byKind` 是绝对计数 → 跨代合并 OK（历史就是历史）
- 但 `esc-<pid>-<seq>` 条目 id 在两代可能重复（seq 跨代从 0 重新计数）→ 同一 id 出现两次

**触发路径**（探针 G5 实证）：5 行 → 搬到 .bak → 新写 3 行 → `lines.length = 8 + 5 = 13`，存在同 id 重复（seq 重置到 0 附近）

**威胁**：report 的 `redList`/`tasteRec`/`selfMod` 用 id 去重（`.slice(-limit)`），跨代重复 id 可能让显示结果误导。

**建议**：
- `readLedgerLines` 接受 `{ includeBak }` 选项，report 默认 include，reduce 默认 exclude .bak（避免统计重复）
- 或每行带 `gen: <n>` 字段标记代数（需 ledger schema 升级）

**优先级**：MEDIUM（不影响安全，只影响统计准确度）。

---

### 🟡 MEDIUM R8-3：report / reduce 分母口径不一致

**现象**（探针 G4 实证）：同一份账本（3 observe + 2 denied + 1 approved + 1 blacklisted + 1 whitelisted）：
- `rep.approveRate = 0.25`（approved/(approved+denied) = 1/(1+3)）
- `reduce.interruptRate = 0.43`（denied/(total+denied) = 3/(4+3)）

**口径差异**：
- report 排除所有 EXEC_KINDS（observe/whitelisted/approved_executed），只算决策
- reduce 用 EXEC_KINDS 作分母

**结果**：模型读 `/escrow report --json` 的 `reduce.interruptRate` 和 README 解释的"打扰率"可能不一致——同一指标两份数字。

**建议**：
- README 显式说明"report 关注决策、reduce 关注执行"两个视角
- report JSON 里 `reduce.interruptRate` 改名为 `reduce.execInterruptRate`（更准确）

**优先级**：MEDIUM（文档级修正，不影响安全）。

---

### 🟢 LOW R8-4：report.avgWaitMs 与 roi.avgHumanWaitMs 字段冗余

**现象**（探针 G3 实证）：同一份账本 `rep.avgWaitMs=1500, rep.roi.avgHumanWaitMs=1500, rep.roi.confirmCount=1`——JSON 暴露两个数值相同的字段。

**建议**：删 `avgWaitMs` 顶层字段，统一走 `roi.avgHumanWaitMs`；或反之。

**优先级**：LOW（清理项）。

---

### ⚪ 已知接受：payload.h 字段被链 h 静默覆盖（findings-log 第八轮已记）

探针 G2 复现：`ledger.write('observe', { h: 'USER_OVERRIDE' })` → 落账时 `rec.h` 是链 h，用户 payload.h 消失。

**当前状态**：已知限制。建议改 `ledger.write(kind, payload)` 用解构排除 `{ h, ...rest } = payload`，明确语义。

**优先级**：LOW（一旦有 kind 需要 h 字段即升级为 MEDIUM）。

---

## 三、回归抽查

复跑 `probes/review-probe-r6.mjs`：所有 [OK]/[闭环] 全部保留，无回退。本轮未触及 R6-1（never-learn 共享口径）修复路径。

---

## 四、总结

- **M6-lite 修复质量**：5 条闭环 4 条成立，1 条（payload.h）按已知限制接受。approved 双计数、.bak 链验证、legacy 软告警、agent 提取四项修复扎实，sha256 链设计在"无 HMAC/外部锚"前提下是合理的。
- **能否进入下一里程碑**：**建议先拍 R8-1 处置策略再进**。v0.3 README 写"防无意篡改、不防知情攻击者"，但 legacy 重置让**非知情攻击者也具备绕过能力**——这与文档承诺不符。建议至少落地方案 C（升级告警 + 暴露 `chainResets` 计数），方案 B（migrate 命令）下个版本规划。
- **遗留风险**：
  - MEDIUM R8-2（readLedgerLines 跨代合并）——下个版本处理或文档显式说明
  - MEDIUM R8-3（口径不一致）——文档级修正，零代码
  - LOW R8-4（字段冗余）——清理项
  - MEDIUM R6-2（命令串自改混淆绕过，引号类已修，glob/变量已知上限）——见 round-6 报告

---

## 附录 A：M6-lite 设计回顾

| 模块 | 职责 | 安全边界 |
|---|---|---|
| `ledger.mjs` write | 每行带 `h = sha256(prevH + JSON.stringify(rest))` | 无密钥/外部锚——防无意篡改；不防知情攻击者 |
| `ledger.mjs` scanChain | 启动时验证 file + .bak；旧格式 → legacy | legacy 重置点=攻击向量（见 R8-1） |
| `report.mjs` computeReport | 统计/红灯清单/品味/自改/ROI | approved/executed 双计数已修；avgWaitMs/roi.avgHumanWaitMs 字段冗余 |
| `commands.mjs` report | text/md/json 三格式 + 署名尾注 | md 格式输出 integrityNote（链失败告警）；text 同样；JSON 含 integrity 字段 |
| `reduce.mjs` readLedgerLines | main + .bak 全读 | 跨代合并，seq 重置风险（见 R8-2） |

**v0.3.14 状态**：通过测试 206/206，闭环 4/5，可安全进入下个里程碑——**前提是先拍 R8-1 处置策略**。
