# dsh-escrow 第三方独立复审报告（round 6：M7 自改治理 + M8 减法审计）

- 审查者：独立第三方（无开发上下文；round-3 的同一方，本轮聚焦 v0.3.4→v0.3.9 新增的 M7/M8，并对 round-3 修复做回归抽查）
- 日期：2026-08-30　对象：dsh-escrow **v0.3.9**（`D:\BigWorkspace\projects\dsh-escrow`）
- 方法：通读 `lib/` 全 10 模块（含新增 `reduce.mjs`）→ 跑基线 → 17 组确定性探针复现
- 基线：`npm run test:all` **181 断言全绿**（smoke 89 + taste 36 + integration 56）✓
- 复现脚本：`third-party-review/probes/review-probe-r6.mjs`（本轮）+ `review-probe.mjs`（round-3 回归抽查，全部 OK）

---

## 一、M7/M8 修复闭环验证（findings-log 第四轮 / 第五轮）

| 条目 | 验证结论 | 证据 |
|---|---|---|
| 四轮 M7-1 HIGH：裸文件名命令串 `echo x > AGENTS.md` classify 红但 never-learn 不认 | ✓ 闭环 | `signature.mjs:104` 与 classify 共用 `findCommandSelfMod`；taste.test 93-104 覆盖 |
| 四轮 M7-1：重定向捕获组 off-by-one（漏双引号 m[1]） | ✓ 闭环 | 探针 C-M7-1：8 种变体（零空格/>>/1>/2>/&>/tee -a/tee --长选项/双引号）目标提取全部正确 |
| 四轮 M7-1：重定向变体绕过（tee -a、零空格、1>/2>/&>） | ✓ 闭环 | 同上，且每条 `neverLearnReason` 均命中 |
| 四轮 M7-1：selfmod 记账不完整（超时/abort/release 漏记） | **部分闭环** | 超时 ✓（C-M7-3）、人工/release ✓（onSettle 路径）、ttl=0 ✓（index.mjs:245）；**预中止信号漏记** → 见 R6-4 |
| 四轮 M7-1：快照不覆盖命令串自改 | ✓ 闭环 | 探针 C-M7-2：命令串重定向目标被写入 `selfmod.queued.snapshots`（path+sha256） |
| 四轮 M7-2 HIGH：非重定向写工具（cp / sed -i / mv）绕过自改治理 | ✓ 闭环（宽松检测生效） | smoke 408-417 + 本轮对照 `echo pwn > AGENTS.md` = red/selfmod；**但存在混淆绕过** → 见 R6-2 |
| 四轮 M7-2：tee 长选项绕过 | ✓ 闭环 | C-M7-1 `tee --ignore-interrupts -a AGENTS.md` → targets=[AGENTS.md] |
| 四轮 M7-2 接受项（引号内 `>` 误报 / 命令串相对路径快照失效） | 复认同 | 保守方向与 M4 前的指针语义，均可接受 |
| 五轮 M8-1 HIGH：whitelisted 落账无 args → signatureOf 重算 null | ✓ 闭环 | C-M8-1：10 条仅带 signature 的白名单行被正确统计为同一重复签名 ×10 |
| 五轮 M8-1：interruptRate 分母错误 | ✓ 闭环 | C-M8-2：`denied/(total+denied)`=0.333 ≤1 |
| 五轮 M8-1：轮转 .bak 不计入历史 | ✓ 闭环 | C-M8-2：.bak 中 5 条 denied 计入 |
| 五轮 M8-1：`--since=7` 等号形式失效 | ✓ 闭环 | C-M8-4：30 天前记录被 sinceMs 过滤（total 2→1） |
| 五轮 M8-1：黑名单自动拒绝不计入"拦下" | ✓ 闭环 | C-M8-3：`escrow.blacklisted` + `escrow.decided(denied)` = denied 2 |
| 五轮 M8-2：口径一致性 / settle 三路互斥 / reduce 不混入 selfmod | ✓ 闭环 | 代码复核：EXEC_KINDS 不含 selfmod.*；reduce 为只读（仅 `readFileSync`） |

**结论：第四轮/第五轮 13 条修复中 12 条闭环成立，1 条（selfmod 记账）在"预中止"分支仍有漏记（R6-4）。**

## 二、新发现缺陷（全部经探针确定性复现）

### HIGH R6-1　never-learn 名单与 v0.3.4 扩红口径脱节：新变红的破坏性命令可自动学习进白名单，两次批准后红灯失效

- 位置：[signature.mjs:74-89](../lib/signature.mjs)（`NEVER_LEARN_COMMAND_PATTERNS` 仍是扩红前的旧集）vs [classify.mjs:92-114](../lib/classify.mjs)（v0.3.4 已扩红）
- 问题：v0.3.4 拍板把 `rm -r`（无 -f）、`rm --recursive`、pwsh `rm -Recurse`、`git checkout -- <path>`、`git restore` 补为红灯（MEDIUM-2），但 never-learn 名单没同步——仍只认 `rm` 的 r+f 双旗标、`Remove-Item -Recurse`、`reset --hard`/`checkout --`（且不含 GIT_OPT）。结果是：这些动作进红名单托管，但人工批准 2 次后自动进入白名单，**从此免托管直接执行**；`git -C` 全局选项穿插还能让两个已覆盖的 git 命令绕出 never-learn。
- 探针证据（6/6 命中 `classify=red` + `neverLearn=可学习`）：
  - `rm -r ./src`、`rm --recursive ./src`、`pwsh: rm -Recurse ./src`、`git restore --worktree src/main.ts`、`git -C repo reset --hard`、`git -C repo checkout -- .`
  - 全链路复现：`rm -r ./src` 学习×2 → `check=allow` → `classify=red/builtin-command` → `hardRed=false`（品味可覆盖 builtin-command）→ **递归删除从此直接执行，不再托管**。
- 冲突点：项目自己的 P7/宪法第 3 条明确"破坏性签名永不自动学习"，`rm -r` 是递归删除，`git restore` 是丢弃工作区——二者都不该进入自动学习。
- 建议修法：把"是否不可学习"从独立正则集改为与红灯共享口径（例如 classify 返回破坏性分类标记，never-learn 直接复用；或 NEVER_LEARN 至少同步扩到 rm 递归旗标、pwsh `rm|rd -Recurse`、`git restore`、GIT_OPT 穿插的 reset/checkout），并加交叉测试：每条新红命令断言 `neverLearnReason(...) !== null`。
- 验证方法：探针 G1（6 样本 + 全链路），修复后全部应 `neverLearn=不可学习` 且全链路 `check` 不为 allow。

### MEDIUM R6-2　命令串自改检测的混淆绕过：引号拆除 / 部分引号 / glob / 变量——写 AGENTS.md 可完全绕过 M7

- 位置：[classify.mjs:177-209](../lib/classify.mjs)（`SELFMOD_TARGET_MARKERS` + `findCommandSelfMod` 只做子串匹配，未做任何 shell 归一化）
- 问题：宽松检测覆盖 `cp`/`sed -i` 等直接形态，但对 shell 层面等价的混淆形态完全失效；这些命令执行后同样写入 AGENTS.md，且 classify 为 yellow（放行+仅 observe），never-learn 也不命中。
- 探针证据（4/4 `classify=yellow/(default)`，`neverLearn=可学习`）：
  - `echo pwn > AGENTS''.md`（bash 拼接为 AGENTS.md）
  - `printf x > "AGENTS".md`
  - `echo x > AGENTS.m?`（glob 展开）
  - `F=AGENTS; echo x > $F.md`
- 严重度判断：需要 agent 主动混淆（非误触）；但 M7 是宪法级第 3 条，且混淆形态对模型毫无成本，故列 MEDIUM 而非 LOW。
- 建议修法：匹配前做轻量归一化（剔除 `'` `"` 后重新匹配，可消掉引号拆除/部分引号两类；glob `?`/`*` 与变量展开属残留，建议写进 findings-log 的已知限制 + 说明书，并在 M4 落地前以账本审计兜底）。
- 验证方法：探针 G2（4 样本），修复后前两类应变 red/selfmod；对照样本 `echo pwn > AGENTS.md` 已是 red/selfmod（不回归）。

### LOW R6-3　hardRed 判定用 ruleId 前缀启发式：用户规则 id 以 `builtin-` 开头即失去"用户 red 不容品味覆盖"保护

- 位置：[index.mjs:203-206](../lib/index.mjs)（`!cls.ruleId.startsWith('builtin-')`）
- 问题：v0.3.4 的 LOW-1 拍板是"用户显式 red > 品味白名单"，实现靠 ruleId 前缀区分来源；用户若把规则 id 写成 `builtin-xxx`（例如 `builtin-guard`），该 red 会被当成内置可学习红，品味白名单可直接放行。
- 探针证据：G3——`rules:[{id:'builtin-guard', pattern:'deploy', action:'red'}]` + 品味 allow → `入队=0`（用户 red 失效）。
- 建议修法：分类结果带显式来源字段（`cls.source: 'builtin'|'user'|'default'`），hardRed 按 source 判定，不再用 id 前缀。

### LOW R6-4　预中止信号的 async 自改条目漏记 selfmod.decided

- 位置：[queue.mjs:174-178](../lib/queue.mjs)（settle 先于 `entries.set`）→ [index.mjs:288-290](../lib/index.mjs)（onSettle 内 `queue.getEntry(entryId)` 取不到条目）
- 问题：callId 的 signal 在入队前已 abort 时，settle 同步发生，onSettle 里 `getEntry` 返回 undefined，`selfmod.decided` 不落账（`escrow.decided` 正常）。超时/人工/release/ttl=0 四路均正常。
- 探针证据：G4——`selfmod.queued=true, selfmod.decided=false, escrow.decided=true`。
- 建议修法：onSettle 取不到条目时回退（把 entry 引用通过闭包带进 onSettle，或在 settle 前先 `entries.set`）。

### LOW R6-5　`cooldownHours: 0` 配置被吞成 24

- 位置：[index.mjs:162](../lib/index.mjs)（`Math.max(0, Number(config.cooldownHours) || 24)`）
- 问题：`0 || 24` → 24，用户无法配置"无冷却期"；同理非数字也回落到 24（后者是设计）。
- 建议修法：`Number.isFinite(Number(v)) ? Math.max(0, Number(v)) : 24`。

## 三、回归抽查（round-3 修复项，复跑 `review-probe.mjs`）

| round-3 项 | 复验 |
|---|---|
| C1 approve all 双实例执行 + 学习一次 | ✓ 闭环 |
| C4 release+async 超时自动重放 | ✓ 闭环 |
| HIGH-1a 已拒绝的迟到调用被拦截 | ✓ OK（next=0） |
| HIGH-1b 批准重放后不双执行 | ✓ OK |
| HIGH-2 重放按审批时快照执行 | ✓ OK（replayed="git push origin main"） |
| MEDIUM-1 sync 去重一次批准只执行一次 | ✓ OK（next=1） |
| 0.3.4 分类扩红（rm -r / pwsh rm -Recurse / checkout -- / restore / filename / outputFile） | ✓ 全部 red |
| LOW-1 用户 red 不被品味覆盖 | ✓ OK（入队=1） |

## 四、总结

- **M7/M8 修复质量**：13 条闭环 12 条成立，仅"预中止"分支漏记一条（LOW）。M7 的宽松命令串检测与 M8 的统计口径修复是扎实的。
- **能否进入下一里程碑**：**建议先修 R6-1 再进**。它是本轮唯一 HIGH，且性质是"自己拍板的扩红被自己的品味机制架空"——不修的话，v0.3.4 那次扩红对递归删除/丢弃工作区的保护，在两次人工批准后即归零。修法成本低（口径共享 + 交叉测试）。
- **遗留风险**：R6-2 需要一次误报权衡拍板（shell 归一化后仍残留 glob/变量绕过，属确定性检测的固有上限）；R6-3/4/5 是三处小实现瑕疵，可随下个版本一并清理。

---

## 附录 A：R6-1 修复状态（v0.3.10，2026-08-30）

按本报告建议落地：`classify.mjs` 导出 `GIT_GLOBAL_OPT`，`signature.mjs` 的 `NEVER_LEARN_COMMAND_PATTERNS` 与 builtin 红灯按"绝对不可逆/不可恢复"口径对齐——`rm` 任意递归形态（去 `-f` 限定）、pwsh `rm -Recurse`、`git restore`、`git -C repo reset --hard`、`git -C repo checkout -- .` 均纳入 never-learn；`RE_DESTRUCTIVE_BASE` 同步加 `restore` 与 GIT_OPT 支持。

固化测试：
- `taste.test.mjs` +7 单元断言覆盖上述 5 形态 + `rm -rf` 回归 + `git checkout feature/x -f` 破坏性+force 组合
- `plugin.integration.test.mjs` +5 全链路断言：批准 ×2 后白名单**绝不出现**对应签名（实证探针的固化版）

验证：
- `npm run test:all`：**193/193 全绿**（89 + 43 + 61；+12）
- 复跑 `probes/review-probe-r6.mjs` G1 段 7 条：**全部 OK**（包括全链路"学习×2 → 白名单激活 → 品味放行"——修复后白名单不入、check=null、仍走 builtin-command 红灯）
- 复跑 `probes/review-probe.mjs`（round-3 旧探针）：所有 [OK]/[闭环] 全部保留，无回归
- R6-1 状态：✅ **已修（v0.3.10）**

详细变更与剩余项见 [findings-log.md 第七轮](findings-log.md#第七轮修复-r6-12026-08-30v0310)。
