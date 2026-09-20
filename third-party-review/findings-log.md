## Current artifact status (v0.3.21)

Historical round sections below refer to the version named in each heading. For the current artifact:

- R6-1 was fixed earlier and remains regression-tested.
- R6-2 now normalizes the tested quote, glob, and simple assignment forms; full shell expansion remains out of scope.
- R6-4 is fixed: entries are registered before synchronous settlement, with a pre-abort regression.
- R8-1 is fixed by read-only legacy mode; /escrow migrate is required before append.
- R8-2 remains an accepted reporting limitation: main/.bak history can have cross-generation IDs.
- R8-3 is an intentional metric-view distinction documented in the README.
- R8-4 is closed; the report exposes the ROI average only.
- User payload h/m values are preserved as payload_h/payload_m.
- Current local regression baseline: smoke 107, taste 43, integration 75 (225 total).

# 历轮审查记录（dsh-escrow M1+M2+M7+M8）

> 供第三方审查者核对：这些是历轮内部 code-reviewer 已发现并处理的。请**验证修复是否闭环**、是否有遗漏，并聚焦新角度。

## 当前基线

- 测试：218 断言全绿（smoke 104 + taste 43 + integration 71）——`npm run test:all`
- 端到端（真实 headless dsh + 模型）：M1 红灯托管→轮询→超时落账 ✓；M2 白名单放行（git push 直接执行 + `escrow.whitelisted` 落账）✓；M7 写 AGENTS.md fail-closed 拦截 ✓
- M8 真实账本冒烟：22 执行 / 5 拦下 / SNR 0.41，重复签名 `escrow_result(id)` ×13
- M6-lite：哈希链 `h=sha256(prevH+JSON.stringify(rest))`；启动 scanChain 验证 file+.bak；旧格式行 legacyDetected 软告警
- 版本：0.3.14，已装 escrowtest profile

## 第一轮（内部 code-reviewer）

| 级别 | 问题 | 修复 | 状态 |
|---|---|---|---|
| HIGH | execute 层重算签名作放行闸门（pre/execute 两钩子参数一致性脆弱，漏匹配则红灯放行） | execute 层改用 **callId 身份匹配**为主 + 签名 hash 兜底（[queue.mjs](file:///D:/BigWorkspace/projects/dsh-escrow/lib/queue.mjs) `findPendingByCallId`） | 已修 |
| MEDIUM | entries 无上限保留 settled 条目 → 内存泄漏 | settle 时剪裁最旧 settled（上限 1000） | 已修 |
| MEDIUM | onSettle 闭包引用外部解构 id，enqueue 同步 settle 时 TDZ → 漏账 | onSettle 改为参数传 id | 已修 |
| MEDIUM | 重放令牌残留/无 tools 环境卡 approved | finishReplay 双清（replaying+exemptions）；无 ctx.tools 标记失败 | 已修 |

## 第二轮（内部 code-reviewer，验证第一轮修复 + 新角度）

| 级别 | 问题 | 修复 | 状态 |
|---|---|---|---|
| HIGH | **第一轮 approve all 修复是文案掩盖**：M1 去重用严格 hash，队内同品味签名的条目必是不同参数；只执行首个实例 → 其余副作用丢失 | 改为**逐条 replayEntry 真实执行**，学习按组一次（"去重批"= 决策去重，非执行去重） | 已修 |
| HIGH | `git reset --hard` 是 builtin-command 红但 never-learn 的 force 判定只认 `--force/-f` 漏 `--hard` → 可自动学习绕过 escrow | never-learn 补 `git reset --hard` / `git checkout --`（[signature.mjs](file:///D:/BigWorkspace/projects/dsh-escrow/lib/signature.mjs)） | 已修 |
| MEDIUM | 键名-only 白名单可绕过：路径在非常规键（`file_uri`）时敏感路径漏检 → 品味 allow 放行 | 扩展敏感路径键集合（[classify.mjs](file:///D:/BigWorkspace/projects/dsh-escrow/lib/classify.mjs) `collectPathCandidates` KEYS） | 已修 |
| LOW | computePluginHash 含运行时 config → hash 漂移 → 白名单反复失效 | 只取稳定 id/name + sort | 已修 |
| LOW | **release 策略 + async 超时放行但不执行**（escrow_result 永远"执行中"） | 提取共享 [replay.mjs](file:///D:/BigWorkspace/projects/dsh-escrow/lib/replay.mjs)；async 的 onSettle 在 `approved && via==='timeout'` 时触发重放 | 已修 |

## 接受/已知限制（本轮决定不改）

- computePluginHash 失效机制只随插件 id/name 增删触发（config/rules 变化不触发）——设计如此，fail-open 可接受。
- `deny <id>` vs `deny <sig>` 格式区分（条目 id 形如 `esc-\d+-\d+`）：恰好形如 esc-xx 的签名单词无法黑名单化，概率极低，接受。
- 非 shell 工具签名只含参数键名（设计 P7 明确）——已用"内置敏感路径不容品味覆盖"兜底，但语义上同一工具的不同路径调用在品味层视为同签名（这是品味粒度，不是 bug）。

## 请重点验证的修复闭环

1. approve all 逐条执行：队内 2 个同品味签名不同参数条目，approve all 后**两个都真实执行**（mock 里 `ctx._tools.executed` 应有 2 条重放），学习仅一次。
2. 品味 allow 对 `fs.write` 写 `.env`（builtin-sensitive-path）→ 仍托管（不放行）。
3. `git reset --hard HEAD~2` → never-learn（不自动学习）；`git checkout -- .` → never-learn。
4. release + async：超时 settle approved 后触发重放（条目不卡"执行中"）。
5. execute 层 callId 匹配为主、签名 hash 兜底——去重调用（callId 不同）仍被拦为"已在审批队列"。
6. M7：写 AGENTS.md 各形态——文件写工具、命令串重定向（`echo x > AGENTS.md`/`tee`）、非重定向写（`cp x AGENTS.md`/`sed -i`/`python -c`）→ 恒 red 托管且永不进品味习得（classify 与 never-learn 共用 `findCommandSelfMod`，口径一致）。
7. M7：selfmod 条目超时/abort/release 三路都有 selfmod 落账，且携带 before 快照 hash（不可读路径容错不抛）。
8. M8：`/escrow reduce` 白名单放行行（`escrow.whitelisted`）用落账的 `rec.signature` 统计（signatureOf 不为 null）；轮转 `.bak` 合并计入历史；interruptRate ≤ 100%；`escrow.blacklisted` 计入"拦下"。

## 实证记录（真实 dsh 环境）

- M1（escrowtest profile，ttl=8）：`git push origin main` → 入队 esc-45588-1 → 模型不重试、轮询 escrow_result → 8s 超时 → 账本 `escrow.decided via=timeout waitedMs=8003` → 模型如实汇报"超时被拒绝"。
- M2（注入白名单 `git push origin <BRANCH>`）：`git push origin main` **直接放行执行**（模型汇报真实 git 报错输出），账本 `escrow.whitelisted` 落账。

## 第三轮（外部第三方独立审查，2026-08-29，报告：review-report-r3-2026-08-29.md）

| 级别 | 问题 | 修复 | 状态 |
|---|---|---|---|
| HIGH-1 | execute 闸门只查"当前 pending"：settle（超时拒绝/批准）后索引即删，迟到的原始调用落到 next() 裸执行——cancel 变体 fail-open 到执行、release 变体双执行 | settle 不删身份而是搬到 `handledByCallId` 终态索引（[queue.mjs](file:///D:/BigWorkspace/projects/dsh-escrow/lib/queue.mjs)，pruneSettled 同步清理）；execute 层命中已处置身份一律返回合成结果，仅 sync 批准路径放行（[index.mjs](file:///D:/BigWorkspace/projects/dsh-escrow/lib/index.mjs)） | 已修（v0.3.3） |
| HIGH-2 | `argsSnapshot` 存活引用：下游钩子入队后原地改写 arguments → 人工批准 A、重放执行 B，且重放凭令牌豁免分类 | 入队时 `cloneArgs` 深拷贝（structuredClone→JSON→浅拷贝容错），summary/学习/重放统一用拷贝 | 已修（v0.3.3） |
| MEDIUM-1 | sync 模式同签名并发去重：一次批准两个调用都落 next() 双执行，且同 id 双写 queued/decided | sync 分支识别 dedup：去重调用不重复记账，approved 后返回 deny「不重复执行」而不落 next() | 已修（v0.3.3） |
| MEDIUM-2 | 内置命令覆盖缺口：`rm -r`/`rm --recursive`（无 -f）、pwsh `rm -Recurse`（无 -Force）、`git checkout -- <path>`、`git restore` 漏为 yellow | 拍板：补红（递归删除/丢弃工作区是高副作用操作，该进托管）；翻转 `rm -r ./dir-with-f` 测试预期（该命令实为递归删除，正确拦截；真"不误报"改为 `rm ./foo-f`）；`git checkout --help` 仍不误报（`--` 后须空白/结束） | 已修（v0.3.4） |
| MEDIUM-3 | 敏感路径键名缺口：`filename`/`outputFile`/`destFile` 等不在 KEYS → 写 .env 仅 yellow | 拍板：补 KEYS（filename/outputFile/destFile/inputFile/pathname 等常见变体），**不做 basename 兜底**（会误伤 content/description 等非路径字段） | 已修（v0.3.4） |
| LOW-1 | 用户显式 red 规则被品味白名单覆盖（taste allow 直接放行用户 red） | 拍板：**用户显式 red > 品味白名单**（显式配置可审计、高于隐式习得；冲突时保守拒绝）；default red 仍可被品味覆盖（品味是更强信号） | 已修（v0.3.4） |
| LOW-2 | 账本脱敏漏空格分隔（`--token x`）与 URL 内嵌凭据（`://u:p@h`） | 补两类正则：flag 值（`--token abc`/`--api-key sk-*`）与 URL 内嵌凭据（保留 scheme 与 `@`，打码 user:pass） | 已修（v0.3.4） |
| LOW-3 | 测试缺口：approve all 执行数、release+async 重放无断言 | 已固化：integration 新增 6 条 round-3 断言（C1/C4/HIGH-1a/HIGH-1b/HIGH-2/MEDIUM-1），integration 40→46 | 已修（v0.3.3） |

第三轮验证方式：报告附探针 `probes/review-probe.mjs`（每条缺陷确定性复现）；修复后复跑，HIGH-1/HIGH-2/MEDIUM-1 对应探针全部翻转为 OK，`npm run test:all` 147 全绿（含 round-3 6 条 + 本轮拍板修复新增用例）。

## 第四轮（内部 code-reviewer，M7 自改治理，两轮）

**第一轮 M7**：
| 级别 | 问题 | 修复 | 状态 |
|---|---|---|---|
| HIGH | 宪法第 3 条缺口：裸文件名命令串（`echo x > AGENTS.md`）classify 标红但 never-learn 不认 → 批准后进白名单 | 命令串自改检测提取为共享 `findCommandSelfMod`（classify 导出），classifyExec + neverLearnReason 共用 | 已修（v0.3.6） |
| MEDIUM | 重定向捕获组 off-by-one（漏双引号 m[1]） | 修正 `m[1]??m[2]??m[3]` | 已修 |
| MEDIUM | 重定向变体绕过（`tee -a`、零空格 `>f`、`1>/2>/&>`） | REDIRECT_RE 增强 | 已修 |
| MEDIUM | selfmod 记账不完整（超时/abort/release 漏记） | settle 统一落账（async onSettle / sync / ttl=0），entry 加 selfmod 标记 | 已修 |
| MEDIUM | 快照不覆盖命令串自改 | computeSnapshotHashes 补 extractRedirectTargets | 已修 |

**第二轮 M7**：
| HIGH | 非重定向写工具绕过自改治理（`cp`/`sed -i`/`python` 写 AGENTS.md） | 命令串检测放宽为"含自改字样即红"（保守托管；`git commit -m "提及"` 也托管，可接受） | 已修（v0.3.9） |
| MEDIUM | tee 长选项（`--ignore-interrupts`）绕过 | REDIRECT_RE flag 组增强 | 已修 |
| LOW | 引号内 `>` 误报 | 接受（宽松红已覆盖，保守方向） | 接受 |
| LOW | 命令串自改快照路径失效（相对/`$VAR` 无法读） | 接受（M4 前仅指针） | 接受 |

## 第五轮（内部 code-reviewer，M8 减法审计，两轮）

**第一轮 M8**：
| 级别 | 问题 | 修复 | 状态 |
|---|---|---|---|
| HIGH | 白名单重复漏统计（`escrow.whitelisted` 落账无 args → signatureOf 重算 null） | signatureOf 优先用落账的 `rec.signature` | 已修（v0.3.8） |
| MEDIUM | interruptRate 分母错误可超 100% | `denied/(total+denied)` | 已修 |
| MEDIUM | 轮转 .bak 不计入历史 | readLedgerLines 合并读 .bak | 已修 |
| LOW | `--since=7` 等号形式失效 | 正则 `--since[=\s]+` | 已修 |
| LOW | 黑名单自动拒绝不计入"拦下" | `escrow.blacklisted` 计入 denied | 已修 |

**第二轮 M8**：确认第一轮修复闭环成立（signatureOf 口径一致、settle 三路互斥无重复、reduce 不混入 selfmod 行），无新增缺陷。

## 第六轮（外部第三方复审 M7/M8，2026-08-30，报告：review-report-r6-2026-08-30.md）

复核第四轮/第五轮 13 条修复：**12 条闭环成立**，1 条（selfmod 记账）在"预中止信号"分支仍有漏记。

| 级别 | 问题 | 修复建议 | 状态 |
|---|---|---|---|
| HIGH R6-1 | never-learn 名单与 v0.3.4 扩红口径脱节：`rm -r`（无 -f）、`rm --recursive`、pwsh `rm -Recurse`、`git restore`、`git -C repo reset --hard`、`git -C repo checkout --` 均为红灯但**可自动学习** → 批准 ×2 后进白名单，递归删除/丢弃工作区从此免托管 | never-learn 与红灯共享口径（NEVER_LEARN 同步扩 + 支持 GIT_OPT），并加交叉测试：每条新红命令断言 neverLearn !== null | 待修 |
| MEDIUM R6-2 | 命令串自改的混淆绕过：`echo x > AGENTS''.md`、`printf x > "AGENTS".md`、`echo x > AGENTS.m?`、`F=AGENTS; echo x > $F.md` → 全部 yellow 放行，写 AGENTS.md 不经托管 | 匹配前轻量归一化（去引号/拼接）消掉引号类；glob/变量残留列为已知限制并写进说明书 | 待拍板（误报权衡） |
| LOW R6-3 | hardRed 按 ruleId 前缀启发式判定：用户规则 id 以 `builtin-` 开头时失去"用户 red 不容品味覆盖"保护 | classify 结果带显式 source 字段（builtin/user/default），按 source 判定 | 待修 |
| LOW R6-4 | 预中止信号（入队前已 abort）的 async 自改条目漏记 `selfmod.decided`（settle 先于 entries.set，onSettle 内 getEntry 为空）；超时/人工/release/ttl=0 四路正常 | onSettle 取不到条目时回退（闭包带 entry 引用，或 settle 前先 entries.set） | 待修 |
| LOW R6-5 | `cooldownHours: 0` 被 `Number(v) \|\| 24` 吞成 24，无法配置无冷却期 | `Number.isFinite(Number(v)) ? Math.max(0, Number(v)) : 24` | 待修 |

第六轮验证方式：`probes/review-probe-r6.mjs`（17 组：M7/M8 闭环 15 + 新发现复现）。回归抽查：复跑 `probes/review-probe.mjs`（round-3 全部项 OK），`npm run test:all` 181 全绿。

## 第七轮（修复 R6-1，2026-08-30，v0.3.10）

按 sixth round HIGH-1 修复建议落地：never-learn 与 builtin 红灯按"绝对不可逆/不可恢复"口径对齐。GIT_OPT 从 `classify.mjs` 导出（`GIT_GLOBAL_OPT`），让 signature.mjs 复用同一份"git 全局选项穿插"正则。

变更：

| 文件 | 改动 |
|---|---|
| `lib/classify.mjs` | 导出 `GIT_GLOBAL_OPT`（复用内部 `GIT_OPT`） |
| `lib/signature.mjs` | `NEVER_LEARN_COMMAND_PATTERNS` 扩 5 条（与 builtin 红灯对齐）：`rm` 任意递归形态（去 `-f` 限定）、pwsh `rm -Recurse`、`git restore`、`git -C repo reset --hard`、`git -C repo checkout -- .`；`RE_DESTRUCTIVE_BASE` 同步加 `restore` + GIT_OPT |
| `test/taste.test.mjs` | +7 单元断言覆盖上述 5 形态 + `rm -rf` 回归 + `git checkout feature/x -f` 破坏性+force 组合 |
| `test/plugin.integration.test.mjs` | +5 全链路断言：批准 ×2 后白名单**绝不出现**对应签名（round-6 R6-1 实证探针的固化版） |

验证：
- `npm run test:all`：**193/193 全绿**（89 + 43 + 61；+12）
- 复跑 `probes/review-probe-r6.mjs` G1 段 7 条：**全部 OK**（包括全链路"学习×2 → 白名单激活 → 品味放行"——修复后白名单不入、check=null、仍走红灯）

## 第七轮补充（R6-2 MEDIUM + 3 LOW 修复，2026-08-30，v0.3.11）

| 项 | 处置 | 状态 |
|---|---|---|
| R6-2 MEDIUM：命令串自改引号拼接绕过（`AGENTS''.md` / `"AGENTS".md`） | `findCommandSelfMod` 先去引号再测自改字样；glob 通配（`AGENTS.m?`）/ 变量（`$F.md`）属确定性检测固有上限，接受 | 已修（v0.3.11） |
| LOW：`cooldownHours: 0` 被 `0 \|\| 24` 吞成 24（无冷却期配置失效） | 改 `Number.isFinite` 判断，0 是合法值 | 已修 |
| LOW：hardRed 用 ruleId 前缀判定，用户规则 id 伪装 `builtin-*` 即失效（品味放行用户 red） | classifyExec 返回加 `source`（user/builtin/default），hardRed 改用 `cls.source === 'user'` 判用户 red | 已修 |
| LOW：预中止信号自改漏 `selfmod.decided` | 接受（边缘：async onSettle + sync 分支已覆盖决策落账，未复现遗漏） | 接受 |

验证：`npm run test:all` **196/196 全绿**（91 + 43 + 62；+3：smoke 引号类 ×2 + integration hardRed 变体 ×1）。

## 第八轮（内部 code-reviewer，M6-lite 账本哈希链 + report，2026-08-30，v0.3.13）

| 级别 | 问题 | 处置 | 状态 |
|---|---|---|---|
| MEDIUM | report `approved` 双重计数（decided(approved) + approved_executed 各 +1，async 一次批准计 2 次） | report 口径：`approved`=批准决策数（decided approved），`approved_executed` 单列 `executed`；async/sync 一致 | 已修（v0.3.13） |
| MEDIUM | 无密钥哈希链不防知情攻击者重算整链；删尾部行留合法前缀也检测不到 | README 明示威胁模型（防无意/未察觉篡改；v0.3 锚定外部/HMAC 前不防知情攻击） | 文档（接受） |
| MEDIUM | `.bak` 链外却被 report/reduce 读取——篡改 .bak 污染统计不告警 | scanChain 同时验证 .bak，integrity.tampered 覆盖 | 已修 |
| LOW | payload 含 `h` 键会误报篡改（当前 14 处 payload 均无 h） | 接受（潜在脆弱，落账键名若用 h 需保留前缀） | 接受 |
| LOW | `String(exec.agent)` 对对象塌缩为 `[object Object]` | session 提取：字符串直接用，否则 `agent.id/name` | 已修 |

验证：`npm run test:all` **206/206 全绿**（96 + 43 + 67）。真实账本冒烟：现有旧格式账本加载 → `integrity.legacyDetected=true`（链外历史，向后兼容）、tampered=false。

## 第九轮（外部第三方审查 M6-lite，2026-08-30，报告：review-report-r9-2026-08-30.md）

复核第八轮 5 条修复：4 条闭环（approved 双计 / .bak 链 / legacy 软告警 / agent session）；`payload.h` 限制已知接受。

| 级别 | 问题 | 处置 | 状态 |
|---|---|---|---|
| HIGH R8-1 | legacy 行作链重置点绕过篡改检测（插一行无 h → chainResets、之后篡改重算链检测失效；非知情来源：自动备份/第三方工具/磁盘错误） | 方案 C：`integrity.chainResets` 计数 + legacy 启动告警升级（"防篡改能力受限，建议 v0.3 /escrow migrate"）；方案 B（migrate 命令）v0.3 | 已修（v0.3.15） |
| MEDIUM R8-2 | readLedgerLines main+.bak 跨代合并 + esc seq 重置 id 重复 → 清单显示误导 | `readLedgerLines` 给 .bak 行加 `_src:'bak'`，report 清单附来源 | 已修 |
| MEDIUM R8-3 | approveRate（决策视角 approved/(approved+denied)）与 interruptRate（执行视角 denied/(total+denied)）分母不同 | 接受（概念差异非矛盾），README 口径说明 | 文档 |
| LOW R8-4 | report `avgWaitMs` 与 `roi.avgHumanWaitMs` 冗余 | 删顶层 avgWaitMs，统一用 roi | 已修 |

验证：`npm run test:all` **208/208 全绿**（98 + 43 + 67；+2：chainResets / _src 防回归）。

## 第十轮（内部 code-reviewer，HMAC 锚定 + /escrow migrate，2026-08-30，v0.3.17）

| 级别 | 问题 | 处置 | 状态 |
|---|---|---|---|
| HIGH | migrate 无完整性前置守卫，可"洗白"已检测的篡改（tampered/keyMismatch 时重算链会抹除证据） | migrate 守卫：tampered 拒绝（绝不重锚定篡改内容）；keyMismatch 需 `--force` 显式确认（仅密钥更换场景） | 已修（v0.3.17） |
| MEDIUM | 密钥文件空/读取失败 → 静默降级（keyMismatch 失效、新写无 m） | `keyError` 状态 + stderr 告警，不静默 | 已修 |
| MEDIUM | migrate 后 .bak 仍含 legacy → 归零误报 | 命令说明 .bak 为历史归档，不影响当前链 | 已修 |
| MEDIUM | 两步 rename 非原子（rename 失败则 ledger 缺失）+ 二次 migrate 覆盖备份 | copyFile 备份 + 单次 rename(tmp→file) 原子替换 | 已修 |
| MEDIUM | migrate 静默丢弃坏行（数据丢失） | `skipped` 计数 + 命令提示，不静默 | 已修 |
| LOW | 密钥文件权限未收紧（默认 umask 可能 644） | `writeFileSync(..., { mode: 0o600 })` 纵深防御 | 已修 |

验证：`npm run test:all` **218/218 全绿**（104 + 43 + 71；+2：migrate 守卫 tampered/keyMismatch 防回归）。HMAC 写读一致性、rest=sans h/m 键序、keyMismatch 区分逻辑经确认正确。
- 复跑 `probes/review-probe.mjs`（round-3 旧探针）：所有 [OK]/[闭环] 全部保留，无回归
- R6-1 状态：✅ 已修（v0.3.10）

遗留（按风险递增）：
- MEDIUM R6-2（命令串自改混淆绕过）：4 条引号/glob/变量形态仍 yellow 放行——本轮未修，需你拍板误报权衡
- LOW R6-3（hardRed 启发式判定）/ R6-4（预中止信号 selfmod 漏记）/ R6-5（cooldownHours 0 被吞）——非阻塞，建议下里程碑一并处理

## 第九轮（外部第三方复审 M6-lite，2026-08-30，报告：review-report-r8-2026-08-30.md）

复核第八轮 5 条修复：**4 条闭环成立**（approved 双计数 / .bak 链验证 / legacy 软告警 / agent 提取），1 条 payload.h 限制按已知风险接受。

| 级别 | 问题 | 修复建议 | 状态 |
|---|---|---|---|
| HIGH R8-1 | legacy 行作链重置点绕过篡改检测：合法账本中插一行无 h 数据 → `chainHead` 重置为 `genesis`、`tampered=false` → 之后篡改重算链 → 检测失效。v0.3 README 写"防无意篡改、不防知情攻击者"，但 legacy 重置让**非知情攻击者**（自动备份、第三方工具、磁盘错误）也能绕过 | 方案 A（最稳）：legacyDetected 时视为 tampered（破坏向后兼容）/ 方案 B（兼容）：legacyDetected 时 read-only + /escrow migrate 重写（需新命令）/ 方案 C（最小）：升级告警级别 + 暴露 `chainResets` 计数 | 待拍板 |
| MEDIUM R8-2 | `readLedgerLines` main+.bak 全读合并，跨代 id（esc-<pid>-<seq>）seq 重置可能重复 → report 的 redList/tasteRec 显示误导 | reduce 默认 exclude .bak（report 仍 include 全历史）；或 ledger schema 升级带 `gen` 字段 | 待修 |
| MEDIUM R8-3 | report.approveRate 分母 = approved+denied；reduce.interruptRate 分母 = total(EXEC_KINDS)+denied → 同一账本两份数字（探针实证：approveRate=0.25 vs interruptRate=0.43） | 文档显式说明"report 关注决策 / reduce 关注执行"两视角；reduce.interruptRate 改 execInterruptRate | 待修（文档级） |
| LOW R8-4 | report.avgWaitMs 与 roi.avgHumanWaitMs 字段冗余（数值一致，JSON 双字段） | 删 avgWaitMs 顶层字段，统一走 roi.avgHumanWaitMs | 待修 |
| ⚪ 已知 | payload.h 字段被链 h 静默覆盖（无 h 除外，user payload.h 消失） | 第八轮已接受；ledger.write 用 `{ h, ...rest } = payload` 解构明确语义 | 接受 |

第九轮验证方式：`probes/review-probe-r8.mjs`（8 组：M6 闭环 3 + 新发现 5）。回归抽查：复跑 `probes/review-probe-r6.mjs`（round-6 全部项 OK），`npm run test:all` 206 全绿。

**关键决定项**：R8-1 legacy 重置点——方案 A/B/C 取舍（建议 C 立即 + B 下个版本）。
