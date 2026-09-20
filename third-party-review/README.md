# dsh-escrow 第三方独立审查包

> 给**没有本项目开发上下文**的独立审查者（另一个 AI、人类安全工程师、或独立 code review 工具）。
> 你的任务是独立审查 dsh-escrow 插件（M1+M2+M7+M8）的设计与实现，找出实现者与历轮内部审查都没发现的问题——尤其是安全/正确性缺陷。
> 配套文件：`reviewer-prompt.md`（可整段粘贴给 AI 审查者的自包含 prompt）、`findings-log.md`（历轮发现与修复记录，供核对）。

## 项目是什么（30 秒）

dsh-escrow 是 DeepSeek Harness (dsh) 的安全审批插件：把 agent 的**不可逆动作**（`rm -rf`、`git push`、写 `.env` 等）放进托管队列，**人工批准才执行，超时默认拒绝**（silence means no）。定位是"生效前可取消"，不是"出事后再回滚"。MIT，单人认证者项目。

## 安全心理模型（审查时带着这个）

- 拦截决策必须是**确定性的**（正则规则，绝不用 AI 分类器做安全决策）。
- **任何路径都不该让"已判 red"的动作被静默放行**（fail-open 到托管/拒绝，绝不 fail-open 到执行）。
- **任何 wrapper 都不该抛异常**（会终结 agent 当前 turn）。
- **超时 = 拒绝**；`release`（超时放行）是唯一例外且需显式配置。
- 令牌/豁免必须**单次有效**，绝不进 arguments（模型可见）。
- 品味习得：**仅人工决策塑造品味**（超时/取消不算负面学习）；破坏性签名**永不自动学习**。

## 架构（M1 非阻塞托管 + M2 品味习得 + M7 自改治理 + M8 减法审计）

```
模型调用工具 → tools/pre-execute（escrow 分类）
  ├─ 豁免检查（重放令牌）→ allow
  ├─ 品味 check（M2）：白名单签名 → 放行（但内置敏感路径/涉敏命令串的 red 不容覆盖）
  │                     黑名单签名 → 拒绝
  ├─ 分类：green/yellow → 放行；red → 入队托管（async 不等待）→ 放行到 execute 层
tools/execute（escrow 拦截）
  ├─ 重放令牌（replaying）→ next() 真实执行
  ├─ pending 签名 → 返回合成结果「已进入人工审批 esc-x，请用 escrow_result 查询」
  └─ 否则 next()
模型轮询 escrow_result(id) → pending/executed+结果/denied/expired
人工 /escrow approve esc-x → decide + 令牌重放（ctx.tools.execute 走完整流水线）→ 结果存条目
人工 /escrow deny esc-x → decide + 学习黑名单（≥2 次后自动拒绝）
品味：签名批准 ≥ learnThreshold(2) → 冷却期(24h) 后白名单自动放行；拒绝 ≥2 → 黑名单即时生效
M7 自改：写 $DSH_HOME/AGENTS.md/配置/插件状态目录 → 恒 red（托管）+ 永不进品味习得 + before 快照 hash 标记
M8 减法：/escrow reduce 从账本审计重复动作 / SNR / 署名尾注（永不自动卸载，只建议）
```

## 模块与文件

| 文件 | 职责 |
|---|---|
| [lib/index.mjs](../lib/index.mjs) | 主链路：pre-execute/execute 拦截、escrow_result 工具、品味接线、插件树 hash、release 超时重放 |
| [lib/queue.mjs](../lib/queue.mjs) | 队列状态机、同签名(pending)去重、重放令牌(exemptions/replaying)、onSettle、entries 剪裁 |
| [lib/classify.mjs](../lib/classify.mjs) | 确定性分类：内置危险命令/敏感路径/涉敏命令串、用户规则 |
| [lib/signature.mjs](../lib/signature.mjs) | 签名提取（shell 白名单式 / 非 shell 键名）+ never-learn 名单 |
| [lib/taste.mjs](../lib/taste.mjs) | 品味存储：状态机(learning/cooling/active/pending-review)、冷却期、品味包、失效 |
| [lib/synth-result.mjs](../lib/synth-result.mjs) | M1 合成结果构造（foreground Success 形态）+ 占位文本 + 结果摘要 |
| [lib/replay.mjs](../lib/replay.mjs) | 批准/超时放行后异步重放执行 |
| [lib/reduce.mjs](../lib/reduce.mjs) | M8 减法审计：重复动作/SNR/署名（数据源=账本，复用 M2 签名） |
| [lib/commands.mjs](../lib/commands.mjs) | /escrow 命令：pending/approve/deny/allowlist/allow/forget/export/import/approve all/deny all/reduce |
| [lib/ledger.mjs](../lib/ledger.mjs) | append-only JSONL 账本 + 密钥脱敏 + 轮转 |

## 验证方法（先跑测试确认基线）

依赖：Node ≥ 20，项目根已有 `node_modules`（含 `@deepseek-ai/schemastery`）。

```bash
cd D:\BigWorkspace\projects\dsh-escrow
npm run test:all      # 等价：smoke + taste + integration 依次跑
```

期望基线：**218 断言全绿**（smoke 104 + taste 43 + integration 71）。
若 `node_modules` 缺失：`pnpm install`（或 `npm install`）。
端到端（可选，需 dsh 环境 + 真实模型）：见 `findings-log.md` 的实证记录。

## 历轮审查已发现并修复（供核对，不必重复审——聚焦验证修复 + 找新问题）

见 [findings-log.md](findings-log.md)。

## 审查重点（找新问题的方向）

1. **fail-open/fail-closed 一致性**：品味 check 异常 fail-open → 正常分类（仍托管）；分类异常 fail-open to default；已判 red 后链路异常 fail-closed——每层决策是否自洽？有没有"fail-open 到执行"的路径？
2. **重复执行/双调用点**：pre-execute 里品味 allow 的 `return next()` 与底部 `next()`；approve all 的逐条重放；execute 层 replaying 与 pending 判定——有没有路径重复执行工具？
3. **令牌生命周期**：mintToken → exemptions(pre-execute 豁免) + replaying(execute 放行) → consume/finish 清理——有没有泄漏窗口、复用窗口、或跨调用串用？
4. **签名粒度与品味放行边界**：非 shell 签名只含参数键名（`fs.write(content,path)`）——已修内置敏感路径/涉敏命令串不容品味覆盖，还有没有其他形态能绕过？
5. **竞态**：pendingList 快照与 decide 之间超时、approve all 部分成功、重放与超时并发、onSettle 与命令并发。
6. **账本格式与 kinds**：ledger 记录字段/kinds 完整性；与未来 M6 哈希链（`h=sha256(prevH+行)`）的兼容前提。
7. **配置组合矩阵**：`mode: async|sync` × `syncTools` × `ttlSec(0..N)` × `timeoutPolicy(cancel|release|hold)` × 品味开关——组合有没有死角（如 release+async 已修，还有别的吗）。
8. **命令解析**：`deny <id>` vs `deny <sig>` 格式区分（`/^esc-\d+-\d+$/`）、rawInput 空白分割、多 token 签名。
9. **M7 自改治理**：命令串自改宽松检测（"含自改字样即红"）的绕过形态——编码/变量拼接/引号变体/路径别名（`$DSH_HOME` 展开、`~`、反斜杠、大小写）；classify 红与 never-learn 的口径一致性（还有没有"classify 红但 never-learn 不认"的残留）；selfmod 记账 settle 三路（async onSettle / sync / ttl=0）完整性；before 快照 hash 对不可读/相对/`$VAR` 路径的容错。
10. **M8 减法审计**：`signatureOf` 统计口径（落账 `rec.signature` vs 现场重算，混用会不会漏/重）；比率分母边界（0 除、interruptRate 超 100%）；轮转 `.bak` 合并读的顺序与去重；reduce 是否纯只读（有没有任何路径改账本/名单/队列状态）。

## 交付格式

按严重度分级（CRITICAL / HIGH / MEDIUM / LOW），每条给出：
`文件:行号` + 问题描述 + 触发路径/复现条件 + 建议修法。
**只报真实缺陷，宁缺毋滥**——避免泛泛的"建议优化"。目标：验证 193 测试 + 历轮修复是否闭环，并抓出新问题。
