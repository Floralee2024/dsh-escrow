# dsh-escrow 第三方独立审查报告（round 3）

> **修复状态（2026-08-29 当日）**：本报告 HIGH-1、HIGH-2、MEDIUM-1、LOW-3 已于 v0.3.3 修复并固化回归断言（integration 40→46，全量 139 绿）；MEDIUM-2、MEDIUM-3、LOW-1、LOW-2 待决策者拍板（详见 findings-log.md 第三轮表格）。探针复跑：已修项全部翻转 OK。

- 审查者：独立第三方（无本项目开发上下文，按 `reviewer-prompt.md` 执行）
- 日期：2026-08-29　对象：dsh-escrow v0.3.2（`D:\BigWorkspace\projects\dsh-escrow`）
- 方法：通读 `lib/` 全 9 个模块（1710 行）建立独立理解 → 跑基线 → 确定性探针复现
- 基线：`npm run test:all` **133 断言全绿**（smoke 61 + taste 32 + integration 40）✓
- 复现脚本：`third-party-review/probes/review-probe.mjs`（`node` 直接运行，全部结论可重算）

---

## 一、修复闭环验证（findings-log 要求的 5 条）

| # | 闭环项 | 结论 | 验证方法 |
|---|---|---|---|
| 1 | approve all 逐条真实执行，学习一次 | ✓ 闭环（**但测试套件未覆盖执行级断言**，见 L3） | 探针 C1：同品味签名 2 条不同参数入队 → approve all → `ctx._tools.executed=2`、两条状态均 `executed`、白名单 `count=1` |
| 2 | 品味 allow 不覆盖内置敏感路径（写 .env 仍托管） | ✓ 闭环 | integration「M2 品味 allow 不覆盖内置敏感路径」绿 + 读 index.mjs:156-166 确认 sensitiveRed 回落分类 |
| 3 | `git reset --hard` / `git checkout --` never-learn | ✓ 闭环（**但内置红灯对 `checkout -- <path>` 本身有覆盖缺口**，见 M2） | smoke「git reset --hard → 不可学习」「git checkout -- 丢弃工作区 → 不可学习」绿 |
| 4 | release + async 超时触发重放 | ✓ 闭环（**测试套件未覆盖**，见 L3） | 探针 C4：ttl=1 release async → 超时后条目 `executed`、重放执行 1 次、账本含 `escrow.replayed` |
| 5 | execute 层 callId 主匹配 + 签名兜底，去重调用仍被拦 | ✓ 闭环 | integration「去重调用占位文本含已在审批队列」等 3 条绿 + 读 index.mjs:258-267 |

代码层面 5 条修复均真实有效。但第 1、4 条的**关键断言不在测试套件里**（见 L3），属于"修了但测试没盯住房梁"。

---

## 二、新发现缺陷（按严重度排序，全部经探针确定性复现）

### HIGH-1　已超时拒绝/已超时放行的动作，迟到的原始调用到达 execute 层仍会真实执行

- 位置：[index.mjs:260-268](../lib/index.mjs)（execute 闸门只查"当前 pending"）+ [queue.mjs:143-145](../lib/queue.mjs)（settle 即删 `pendingByCallId`/`pendingBySig` 索引）
- 问题：async 模式下 pre-execute 入队即放行，原始调用抵达 execute 层之前若条目已 settle（超时拒绝/超时放行），两个 pending 索引已被删除，闸门查不到任何东西 → 落到 `next()` → **真实执行**。
- 触发路径（两个变体）：
  - **cancel 变体（fail-open 到执行，违反核心不变式）**：ttl=1s，pre-execute 与 execute 钩子之间事件循环被下游钩子（如同时安装的 dsh-user-approval 人工确认、慢插件、I/O 抖动）阻塞 >1s → 条目超时**拒绝**并落账 → 原始调用到达 execute 层 → `next()` → 一个**已被拒绝**的动作被执行。探针 F6a：`超时落账=true 迟到调用 next()=1`。
  - **release 变体（双执行）**：release 超时 → onSettle 自动重放执行 1 次 → 迟到的原始调用再 `next()` 执行 1 次。探针 F6b：`自动重放=1 迟到调用 next()=1`。
- 现实性：两个钩子之间隔的是整条下游中间件链，任何 `await` 都让出事件循环；ttl 允许配 1s。多插件共存时这不是理论场景。
- 建议修法：settle 不删身份索引，改为记录终态（`originalCallId → state`，可带短宽限 TTL）；execute 层命中已 settle 条目时按终态返回合成结果（`expired/denied` → 「该动作已超时拒绝，未执行」；`approved` → 「该动作已由审批通道负责执行」），**只有查无此调用才 `next()`**。即闸门语义从"当前 pending 才拦"改为"凡经托管的调用身份，除重放令牌外一律不得裸执行"。
- 验证方法：探针 F6a/F6b（手动构造 settle 后调用 execute 钩子）；修复后两例应返回合成结果且 `next()=0`。

### HIGH-2　`argsSnapshot` 是活引用：人工批准 A、实际执行 B，且 B 不经任何分类（TOCTOU）

- 位置：[index.mjs:200](../lib/index.mjs) / [index.mjs:220](../lib/index.mjs)（`argsSnapshot: exec?.arguments` 存引用非快照）+ [replay.mjs:23-31](../lib/replay.mjs)（重放走令牌豁免，跳过全部分类）
- 问题：入队时存的 `argsSnapshot` 与 `exec.arguments` 是同一对象引用。escrow 的 pre-execute 之后若有下游钩子原地改写 `arguments`，人工在 `/escrow pending` 看到的是**改写前**的摘要，approve 后重放执行的却是**改写后**的参数；重放凭令牌豁免分类，改写成 `rm -rf` 也照跑。
- 触发路径：探针 F5——入队 `git push origin main` → 模拟下游钩子 `args.command = 'rm -rf /tmp/innocent'` → 人工批准（看到 git push）→ 实际执行 `rm -rf /tmp/innocent`。输出：`人工看到="git push origin main" 实际执行="rm -rf /tmp/innocent"`。
- 建议修法：入队时深拷贝（`structuredClone`，不可克隆时 JSON 深拷贝容错），summary、学习判定（`learnDecision` 也读 `argsSnapshot`）、重放统一使用拷贝。改动一行级，收益是审批绑定不可篡改。
- 验证方法：探针 F5；修复后 `实际执行` 应等于 `git push origin main`。

### MEDIUM-1　sync 模式同签名并发去重：一次批准、两次真实执行（且同 id 重复记账）

- 位置：[queue.mjs:116-120](../lib/queue.mjs)（去重返回共享 promise）+ [index.mjs:196-215](../lib/index.mjs)（sync 分支不解构 `dedup`，两个调用 await 同一 promise 后都落到底部 `next()`；且不去重地重复写 `escrow.queued`）
- 问题：模型单 turn 并行发起两个完全相同调用（sync 模式/`syncTools` 命中）→ 去重为 1 条 pending → 人工只批准 1 次 → 两个调用都收到 approved → 都执行。与 async 模式语义不一致（async 去重调用拿"已在审批队列"占位，只执行 1 次）。
- 触发路径：探针 F4——`入队=1 next()=2 账本queued行=2（同 id 重复记账）`。
- 建议修法：sync 分支识别 `dedup`：去重调用在 await 结果 approved 后不落 `next()`，返回「该动作已由同签名调用执行」的 deny/合成结果；`escrow.queued` 仅在 `!dedup` 时写（与 async 分支对齐）。
- 验证方法：探针 F4；修复后 `next()=1`、`queued行=1`。

### MEDIUM-2　内置危险命令覆盖缺口：`rm -r`（无 -f）、pwsh `rm -Recurse`（无 -Force）、`git checkout -- <path>`、`git restore` 全部漏为 yellow（放行+仅记账）

- 位置：[classify.mjs:92](../lib/classify.mjs)（rm 模式要求 r、f 双旗标）、[classify.mjs:96](../lib/classify.mjs)（`checkout\s+--\s*\.` 只认 `.`）、`git restore` 无模式
- 复现（探针 F1/F2/F3，全部 `分类=yellow ruleId=(default)`）：
  - `rm -r ./src`——bash 下递归删除不需要 `-f`（仅写保护文件才提示）；
  - `rm --recursive ./src`——长旗标同理；
  - `pwsh: rm -Recurse ./src`——PowerShell 别名递归删除不需要 `-Force`；`rd -Recurse` 同漏；
  - `git checkout -- src/main.ts`——丢弃文件未提交改动，内置只拦 `checkout -- .`；
  - `git restore --worktree src/main.ts`——现代等价写法，完全无覆盖。
- 建议修法：rm 类改为「递归旗标单独命中即红」（`-r`/`--recursive`/`-Recurse` 足以构成递归删除，无需强求 force）；`checkout --` 放宽到任意路径；补 `git restore`、`rd -Recurse`；NEVER_LEARN 列表同步对齐（never-learn 目前比红灯宽，方向是对的，红灯应补齐）。
- 验证方法：探针 F1/F2/F3；修复后上述样本全部 `red`。

### MEDIUM-3　敏感路径键名覆盖缺口：`filename`/`outputFile` 等常见键不提取 → 写 `.env` 仅 yellow

- 位置：[classify.mjs:57-64](../lib/classify.mjs)（`collectPathCandidates` KEYS）
- 问题：第二轮修的 `file_uri` 是同一个锅补了一个洞——`filename`、`outputFile`、`destFile`、`savePath` 均不在 KEYS。`fs.write({filename:'.env',content})` 分类 yellow 直接放行；且该签名可学习，白名单后连观察都不显眼。
- 复现：探针 F8——`fs.write filename=".env"` 与 `outputFile=".env"` 均 `yellow`。
- 建议修法：KEYS 补 `filename`/`outputfile`/`destfile`/`savepath` 等；或加兜底——对未识别键的字符串值，若其 basename 命中敏感 glob（`.env*`、`id_rsa*` 等）也计入候选（误报可控，因为这些 glob 已收窄为真实密钥形态）。
- 验证方法：探针 F8；修复后两样例 `red`。

### LOW-1　用户显式 red 规则被品味白名单覆盖

- 位置：[index.mjs:156-166](../lib/index.mjs)（sensitiveRed 只认 `builtin-sensitive-path`/`builtin-command-sensitive`）
- 问题：用户配置了 `deploy` 必托管的 red 规则，但该签名一旦进白名单（学习或手动），taste allow 直接 `next()`，用户 red 形同虚设。内置 `builtin-command`（git push 类）可学习是 P7 设计，但**用户自己写的 red** 被学习行为推翻，与"用户规则优先于内置"的优先级哲学（classify.mjs 头注）矛盾。
- 复现：探针 F7——`入队=0 白名单落账=true`（deploy 未进托管）。
- 建议修法：品味 allow 放行前，凡分类为 red 且 ruleId 不是可学习的 `builtin-command`（即用户规则 red + 内置涉敏 red）一律回落托管；或在说明书显式声明"品味白名单高于用户 red"由用户自担。

### LOW-2　账本脱敏漏空格分隔与 URL 内嵌凭据

- 位置：[ledger.mjs:25-27](../lib/ledger.mjs)（键值模式要求 `[:=]`）
- 问题：`--token abcdefgh`、`mysql -p secret`、`postgres://user:pass@host` 这类空格分隔/URL 内嵌凭据不匹配任何脱敏模式，明文落 `observe`/`escrow.queued` 账本。
- 建议修法：补 `\s--?(?:token|password|api-?key)\s+\S+` 与 `://[^:]+:[^@]+@` 两类模式。

### LOW-3（测试缺口，非代码缺陷）　两条关键闭环无测试盯防

- 位置：[plugin.integration.test.mjs:319-324](../test/plugin.integration.test.mjs)
- 问题：① approve all 只断言回执文本（"1 组/2 条"）与队列清空，**未断言两个实例都真实执行**（findings-log 闭环 1 要求的 `executed=2` 本次由探针 C1 补验）；② release+async 超时重放（闭环 4）全套件无用例，仅 queue 层有 release→approved 的单测。两条都是本次 HIGH-1 同区域的行为，缺测试 = 回归无报警。
- 建议修法：把探针 C1/C4 固化进 integration（各 1 条断言即可）。

---

## 三、审查过且认定干净的方向（抽样）

- 令牌生命周期：mintToken 双登记、execute 层 finishReplay 先行消费、replay `.then/.catch` 双清兜底，未见泄漏/复用窗口（重放永不 settle 时令牌驻留内存，随机串不可铸造，影响可忽略）。
- wrapper 不抛异常：execute 层全 try/catch 合成兜底；pre-execute 各分支 next() 单调性有回归测试盯防。
- 品味存储：schema 拒绝加载、原子写盘、导入校验和、pending-review 惰性晋升，状态机自洽。
- fail-closed 主链路：分类后异常 deny、ttl=0 立即拒绝、黑名单优先于白名单，方向均正确。

## 四、总结

- **历轮修复**：5 条闭环代码层面全部成立 ✓；其中 2 条缺测试盯防（L3）。
- **能否进入下一里程碑**：**建议先修 HIGH-1 与 HIGH-2 再进**。两条都直击"批准什么、执行什么"的核心契约：HIGH-1 让"超时=拒绝"在时序边缘失效（fail-open 到执行），HIGH-2 让审批内容可被下游改写且重放零分类。两者修复成本都不大（索引保留 + 深拷贝）。
- **遗留风险**：MEDIUM-2/3 是分类覆盖的系统性缺口（规则永远追不全命令形态），建议在修完样本后，把"危险形态样本集"沉淀为回归语料持续补；LOW-1 需要一次明确的设计裁决（用户 red vs 品味白名单谁高）。
