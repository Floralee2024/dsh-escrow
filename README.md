# dsh-escrow

**延迟执行窗口（escrow）**：把 agent 的不可逆动作放进托管队列——批准才交割，超时默认拒绝。
给 DeepSeek Harness 补上「生效前可取消」这一层，而不是「出事后再回滚」。

> Everything is a plugin 解决了「什么可以被扩展」；本插件回答「什么值得被执行」的最后一个问题：*谁来决定什么时候放行。*

## 为什么

- dsh 三档权限管不住插件（插件即 dsh 本身）；官方 approval 服务在无头环境会卡死（`ask` 需要人应答）。
- 现有方案都是「事后撤销」（快照/回滚）；**没有一个是「生效前托管」**。
- 本插件补的是第四态：**非阻塞的托管 + 超时即拒绝**（silence means no）。

## 安装

```bash
# 从本地目录装进 web profile
dsh plugin --profile web add "D:\BigWorkspace\projects\dsh-escrow"

# 或发布到 npm 后
dsh plugin --profile web add dsh-escrow
```

装完重启 dsh（改 profile 的 package.json 后必须重新 pnpm install，否则启动报
`cannot resolve profile bundle`；Windows 下 pnpm 请走 PowerShell 通道执行）。

## 使用

红灯动作（如 `rm -rf`、`git push`、写 `.env`）不会立即执行，而是进入托管窗口：

```
/escrow pending           # 查看待决动作（含脱敏后的动作摘要，批准的正是你看到的那条）
/escrow approve esc-3     # 批准 → 放行执行（异步重放）
/escrow deny esc-3        # 拒绝
/escrow stats             # 统计 + 账本路径
```

**非阻塞（v0.2 M1，默认 async 模式）**：红灯动作入队后**立即返回**「已进入人工审批（esc-x）」的合成结果，agent 不停顿。模型可调用模型可见只读工具 `escrow_result(id)` 轮询状态：

- `pending` 审批中 / `executed` 已执行 + 真实结果 / `denied` 已拒绝 / `expired` 超时拒绝

- 默认窗口 **30 秒**，超时 → **默认拒绝**（`timeoutPolicy: cancel`）。
- `ttlSec: 0` = **立即拒绝**（CI/无头 fail-closed，不入队不挂起）。
- `mode: sync` 恢复 v0.1.1 同步等待；`syncTools` 可指定"写后读强依赖结果"的工具保持同步。
- 没有人在场也安全：无人批准 = 拒绝，绝不默认放行。

**品味习得（v0.2 M2）**：同一签名人工批准 ≥ `learnThreshold`（默认 2）次 → 冷却期后进白名单自动放行（不再打扰）；人工拒绝 ≥ 2 次 → 黑名单直接拒绝。**仅人工决策塑造品味**（超时/取消不算负面学习）；`rm -rf` 类/`--force`/磁盘/自改类签名**永不自动学习**（只可手动 `allow`）。

```
/escrow allowlist           # 查看白名单/黑名单
/escrow allow <sig>         # 手动加入白名单（立即生效）
/escrow deny <sig>          # 手动加入黑名单（立即生效）
/escrow forget <sig>        # 从名单移除
/escrow approve all         # 按签名组去重批准（同签名多实例合并一次决策）
/escrow deny all            # 按签名组去重拒绝
/escrow export [path]       # 导出品味包（默认 $DSH_HOME/.dsh-escrow/escrow-taste-pack.yaml）
/escrow import <path>       # 导入品味包（校验和/schema 不符拒绝；导入条目待复核）
/escrow reduce [--since 7d] # 减法审计：重复动作 / SNR / 署名尾注（只建议，永不自动卸载）
/escrow migrate            # 迁移 legacy 账本为完整哈希链（h + HMAC；旧文件备份 .premigrate）
/escrow doctor             # 自检报告（哈希链 / 名单 schema / 密钥 / 规则数 / 分类器性能）
```

## 配置（cordis.patch.yml）

```yaml
- id: escrow
  name: dsh-escrow
  config:
    ttlSec: 30            # 窗口秒数；0 = 立即拒绝（CI/fail-closed）
    timeoutPolicy: cancel # cancel(默认拒绝) | release(放行) | hold(无限等)
    defaultAction: yellow # 规则未命中时的默认处置：green/yellow/red
    builtinRules: true    # 内置危险命令/敏感路径规则
    mode: async           # async(默认，非阻塞轮询) | sync(v0.1.1 同步等待)
    syncTools: []         # 工具级同步逃生门（写后读强依赖结果的工具）
    learnWhitelist: true  # 人工批准学习白名单（同签名达阈值后经冷却期放行）
    learnThreshold: 2     # 学习阈值（同签名人工批准次数）
    autoBlacklist: true   # 人工拒绝学习黑名单（即时生效）
    cooldownHours: 24     # 白名单冷却期（小时），防疲劳误批准即时固化
    selfModification:
      red: true           # 自改治理：写 $DSH_HOME/AGENTS.md/配置/插件状态目录恒托管；永不进品味习得（关 = false 会告警）
    ledgerMaxMb: 32       # 账本单文件上限（MB），超限轮转为 ledger.jsonl.bak（保留一代）
    # 用户规则（first match wins，规则内约束为 AND）：
    rules:
      - id: block-git-push
        tools: ['bash', 'pwsh']
        args:
          - key: command
            pattern: 'git push'
        action: red
      - id: allow-safe-tests
        tools: ['bash']
        args:
          - key: command
            pattern: '^(pytest|npm test|pnpm test) '
        action: green
```

注意：patch 替换整行 config，不深合并——改一个字段也要重述全部。
匹配一律大小写不敏感（Windows 语义）；用户 green 规则不能压制内置红灯（yellow/red 可以）。

## 账本

所有决策写入 append-only JSONL（`$DSH_HOME/.dsh-escrow/ledger.jsonl`），密钥自动脱敏。
每行含时间戳、kind（observe / escrow.queued / escrow.decided）、工具、理由、等待时长、会话（session，M6）。
文件超过 `ledgerMaxMb`（默认 32MB）自动轮转为 `ledger.jsonl.bak`（保留一代）。

**哈希链（M6+）**：每行带 `h = sha256(prevH + 行内容)` + `m = HMAC-SHA256(key, h)`（密钥 `$DSH_HOME/.dsh-escrow/keys/hmac.key`，首次自动生成），启动校验整链（含 .bak），篡改/截断/密钥不匹配 → 告警（`/escrow report` 附注区分）。
**威胁模型**：防**无意/未察觉**的篡改与截断，且 **HMAC 锚定防"知道算法但无密钥"**的攻击者重算整链（R8-1 修复）；legacy 旧格式行（无 h）会重置链、削弱防篡改——用 `/escrow migrate` 迁移为完整链。链头外部锚定到 git commit（v0.3）之前，仍不防能同时写账本与密钥的完全知情攻击者。

**指标口径**：批准率 = `批准决策数 / (批准+拒绝决策数)`（决策视角）；打扰率 = `拦下 / (总动作+拦下)`（执行视角）。两者分母不同是概念差异（不是矛盾）；`escrow_result` 反复轮询等重复执行由 `/escrow reduce` 单列。

## 设计取舍（v0.2 M1）

- 非阻塞轮询式托管（默认 async）：红灯动作入队即返回合成结果，agent 不停顿，模型经
  `escrow_result(id)` 轮询真实结果（S0 实证：模型收到合成结果不重试、主动轮询）。
  合成结果选 Success/foreground 形态（避免 `Error:` 前缀诱发"失败→换法重试"直觉）。
- 重放令牌 = 随机 callId（模型无法铸造），批准后异步重放执行，令牌绝不进 arguments。
- 同签名 pending 去重：完全相同参数的重复发起不重复入队。
- `mode: sync` / `syncTools` 保留 v0.1.1 同步等待语义（逃生门）。
- 不依赖 approval 服务（policy: never 时它永远拒绝）；自包含队列 + TTL。
- 确定性规则分类，绝不用 AI 分类器做安全决策。
- 分类器自身异常不阻断主链路（fail-open）；但**已判 red 后链路任何异常都 fail-closed 拒绝**，
  且 `next()` 全函数只有一个调用点——内部异常不会造成重复执行。
- 撤销/回滚（事后）不重复造轮子：配置层用 `dsh-undo-savepoint`，文件层用 `dsh-rollback`。

## 测试

```bash
npm test                              # 单元：node test/smoke.test.mjs（104 断言，含攻击样本回归）
npm run test:taste                    # taste：43 断言
npm run test:integration              # 插件级集成：74 断言
npm run test:all                      # 当前总计：221 断言
```

## 论文与复现

论文草稿、实验卡和一键复现入口位于 [`paper/`](paper/)：

- [`paper/manuscript.md`](paper/manuscript.md)：系统论文草稿及当前证据边界
- [`paper/experiment-card.json`](paper/experiment-card.json)：实验问题、干预、估计量与反证条件
- [`paper/reproduce.ps1`](paper/reproduce.ps1)：打印版本信息并运行完整测试套件

论文当前主张限于实现不变量、故障关闭行为和可复现的测试证据；不声称普遍安全性、生产规模有效性或已完成因果比较。

## Inspired by

- [Zijian-Ni/agent-inbox](https://github.com/Zijian-Ni/agent-inbox) —— timeout=denied（silence means no）的语义
- [Agent Patterns Catalog · Approval Queue](https://agentpatternscatalog.github.io/patterns/patterns/approval-queue.html) —— 异步审批队列
- [FeirAI/vultrino](https://github.com/FeirAI/vultrino) —— TTL 过期 + 外部通知通道
- [pydantic/pydantic-ai](https://github.com/pydantic/pydantic-ai) —— deferred tools 的挂起语义
- [SynapticRelay Safe Deal Escrow](https://synapticrelay.com/articles/safe-deal-escrow-for-ai-agents) —— 评审窗 + 自动处置

## License

MIT
