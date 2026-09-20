# S0 Spike 结论报告 —— dsh-escrow v0.2 开工可行性裁决

- 日期：2026-08-29
- 依据：`设计-v0.2.md` v0.2.2 的 W0 闸门与 S0 决策规则（三个 spike 全部文档级正面 → M1 轮询式 async 判定 GO，待实证升级）
- 证据来源：dsh v0.1.0-rc.7 本地安装源码（已复制到 `D:\BigWorkspace\scratch\dsh-src-study\pkg\`）、各包 README 与类型声明；标注【实证】的条目来自 escrowtest profile 真实运行

## 总结论

**M1 轮询式异步托管：GO（实证级）。** 三个 spike 全部为正面，无阻断项。Spike 1/2 已由真实 headless agent 实证实验升级为实证级（2026-08-29）；Spike 3 为机制性结论保持文档级（源码+类型声明，逻辑链完整）；设计文档三处定案已回填（见 §5）。

## Spike 1：wrapper 返回合成结果后，agent loop 会不会重试风暴？【实证级通过】

事实：

- dsh-agent-loop **从不自动重试**工具调用；工具失败结果以 `Error: <message>` 文本交给模型，重试与否完全是模型的决策。
- harness 已有兜底：dsh-repeat-tool-reminder 坐在 `tools/post-execute` 上，同一工具 + 规范化参数连续 3/5/8 次重复时给出升级劝告，且明确 "denied calls count"——被拒绝的调用也计入。
- 风险点：wrapper/插件**抛错会终结当前 turn**（不是 loop 层面）。M1 的 wrapper 在任何路径上都绝不可抛异常，必须返回正常结果。

M1 需补的设计（已定为正式需求）：

- **同签名 pending 去重**：模型在等待期间重复发起同一调用时，不再入新队列，直接返回"已在审批队列 esc-xxx，请用 escrow_result 查询"。

**实证记录（2026-08-29）**：headless agent（escrowtest profile + `dsh-synth-probe`）执行无害命令，收到 Success 合成结果后**全程未重复发起同一命令**（echo 命令仅 1 次拦截记录），转而**主动多次轮询** `escrow_result`（7 次）获取 pending 状态，最终如实汇报"等待审批"。探针日志（probe.log）为客观工具调用序列，非模型自述。结论：**合成结果 + 占位行为指令有效阻止重试，未出现重试风暴**；同签名去重仍是必要兜底（防异常模型/极端 prompt 场景）。

## Spike 2：插件注册模型可见工具（escrow_result）【实证级通过】

- `ctx.tools.register(definition)` 在平插件上下文即全局注册；强制 canonical `output` 声明 + 正的有限 `timeoutMs`；同层重名抛错；`run_code` 为保留名不可注册。
- Code Mode 投影自动：注册的工具自动进入 SDK 绑定；`mode: code` 下模型只能直调 `run_code`，但 escrow_result 可在程序内被调用；`mode: native|code|both`，`presentAs` 可按 agent 覆盖。

**实证记录（2026-08-29）**：`dsh-synth-probe` 注册的 `escrow_result`（output schema + render + timeoutMs）在真实 headless agent 中**模型可见、可调用**——模型在收到 esc-1001 合成结果后自动调用 `escrow_result("esc-1001")` 轮询，多次拿到 pending 状态并正确理解（"仍在审批中，批准后才可查询真实结果"）。注册姿势实证可用。

## Spike 3：重放令牌在 pre-execute 的验证路径【文档级通过，令牌形态定案】

- `ctx.tools.execute(exec: ToolExecutionInput)` 是公开程序化调用 API，走**完整流水线（含 pre-execute）**——重放必然撞上自己的托管监听，**豁免令牌确有必要**（验证了 P2 设计前提）。
- `ToolExecutionInput = { callId（调用方自选）, rootCallId?, name, arguments, agent?, parent?, signal（必需） }`；`ToolExecutionToken` 是 registry 分配的 branded Symbol，调用方无法伪造。
- PreToolDecision 真实类型 = `{kind:'allow'} | {kind:'deny',reason} | {kind:'ask',reason?}`；ask 在无 ApprovalService 时降级为 deny（印证立项判断）。

**令牌设计定案：令牌 = 随机 callId。**

- 模型无法铸造 callId：模型直调的 callId 由 registry 分配；Code Mode 子分发是确定性 id `<parent>:code:<n>`。两者模型都不可控。
- 流程：批准时铸随机 callId，存 `hash(工具名 + 规范化参数) → callId`；重放时带该 callId；pre-execute 监听验明后豁免一次并立即删除。
- 令牌**绝不进 arguments**（pre-execute 不能改写 args，且 args 进日志、模型可见）。
- 重放时透传原 `exec.agent` 保证会话归属正确；重放结果返回给插件（不给模型），模型经 `escrow_result(id)` 查询——与 M1 轮询设计一致。

## 合成结果形态定案（本次补查关闭的最后缺口）

bash 与 pwsh 工具的 output 声明结构相同（`dsh-tool-bash` / `dsh-tool-pwsh` 的 `defineTool`），为 oneOf 两分支：

- 后台分支：`{ kind:'background', jobId }`
- 前台分支（`additionalProperties: false`，字段全部必填）：
  `{ kind:'foreground', exitCode: int|null, signal: string|null, timedOut: bool, aborted: bool, timeoutMs: number, stdout: {text, truncated, spillPath?}, stderr: {text, truncated, spillPath?} }`

dsh-tools README 明确：**wrapper-authored success 会按目标工具的 output 声明规范化**——合成结果必须符合目标工具的 schema，否则在规范化阶段出问题。

**定案：托管占位用 Success 形态，合成一个合法的前台结果**：

```
kind: 'foreground', exitCode: null, signal: null,
timedOut: false, aborted: false, timeoutMs: 0,
stdout: { text: '[dsh-escrow] 此命令已进入人工审批（esc-xxxx），请调用 escrow_result 查询结果；审批期间不要重复发起同一命令。', truncated: false },
stderr: { text: '', truncated: false }
```

理由：

- Success 形态避免 `Error:` 前缀诱发模型的"失败→换法重试"直觉（对比 Failure 形态会以 `Error: <message>` 呈现给模型）；
- 完全符合 output schema（`additionalProperties:false` 下无多余字段），规范化安全；
- 占位文本自带行为指令（不要重复发起 + 用 escrow_result 查询），与 Spike 1 的去重设计互为双保险。

## 证据等级声明

- 【实证】ttl=0 立即拒绝、黄灯放行入账、模型提权 danger-full-access 被拦：escrowtest profile 真实运行验证（W0 前半）。
- 【实证】Spike 1/2（合成结果→模型不重试、escrow_result 注册+轮询实机可用）：`dsh-synth-probe` 实证实验（2026-08-29），真实 headless agent，判定基于 probe.log 客观工具调用序列（非模型自述）。
- 【文档级】Spike 3（重放令牌路径）：源码+类型声明，逻辑链完整；令牌机制是 registry 层机制、不依赖模型行为，维持文档级即足够。
- 升级路径（已执行）：`dsh-synth-probe` 插件在 `tools/execute` 包装层对 bash/pwsh 返回合成结果，headless agent 实测通过。

## 设计文档回填（已完成，2026-08-29）

1. ✅ M1 增加"同签名 pending 去重"需求（返回既有队列条目 id，不重复入队）。
2. ✅ 重放令牌 = 随机 callId（原 P2 的"令牌"描述落实为具体机制；令牌不进 arguments）。
3. ✅ 托管占位合成结果形态（Success/foreground 结构，占位文本含行为指令）。

均已写入 `设计-v0.2.md` M1 章节，并附实证记录标注。

## 下一步

- W0 收尾：✅ 实证实验（Spike 1/2 实证级）→ ✅ 证据升级 → ✅ 回填设计文档 → **开工 W1（M1 托管核心）**。
