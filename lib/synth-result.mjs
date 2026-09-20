/**
 * M1 合成结果构造（S0 定案：Success / foreground 合法前台结果）。
 *
 * 关键事实：tools/execute wrapper 返回的 content 会被 dsh 丢弃（normalizeDispatchResult
 * 只用 value 重渲染模型可见内容），因此占位文本必须放进 value.stdout.text——实证已验证该
 * 链路（headless agent 收到了 stdout.text 中的占位文本）。
 *
 * value 完全符合 bash/pwsh 的 output 声明（additionalProperties:false 下无多余字段），
 * wrapper 规范化安全。选 Success 而非 Failure：Failure 以 `Error:` 前缀呈现，易诱发
 * "失败→换法重试"直觉；实证中模型收到 Success 占位后不重试、主动轮询 escrow_result。
 */

/** 首次发起：占位文本含完整行为指令。 */
export function placeholderText(id, isRepeat) {
  if (isRepeat) {
    return `[dsh-escrow] 此命令已在审批队列（${id}），请调用 escrow_result("${id}") 查询结果；审批期间不要重复发起同一命令。`;
  }
  return `[dsh-escrow] 此命令已进入人工审批（${id}），请调用 escrow_result("${id}") 查询结果；审批期间不要重复发起同一命令。`;
}

/**
 * 合成一个合法前台结果。content 省略（dsh 用 value 渲染）。
 * @returns {{ isError: false, value: object }}
 */
export function synthForeground(text) {
  return {
    isError: false,
    value: {
      kind: 'foreground',
      exitCode: null,
      signal: null,
      timedOut: false,
      aborted: false,
      timeoutMs: 0,
      stdout: { text, truncated: false },
      stderr: { text: '', truncated: false }
    }
  };
}

/**
 * 从重放执行的 ToolExecutionResult 提取可存账本/供 escrow_result 返回的文本摘要。
 * 优先 stdout.text（bash/pwsh 前台形态），失败时兜底 JSON/错误消息，一律截断。
 */
export function resultToText(result, max = 2000) {
  try {
    if (result?.isError) {
      const e = result.error;
      return `执行失败: ${typeof e === 'string' ? e : JSON.stringify(e ?? {})}`.slice(0, max);
    }
    const v = result?.value;
    if (v && typeof v === 'object') {
      const stdout = v.stdout?.text;
      if (typeof stdout === 'string') return stdout.slice(0, max);
      const stderr = v.stderr?.text;
      if (typeof stderr === 'string') return `（stderr）${stderr}`.slice(0, max);
      return JSON.stringify(v).slice(0, max);
    }
    return String(v ?? '').slice(0, max);
  } catch {
    return '（结果序列化失败）';
  }
}
