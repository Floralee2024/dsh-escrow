# dsh-escrow approval adapter

本地、单机 MVP 审批宿主：把 dsh-escrow 的结构化审批请求显示成浏览器卡片，支持“允许一次”和“拒绝”。

## 启动

在仓库根目录执行：

```powershell
node approval-adapter/bin/dsh-escrow-approval-adapter.mjs
```

启动日志会打印带一次性 token 的本地 URL。只绑定 `127.0.0.1`，不要把它暴露到局域网或公网。

MVP 使用 dsh-user-approval 当前稳定的 `allowed-once` / `rejected` 结果。`approve-now` 和 `approve-and-allow` 仍使用 dsh-escrow 命令；完整的扩展按钮需要后续扩展宿主协议。

## dsh-escrow 配置

```json
{
  "approvalMode": "adapter",
  "approvalAdapterUrl": "http://127.0.0.1:3099",
  "approvalAdapterToken": "启动日志中的 token"
}
```

adapter 断线、超时、未知结果均 fail-closed。当前实现的待审批状态保存在内存中；服务重启会使未完成请求安全拒绝。
