#!/usr/bin/env node
import { startApprovalAdapter } from '../src/server.mjs';

const args = process.argv.slice(2);
const value = (name, fallback) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : fallback;
};

const runtime = await startApprovalAdapter({
  host: value('--host', '127.0.0.1'),
  port: Number(value('--port', 3099)),
  ttlMs: Number(value('--ttl-ms', 300000)),
  token: value('--token', '')
});
console.log(`[dsh-escrow-approval-adapter] listening at ${runtime.url}`);
console.log('[dsh-escrow-approval-adapter] MVP choices: allowed-once / rejected; fail-closed on timeout.');

const stop = async () => {
  await runtime.close();
  process.exit(0);
};
process.once('SIGINT', stop);
process.once('SIGTERM', stop);
