// Hook entry point: reads the PreToolUse payload on stdin, prints a denial or nothing.
// Exit code is 0 either way (the JSON carries the decision). Exit 2 with the reason on stderr is the fallback
// when stdout cannot be used.
import { evaluate, denialJson } from './engine.mjs';
import { loadConfig } from './config.mjs';

export async function runHook({ stdin = process.stdin, stdout = process.stdout, stderr = process.stderr } = {}) {
  let raw = '';
  let config = null;
  try {
    for await (const chunk of stdin) raw += chunk;
    const payload = JSON.parse(raw);
    config = loadConfig({ cwd: payload.cwd });
    const r = await evaluate(payload, { config });
    if (!r) return 0;
    stdout.write(denialJson(r.message) + '\n');
    return 0;
  } catch (e) {
    const closed = (config && config.failClosed) || process.env.TRIPWIRES_FAIL_CLOSED === '1';
    if (closed) {
      stderr.write(`[tripwires] engine error, failing closed: ${e && e.message}\n`);
      return 2;
    }
    return 0;
  }
}
