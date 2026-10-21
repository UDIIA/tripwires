// Append-only log of what the rules did: `<stateDir>/log.jsonl`, one JSON object per line.
//
//   { ts, ms, kind: "deny" | "allow" | "error", rule, tool, agent, session, excerpt }
//
// `ms` is the time from process start to the decision, Node start-up included: that is what the agent waits.
// Test suites set TRIPWIRES_TEST=1 and nothing is written, so the weekly report only counts real sessions.
import fs from 'node:fs';
import path from 'node:path';

export function logPath(stateDir) {
  return path.join(stateDir, 'log.jsonl');
}

export function record(stateDir, entry) {
  if (process.env.TRIPWIRES_TEST === '1') return;
  try {
    fs.mkdirSync(stateDir, { recursive: true });
    const row = { ts: new Date().toISOString(), ms: Math.round(performance.now()), ...entry };
    if (row.excerpt) row.excerpt = String(row.excerpt).replace(/\s+/g, ' ').slice(0, 200);
    fs.appendFileSync(logPath(stateDir), JSON.stringify(row) + '\n');
  } catch {
    // logging never blocks the agent
  }
}

/** Read the log, newest last. Lines that fail to parse are skipped. */
export function readLog(stateDir, { since } = {}) {
  let text = '';
  try {
    text = fs.readFileSync(logPath(stateDir), 'utf8');
  } catch {
    return [];
  }
  const out = [];
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    try {
      const r = JSON.parse(line);
      if (!since || r.ts >= since) out.push(r);
    } catch {
      // skip
    }
  }
  return out;
}
