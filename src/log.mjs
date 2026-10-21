// Append-only log of what the rules did: `<stateDir>/log.jsonl`, one JSON object per line.
//
//   { ts, ms, kind: "deny" | "allow" | "error", rule, tool, agent, session, excerpt }
//
// Only decisions are logged (a denial, an override, a rule or loader error); a call that passes every rule
// writes nothing. `ms` is the time from process start to that decision, Node start-up included: it is what the
// agent waited on that call, not the cost of one rule. Excerpts are redacted (tokens, passwords, URL
// credentials) and cut at 200 characters. Test suites set TRIPWIRES_TEST=1 and nothing is written, so the
// weekly report only counts real sessions.
import fs from 'node:fs';
import path from 'node:path';
import { redact } from './shell.mjs';

export function logPath(stateDir) {
  return path.join(stateDir, 'log.jsonl');
}

export function record(stateDir, entry) {
  if (process.env.TRIPWIRES_TEST === '1') return;
  try {
    fs.mkdirSync(stateDir, { recursive: true });
    const row = { ts: new Date().toISOString(), ms: Math.round(performance.now()), ...entry };
    if (row.excerpt) row.excerpt = redact(String(row.excerpt).replace(/\s+/g, ' ')).slice(0, 200);
    if (row.because) row.because = String(row.because).slice(0, 200);
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
