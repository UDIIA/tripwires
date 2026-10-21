// Weekly report: what fired, how often, in how many sessions, and a verdict line to fill in per rule.
//
// This is the maintenance half of the method. A rule that fires on legitimate work three times in a day is
// hurting; a rule that never fires may be unnecessary or may be doing its job (the agent learned). The report
// gives the numbers and the sample excerpts; the verdict is yours, with the session and time as evidence.
import { readLog } from './log.mjs';

export function buildReport(stateDir, { days = 7, rule = null, samples = 6, now = new Date() } = {}) {
  const since = new Date(now.getTime() - days * 86400e3).toISOString();
  const rows = readLog(stateDir, { since });
  const byRule = new Map();
  for (const r of rows) {
    if (!r.rule) continue;
    if (rule && r.rule !== rule) continue;
    if (!byRule.has(r.rule)) byRule.set(r.rule, { deny: [], allow: [], error: [] });
    const g = byRule.get(r.rule);
    (g[r.kind] || g.error).push(r);
  }
  const report = { since, days, total: rows.length, rules: [] };
  for (const [id, g] of [...byRule].sort((a, b) => b[1].deny.length - a[1].deny.length)) {
    const all = [...g.deny, ...g.allow];
    const sessions = new Set(all.map((r) => r.session).filter(Boolean)).size;
    const perDay = {};
    for (const r of g.deny) perDay[r.ts.slice(5, 10)] = (perDay[r.ts.slice(5, 10)] || 0) + 1;
    const ms = g.deny.map((r) => r.ms).filter((n) => Number.isFinite(n)).sort((a, b) => a - b);
    report.rules.push({
      id,
      denies: g.deny.length,
      allows: g.allow.length,
      errors: g.error.length,
      sessions,
      perDay,
      p50ms: ms.length ? ms[Math.floor(ms.length / 2)] : null,
      samples: g.deny.slice(-samples).map((r) => ({ ts: r.ts, session: String(r.session || '').slice(0, 8), tool: r.tool, excerpt: r.excerpt })),
      overrides: g.allow.slice(-3).map((r) => ({ ts: r.ts, how: r.how, because: r.because || '' })),
    });
  }
  return report;
}

export function renderReport(rep) {
  const out = [];
  out.push(`# tripwires report: last ${rep.days} day(s), ${rep.total} log line(s)`);
  if (!rep.rules.length) {
    out.push('', 'Nothing fired. Either the agent did not step on anything, or the hook is not installed: `tripwires doctor` tells which.');
    return out.join('\n');
  }
  for (const r of rep.rules) {
    const days = Object.entries(r.perDay).sort().map(([d, n]) => `${d}=${n}`).join(' ');
    out.push('', `## ${r.id}: ${r.denies} denied, ${r.allows} overridden, ${r.errors} error(s), ${r.sessions} session(s)${r.p50ms != null ? `, p50 ${r.p50ms} ms` : ''}`);
    if (days) out.push(`per day: ${days}`);
    for (const s of r.samples) out.push(`- ${s.ts.slice(5, 16)} ${s.session} ${s.tool} | ${s.excerpt || ''}`);
    for (const o of r.overrides) out.push(`- override ${o.ts.slice(5, 16)} (${o.how})${o.because ? `: "${o.because}"` : ''}`);
    out.push(`- verdict: ______ (helped | hurt | no effect | confounded)  evidence: ______`);
  }
  out.push('', 'One verdict per rule, citing session and time. "hurt" with 3+ wrong denials in a day: narrow the rule and add the real command to its tests. See docs/method.md.');
  return out.join('\n');
}
