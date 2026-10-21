import fs from 'node:fs';
import path from 'node:path';
import { segments, tokens, withoutQuotes, withoutComment } from '../src/shell.mjs';

// Production deploys cost money or quota (Netlify bills credits per deploy; Vercel and Cloudflare meter builds),
// and a burst of them is almost always an agent iterating on a live site instead of on a preview.
const PROD_DEPLOY = [
  { host: 'netlify', rx: /(?:^|[\s"'`&(\\/])(?:netlify(?:\.cmd|\.exe)?|ntl)["']?\s+(?:--?[\w-]+(?:[=\s]+[^\s-][^\s]*)?\s+)*?deploy\b[^\n]*(?:^|\s)--prod(?:-if-unlocked)?(?:\s|$|=true)/i },
  { host: 'vercel', rx: /(?:^|[\s"'`&(\\/])vercel(?:\.cmd)?["']?\s+(?:deploy\s+)?[^\n]*(?:^|\s)--prod\b/i },
  { host: 'wrangler', rx: /(?:^|[\s"'`&(\\/])wrangler["']?\s+(?:deploy|publish|pages\s+deploy)\b/i },
  { host: 'firebase', rx: /(?:^|[\s"'`&(\\/])firebase["']?\s+deploy\b/i },
  { host: 'fly', rx: /(?:^|[\s"'`&(\\/])fly(?:ctl)?["']?\s+deploy\b/i },
];
const NOT_A_DEPLOY = /--dry-run\b|--help\b|\s-h\b/i;
const ONLY_TEXT = /^\s*(?:echo|printf|grep|rg|cat|sed|awk|head|tail|less|type|git|Write-Output|Write-Host|#|:)\b/i;

export const LIMITS = { windowMinutes: 30, perTargetPerDay: 3, perDay: 25 };

function findDeploy(command) {
  for (const raw of segments(command)) {
    const seg = withoutComment(raw);
    if (ONLY_TEXT.test(seg) || NOT_A_DEPLOY.test(seg)) continue;
    const bare = withoutQuotes(seg);
    const p = PROD_DEPLOY.find((d) => d.rx.test(bare));
    if (p) return { seg, host: p.host };
  }
  return null;
}

function target(seg, host, cwd) {
  const tk = tokens(seg);
  for (let i = 0; i < tk.length; i++) {
    const m = tk[i].v.match(/^(?:--site|-s|--project|--name|--app|-a)(?:=(.+))?$/);
    if (m) return `${host}:${m[1] ?? (tk[i + 1] ? tk[i + 1].v : '')}`;
  }
  return `${host}:${cwd || ''}`;
}

export function readDeploys(file) {
  try {
    return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  } catch {
    return [];
  }
}

const stateFile = (ctx) => path.join(ctx.stateDir, 'deploys.jsonl');

export default {
  id: 'deploy-burst',
  title: 'Production deploy burst',
  tools: /^(?:Bash|PowerShell|mcp__windows-mcp__PowerShell)$/,
  incident:
    'Measured on 2026-10-18 over one month on one Netlify account: 419 production deploys, 6,285 credits spent on deploys alone (the plan includes 5,000), automatic top-up triggered twice. Three sites had 45 to 80 deploys each; 24 of one site\'s deploys happened within five days, several 2 to 10 minutes apart. The owner\'s words: "we need our system to be smart as to not use credits every time".',
  check(input, ctx) {
    const d = findDeploy(input.command);
    if (!d) return null;
    const key = target(d.seg, d.host, input.cwd);
    const now = ctx.now || new Date();
    const rows = ctx.fs === false ? [] : readDeploys(stateFile(ctx));
    const today = now.toISOString().slice(0, 10);
    const todayRows = rows.filter((r) => String(r.ts).slice(0, 10) === today);
    const sameTarget = todayRows.filter((r) => r.target === key);
    const last = sameTarget.map((r) => new Date(r.ts).getTime()).sort((a, b) => b - a)[0];
    const minutesAgo = last ? Math.round((now.getTime() - last) / 60000) : null;
    let why = null;
    if (minutesAgo !== null && minutesAgo < LIMITS.windowMinutes) why = `the same target was sent to production ${minutesAgo} min ago (window: ${LIMITS.windowMinutes} min)`;
    else if (sameTarget.length >= LIMITS.perTargetPerDay) why = `this target already had ${sameTarget.length} production deploy attempts today (limit ${LIMITS.perTargetPerDay})`;
    else if (todayRows.length >= LIMITS.perDay) why = `${todayRows.length} production deploy attempts today across all targets (limit ${LIMITS.perDay})`;
    if (!why) return null;
    return {
      reason: `${why}. Each production deploy costs quota or money, and a burst means iterating on the live site.`,
      fix: 'Deploy a preview (no --prod) while iterating, test it, then promote once. If this is an emergency fix for something broken in production, the person can say so and you pass with the override, which records their words.',
      excerpt: d.seg.trim(),
    };
  },
  // Runs only when no rule denied the call. What is recorded is the attempt the agent was allowed to make; the
  // deploy itself may still fail, which is why the messages say "attempts".
  onPass(input, ctx) {
    if (ctx.fs === false) return;
    const d = findDeploy(input.command);
    if (!d) return;
    fs.mkdirSync(ctx.stateDir, { recursive: true });
    fs.appendFileSync(stateFile(ctx), JSON.stringify({ ts: (ctx.now || new Date()).toISOString(), target: target(d.seg, d.host, input.cwd), host: d.host, session: input.session }) + '\n');
  },
};
