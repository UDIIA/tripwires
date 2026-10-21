// The engine: load rules, normalize the hook input, ask each rule, honor overrides, log, format the denial.
//
// A rule is a module whose default export is:
//   {
//     id: 'kill-by-name',                       // stable, kebab-case; appears in the log and in overrides
//     title: 'Process killed by image name',    // one line
//     tools: /^(Bash|PowerShell)$/,             // RegExp or string[] matched against tool_name
//     platforms: ['win32'],                     // optional; rule is skipped elsewhere
//     incident: '...',                          // what happened, when, how often: the reason the rule exists
//     check(input, ctx) { return null | { reason, fix, excerpt? } },
//     onPass(input, ctx) { }                    // optional bookkeeping, run only when NO rule denied the call
//   }
//
// `input` is the hook payload plus a few derived fields (see normalizeInput). `ctx` carries the clock, the
// platform, the state directory, a `fs` switch so tests can run rules without touching the disk, and `probe`
// (true for `tripwires try`, where nothing should be recorded).
//
// Failure policy: a rule file that fails to load is skipped and logged; the others still run. A rule that
// throws is skipped and logged. The engine itself failing lets the call through, unless `failClosed` is set.
// A guardrail that crashes the session gets removed by its user within a day.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { loadConfig } from './config.mjs';
import { record } from './log.mjs';
import * as shell from './shell.mjs';

const { hasAllowToken } = shell;

export const BUILTIN_RULES_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'rules');

function listRuleFiles(p) {
  let st;
  try {
    st = fs.statSync(p);
  } catch {
    return [];
  }
  if (st.isFile()) return /\.(?:mjs|js|cjs)$/.test(p) && !/\.test\.\w+$/.test(p) ? [p] : [];
  return fs.readdirSync(p)
    .filter((f) => /\.(?:mjs|js|cjs)$/.test(f) && !/\.test\.\w+$/.test(f) && !f.startsWith('_'))
    .sort()
    .map((f) => path.join(p, f));
}

function validRule(r, file) {
  if (!r || typeof r !== 'object') throw new Error(`${file}: default export is not a rule object`);
  if (!/^[a-z0-9][a-z0-9-]*$/.test(String(r.id))) throw new Error(`${file}: rule id must be kebab-case, got ${JSON.stringify(r.id)}`);
  if (typeof r.check !== 'function') throw new Error(`${file}: rule ${r.id} has no check()`);
  if (!(r.tools instanceof RegExp) && !Array.isArray(r.tools)) throw new Error(`${file}: rule ${r.id} needs tools (RegExp or string[])`);
  return r;
}

/**
 * Load built-in rules plus the ones named in the config. `off` rules are returned too, flagged, so `list` can
 * show them. A file that fails to load does not stop the others: it is reported in `errors` (and logged by
 * `evaluate`). Pass `{ strict: true }` to throw instead (the CLI does, so a broken rule is visible).
 */
export async function loadRules(config = loadConfig(), { builtin = true, strict = false } = {}) {
  const files = [...(builtin ? listRuleFiles(BUILTIN_RULES_DIR) : []), ...config.rules.flatMap(listRuleFiles)];
  const rules = [];
  const errors = [];
  const seen = new Set();
  for (const file of files) {
    try {
      const mod = await import(pathToFileURL(file).href);
      const rule = validRule(mod.default, file);
      if (seen.has(rule.id)) throw new Error(`duplicate rule id ${rule.id} (${file})`);
      seen.add(rule.id);
      rules.push({ ...rule, file, off: config.off.has(rule.id) });
    } catch (e) {
      if (strict) throw e;
      errors.push({ file, message: String(e && e.message) });
    }
  }
  Object.defineProperty(rules, 'errors', { value: errors, enumerable: false });
  return rules;
}

/** Added lines and target file of a Codex `apply_patch` payload. */
function parsePatch(patch) {
  const files = [];
  const added = [];
  for (const line of String(patch).split(/\r?\n/)) {
    const f = line.match(/^\*\*\* (?:Add|Update|Delete) File: (.+)$/);
    if (f) files.push(f[1].trim());
    else if (line.startsWith('+') && !line.startsWith('+++')) added.push(line.slice(1));
  }
  return { file: files[0] || '', text: added.join('\n') };
}

/** Hook payload → the shape rules read. Works for Claude Code and Codex CLI payloads. */
export function normalizeInput(raw) {
  const ti = raw?.tool_input && typeof raw.tool_input === 'object' ? raw.tool_input : {};
  const tool = String(raw?.tool_name ?? '');
  let command = String(ti.command ?? ti.cmd ?? ti.script ?? '');
  let file = String(ti.file_path ?? ti.path ?? ti.filePath ?? '');
  let text = '';
  if (typeof ti.content === 'string') text = ti.content;
  else if (typeof ti.new_string === 'string') text = ti.new_string;
  else if (Array.isArray(ti.edits)) text = ti.edits.map((e) => (e && typeof e.new_string === 'string' ? e.new_string : '')).join('\n');
  if (tool === 'apply_patch') {
    // Codex sends the patch in tool_input.command (also `patch` / `input` in some builds). It is an edit, not a shell command.
    const patch = String(ti.patch ?? ti.input ?? ti.command ?? '');
    const p = parsePatch(patch);
    command = '';
    if (!file) file = p.file;
    if (!text) text = p.text;
  }
  return {
    tool,
    tool_input: ti,
    command,
    file,
    text,
    cwd: String(raw?.cwd ?? process.cwd()),
    session: String(raw?.session_id ?? ''),
    transcript: raw?.transcript_path ? String(raw.transcript_path) : '',
    event: String(raw?.hook_event_name ?? 'PreToolUse'),
    raw: raw ?? {},
  };
}

function toolMatches(rule, tool) {
  if (rule.tools instanceof RegExp) return rule.tools.test(tool);
  return rule.tools.includes(tool) || rule.tools.includes('*');
}

/** One-shot override file written by `tripwires allow <id> --because "..."`. Consumed (deleted) when used. */
export function allowFile(stateDir, id) {
  return path.join(stateDir, 'allow', `${String(id).replace(/[^\w-]/g, '_')}.json`);
}

function consumeAllow(stateDir, id) {
  const f = allowFile(stateDir, id);
  try {
    const j = JSON.parse(fs.readFileSync(f, 'utf8'));
    fs.unlinkSync(f);
    return j;
  } catch {
    return null;
  }
}

export function formatDenial(rule, r) {
  const lines = [
    `[tripwires] ${rule.id}: ${rule.title}.`,
    `Why: ${String(r.reason).trim()}`,
  ];
  if (r.fix) lines.push(`Fix: ${String(r.fix).trim()}`);
  lines.push(`Override (visible, logged): start the command with TRIPWIRES_ALLOW=${rule.id}, or run \`tripwires allow ${rule.id} --because "<the person's own words>"\` for a one-shot pass.`);
  return lines.join('\n');
}

/**
 * Evaluate one hook payload. Returns null (let it through) or
 * `{ rule, reason, fix, excerpt, message }` where `message` is the text the agent will read.
 */
export async function evaluate(raw, { rules, config, now = new Date(), platform = process.platform, fsAccess = true, log = true, probe = false } = {}) {
  config = config || loadConfig({ cwd: raw?.cwd });
  rules = rules || (await loadRules(config));
  const input = normalizeInput(raw);
  // `shell` rides along so a rule file outside this package can use the helpers without importing them.
  const ctx = { now, platform, stateDir: config.stateDir, fs: fsAccess, probe, config, env: process.env, shell };
  const agent = process.env.TRIPWIRES_AGENT || (input.raw.turn_id ? 'codex' : 'claude');
  if (log && Array.isArray(rules.errors)) {
    for (const e of rules.errors) record(config.stateDir, { kind: 'error', rule: 'loader', tool: input.tool, agent, session: input.session, excerpt: `${e.file}: ${e.message}` });
  }
  if (log && config.untrustedRules && config.untrustedRules.length && !evaluate.warnedUntrusted) {
    evaluate.warnedUntrusted = true;
    record(config.stateDir, { kind: 'error', rule: 'loader', tool: input.tool, agent, session: input.session, excerpt: `project rules not loaded (run \`tripwires trust\` in the project): ${config.untrustedRules.join(', ')}` });
  }
  const passed = [];
  for (const rule of rules) {
    if (rule.off) continue;
    if (!toolMatches(rule, input.tool)) continue;
    if (Array.isArray(rule.platforms) && !rule.platforms.includes(platform)) continue;
    let r = null;
    try {
      r = rule.check(input, ctx);
    } catch (e) {
      if (log) record(config.stateDir, { kind: 'error', rule: rule.id, tool: input.tool, agent, session: input.session, excerpt: String(e && e.message) });
      continue;
    }
    if (!r) {
      passed.push(rule);
      continue;
    }
    const excerpt = r.excerpt || input.command || input.file || '';
    if (hasAllowToken(input.command, rule.id)) {
      if (log) record(config.stateDir, { kind: 'allow', how: 'token', rule: rule.id, tool: input.tool, agent, session: input.session, excerpt });
      continue;
    }
    const pass = fsAccess && !probe ? consumeAllow(config.stateDir, rule.id) : null;
    if (pass) {
      if (log) record(config.stateDir, { kind: 'allow', how: 'one-shot', because: String(pass.because || ''), rule: rule.id, tool: input.tool, agent, session: input.session, excerpt });
      continue;
    }
    if (log) record(config.stateDir, { kind: 'deny', rule: rule.id, tool: input.tool, agent, session: input.session, excerpt });
    return { rule: rule.id, reason: r.reason, fix: r.fix, excerpt, message: formatDenial(rule, r) };
  }
  // Nothing denied: rules with bookkeeping (deploy-burst records the deploy) run it now, never before the decision.
  if (!probe) {
    for (const rule of passed) {
      if (typeof rule.onPass !== 'function') continue;
      try {
        rule.onPass(input, ctx);
      } catch (e) {
        if (log) record(config.stateDir, { kind: 'error', rule: rule.id, tool: input.tool, agent, session: input.session, excerpt: String(e && e.message) });
      }
    }
  }
  return null;
}

/** The JSON both Claude Code and Codex CLI accept on stdout to deny a PreToolUse call. */
export function denialJson(message) {
  return JSON.stringify({
    hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: message },
  });
}
