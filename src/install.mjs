// Install / remove the hook in Claude Code (settings.json) and Codex CLI (hooks.json).
//
// Both agents use the same shape for PreToolUse hooks: an array of { matcher, hooks: [{ type, command, timeout }] }.
// The command is an absolute `node` plus an absolute path to this package, so it works from any cwd and does not
// pay npx start-up on every tool call. Our handlers are recognized by the `tripwires.mjs` marker in the command;
// only those handlers are added or removed, never a whole group that also holds someone else's handler. The file
// is backed up once before the first change.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HOME = os.homedir();
const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'tripwires.mjs');

export const TARGETS = {
  // Claude Code reads its settings from CLAUDE_CONFIG_DIR when it is set (one directory per account), so install there.
  claude: { global: path.join(process.env.CLAUDE_CONFIG_DIR ? path.resolve(process.env.CLAUDE_CONFIG_DIR) : path.join(HOME, '.claude'), 'settings.json'), project: (cwd) => path.join(cwd, '.claude', 'settings.json'), key: 'hooks' },
  codex: { global: path.join(HOME, '.codex', 'hooks.json'), project: (cwd) => path.join(cwd, '.codex', 'hooks.json'), key: 'hooks' },
};

// Tools the built-in rules care about. Anything else never starts the hook process.
export const MATCHERS = {
  claude: ['Bash|PowerShell', 'Read|Write|Edit|MultiEdit|CronCreate|ScheduleWakeup'],
  codex: ['Bash|PowerShell', 'apply_patch|Read|Write|Edit'],
};

const q = (s) => `"${String(s).replace(/"/g, '\\"')}"`;

export function hookCommand(agent, node = process.execPath) {
  return `${q(node)} ${q(BIN)} hook --agent ${agent}`;
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    if (e && e.code === 'ENOENT') return {};
    throw new Error(`${file}: not valid JSON (${e.message}). Fix it or move it aside; nothing was written.`);
  }
}

const isOurs = (h) => h && typeof h.command === 'string' && /tripwires\.mjs/i.test(h.command);

/** Remove our handlers from every group; drop groups left empty; keep everything else byte for byte. */
function withoutOurs(groups) {
  return groups
    .map((g) => (Array.isArray(g.hooks) ? { ...g, hooks: g.hooks.filter((h) => !isOurs(h)) } : g))
    .filter((g) => !Array.isArray(g.hooks) || g.hooks.length > 0);
}

/** Returns { file, changed, entries } without writing when dryRun is set. */
export function install(agent, { scope = 'global', cwd = process.cwd(), dryRun = false, node = process.execPath } = {}) {
  const t = TARGETS[agent];
  if (!t) throw new Error(`unknown agent ${agent}`);
  const file = scope === 'project' ? t.project(cwd) : t.global;
  const json = readJson(file);
  const root = (json[t.key] = json[t.key] && typeof json[t.key] === 'object' ? json[t.key] : {});
  const pre = Array.isArray(root.PreToolUse) ? root.PreToolUse : [];
  const command = hookCommand(agent, node);
  // Codex reads `commandWindows` on Windows; the same absolute command works there, so both are set.
  const handler = agent === 'codex' ? { type: 'command', command, commandWindows: command, timeout: 10, statusMessage: 'tripwires' } : { type: 'command', command, timeout: 10 };
  const wanted = MATCHERS[agent].map((matcher) => ({ matcher, hooks: [{ ...handler }] }));
  const next = [...withoutOurs(pre), ...wanted];
  const changed = JSON.stringify(next) !== JSON.stringify(pre);
  if (changed && !dryRun) {
    root.PreToolUse = next;
    writeWithBackup(file, json);
  }
  return { file, changed, entries: wanted.length, command };
}

export function uninstall(agent, { scope = 'global', cwd = process.cwd(), dryRun = false } = {}) {
  const t = TARGETS[agent];
  const file = scope === 'project' ? t.project(cwd) : t.global;
  if (!fs.existsSync(file)) return { file, changed: false };
  const json = readJson(file);
  const root = json[t.key];
  if (!root || !Array.isArray(root.PreToolUse)) return { file, changed: false };
  const next = withoutOurs(root.PreToolUse);
  const changed = JSON.stringify(next) !== JSON.stringify(root.PreToolUse);
  if (changed && !dryRun) {
    root.PreToolUse = next;
    writeWithBackup(file, json);
  }
  return { file, changed };
}

function writeWithBackup(file, json) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  if (fs.existsSync(file)) {
    const bak = `${file}.bak-tripwires`;
    if (!fs.existsSync(bak)) fs.copyFileSync(file, bak);
  }
  fs.writeFileSync(file, JSON.stringify(json, null, 2) + '\n');
}

/** What is installed where, for `tripwires doctor`. */
export function status({ cwd = process.cwd() } = {}) {
  const out = [];
  for (const agent of Object.keys(TARGETS)) {
    for (const scope of ['global', 'project']) {
      const t = TARGETS[agent];
      const file = scope === 'project' ? t.project(cwd) : t.global;
      let installed = false;
      let exists = fs.existsSync(file);
      if (exists) {
        try {
          const json = readJson(file);
          const root = json[t.key];
          installed = !!(root && Array.isArray(root.PreToolUse) && root.PreToolUse.some((g) => Array.isArray(g.hooks) && g.hooks.some(isOurs)));
        } catch {
          exists = 'invalid';
        }
      }
      out.push({ agent, scope, file, exists, installed });
    }
  }
  return out;
}
