// Configuration: a small JSON file, merged from home and project.
//
//   ~/.tripwires/config.json          user-wide
//   <cwd>/.tripwires.json             per project (walks up to the git root)
//   $TRIPWIRES_CONFIG                 explicit path, replaces both
//
// Shape:
//   {
//     "off": ["rule-id", ...],          rules switched off (they still exist, they just never fire)
//     "rules": ["./my-rules", ...],     extra rule files or directories, relative to the config file
//     "failClosed": false,              deny when the engine itself throws (default: let the call through)
//     "stateDir": "~/.tripwires"        where the log and one-shot overrides live
//   }
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const HOME = os.homedir();
export const DEFAULT_STATE_DIR = path.join(HOME, '.tripwires');

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function expandHome(p) {
  return String(p).replace(/^~(?=$|[\\/])/, HOME);
}

function resolveRules(list, base) {
  return (Array.isArray(list) ? list : []).map((p) => path.resolve(base, expandHome(p)));
}

/** Find `.tripwires.json` in cwd or any parent, stopping at the filesystem root. */
export function findProjectConfig(cwd) {
  let dir = path.resolve(cwd || process.cwd());
  for (let i = 0; i < 60; i++) {
    const f = path.join(dir, '.tripwires.json');
    if (fs.existsSync(f)) return f;
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return null;
}

/** Merged config. Project `off` and `rules` are added to the user's, never replace them. */
export function loadConfig({ cwd, env = process.env } = {}) {
  const cfg = { off: new Set(), rules: [], failClosed: false, stateDir: DEFAULT_STATE_DIR, sources: [] };
  const apply = (file) => {
    const j = readJson(file);
    if (!j) return;
    cfg.sources.push(file);
    for (const id of Array.isArray(j.off) ? j.off : []) cfg.off.add(String(id));
    cfg.rules.push(...resolveRules(j.rules, path.dirname(file)));
    if (typeof j.failClosed === 'boolean') cfg.failClosed = j.failClosed;
    if (typeof j.stateDir === 'string' && j.stateDir) cfg.stateDir = path.resolve(path.dirname(file), expandHome(j.stateDir));
  };
  if (env.TRIPWIRES_CONFIG) {
    apply(env.TRIPWIRES_CONFIG);
  } else {
    apply(path.join(HOME, '.tripwires', 'config.json'));
    const project = findProjectConfig(cwd);
    if (project) apply(project);
  }
  if (env.TRIPWIRES_STATE_DIR) cfg.stateDir = env.TRIPWIRES_STATE_DIR;
  if (env.TRIPWIRES_FAIL_CLOSED === '1') cfg.failClosed = true;
  return cfg;
}
