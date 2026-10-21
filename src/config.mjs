// Configuration: a small JSON file, merged from home and project.
//
//   ~/.tripwires/config.json          user-wide
//   <cwd>/.tripwires.json             per project (walks up to the filesystem root)
//   $TRIPWIRES_CONFIG                 explicit path, replaces both
//
// Shape:
//   {
//     "off": ["rule-id", ...],          rules switched off (they still exist, they just never fire)
//     "rules": ["./my-rules", ...],     extra rule files or directories, relative to the config file
//     "trust": ["/abs/project", ...],   (user config only) projects whose .tripwires.json may load rule CODE
//     "failClosed": false,              deny when the engine itself throws (default: let the call through)
//     "stateDir": "~/.tripwires"        where the log and one-shot overrides live
//   }
//
// A rule file is JavaScript that runs inside the hook, with the hook's file and environment access. A project
// config found in a cloned repository therefore cannot add rule code on its own: its `rules` entries are ignored
// until the project directory is listed in `trust` of the user config (`tripwires trust` adds the current one).
// Its `off` list applies regardless; switching a rule off runs nothing.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const HOME = os.homedir();
export const DEFAULT_STATE_DIR = path.join(HOME, '.tripwires');
export const USER_CONFIG = path.join(DEFAULT_STATE_DIR, 'config.json');

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

const norm = (p) => path.resolve(expandHome(p)).replace(/[\\/]+$/, '').toLowerCase();

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
  const cfg = { off: new Set(), rules: [], trust: [], failClosed: false, stateDir: DEFAULT_STATE_DIR, sources: [], untrustedRules: [] };
  const apply = (file, { project = false } = {}) => {
    const j = readJson(file);
    if (!j) return;
    cfg.sources.push(file);
    for (const id of Array.isArray(j.off) ? j.off : []) cfg.off.add(String(id));
    if (!project && Array.isArray(j.trust)) cfg.trust.push(...j.trust.map(norm));
    const rules = resolveRules(j.rules, path.dirname(file));
    if (project && !cfg.trust.includes(norm(path.dirname(file)))) cfg.untrustedRules.push(...rules);
    else cfg.rules.push(...rules);
    if (typeof j.failClosed === 'boolean') cfg.failClosed = j.failClosed;
    if (typeof j.stateDir === 'string' && j.stateDir && !project) cfg.stateDir = path.resolve(path.dirname(file), expandHome(j.stateDir));
  };
  if (env.TRIPWIRES_CONFIG) {
    apply(env.TRIPWIRES_CONFIG);
  } else {
    apply(USER_CONFIG);
    const project = findProjectConfig(cwd);
    if (project) apply(project, { project: true });
  }
  if (env.TRIPWIRES_STATE_DIR) cfg.stateDir = env.TRIPWIRES_STATE_DIR;
  if (env.TRIPWIRES_FAIL_CLOSED === '1') cfg.failClosed = true;
  return cfg;
}

/** Add a project directory to `trust` in the user config. Returns the file written. */
export function trustProject(dir) {
  const j = readJson(USER_CONFIG) || {};
  const trust = new Set(Array.isArray(j.trust) ? j.trust : []);
  trust.add(path.resolve(dir));
  j.trust = [...trust];
  fs.mkdirSync(path.dirname(USER_CONFIG), { recursive: true });
  fs.writeFileSync(USER_CONFIG, JSON.stringify(j, null, 2) + '\n');
  return USER_CONFIG;
}
