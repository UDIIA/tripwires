// Masked reader for files that hold credentials: prints the structure, never a whole value.
//
// Masking by key name repeats the leak (TEL_SALT and trusted_devices have no "token" in their names), so the rule
// is inverted: everything is masked except what is structural for sure (a file path, a boolean, a number, a known
// structural key, a short string with no digits). Supports JSON and line-oriented key=value / TOML / .env files.
import fs from 'node:fs';
import path from 'node:path';

const STRUCTURAL_KEYS = new Set(['type', 'matcher', 'command', 'timeout', 'hookEventName', 'model', 'effort', 'enabled', 'status', 'version', 'mode', 'defaultMode', 'outputStyle', 'allow', 'deny', 'ask', 'publish', 'functions', 'node_bundler', 'package', 'force', 'conditions', 'role', 'provider', 'approval_policy', 'sandbox_mode', 'model_reasoning_effort', 'preferred_auth_method', 'theme', 'lang', 'language', 'name', 'env', 'build', 'base', 'dir']);
const STRUCTURAL_PARENTS = new Set(['allow', 'deny', 'ask', 'hooks', 'matcher', 'args', 'enabledPlugins', 'plugins', 'files', 'include', 'exclude']);
const SENSITIVE = /(token|secret|key|senha|passw|pass$|auth|salt|pin|cookie|session|private|cred|^from$|^to$|url|webhook|slug|dsn|conn|trusted|device|id$|email|phone|tel|account|user$)/i;
const isPath = (s) => /^(?:[A-Za-z]:[\\/]|~[\\/]|\/(?:c|d|e|mnt|home|usr|etc|tmp|opt|var)\/|\.{0,2}[\\/])[^\s?#]*$/.test(s) && !/(token|secret|key)=/i.test(s);

function mask(key, v) {
  if (v === null || typeof v === 'boolean' || typeof v === 'number') return String(v);
  if (typeof v !== 'string') return String(v);
  const k = String(key ?? '');
  if (STRUCTURAL_KEYS.has(k) && !/\d{6,}/.test(v)) return JSON.stringify(v.length > 160 ? v.slice(0, 157) + '…' : v);
  if (isPath(v)) return JSON.stringify(v);
  if (!SENSITIVE.test(k) && v.length <= 12 && !/\d{3,}/.test(v) && /^[\p{L}\s_./-]*$/u.test(v)) return JSON.stringify(v);
  const kind = /^https?:\/\//i.test(v) ? 'url' : /^\d+$/.test(v) ? 'numeric' : /^[A-Za-z0-9+/=_-]{20,}$/.test(v) ? 'token-like' : /^[0-9a-f-]{32,}$/i.test(v) ? 'hex/uuid' : 'text';
  const hint = kind === 'url' ? ` host=${v.replace(/^https?:\/\/([^/]+).*$/i, '$1')}` : '';
  return `"${v.slice(0, 2)}"… (${v.length} chars, ${kind}${hint})`;
}

export function peek(file, { max = 400, key = null } = {}) {
  const lines = [];
  let n = 0;
  const out = (s) => {
    if (n++ < max) lines.push(s);
    else if (n === max + 1) lines.push(`… (cut at ${max} lines; --max N for more)`);
  };
  const text = fs.readFileSync(file, 'utf8');
  const base = path.basename(file).toLowerCase();
  lines.push(`# ${file} (${text.length} bytes, masked: values never appear whole)`);
  let json = null;
  if (base.endsWith('.json') || base === '.claude.json') {
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
  }
  if (json !== null) {
    const walk = (obj, pref, k, parent) => {
      if (Array.isArray(obj)) {
        out(`${pref}${k}: [${obj.length}]`);
        obj.forEach((v, i) => walk(v, pref + '  ', `[${i}]`, k));
        return;
      }
      if (obj && typeof obj === 'object') {
        if (k !== undefined) out(`${pref}${k}:`);
        for (const [kk, vv] of Object.entries(obj)) walk(vv, k === undefined ? pref : pref + '  ', kk, k);
        return;
      }
      const keyName = typeof k === 'string' && k.startsWith('[') ? parent : k;
      if (STRUCTURAL_PARENTS.has(parent) && typeof obj === 'string' && obj.length <= 120 && !/\d{6,}/.test(obj)) {
        out(`${pref}${k} = ${JSON.stringify(obj)}`);
        return;
      }
      out(`${pref}${k} = ${mask(keyName, obj)}`);
    };
    let target = json;
    if (key) for (const part of key.split('.')) target = target?.[part];
    walk(target, '', key || undefined);
    return lines.join('\n');
  }
  let section = '';
  for (const rawLine of text.split(/\r?\n/)) {
    const l = rawLine.trimEnd();
    if (!l.trim()) continue;
    if (/^\s*[#;]/.test(l)) {
      out(/[=:]\s*\S{8,}/.test(l) ? '# (comment with a value, hidden)' : l.slice(0, 100));
      continue;
    }
    const sec = l.match(/^\s*\[\[?([^\]]+)\]\]?\s*$/);
    if (sec) {
      section = sec[1];
      out(l.trim());
      continue;
    }
    const kv = l.match(/^\s*(?:export\s+)?([\w.\-\[\]"' ]+?)\s*[=:]\s*(.*)$/);
    if (!kv) {
      out(`  (line without key=value, ${l.length} chars)`);
      continue;
    }
    let [, k, v] = kv;
    k = k.trim().replace(/^["']|["']$/g, '');
    v = v.trim().replace(/^["']|["']$/g, '');
    if (key && !(section + '.' + k).includes(key) && k !== key) continue;
    const shown = v === '' ? '(empty)' : /^(true|false)$/i.test(v) ? v : /^-?\d+(\.\d+)?$/.test(v) ? v : /^\[.*\]$/.test(v) ? `[list, ${v.split(',').length} items]` : mask(k, v);
    out(`  ${k} = ${shown}`);
  }
  return lines.join('\n');
}
