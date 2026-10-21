// Masked reader for files that hold credentials: prints the structure and the shape of each value.
//
// Masking by key name repeats the leak (TEL_SALT and trusted_devices have no "token" in their names), so the rule
// is inverted: everything is masked except what is structural for sure: a file path, a boolean, a short number,
// a known structural key whose value does not look like a secret, a short string with no digits. URL user info
// is never printed. Supports JSON and line-oriented key=value / TOML / .env files.
//
// This is a convenience for keeping values out of transcripts, not a guarantee; see SECURITY.md.
import fs from 'node:fs';
import path from 'node:path';

const STRUCTURAL_KEYS = new Set(['type', 'matcher', 'command', 'timeout', 'hookEventName', 'model', 'effort', 'enabled', 'status', 'version', 'mode', 'defaultMode', 'outputStyle', 'allow', 'deny', 'ask', 'publish', 'functions', 'node_bundler', 'package', 'force', 'conditions', 'role', 'provider', 'approval_policy', 'sandbox_mode', 'model_reasoning_effort', 'preferred_auth_method', 'theme', 'lang', 'language', 'name', 'env', 'build', 'base', 'dir']);
const STRUCTURAL_PARENTS = new Set(['allow', 'deny', 'ask', 'hooks', 'matcher', 'args', 'enabledPlugins', 'plugins', 'files', 'include', 'exclude']);
const SENSITIVE = /(token|secret|key|senha|passw|pass$|auth|salt|pin|cookie|session|private|cred|^from$|^to$|url|webhook|slug|dsn|conn|trusted|device|id$|email|phone|tel|account|user$)/i;
// A "structural" value that carries a credential anyway: a bearer, a key=value with a long value, a long token-like run.
const LOOKS_SECRET = /bearer\s+\S|(?:token|secret|key|passw|auth)\w*\s*[=:]\s*\S|[A-Za-z0-9+/=_-]{24,}|\d{6,}/i;
const isPath = (s) => /^(?:[A-Za-z]:[\\/]|~[\\/]|\/(?:c|d|e|mnt|home|usr|etc|tmp|opt|var)\/|\.{0,2}[\\/])[^\s?#]*$/.test(s) && !/(token|secret|key)=/i.test(s);

function urlHost(v) {
  try {
    return new URL(v).host; // host never includes user:password
  } catch {
    return '?';
  }
}

function mask(key, v) {
  if (v === null || typeof v === 'boolean') return String(v);
  if (typeof v === 'number') return Math.abs(v) < 10000 ? String(v) : `(number, ${String(v).length} digits)`;
  if (typeof v !== 'string') return String(v);
  const k = String(key ?? '');
  if (STRUCTURAL_KEYS.has(k) && !LOOKS_SECRET.test(v)) return JSON.stringify(v.length > 160 ? v.slice(0, 157) + '…' : v);
  if (isPath(v) && !LOOKS_SECRET.test(v)) return JSON.stringify(v);
  if (!SENSITIVE.test(k) && v.length <= 12 && !/\d{3,}/.test(v) && /^[\p{L}\s_./-]*$/u.test(v)) return JSON.stringify(v);
  const kind = /^https?:\/\//i.test(v) ? 'url' : /^\d+$/.test(v) ? 'numeric' : /^[A-Za-z0-9+/=_-]{20,}$/.test(v) ? 'token-like' : /^[0-9a-f-]{32,}$/i.test(v) ? 'hex/uuid' : 'text';
  const hint = kind === 'url' ? ` host=${urlHost(v)}` : '';
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
  lines.push(`# ${file} (${text.length} bytes, masked: value shapes, not values)`);
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
      if (STRUCTURAL_PARENTS.has(parent) && typeof obj === 'string' && obj.length <= 120 && !LOOKS_SECRET.test(obj)) {
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
    const shown = v === '' ? '(empty)' : /^(true|false)$/i.test(v) ? v : /^-?\d{1,4}(\.\d+)?$/.test(v) ? v : /^\[.*\]$/.test(v) ? `[list, ${v.split(',').length} items]` : mask(k, v);
    out(`  ${k} = ${shown}`);
  }
  return lines.join('\n');
}
