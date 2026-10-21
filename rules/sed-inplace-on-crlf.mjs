import fs from 'node:fs';
import path from 'node:path';
import { segments, tokens } from '../src/shell.mjs';

function resolveFile(p, cwd) {
  try {
    return path.resolve(cwd || process.cwd(), p.replace(/^~(?=[\\/])/, process.env.HOME || process.env.USERPROFILE || ''));
  } catch {
    return null;
  }
}

function hasCRLF(file) {
  try {
    const fd = fs.openSync(file, 'r');
    const buf = Buffer.alloc(65536);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    fs.closeSync(fd);
    return buf.subarray(0, n).includes('\r\n');
  } catch {
    return false;
  }
}

export function insideGit(p) {
  try {
    let d = path.dirname(path.resolve(p));
    for (let i = 0; i < 40; i++) {
      if (fs.existsSync(path.join(d, '.git'))) return true;
      const up = path.dirname(d);
      if (up === d) break;
      d = up;
    }
  } catch {
    // ignore
  }
  return false;
}

/** Files named on a `sed -i` invocation. Exported for tests. */
export function sedInPlaceTargets(command) {
  const out = [];
  for (const seg of segments(command)) {
    const tk = tokens(seg);
    const i = tk.findIndex((t) => !t.q && /^(?:\S*[\\/])?sed(?:\.exe)?$/i.test(t.v));
    if (i < 0) continue;
    const rest = tk.slice(i + 1);
    const inPlace = rest.some((t) => !t.q && (/^--in-place/.test(t.v) || (/^-[a-zA-Z]+$/.test(t.v) && /i/.test(t.v)) || /^-i[.\w]*$/.test(t.v)));
    if (!inPlace) continue;
    let sawExpr = false;
    for (let k = 0; k < rest.length; k++) {
      const t = rest[k];
      if (!t.q && /^-/.test(t.v)) {
        if (/^-[ef]$/.test(t.v) || t.v === '--expression' || t.v === '--file') { k++; sawExpr = true; }
        continue;
      }
      if (!sawExpr && (t.q || /^(?:\d+(?:,\d+)?)?[sydpaicg]?[\/|#,!]/.test(t.v))) { sawExpr = true; continue; }
      if (/[\\/]|\.\w{1,6}$/.test(t.v)) out.push(t.v);
    }
  }
  return out;
}

export default {
  id: 'sed-inplace-on-crlf',
  title: 'sed -i on a CRLF file inside a git repo',
  tools: /^(?:Bash)$/,
  incident:
    'On 2026-10-02 four HTML files in a Windows project were edited with `sed -i` to change six strings. GNU sed 4.9 rewrote every line ending from CRLF to LF; the pull request showed 347 changed lines for 6 real changes and the review was useless. Measured again on 2026-10-12: same behavior.',
  check(input, ctx) {
    const targets = sedInPlaceTargets(input.command);
    if (!targets.length) return null;
    if (ctx.fs === false) return { reason: 'candidate (no disk access)', fix: '', excerpt: targets.join(', ') };
    const hit = targets.map((t) => resolveFile(t, input.cwd)).filter((p) => p && fs.existsSync(p) && hasCRLF(p) && insideGit(p));
    if (!hit.length) return null;
    return {
      reason: `${hit.map((p) => path.basename(p)).join(', ')} uses CRLF line endings and lives in a git repository. sed -i rewrites the whole file with LF and the diff becomes every line.`,
      fix: 'Edit with the agent\'s Edit tool (it preserves line endings), or with a script that reads and writes the whole file preserving bytes (node: split/join on the buffer; python: open(..., newline=\'\')). If converting to LF is the intent, say so with the override.',
      excerpt: targets.join(', '),
    };
  },
};
