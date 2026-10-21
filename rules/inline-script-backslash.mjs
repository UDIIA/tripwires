// Windows only. Claude Code's Bash tool on Windows hands a double backslash to the shell as a single one, so an
// inline script (`node -e`, `python -c`, a heredoc, `printf`) that contains `\\` runs with different source than
// the agent wrote, and fails silently or does the wrong thing. The check simulates what bash hands the program for
// the text as written and for the text with `\\` collapsed; it denies only when the two differ outside comments.

const collapse = (s) => s.replace(/\\\\/g, '\\');

// What bash delivers to the program: strips quotes and treats backslashes by context. null = unclosed quote.
function bash(s) {
  let out = '';
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === "'") {
      const f = s.indexOf("'", i + 1);
      if (f < 0) return null;
      out += s.slice(i + 1, f);
      i = f + 1;
      continue;
    }
    if (c === '"') {
      let k = i + 1;
      let closed = false;
      while (k < s.length) {
        if (s[k] === '"') { closed = true; k++; break; }
        if (s[k] === '\\' && k + 1 < s.length && '$`"\\\n'.includes(s[k + 1])) { if (s[k + 1] !== '\n') out += s[k + 1]; k += 2; continue; }
        out += s[k++];
      }
      if (!closed) return null;
      i = k;
      continue;
    }
    if (c === '\\') { if (i + 1 < s.length && s[i + 1] !== '\n') out += s[i + 1]; i += 2; continue; }
    out += c;
    i++;
  }
  return out;
}
function bashHeredoc(s) {
  let out = '';
  for (let k = 0; k < s.length; k++) {
    if (s[k] === '\\' && k + 1 < s.length && '$`\\\n'.includes(s[k + 1])) { if (s[k + 1] !== '\n') out += s[k + 1]; k++; }
    else out += s[k];
  }
  return out;
}

const OPENS = /(?:^|[\s;&|(])(?:node(?:\.exe)?\s(?:[^|;&'"\n]*?\s)?(?:-e|--eval|-p|--print)(?:=|\s+)|(?:python(?:3|\.exe)?|py)\s(?:[^|;&'"\n]*?\s)?-c\s+)/g;
const TEXT = /(?:^|[\s;&|(])(?:printf|echo\s+-e)\b/g;
const HEREDOC = /<<-?\s*(['"]?)(\w+)\1[^\n]*\n([\s\S]*?)\n\s*\2\s*(\n|$)/g;

function argEnd(cmd, i) {
  const q = cmd[i];
  if (q === "'") { const f = cmd.indexOf("'", i + 1); return f < 0 ? cmd.length : f + 1; }
  if (q === '"') { let k = i + 1; while (k < cmd.length && cmd[k] !== '"') k += cmd[k] === '\\' ? 2 : 1; return Math.min(k + 1, cmd.length); }
  const f = cmd.slice(i).search(/[\s;&|]/);
  return f < 0 ? cmd.length : i + f;
}
function cmdEnd(cmd, i) {
  let k = i;
  while (k < cmd.length) {
    const c = cmd[k];
    if (c === "'") { const f = cmd.indexOf("'", k + 1); k = f < 0 ? cmd.length : f + 1; continue; }
    if (c === '"') { k = argEnd(cmd, k); continue; }
    if (c === '\\') { k += 2; continue; }
    if ('|;&\n'.includes(c)) break;
    k++;
  }
  return k;
}
function pieces(cmd) {
  const out = [];
  let m;
  OPENS.lastIndex = 0;
  while ((m = OPENS.exec(cmd))) { const s = m.index + m[0].length; out.push({ kind: 'script', text: cmd.slice(s, argEnd(cmd, s)) }); }
  TEXT.lastIndex = 0;
  while ((m = TEXT.exec(cmd))) out.push({ kind: 'text', text: cmd.slice(m.index, cmdEnd(cmd, m.index + m[0].length)) });
  HEREDOC.lastIndex = 0;
  while ((m = HEREDOC.exec(cmd))) out.push({ kind: m[1] ? 'heredoc-literal' : 'heredoc', text: m[3] });
  return out;
}
const stripComments = (s) => s.replace(/(^|[^\\])\/\*[\s\S]*?\*\//g, '$1').replace(/^[ \t]*(\/\/|#).*$/gm, '');
const deliver = (p, s) => (p.kind === 'heredoc-literal' ? s : p.kind === 'heredoc' ? bashHeredoc(s) : bash(s));
function escapes(s) {
  let out = '';
  for (let k = 0; k < s.length; k++) {
    if (s[k] !== '\\' || k + 1 >= s.length) { out += s[k]; continue; }
    const x = s[++k];
    out += x === '\\' ? '\\' : /[abcefnrtvEuUx0-7"'?]/.test(x) ? '\u0000' + x : '\\' + x;
  }
  return out;
}
function breaks(p) {
  const a = deliver(p, p.text);
  const b = deliver(p, collapse(p.text));
  if (a === b) return false;
  if (a === null || b === null) return true;
  return p.kind === 'text' ? escapes(a) !== escapes(b) : stripComments(a) !== stripComments(b);
}

/** Exported for tests: `{ deny, excerpt }`. */
export function inlineBackslashBreaks(cmd) {
  if (!cmd || !cmd.includes('\\\\')) return { deny: false };
  const hit = pieces(cmd).find((p) => p.text.includes('\\\\') && breaks(p));
  if (!hit) return { deny: false };
  return { deny: true, excerpt: (hit.text.match(/.{0,30}\\\\.{0,30}/) || [''])[0] };
}

export default {
  id: 'inline-script-backslash',
  title: 'Inline script with a double backslash (Windows Bash tool)',
  tools: /^(?:Bash)$/,
  platforms: ['win32'],
  incident:
    'On 2026-10-04 the same session broke four inline Python scripts in a row with a Windows path in a string: the tool collapsed `C:\\\\Users` to `C:\\Users`, Python read `\\U` as a unicode escape and died, and the agent retried with cosmetic variations. A memory note about the behavior was loaded in that session; it did not help. The rule did: 403 denials in 168 sessions over the next 17 days, each one a retry loop that did not happen.',
  check(input) {
    const r = inlineBackslashBreaks(input.command);
    if (!r.deny) return null;
    return {
      reason: `the Bash tool hands a double backslash to the shell as a single one, and the program receives different source than you wrote (near: ${r.excerpt}).`,
      fix: 'Write the script to a file with the Write tool (it stores the exact text), then run `node <file>` or `python -X utf8 <file>` with the data as arguments. Another inline variation lands on the same rule.',
      excerpt: r.excerpt,
    };
  },
};
