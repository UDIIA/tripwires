// Shell-text helpers shared by rules. Pure functions, no I/O.
//
// Rules look at the command the agent is about to run. A naive regex over the whole string is wrong more often
// than it is right: `grep -nE "from|to" netlify.toml` is one command, not two; a heredoc body written to a file is
// data, not a command; `sudo time nohup foo` still starts `foo`. These helpers do that parsing once.

/** Split a command line into simple commands: cuts at `|`, `||`, `;`, `&&` and newlines, never inside quotes. */
export function segments(cmd) {
  const c = String(cmd ?? '');
  const out = [];
  let cur = '';
  let quote = null;
  for (let i = 0; i < c.length; i++) {
    const ch = c[i];
    if (quote) {
      cur += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      cur += ch;
      continue;
    }
    if (ch === '|' || ch === ';' || ch === '\n' || (ch === '&' && c[i + 1] === '&')) {
      out.push(cur);
      cur = '';
      if (ch === '&' || (ch === '|' && c[i + 1] === '|')) i++;
      continue;
    }
    cur += ch;
  }
  out.push(cur);
  return out;
}

/** Tokenize one simple command: `[{ v, q }]` where `q` is true when the token was quoted. */
export function tokens(segment) {
  const s = String(segment ?? '');
  const out = [];
  let i = 0;
  while (i < s.length) {
    if (/\s/.test(s[i])) { i++; continue; }
    let v = '';
    let q = false;
    while (i < s.length && !/\s/.test(s[i])) {
      const ch = s[i];
      if (ch === "'" || ch === '"') {
        q = true;
        const end = s.indexOf(ch, i + 1);
        if (end < 0) { v += s.slice(i + 1); i = s.length; break; }
        v += s.slice(i + 1, end);
        i = end + 1;
        continue;
      }
      if (ch === '\\' && i + 1 < s.length) { v += s[i + 1]; i += 2; continue; }
      v += ch;
      i++;
    }
    out.push({ v, q });
  }
  return out;
}

/** Every heredoc in the command: `{ line, marker, quoted, body }`. `line` is the text before the body. */
export function heredocs(cmd) {
  const c = String(cmd ?? '').replace(/\r/g, '');
  const re = /^([^\n]*<<-?\s*(['"]?)(\w+)\2[^\n]*)\n([\s\S]*?)\n\3[ \t]*(?=\n|$)/gm;
  const out = [];
  let m;
  while ((m = re.exec(c))) out.push({ line: m[1], marker: m[3], quoted: !!m[2], body: m[4] });
  return out;
}

const INTERPRETER_LINE = /\b(?:bash|sh|zsh|dash|python\d*|py|node|pwsh|powershell|cmd|perl|ruby|php|osascript)\b/i;

/**
 * Replace the body of every heredoc that goes to a FILE (cat > x <<EOF, tee, redirect) with a placeholder.
 * Heredocs fed to an interpreter (`python - <<EOF`) are code and stay. Use this before matching command patterns,
 * or a Markdown table mentioning `ffmpeg` on its way into a notes file will trip a rule about running ffmpeg.
 */
export function stripFileHeredocs(cmd) {
  const c = String(cmd ?? '').replace(/\r/g, '');
  return c.replace(/^([^\n]*?)<<-?\s*(['"]?)(\w+)\2[^\n]*\n([\s\S]*?)\n\3[ \t]*(?=\n|$)/gm, (all, line, _q, marker, body) =>
    INTERPRETER_LINE.test(line) ? all : `${line}<<${marker}\n(heredoc body written to a file, ${body.length} chars)\n${marker}`);
}

const WRAPPERS = /^(?:&\s*|@|exec\s+|time\s+|nohup\s+|sudo\s+(?:-u\s+\S+\s+|-\S+\s+)*|call\s+|cmd(?:\.exe)?\s+\/[cdks]\s+(?:\/\w\s+)*|start\s+(?:\/\w+\s+)*(?:"[^"]*"\s+)?)+/i;

/** First program of a simple command, with `VAR=x` prefixes and wrappers (sudo, time, nohup, exec, cmd /c) removed. */
export function firstWord(segment) {
  const t = String(segment ?? '').trim().replace(/^(?:[A-Za-z_]\w*=\S*\s+)*/, '').replace(WRAPPERS, '');
  const m = /^["']?([^\s"']+)/.exec(t);
  return m ? m[1] : '';
}

/** Base name of a program path: `C:\tools\ffmpeg.exe` → `ffmpeg`. */
export function programName(word) {
  return String(word ?? '').replace(/^.*[\\/]/, '').replace(/\.(?:exe|cmd|bat)$/i, '').toLowerCase();
}

/** True when the command text carries `TRIPWIRES_ALLOW=<id>` (or `=*`): the explicit, visible override. */
export function hasAllowToken(cmd, id) {
  const re = /(?:^|[\s;&|(])(?:\$env:)?TRIPWIRES_ALLOW\s*=\s*["']?([\w*,-]+)/g;
  let m;
  while ((m = re.exec(String(cmd ?? '')))) {
    const ids = m[1].split(',');
    if (ids.includes('*') || ids.includes(id)) return true;
  }
  return false;
}

/** Strip quoted strings so a pattern can tell code from a string that merely mentions the code. */
export function withoutQuotes(segment) {
  return String(segment ?? '').replace(/"(?:[^"\\]|\\.)*"|'[^']*'/g, '""');
}
