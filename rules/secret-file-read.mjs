import { segments, tokens, firstWord, programName } from '../src/shell.mjs';

// Files that hold a credential or a secret route. A `.example` / `.sample` twin is fine to read.
const SECRET_FILE = /(?:^|[\\/])(?:\.claude(?:-[\w-]+)?[\\/](?:settings\.json|settings\.local\.json|\.claude\.json|\.credentials\.json)|\.claude\.json|\.codex[\\/](?:auth\.json|config\.toml)|\.netlify[\\/]config\.json|netlify\.toml|\.env(?:\.[\w-]+)?|secrets?\.(?:json|ya?ml|toml|env)|credentials?\.json|\.npmrc|\.pypirc|\.git-credentials|\.aws[\\/]credentials|\.docker[\\/]config\.json|kubeconfig|id_(?:rsa|ed25519|ecdsa|dsa)(?!\.pub))$/i;
const EXEMPT = /\.(?:example|sample|schema|template|dist)(?:\.\w+)?$/i;
// Programs that print file CONTENT. `ls`, `stat`, `wc -l`, `grep -l`, `grep -c` do not.
const READERS = /^(?:cat|type|more|less|head|tail|bat|batcat|strings|xxd|hexdump|od|nl|tac|get-content|gc|select-string|sls|sed|awk|rg|grep|egrep|fgrep|jq|yq|format-hex|out-string|source|\.)$/i;
const GREP_NO_CONTENT = /^(?:grep|rg|egrep)$/i;

function readsWhole(seg) {
  const tk = tokens(seg, { keepBackslashes: true }); // Windows paths keep their backslashes
  if (!tk.length) return null;
  const prog = programName(firstWord(seg));
  if (!READERS.test(prog)) return null;
  if (GREP_NO_CONTENT.test(prog) && tk.some((t) => !t.q && /^-[A-Za-z]*[lLc][A-Za-z]*$/.test(t.v))) return null;
  // Each operand is judged on its own: `cat .env .env.example` reads .env whole whatever the second file is.
  const hit = tk.slice(1).find((t) => SECRET_FILE.test(t.v) && !EXEMPT.test(t.v));
  return hit ? hit.v : null;
}

export default {
  id: 'secret-file-read',
  title: 'Credential file read whole',
  tools: /^(?:Bash|PowerShell|mcp__windows-mcp__PowerShell|Read)$/,
  incident:
    'Six times between 2026-09-06 and 2026-10-09 a `cat settings.json`, a `sed -n` over a `netlify.toml` and a `grep` over a `RustDesk.toml` printed a gateway token, a secret admin route and a private key into the session transcript. Transcripts are kept, synced and sometimes shared; each leak meant deciding whether to rotate.',
  check(input) {
    if (input.tool === 'Read') {
      const fp = input.file;
      if (!SECRET_FILE.test(fp) || EXEMPT.test(fp)) return null;
      return {
        reason: `${fp} holds credentials or secret routes. Reading it whole puts the values in the transcript.`,
        fix: `\`tripwires peek "${fp}"\` prints the keys, the paths and the shape of each value (length, kind) with the values masked. To use a value in a command, pass it through the environment or the script that reads it, without printing.`,
      };
    }
    for (const seg of segments(input.command)) {
      const file = readsWhole(seg);
      if (!file) continue;
      return {
        reason: `${file} holds credentials or secret routes; cat, sed, grep and Get-Content put the values in the transcript.`,
        fix: '`tripwires peek <file>` shows keys and value shapes with the values masked. To check that a file exists or count lines: ls, Test-Path, wc -l, grep -c, grep -l pass.',
        excerpt: seg.trim(),
      };
    }
    return null;
  },
};
