import { segments } from '../src/shell.mjs';

// Files that hold a credential or a secret route. A `.example` / `.sample` twin is fine to read.
export const SECRET_PATH = /(?:[\\/]|^|~|\s|["'`=])(?:\.claude(?:-[\w-]+)?[\\/](?:settings\.json|settings\.local\.json|\.claude\.json|\.credentials\.json)|\.claude\.json|\.codex[\\/](?:auth\.json|config\.toml)|\.netlify[\\/]config\.json|netlify\.toml|\.env(?:\.[\w-]+)?|secrets?\.(?:json|ya?ml|toml|env)|credentials?\.json|\.npmrc|\.pypirc|\.git-credentials|\.aws[\\/]credentials|\.docker[\\/]config\.json|kubeconfig|id_(?:rsa|ed25519|ecdsa|dsa)(?!\.pub))(?=$|[\s"'`;|)&])/i;
const SECRET_PATH_END = /(?:[\\/]|^|~)(?:\.claude(?:-[\w-]+)?[\\/](?:settings\.json|settings\.local\.json|\.claude\.json|\.credentials\.json)|\.claude\.json|\.codex[\\/](?:auth\.json|config\.toml)|\.netlify[\\/]config\.json|netlify\.toml|\.env(?:\.[\w-]+)?|secrets?\.(?:json|ya?ml|toml|env)|credentials?\.json|\.npmrc|\.pypirc|\.git-credentials|\.aws[\\/]credentials|\.docker[\\/]config\.json|kubeconfig|id_(?:rsa|ed25519|ecdsa|dsa)(?!\.pub))$/i;
const EXEMPT = /\.(?:example|sample|schema|template|dist)\b/i;
// Programs that print file CONTENT. `ls`, `stat`, `wc -l`, `grep -l`, `grep -c` do not.
const READERS = /(?:^|[\s;&|(])(?:cat|type|more|less|head|tail|bat|batcat|strings|xxd|hexdump|od|nl|tac|Get-Content|gc|Select-String|sls|sed|awk|rg|grep|egrep|fgrep|jq|yq|python(?:3)?\s+-c[^|]*open\(|node\s+-e[^|]*readFileSync|Format-Hex|Out-String|source|\.)\s/i;
const READERS_NO_CONTENT = /(?:^|[\s;&|(])(?:grep|rg|egrep)\s+(?:-\w+\s+)*-[A-Za-z]*[lLc][A-Za-z]*\s/i;

export default {
  id: 'secret-file-read',
  title: 'Credential file read whole',
  tools: /^(?:Bash|PowerShell|mcp__windows-mcp__PowerShell|Read)$/,
  incident:
    'Six times between 2026-09-06 and 2026-10-09 a `cat settings.json`, a `sed -n` over a `netlify.toml` and a `grep` over a `RustDesk.toml` printed a gateway token, a secret admin route and a private key into the session transcript. Transcripts are kept, synced and sometimes shared; each leak meant deciding whether to rotate.',
  check(input) {
    if (input.tool === 'Read') {
      const fp = input.file;
      if (!SECRET_PATH_END.test(fp) || EXEMPT.test(fp)) return null;
      return {
        reason: `${fp} holds credentials or secret routes. Reading it whole puts the values in the transcript.`,
        fix: `\`tripwires peek "${fp}"\` prints the keys, the paths and the shape of each value (length, kind), never the value. To use a value in a command, pass it through the environment or the script that reads it, without printing.`,
      };
    }
    // Bash / PowerShell: reader and path must be in the SAME simple command. `ls -la netlify.toml | head` is fine.
    const bad = segments(input.command).find((s) => SECRET_PATH.test(s) && READERS.test(' ' + s) && !READERS_NO_CONTENT.test(' ' + s));
    if (!bad || EXEMPT.test(bad) || /tripwires\s+peek/.test(input.command)) return null;
    const m = bad.match(SECRET_PATH);
    const name = m ? m[0].replace(/^[\\/\s"'`=~]+/, '') : 'that file';
    return {
      reason: `${name} holds credentials or secret routes; cat, sed, grep and Get-Content put the values in the transcript.`,
      fix: `\`tripwires peek <file>\` shows keys and value shapes, never values. To check that a file exists or count lines: ls, Test-Path, wc -l, grep -c, grep -l pass.`,
      excerpt: bad.trim(),
    };
  },
};
