import { segments, withoutQuotes } from '../src/shell.mjs';

// Commands that publish. Each one may be preceded by other gates (a copy check, a smoke test) that deny the WHOLE
// command line; when the edit sits in the same line, the edit silently never happens.
const DEPLOY = /(?:^|[\s"'`&(\\/])(?:netlify(?:\.cmd)?\s+(?:--?[\w-]+(?:[=\s]+\S+)?\s+)*?deploy\b|vercel(?:\.cmd)?\s+(?:--?[\w-]+(?:[=\s]+\S+)?\s+)*?(?:deploy|--prod)\b|wrangler\s+(?:deploy|publish|pages\s+deploy)\b|firebase\s+deploy\b|fly(?:ctl)?\s+deploy\b|npm\s+publish\b|gh\s+release\s+create\b|git\s+push\b[^\n]*--tags)/i;
// Only content EDITS count: writing to a file, in-place sed/perl, cp/mv, write cmdlets, git commands that move the tree.
const EDITS = /(?:(?<![<>\d-])>>?(?!&|\s*(?:\/dev\/null|\$null|NUL\b|\/tmp\/|\$\w*TMP\w*|\S*\.log\b))|\btee\b|(?:^|\s)(?:cp|mv)\s|\bsed\s+(?:-[a-zA-Z]*i|--in-place)|\bperl\s+-[a-z]*i|Set-Content|Out-File|Add-Content|Copy-Item|Move-Item|\bgit\s+(?:checkout|restore|stash|pull|merge|reset)\b)/i;
const INTERP = /\b(?:python3?|py|node)(?:\.exe)?\s+(.*)$/i;
const CODE_WRITES = /(?:\.write\(|open\([^)]*['"][wa]b?['"]|writeFileSync|writeFile\(|appendFile|write_text|\.save\(|copyfile|shutil\.|rename\()/i;
const CHECK_SCRIPT = /(?:check|gate|smoke|lint|verif|test|measure|audit|diff|list|count|print|show|dump|status|read|inspect|scan|probe)/i;
const CLEANUP = /^\s*(?:rm\s+-[rf]+\s+|Remove-Item\s+(?:-\w+\s+)*)["']?\S*\.(?:netlify|vercel)(?:[\\/]\S*)?["']?\s*$/i;

function interpreterEdits(whole, seg) {
  const m = seg.match(INTERP);
  if (!m) return false;
  const rest = m[1].trim();
  if (/^-\s*<<|^<<|^-c\b|^-e\b|^--eval\b/.test(rest)) return CODE_WRITES.test(rest) || (/<<-?\s*['"]?\w+/.test(rest) && CODE_WRITES.test(whole));
  const script = (rest.match(/^(?:-\w+\s+)*["']?([^\s"']+)/) || [])[1] || '';
  return !!script && !CHECK_SCRIPT.test(script.replace(/^.*[\\/]/, ''));
}

export default {
  id: 'edit-chained-with-deploy',
  title: 'File edit chained with a deploy in one command',
  tools: /^(?:Bash|PowerShell|mcp__windows-mcp__PowerShell)$/,
  incident:
    'On 2026-10-02 and 2026-10-03 the agent ran `python fix_toml.py && netlify deploy --prod`. A publication gate denied the line because of the deploy; the edit in front of it never ran, nothing said so, and the next deploy went out without the fix. Twice.',
  check(input) {
    const segs = segments(input.command);
    const i = segs.findIndex((s) => DEPLOY.test(s));
    if (i <= 0) return null;
    for (let k = 0; k < i; k++) {
      const s = segs[k];
      if (!s.trim() || CLEANUP.test(s)) continue;
      if (EDITS.test(withoutQuotes(s)) || interpreterEdits(input.command, s)) {
        return {
          reason: 'When any gate denies the deploy it denies the whole line, so the edit before it silently does not happen and the next deploy ships without it.',
          fix: 'Edit in one command, verify in another (ls, git diff, hash), deploy alone in a third. `cd`, `mkdir`, `git`, `npm run build` and `node --check` before a deploy pass.',
          excerpt: s.trim(),
        };
      }
    }
    return null;
  },
};
