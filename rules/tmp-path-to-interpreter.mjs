import { segments, tokens } from '../src/shell.mjs';

// Windows only. Git Bash (MSYS) rewrites a bare `/tmp/x` argument to the real Temp folder before the program runs,
// so that works. It does NOT rewrite `/tmp` inside code (-c, -e, heredoc), inside a quoted string with other text,
// or when MSYS_NO_PATHCONV=1 is set. Python and Node then open C:\tmp, which is empty or missing.
const INTERP = /^(?:\S*[\\/])?(?:python3?|py|pythonw|node)(?:\.exe)?$/i;
const TMP_IN_CODE = /(?<![+\w$}\]])['"(=:,\s]\/tmp(?:\/|['")])/;
const TMP_IN_TOKEN = /(?:^|(?<![+\w$}\]])['"=(,])\/tmp(?:\/|$|['")])/;

export default {
  id: 'tmp-path-to-interpreter',
  title: '/tmp passed to Python or Node on Windows',
  tools: /^(?:Bash)$/,
  platforms: ['win32'],
  incident:
    'On 2026-10-07 a script received `/tmp/contact.json` inside a quoted argument. The shell had written the file to AppData\\Local\\Temp, Python read C:\\tmp, the phone number came back empty and the API call failed with 400. Found again in six sessions over the following week.',
  check(input) {
    const c = input.command;
    if (!/\/tmp(?:\/|\b)/.test(c)) return null;
    const hd = /((?:python3?|py|node)(?:\.exe)?\b[^\n]*)<<-?\s*['"]?(\w+)['"]?[^\n]*\n([\s\S]*?)\n\2[ \t]*(?=\n|$)/g;
    let m;
    while ((m = hd.exec(c))) {
      if (/\bwsl(?:\.exe)?\b/i.test(m[1])) continue;
      const line = m[3].split('\n').find((l) => TMP_IN_CODE.test(' ' + l));
      if (line) return hit('inside a heredoc fed to the interpreter', line.trim());
    }
    const noConv = /\bMSYS_NO_PATHCONV=1\b/.test(c);
    for (const seg of segments(c)) {
      if (/\bwsl(?:\.exe)?\b/i.test(seg)) continue;
      const tk = tokens(seg);
      const i = tk.findIndex((t) => !t.q && INTERP.test(t.v));
      if (i < 0) continue;
      let redirect = false;
      for (const t of tk.slice(i + 1)) {
        if (!t.q && /^(?:\d?>>?|<|&>|2>&1)$/.test(t.v)) { redirect = true; continue; }
        if (!t.q && /^(?:\d?>>?|<)\/tmp(?:\/|$)/.test(t.v)) continue;
        if (redirect) { redirect = false; continue; }
        if (!TMP_IN_TOKEN.test(t.v)) continue;
        const bare = /^(?:--?[\w-]+=)?\/tmp(?:\/[\w.\-\/]*)?$/.test(t.v);
        if (bare && !noConv) continue;
        return hit(noConv && bare ? 'MSYS_NO_PATHCONV=1 is set' : 'inside code or a quoted string with other text', t.v);
      }
    }
    return null;
  },
};

function hit(why, excerpt) {
  return {
    reason: `${why}: Git Bash does not translate this /tmp, so the interpreter opens C:\\tmp while the shell wrote to AppData\\Local\\Temp.`,
    fix: 'Use the same explicit path on both sides: "$TMPDIR/file" or the full Temp path (`cygpath -w /tmp/x` prints it). A bare `/tmp/x` argument with no quotes around other text is translated and works.',
    excerpt,
  };
}
