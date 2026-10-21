import { stripFileHeredocs } from '../src/shell.mjs';

const HAS_CD = /(?:^|[;&|(]|\n)\s*cd\s/m;
// rm -r with a target that is relative (no leading /, drive letter, ~/ or $) and contains a glob.
const RM_RELATIVE_GLOB = /(?:^|[\s;&|(])rm\s+(?:-[a-zA-Z]*[rR][a-zA-Z]*\s+)+(?:[^\s;&|*?]+\s+)*(?!\/|[a-zA-Z]:[\\/]|~\/|\$)[^\s;&|]*[*?]/m;

export default {
  id: 'rm-relative-glob-after-cd',
  title: 'rm -r with a relative glob after cd',
  tools: /^(?:Bash)$/,
  incident:
    'On 2026-10-09 21:15 an unattended background session ran `cd build && rm -rf tmp-*`. Claude Code\'s own safety check flagged "relative glob target cannot be statically resolved" and opened an approval prompt even in bypass-permissions mode. Nobody was there to answer; the session hung until morning.',
  check(input) {
    const c = stripFileHeredocs(input.command);
    if (!HAS_CD.test(c) || !RM_RELATIVE_GLOB.test(c)) return null;
    return {
      reason: 'The agent runtime cannot resolve a relative glob after a `cd` and asks a human to approve it. In a background session no one answers, and the session stalls.',
      fix: 'Use an absolute path without a glob (`rm -rf /abs/path/dir`), or delete from code: `node -e "require(\'fs\').rmSync(p,{recursive:true,force:true})"` / `python -c "import shutil; shutil.rmtree(p, ignore_errors=True)"`.',
    };
  },
};
