import { segments, stripFileHeredocs, withoutQuotes, withoutComment } from '../src/shell.mjs';

const BY_NAME = [
  /taskkill\b(?=[^\n]*\/im\b)/i,
  /\b(?:Stop-Process|spps|kill)\b(?=[^\n|]*\s-name\b)/i,
  /(?:^|[\s;&|(])pkill\b/i,
  /(?:^|[\s;&|(])killall\b/i,
  /\bGet-Process\s+(?!-id\b)[^|\n]*\|\s*(?:Stop-Process|spps|kill|%\s*\{[^}]*\.Kill)/i,
  /Win32_Process[^\n]*(?:Terminate|\.Kill\(|Remove-CimInstance|Invoke-CimMethod)/i,
  /wmic\s+process\s+where[^\n]*(?:delete|terminate)/i,
];

export default {
  id: 'kill-by-name',
  title: 'Process killed by image name',
  tools: /^(?:Bash|PowerShell|mcp__windows-mcp__PowerShell)$/,
  incident:
    'Three times in one month (2026-09 to 2026-10) a `taskkill /IM node.exe`, a `pkill -f <name>` and a `Get-Process node | Stop-Process` took down the shell the agent itself was running in, plus unrelated work in other sessions with the same image name. The agent then reported the kill as done and moved on.',
  check(input) {
    // Code only: heredoc bodies headed for a file, quoted strings and trailing comments are not the command.
    // Get-Process ... | Stop-Process spans a pipe, so the pipeline is checked whole after the strings are blanked.
    const whole = withoutQuotes(stripFileHeredocs(input.command));
    const pieces = [whole, ...segments(whole).map(withoutComment)];
    if (!pieces.some((p) => BY_NAME.some((re) => re.test(p)))) return null;
    return {
      reason: 'Killing by image name hits every process with that name, including the shell this session runs in and other sessions\' work. It has done exactly that.',
      fix: 'List first, then kill one PID: `tripwires pids <name>` (or `tasklist /FI "IMAGENAME eq <name>"` / `pgrep -af <name>`), pick the PID whose command line is the one you mean, then `taskkill /PID <n>` or `kill <n>`.',
    };
  },
};
