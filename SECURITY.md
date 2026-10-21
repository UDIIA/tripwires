# Security

## What tripwires is and is not

tripwires is a guardrail for a cooperative agent that forgets. It is not a sandbox and not a security boundary. A rule inspects the text of the tool call it is given; an agent that writes a script to disk and runs it, or that calls a tool the matcher does not cover, goes around it. Use a sandbox for adversarial cases.

## What the hook reads and writes

- Reads: the PreToolUse payload on stdin, the config files, and for a few rules the file named in the command (`sed-inplace-on-crlf` reads the first 64 KB to detect CRLF; `powershell-write-without-encoding` reads the target file to detect non-ASCII bytes).
- Writes: `~/.tripwires/log.jsonl` (rule id, tool, session id, a 200-character excerpt of the command, timing) and `~/.tripwires/deploys.jsonl` for `deploy-burst`. The excerpt can contain whatever was in the command; the log is local and not transmitted anywhere.
- `tripwires peek` prints a credential file with every value masked. It is a convenience to keep secrets out of transcripts, not a guarantee: a value stored under a structural key name, or a short string with no digits, is printed. Check the output before pasting it anywhere.
- No network access anywhere in the package.

## Reporting

Email the maintainers through the address on the npm package page, or open a GitHub security advisory on the repository. Please do not open a public issue for a vulnerability. You will get an answer within seven days.
