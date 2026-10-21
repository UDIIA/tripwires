# Changelog

## 0.1.1 (2026-10-21)

Fixes from a blind review of 0.1.0 (fifteen findings, all reproduced before the fix, each now a test):

- Overrides: `TRIPWIRES_ALLOW=<id>` counts only where an environment assignment goes (head of a simple command, `export`, `$env:`); a comment or a string no longer passes. Written content (Write/Edit) is not scanned for it.
- Shell parsing: an unquoted heredoc whose body carries `$(...)`, backticks or `${...}` is kept as code; quoted strings and trailing comments are not commands (`echo "pkill -f node"` passes; `pkill -f node # note` is denied).
- `secret-file-read`: exemptions apply per operand (`cat .env .env.example` is denied) and the `tripwires peek` exemption applies to the segment that runs it, not the whole line.
- `deploy-burst`: bookkeeping moved to `onPass`, which runs only when no rule denied the call; `--dry-run` is not a deploy; `tripwires try` records nothing.
- `peek`: numbers with five or more digits, structural keys whose value looks like a credential, and URL user info are masked.
- Log: excerpts are redacted before being written.
- Loader: a rule file that fails to import or duplicates an id is skipped and reported; the other rules still run. `tripwires doctor` lists the failures.
- Config: a project `.tripwires.json` cannot load rule code until `tripwires trust` is run in that project; `off` applies regardless.
- Installer: only our handlers are added or removed; a group that also holds someone else's handler keeps it.
- Codex `apply_patch` payloads are normalized to file + added text; the weekday rule covers them.
- `tripwires pids` runs `ps` without a shell on Unix.
- README: latency figure tied to `bench/latency.mjs`; effectiveness claims cut to what the log shows.

## 0.1.0 (2026-10-21)

First public release. Extracted from the hooks of one Claude Code setup where they had run since 2026-10-04 (see docs/case-study.md).

- Engine: rule loading (built-in plus configured), tool and platform matching, fail-open, overrides (`TRIPWIRES_ALLOW=<id>`, one-shot `tripwires allow --because`), JSONL log with timing.
- Installer for Claude Code (`settings.json`) and Codex CLI (`hooks.json`, with `commandWindows`), idempotent, with a one-time backup; `uninstall`; `doctor`.
- CLI: `init`, `uninstall`, `doctor`, `list`, `try`, `report`, `allow`, `off`, `on`, `new`, `peek`, `pids`, `hook`.
- Eleven built-in rules: `kill-by-name`, `secret-file-read`, `rm-relative-glob-after-cd`, `edit-chained-with-deploy`, `send-scheduled-in-session-cron`, `sed-inplace-on-crlf`, `weekday-date-mismatch`, `deploy-burst`, and three Windows-only: `tmp-path-to-interpreter`, `powershell-write-without-encoding`, `inline-script-backslash`.
- Three example house rules.
- Tests from the real commands of the incidents, on Linux, macOS and Windows, Node 18 to 22.
