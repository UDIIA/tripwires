# Changelog

## 0.1.0 (2026-10-21)

First public release. Extracted from the hooks of one Claude Code setup where they had run since 2026-10-04 (see docs/case-study.md).

- Engine: rule loading (built-in plus configured), tool and platform matching, fail-open, overrides (`TRIPWIRES_ALLOW=<id>`, one-shot `tripwires allow --because`), JSONL log with timing.
- Installer for Claude Code (`settings.json`) and Codex CLI (`hooks.json`, with `commandWindows`), idempotent, with a one-time backup; `uninstall`; `doctor`.
- CLI: `init`, `uninstall`, `doctor`, `list`, `try`, `report`, `allow`, `off`, `on`, `new`, `peek`, `pids`, `hook`.
- Eleven built-in rules: `kill-by-name`, `secret-file-read`, `rm-relative-glob-after-cd`, `edit-chained-with-deploy`, `send-scheduled-in-session-cron`, `sed-inplace-on-crlf`, `weekday-date-mismatch`, `deploy-burst`, and three Windows-only: `tmp-path-to-interpreter`, `powershell-write-without-encoding`, `inline-script-backslash`.
- Three example house rules.
- Tests from the real commands of the incidents, on Linux, macOS and Windows, Node 18 to 22.
