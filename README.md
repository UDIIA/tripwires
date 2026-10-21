# tripwires

Guardrails that fire before the tool runs. For Claude Code and Codex CLI.

[![ci](https://github.com/UDIIA/tripwires/actions/workflows/ci.yml/badge.svg)](https://github.com/UDIIA/tripwires/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/tripwires)](https://www.npmjs.com/package/tripwires)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

You wrote "never kill a process by name" in `CLAUDE.md`. The agent did it again on Thursday and took down its own shell. You wrote "never read `.env` whole" in `AGENTS.md`. It ran `cat .env` the next week and the key is now in a transcript.

A rule in a prompt is advice. A rule in a `PreToolUse` hook runs before the tool does and can say no. tripwires is that hook, with four things attached to every rule: the incident that caused it, the fix the agent should use instead, a test built from the real command, and a weekly report that tells you whether the rule is helping or hurting. It is a guardrail for an agent that forgets, not a sandbox for one that is trying to get around you; [SECURITY.md](SECURITY.md) says where that line is.

```
$ tripwires try "pkill -f node"
DENY
[tripwires] kill-by-name: Process killed by image name.
Why: Killing by image name hits every process with that name, including the shell this session runs in and other sessions' work. It has done exactly that.
Fix: List first, then kill one PID: `tripwires pids <name>` (or `tasklist /FI "IMAGENAME eq <name>"` / `pgrep -af <name>`), pick the PID whose command line is the one you mean, then `taskkill /PID <n>` or `kill <n>`.
Override (visible, logged): add TRIPWIRES_ALLOW=kill-by-name to the command, or run `tripwires allow kill-by-name --because "<the person's own words>"` for a one-shot pass.
```

The agent reads that text instead of running the command. The denial names what it was about to do, why that is the mistake, and the exact thing to do instead. A retry with a cosmetic variation hits the same rule as long as the rule covers the variation; the ones it misses go into the rule's tests, which is what the weekly report is for.

## Install

```bash
npx tripwires init
```

That finds `~/.claude` and `~/.codex` and adds the hook to each one it finds. `--claude`, `--codex` choose; `--project` writes to the repo's `.claude/settings.json` or `.codex/hooks.json` instead of the home directory; `--dry-run` shows what would change. Existing hooks are kept; the file is backed up once.

Codex trusts each hook definition once: open Codex, run `/hooks`, trust the two tripwires entries. Claude Code picks the hook up on the next tool call.

```bash
tripwires doctor      # what is installed where, which rules load
tripwires list --all  # every rule and the incident behind it
```

Requires Node 18.17 or newer. No dependencies.

## What is in the box

Eleven rules, each born from a real incident, dated, with the count of how often it happened before the rule existed. `tripwires list --all` prints the full text.

| rule | fires on | the incident, in short |
|---|---|---|
| `kill-by-name` | `taskkill /IM`, `pkill`, `Stop-Process -Name` | killed the agent's own shell, three times in a month |
| `secret-file-read` | `cat .env`, `Read settings.json`, `sed netlify.toml` | a token, a secret route and a private key printed into transcripts, six times in five weeks |
| `rm-relative-glob-after-cd` | `cd x && rm -rf tmp-*` | the runtime's own safety check opened a prompt in an unattended session; it hung all night |
| `edit-chained-with-deploy` | `python fix.py && netlify deploy --prod` | a gate denied the line, the edit silently never ran, the next deploy shipped without it |
| `send-scheduled-in-session-cron` | `CronCreate` / `ScheduleWakeup` with a send, post or deploy | ten customer messages queued in-session; the session restarted; nothing was sent, nothing said so |
| `sed-inplace-on-crlf` | `sed -i` on a CRLF file in a git repo | 347 changed lines in a PR for 6 real changes |
| `weekday-date-mismatch` | writing "Saturday, October 11" when it is a Sunday (en, pt-BR) | a deadline went out in 13 places with the wrong weekday; 27 sessions had the same error |
| `deploy-burst` | 2nd production deploy of the same target inside 30 min, 4th in a day | 419 production deploys in a month, 6,285 credits, auto top-up twice |
| `tmp-path-to-interpreter` (Windows) | `/tmp/x` inside a quoted argument to Python or Node | Python opened `C:\tmp`, the payload came back empty, the API returned 400 |
| `powershell-write-without-encoding` (Windows) | `Set-Content` with accented text, no `-Encoding` | a YAML config came out in ANSI and the service ran on its fallback for two minutes |
| `inline-script-backslash` (Windows) | `python -c '...C:\\Users...'` | the Bash tool collapses `\\` to `\`; four retries in one session, then 403 denials in 168 sessions over 17 days |

Three more live in [`examples/house-rules/`](examples/house-rules/) as templates for rules that are true on one machine only: ffmpeg banned on a laptop that froze, every message routed through the wrapper that dedupes and logs, no metered API call without the person's words.

## Why not a blocklist of dangerous commands

Blocklists are good and you should run one. [Destructive Command Guard](https://github.com/Dicklesworthstone/destructive_command_guard) catches `git reset --hard` and `rm -rf /` for everyone, and tripwires runs alongside it without conflict.

tripwires is for the other class of mistake: the one that is only a mistake here. `sed -i` is fine on a Linux repo and ruins a Windows one. A production deploy is fine once and a problem five times an hour. `ffmpeg` is fine everywhere except the laptop whose cursor froze. Nobody can ship those rules to you; you have to write them from your own incidents, and the hard part is not the regex. The hard part is remembering why the rule exists three weeks later, knowing whether it is still earning its keep, and narrowing it when it starts blocking real work. That is what the incident field, the test file, the log and the weekly report are for.

## Writing a rule

```bash
tripwires new sed-on-generated-files
```

That scaffolds `tripwires-rules/sed-on-generated-files.mjs` and its test. A rule is one object:

```js
export default {
  id: 'sed-on-generated-files',
  title: 'sed on a generated file',
  tools: /^(?:Bash)$/,
  incident: '2026-10-14 16:20: `sed -i` on dist/app.js fixed the symptom, the next build undid it, the bug came back twice.',
  check(input, ctx) {
    const hit = ctx.shell.segments(input.command).find((s) => /\bsed\s+-i\b.*\b(?:dist|build)\//.test(s));
    if (!hit) return null;
    return {
      reason: 'dist/ and build/ are generated; an edit there is overwritten by the next build.',
      fix: 'Edit the source under src/ and rebuild.',
      excerpt: hit.trim(),
    };
  },
};
```

`input` carries `command` (Bash, PowerShell), `file` and `text` (Read, Write, Edit), `cwd` and `session`. `ctx` carries `now`, `platform`, `stateDir`, `fs` (false when a test asks the rule not to touch the disk) and `shell`, the parsing helpers: `segments` splits a pipeline outside quotes, `stripFileHeredocs` turns a heredoc headed for a file into data, `firstWord` sees through `sudo`, `time`, `nohup` and `cmd /c`. [docs/writing-a-rule.md](docs/writing-a-rule.md) has the full reference.

Point the config at the folder and the rule is live:

```json
// ~/.tripwires/config.json  (or .tripwires.json at the repo root, after `tripwires trust` in that repo)
{ "rules": ["./tripwires-rules"], "off": [] }
```

A rule file is code that runs inside the hook, with your file and environment access. A `.tripwires.json` found in a cloned repository therefore cannot load rule code until you run `tripwires trust` in that project; its `off` list applies without trust, since switching a rule off runs nothing.

Two habits make the difference between a rule that lasts and one that gets deleted in a week:

1. **The deny case is the real command.** Copy it from the transcript into the test. The pass cases are the legitimate neighbours a sloppy regex would catch (`grep -c "" .env` is not `cat .env`).
2. **The denial teaches the fix.** An agent that reads "blocked" tries a variation. An agent that reads "use `tripwires peek .env`" uses it.

## Overrides, switching off, and the log

Every override is visible in the command and recorded in the log, so the weekly report shows where the rule was wrong or where the person decided it did not apply this time.

- `TRIPWIRES_ALLOW=<rule-id> <command>` passes that one command. It only counts where an environment assignment goes, at the start of the command; the same text in a comment or a string does nothing.
- `tripwires allow <rule-id> --because "<the person's own words>"` writes a one-shot pass consumed by the next denial. The words go into the log next to it. Nothing stops an agent from typing a reason itself; what this gives you is that every pass is in the report with its justification, so an invented one is a sentence you can read on Monday.
- `tripwires off <rule-id>` / `on` switch a rule off in the config. Write down why; a rule switched off without a reason comes back as the same incident.

The log is `~/.tripwires/log.jsonl`: one line per denial, override or rule error (a call that passes writes nothing), with the rule, the tool, the session, a redacted 200-character excerpt and the milliseconds from hook start to that decision.

## The weekly report

```
$ tripwires report --days 7

## inline-script-backslash: 26 denied, 0 overridden, 0 error(s), 14 session(s), p50 212 ms
per day: 10-15=5 10-16=7 10-17=3 10-18=4 10-19=4 10-20=3
- 10-20 09:14 a1b2c3d4 Bash | python -c 'open("C:\\Users\\me\\x.txt")'
- ...
- verdict: ______ (helped | hurt | no effect | confounded)  evidence: ______
```

One verdict per rule, citing a session and a time. "Hurt" with three wrong denials in a day means the rule gets narrowed and the real command goes into its tests first. "No effect" for a month means the rule is retired or the agent learned; either way you decide with numbers. [docs/method.md](docs/method.md) describes the loop; [docs/case-study.md](docs/case-study.md) has the numbers from the setup the rules came from.

## Agents

Both agents send the same JSON on stdin (`tool_name`, `tool_input`, `cwd`, `session_id`) and accept the same denial on stdout:

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"..."}}
```

- **Claude Code**: `~/.claude/settings.json`, matchers `Bash|PowerShell` and `Read|Write|Edit|MultiEdit|CronCreate|ScheduleWakeup`. [docs/claude-code.md](docs/claude-code.md)
- **Codex CLI** (0.124 or newer): `~/.codex/hooks.json`, matchers `Bash|PowerShell` and `apply_patch|Read|Write|Edit`; `commandWindows` is set for Windows; trust once via `/hooks`. [docs/codex.md](docs/codex.md)

Anything else that speaks this protocol can run `tripwires hook` as its command.

## Design rules

- **Fails open.** A rule that throws is skipped and logged. The engine crashing lets the call through. A guardrail that breaks the session gets uninstalled within a day, and then it protects nothing. `TRIPWIRES_FAIL_CLOSED=1` flips this for CI.
- **Never denies a read on its own.** Rules look at what the agent is about to change, send or spend. The one exception is reading a credential file whole, and that denial hands over `tripwires peek`, a reader that prints value shapes instead of values (with the limits listed in [SECURITY.md](SECURITY.md)).
- **Data is not code.** A heredoc written to a file is not a command, unless it is unquoted and carries a `$(...)` the shell will run. A string that mentions `Set-Content` is not an invocation. A trailing `# comment` is not an override. The parsing helpers exist so rules do not block the notes file that describes the incident, and so the notes file cannot smuggle a command.
- **Each matched tool call costs one Node start-up plus the rules.** Measured with [`bench/latency.mjs`](bench/latency.mjs) on a loaded Windows laptop, two runs an hour apart: 200 to 600 ms above bare `node -e 0`, which itself took 0.7 to 2.6 s there depending on load (an idle machine starts Node in under 100 ms). Run the bench on your own machine; the number that matters is yours. Tools the rules do not care about never start the process. The log carries the milliseconds from hook start to each denial, and `tripwires report` shows p50 per rule; it is the wait the agent saw on denials, not a per-rule profile.
- **The override is loud.** It is at the head of the command text or in a file written through the CLI with a reason, and it ends up in the log either way.
- **Rule loading is isolated.** A rule file that fails to import is reported by `tripwires doctor`, logged, and skipped; the other rules still run.

## Contributing

Rules are welcome when they come with the incident. See [CONTRIBUTING.md](CONTRIBUTING.md). Found a rule denying legitimate work? Open an issue with the command; that command becomes a test case.

## License

MIT.
