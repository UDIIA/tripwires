# Writing a rule

```bash
tripwires new <rule-id>            # scaffolds ./tripwires-rules/<rule-id>.mjs and its test
node --test tripwires-rules        # run the tests
```

Then add the folder to the config and the rule is live:

```json
// ~/.tripwires/config.json, or .tripwires.json at the repo root (found by walking up from cwd)
{
  "rules": ["./tripwires-rules"],
  "off": ["deploy-burst"],
  "failClosed": false,
  "stateDir": "~/.tripwires"
}
```

Home and project configs merge: `rules` and `off` from both apply. `$TRIPWIRES_CONFIG` names one file and replaces both. `$TRIPWIRES_STATE_DIR` overrides the state directory.

## The rule object

```js
export default {
  id: 'kebab-case-id',          // stable; appears in the log, the report and the override
  title: 'Six words, no period',
  tools: /^(?:Bash|PowerShell)$/, // RegExp or string[] against tool_name; ['*'] matches every tool
  platforms: ['win32'],         // optional: 'win32' | 'darwin' | 'linux'; skipped elsewhere
  incident: '2026-10-05 06:57: what ran, what broke, how it was noticed, how many times before.',
  check(input, ctx) {
    return null;                                  // let it through
    // or
    return { reason, fix, excerpt };              // deny; `fix` and `excerpt` are optional but expected
  },
};
```

The first rule that returns an object wins; the rest are not asked. Built-in rules run before configured ones, in file-name order within each set.

### `input`

| field | content |
|---|---|
| `tool` | `tool_name` from the payload (`Bash`, `PowerShell`, `Read`, `Write`, `Edit`, `MultiEdit`, `apply_patch`, `CronCreate`, `ScheduleWakeup`, `mcp__...`) |
| `command` | `tool_input.command` (also `cmd`, `script`), or `''` |
| `file` | `tool_input.file_path` (also `path`, `filePath`), or `''` |
| `text` | `content` (Write), `new_string` (Edit) or all `edits[].new_string` joined (MultiEdit) |
| `cwd` | the session's working directory |
| `session` | `session_id`, used in the log |
| `transcript` | `transcript_path` when the agent sends one (Claude Code does) |
| `tool_input` | the raw object, for anything else |
| `raw` | the whole payload |

### `ctx`

| field | content |
|---|---|
| `now` | a `Date`; tests pass a fixed one |
| `platform` | `process.platform`, or what the test asks for |
| `stateDir` | where the log and overrides live; a rule may keep its own file there (`deploy-burst` does) |
| `fs` | `false` when the caller asks the rule not to touch the disk; return a candidate or `null` in that case |
| `shell` | the helpers below |
| `config` | the merged config |

### `ctx.shell`

| helper | does |
|---|---|
| `segments(cmd)` | splits at `\|`, `\|\|`, `;`, `&&` and newlines, never inside quotes |
| `tokens(segment)` | `[{ v, q }]`, `q` true when the token was quoted |
| `heredocs(cmd)` | `[{ line, marker, quoted, body }]` |
| `stripFileHeredocs(cmd)` | replaces the body of heredocs headed for a file with a placeholder; interpreter heredocs stay |
| `firstWord(segment)` | the program, with `VAR=x`, `sudo`, `time`, `nohup`, `exec`, `cmd /c` removed |
| `programName(word)` | `C:\tools\FFmpeg.EXE` → `ffmpeg` |
| `withoutQuotes(segment)` | string contents blanked, so patterns see code and not strings |
| `hasAllowToken(cmd, id)` | the override check the engine already applies |

The same module is importable as `tripwires/shell` when tripwires is a dependency.

## The denial

```
[tripwires] <id>: <title>.
Why: <reason>
Fix: <fix>
Override (visible, logged): add TRIPWIRES_ALLOW=<id> to the command, or run `tripwires allow <id> --because "..."` for a one-shot pass.
```

`reason` is one or two sentences the agent can verify against what it was doing. `fix` is concrete enough to paste. `excerpt` is the part of the command that matched; it goes to the log (200 characters at most) and makes the report readable.

## Tests

The scaffold uses `node:test`. Every deny case is the real command from the incident. Every pass case is legitimate work a sloppy pattern would block. Keep `TRIPWIRES_TEST=1` set (the scaffold does) so the suite never writes the log.

A rule that reads the disk takes `ctx.fs === false` as "answer from the command text only"; the built-in `sed-inplace-on-crlf` returns a candidate in that case and the real check runs in a test with a temporary git repo. See [`test/rules.test.mjs`](../test/rules.test.mjs).

## Checklist before the rule goes live

- [ ] `incident` has a date and a count.
- [ ] The deny test is the real command.
- [ ] At least two pass cases are neighbours of the deny case.
- [ ] The denial names the alternative, not just the prohibition.
- [ ] The rule looks at what changes, sends or spends, not at what reads.
- [ ] Heredocs to files and quoted strings are treated as data where that matters.
- [ ] A week later, the report has a verdict for it.
