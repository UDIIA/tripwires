# Claude Code

```bash
npx tripwires init --claude            # ~/.claude/settings.json
npx tripwires init --claude --project  # ./.claude/settings.json
```

What gets written, merged into whatever `hooks.PreToolUse` already holds:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash|PowerShell",
        "hooks": [{ "type": "command", "command": "\"/path/to/node\" \"/path/to/tripwires/bin/tripwires.mjs\" hook --agent claude", "timeout": 10 }] },
      { "matcher": "Read|Write|Edit|MultiEdit|CronCreate|ScheduleWakeup",
        "hooks": [{ "type": "command", "command": "...the same...", "timeout": 10 }] }
    ]
  }
}
```

The command is absolute (`node` and the package path) so it works from any cwd and does not pay npx start-up per tool call. A backup of the settings file is written once as `settings.json.bak-tripwires`. `tripwires uninstall --claude` removes only the entries whose command mentions `tripwires.mjs`.

Claude Code sends on stdin:

```json
{ "session_id": "...", "transcript_path": "...", "cwd": "...", "hook_event_name": "PreToolUse",
  "tool_name": "Bash", "tool_input": { "command": "pkill -f node" } }
```

and accepts on stdout:

```json
{ "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "..." } }
```

The `permissionDecisionReason` is shown to the model as the tool result, so the fix in the denial is what it reads next.

## Matching MCP tools

The `tools` field of a rule is matched against `tool_name`, which for MCP servers looks like `mcp__<server>__<tool>`. To make the hook run for them, add a matcher group to `settings.json` by hand (the installer only writes the two above), for example `"matcher": "mcp__windows-mcp__PowerShell"`, and name that tool in the rule's `tools`.

## Windows

Claude Code on Windows runs hook commands through the shell it was configured with (Git Bash by default). The quoted absolute paths work there. The three Windows-only built-in rules (`tmp-path-to-interpreter`, `powershell-write-without-encoding`, `inline-script-backslash`) exist because of that shell's path translation and quoting; they are skipped on other platforms.

## Background sessions

A denial in a background session (`claude --bg`) is read by the model like any other tool result. `rm-relative-glob-after-cd` exists because the runtime's own approval prompt in that situation has no one to answer it; a denial with the fix keeps the session moving.
