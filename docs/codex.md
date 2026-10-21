# Codex CLI

Codex CLI 0.124 or newer (hooks became stable in that release).

```bash
npx tripwires init --codex            # ~/.codex/hooks.json
npx tripwires init --codex --project  # ./.codex/hooks.json (loads only when the project layer is trusted)
```

What gets written, merged into whatever `hooks.PreToolUse` already holds:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash|PowerShell",
        "hooks": [{ "type": "command",
                    "command": "\"/path/to/node\" \"/path/to/tripwires/bin/tripwires.mjs\" hook --agent codex",
                    "commandWindows": "...the same...",
                    "timeout": 10, "statusMessage": "tripwires" }] },
      { "matcher": "apply_patch|Read|Write|Edit",
        "hooks": [{ "...": "..." }] }
    ]
  }
}
```

`timeout` is in seconds for Codex. `commandWindows` is Codex's Windows-only override and carries the same command.

## Trust

Codex hashes every non-managed hook definition and does not run it until it has been reviewed and trusted. After `init`:

1. open Codex in a terminal,
2. run `/hooks`,
3. trust the two tripwires entries.

Any change to the command string (an upgrade that moves the package path, for instance) changes the hash and needs trusting again. `tripwires doctor` shows the exact command installed. CI runners can pass `--dangerously-bypass-hook-trust` to Codex.

## Payload and decision

Codex sends the same core fields as Claude Code (`session_id`, `cwd`, `hook_event_name`, `tool_name`, `tool_input`) plus `turn_id`, `tool_use_id`, `model` and `permission_mode`. For shell calls `tool_input.command` holds the command; for `apply_patch` the matcher also answers to `Edit` and `Write`, and `tool_input` carries the patch.

The denial is the same JSON on stdout with `permissionDecision: "deny"`. Codex also accepts exit code 2 with the reason on stderr; tripwires uses that only when failing closed on an engine error (`TRIPWIRES_FAIL_CLOSED=1`).

`permissionDecision: "ask"` is not supported by Codex at the time of writing; tripwires never emits it.

## Inline TOML instead of hooks.json

If you prefer hooks inline in `~/.codex/config.toml`, use one format per layer and copy the command from `tripwires doctor`:

```toml
[[hooks.PreToolUse]]
matcher = "Bash|PowerShell"

[[hooks.PreToolUse.hooks]]
type = "command"
command = '"/path/to/node" "/path/to/tripwires/bin/tripwires.mjs" hook --agent codex'
timeout = 10
```
