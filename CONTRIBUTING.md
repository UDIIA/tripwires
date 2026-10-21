# Contributing

## A rule denied legitimate work

Open an issue with the exact command and the denial text. That command becomes a pass case in the rule's tests before the rule is narrowed. This is the most useful kind of contribution; it is how every built-in rule got to its current shape.

## A new built-in rule

A built-in rule has to be a mistake that coding agents make on more than one machine. Send the pull request with:

- the `incident` field filled in with a date, what ran, what broke, and how many times it happened before;
- the deny test built from the real command, and at least two pass cases that are legitimate neighbours;
- a denial whose `fix` the agent can act on without asking.

A rule that is only true on your machine belongs in `examples/house-rules/` as a template, or in your own `tripwires-rules/` folder. Both are welcome in the examples directory when the incident is instructive.

## Code

- Node 18.17 or newer, ES modules, no dependencies. Keep it that way; the hook starts once per matched tool call.
- `npm test` runs everything with `node:test`. Keep `TRIPWIRES_TEST=1` in any new suite.
- Rules never throw to the caller on purpose; the engine catches and logs, but a rule that throws on ordinary input is a bug.
- Messages are written for the agent that will read them: what, why, the alternative. No "blocked" without a fix.

## Reporting a security issue

See [SECURITY.md](SECURITY.md).
