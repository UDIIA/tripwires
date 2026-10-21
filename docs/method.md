# The method: from incident to rule to verdict

tripwires is a small engine. The method around it is what keeps the rules honest. It was worked out over six weeks on one setup, and the numbers in [case-study.md](case-study.md) come from it.

## The loop

1. **An incident happens.** The agent does something it was told not to, or something no one thought to forbid. You notice because something broke, cost money, or reached a person who should not have seen it.
2. **Write it down with a date, before the rule.** What was run, what broke, how it was noticed, how many times it had already happened. This text goes in the rule's `incident` field. A rule without it is a superstition in three weeks.
3. **Write the rule from the real command.** The deny case in the test is the exact command from the transcript. Then write the pass cases: the legitimate neighbours a sloppy pattern would block. `grep -c "" .env` next to `cat .env`. `ffprobe` next to `ffmpeg`. `cd build && rm -rf /abs/path` next to `cd build && rm -rf tmp-*`.
4. **Make the denial teach.** The message has three parts: what the agent was about to do, why it is the mistake (one verifiable sentence), and the exact alternative. An agent that reads "blocked" retries with a variation. An agent that reads the alternative uses it.
5. **Install and let it run.** Every denial, override and rule error goes to the log with the session and the milliseconds it cost.
6. **Once a week, read the report and write a verdict per rule**, citing a session and a time:
   - *helped*: it fired on the mistake, the agent took the fix.
   - *hurt*: it fired on legitimate work. Three wrong denials in a day means the rule gets narrowed today, and the wrong command goes into the pass cases first.
   - *no effect*: it never fired. After a month, either the agent learned or the rule guards a path nobody takes. Retire it or keep it; decide with the number.
   - *confounded*: it fired but something else changed at the same time. Note it and wait a week.
7. **One lesson per round, at most.** When a round shows a reusable contrast (not "be careful", not "the key changed"), write it in a lessons file with the trigger, the lesson, the evidence and a confidence level. The next person writing a rule reads that file first.

## Rules for rules

- **One incident per rule.** A rule that covers three unrelated mistakes cannot be narrowed when one of them turns out to be fine.
- **Never deny a read on its own.** Rules look at what the agent is about to change, send or spend. Reading a credential file whole is the one exception, and the denial hands over a masked reader.
- **Data is not code.** A heredoc written to a file, a string inside `echo`, a Markdown table that mentions the command: none of these are the command. Use `stripFileHeredocs`, `withoutQuotes` and `segments`. The first version of the ffmpeg rule in the case study blocked the notes file that described the ffmpeg incident.
- **Fail open.** A rule that throws is skipped. The engine crashing lets the call through. A guardrail that breaks the session gets uninstalled within a day and then protects nothing.
- **The override is loud.** `TRIPWIRES_ALLOW=<id>` in the command, or a one-shot file written with the person's words. Both are logged. No silent exceptions, no environment variable the agent can set for itself without it showing in the command text.
- **Switching off needs a note.** A rule switched off without a reason comes back as the same incident, and nobody remembers why it was off.
- **Tests do not write the log.** `TRIPWIRES_TEST=1` is set by every suite; the report only counts real sessions. (This one was learned the hard way: a test run wrote 41 lines into the log the day before a review that counted wrong denials.)
- **Measure the cost.** The log carries the milliseconds from process start to decision. A rule that reads the transcript to find the person's words can cost seconds on a long session; the report shows p50 per rule so you see it.

## What this is not

It is not a sandbox and not a security boundary. An agent that writes a script to disk and runs it goes around any command-text rule; a sandbox is the tool for that. tripwires is for the class of mistake where the agent is not adversarial, just forgetful: it was told, it agreed, and it did it again on Thursday.
