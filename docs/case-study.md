# Case study: one setup, six weeks

These are the measurements the built-in rules came from. One developer, one Windows 11 laptop, five Claude Code accounts running in parallel (a main session plus background sessions), Codex CLI for review and delegated work. The rules were the house's own hooks before they were generalized into this package; the identifiers were renamed, the numbers were not.

Every count below was produced by the report command over the hook log, not estimated. "Sessions" means distinct `session_id` values that hit the rule.

## Before: rules as text

The house had a long `CLAUDE.md` and a memory system. Each repeated mistake had a line in one or the other. Replays of five weeks of transcripts in October found the same mistakes recurring in sessions where the relevant memory had been loaded. The line that opened the hooks file afterwards: "a rule that only exists written does not act in the moment".

Example: the Bash tool on Windows collapses `\\` to `\` in inline scripts. A memory note about it existed. On 2026-10-04 one session broke four inline Python scripts in a row with the note loaded, retrying with cosmetic variations each time.

## After: the first rule

The `inline-script-backslash` rule went in on 2026-10-04 at night. From then to 2026-10-21:

| | |
|---|---|
| denials | 403 |
| sessions | 168 |
| per day (median) | 22 |

Each of those 403 denials is a command that did not run. Whether the agent then took the fix (write the script to a file) is not in the log; what is in the log is that the rule has not had a "hurt" verdict since its second week, when it was narrowed to deny only when the delivered program text actually differs (inside double quotes `\\d` and `\d` arrive the same, and the first version denied those too). It is the most frequent rule in the log by a factor of eight.

## The second wave (2026-10-12 to 2026-10-20)

Seven more rules, from the lab's classification of recurring errors, each with the incident that justified it:

| rule (built-in name) | denials | sessions |
|---|---|---|
| metered API call without the person's words (example rule) | 46 | 23 |
| `sed-inplace-on-crlf` | 19 | 17 |
| `weekday-date-mismatch` | 11 | 8 |
| accented text inline in an HTTP body on Windows (house rule, not shipped) | 8 | 8 |
| `tmp-path-to-interpreter` | 6 | 6 |
| `deploy-burst` (in its first two days) | 6 | 4 |
| direct send bypassing the wrapper (example rule) | 2 | 2 |

The weekday rule is the one people doubt until they see it: 11 denials in 8 sessions in nine days, almost all of them the 2025 calendar applied to 2026 dates.

## What the weekly review changed

Three rounds of the report produced three lessons that are now in the method and in the code:

1. **A rule that reads a file from disk must normalize `\r` before matching.** A CRLF script contained the exact exemption the rule looked for and was denied three times in three sessions (2026-10-16 17:58, 20:08; 2026-10-17 22:41). The fixture in the test is CRLF now.
2. **A negation anywhere in a sentence is not a veto.** The metered-API rule read the person's messages to find authorization. "Since I did not do the transcription this time, go ahead and use Mistral" was read as a veto because of "not". Negation counts only within 25 characters of the verb; a question is neutral. Four commands were wrongly denied in 30 minutes on 2026-10-18 before this was fixed; the fix is a test case now.
3. **Test suites must not write the production log.** On 2026-10-18 at 14:48 the suites wrote 41 lines into the log, one day before a review that counts wrong denials. `TRIPWIRES_TEST=1` is read at call time, not import time, and every suite sets it.

## Cost

Each matched tool call starts one Node process. See the measured numbers in the README; the dominant cost is Node start-up, not the rules. One hook in the house that read the whole transcript at the end of every turn reached 45 seconds on a 120 MB transcript and was changed to read only the last turns; the report's per-rule p50 is how that was noticed. None of the shipped rules read the transcript.

## Limits of this evidence

- One developer, one machine, no control group. The "before" is a replay of transcripts, not a parallel run without hooks.
- "Denials" count the hook firing, not the mistake being avoided; an agent could in principle give up on the task instead of taking the fix. The log does not record what the agent did next. The override count and the "hurt" verdicts in the weekly review are the only proxies, and they are read by a person.
- Four of the eleven rules are Windows-only, because that is where the setup lives. The engine and the method are not.
