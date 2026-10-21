// Example of a house rule: every outbound message must go through the one script that dedupes, logs and lints.
// A direct HTTP call to the messaging API skips all three. The pattern is common: a wrapper exists for a reason,
// and the agent reaches for curl because it is shorter.
import { segments } from 'tripwires/shell';

const CALLER = /(?:^|[\s;&|(`$'"])(?:curl|wget|http|Invoke-RestMethod|irm|Invoke-WebRequest|iwr|fetch\s*\(|urllib\.request|requests\.(?:post|put)|axios\.(?:post|put))/i;
const TARGET = /\/message\/send(?:Text|List|Buttons)\b|\/api\/v1\/messages\b/i;
const WRITING_A_FILE = /\.replace\(|\bscp\b|\bgit\s+(?:diff|log|show|add|commit)\b|<<-?\s*['"]?\w+['"]?[^\n]*>\s*\S+/i;

export default {
  id: 'send-through-the-wrapper',
  title: 'Message sent by a direct HTTP call',
  tools: /^(?:Bash|PowerShell)$/,
  incident:
    '213 direct sends in 37 days (counted in the command cache on 2026-10-15). The wrapper carries the duplicate check, the send log and the message lint; curl carries none. On 2026-10-14 a machine-formatted status line reached a customer\'s phone through a direct call and the owner asked what that was.',
  check(input) {
    for (const s of segments(input.command)) {
      if (!CALLER.test(s) || !TARGET.test(s)) continue;
      if (WRITING_A_FILE.test(s) || /--dry-run|\/health\b|\/status\b|(?:^|[\s;&|(])(?:grep|echo|sed|head|tail|type)\s/i.test(s)) continue;
      return {
        reason: 'A direct call to the send endpoint skips the duplicate check, the send log and the message lint that the wrapper carries.',
        fix: 'Use the wrapper: `python send.py --to <number> --text "..."`; it logs, dedupes and lints. For media the wrapper does not cover, switch the rule off with a note.',
        excerpt: s.trim().slice(0, 120),
      };
    }
    return null;
  },
};
