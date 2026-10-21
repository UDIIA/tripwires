// Example of a house rule: calling a metered API costs money the person did not agree to spend.
// The override is the point of this rule: `TRIPWIRES_ALLOW=paid-api-needs-the-persons-words` in the command, or
// `tripwires allow ... --because "<their words>"`, which puts the words in the log next to the pass.
import { segments } from 'tripwires/shell';

const PAID = [
  { vendor: 'ElevenLabs', rx: /api\.elevenlabs\.io|ELEVENLABS_API_KEY|elevenlabs\.(?:generate|text_to_speech)/i },
  { vendor: 'OpenAI API', rx: /api\.openai\.com|OPENAI_API_KEY|openai\.(?:chat|audio|images)\./i },
  { vendor: 'Anthropic API', rx: /api\.anthropic\.com|ANTHROPIC_API_KEY|anthropic\.messages\.create/i },
  { vendor: 'Google AI API', rx: /generativelanguage\.googleapis\.com|GEMINI_API_KEY|GOOGLE_API_KEY/i },
];
const READ_ONLY = /(?:^|[\s;&|(])(?:grep|rg|echo|cat|sed|head|tail|type|git)\s/i;

export default {
  id: 'paid-api-needs-the-persons-words',
  title: 'Metered API call without the person\'s go-ahead',
  tools: /^(?:Bash|PowerShell)$/,
  incident:
    '2026-10-02: a translation loop ran every step through a paid API 29 seconds after the person asked "maybe through our subscription instead?". 2026-10-05: a dubbing job went to a paid voice API no one asked for ("am I made of money?"), and the session went back to it six hours later, still without a word from them. 46 denials in 23 sessions in the nine days after the rule went in.',
  check(input) {
    for (const s of segments(input.command)) {
      if (READ_ONLY.test(s)) continue;
      const hit = PAID.find((p) => p.rx.test(s));
      if (!hit) continue;
      return {
        reason: `${hit.vendor} is metered. Nothing in this command shows the person agreed to pay for this call.`,
        fix: 'Use the subscription path (the CLI logged into the account, the free tier already measured), or get the person\'s words and pass them with the override so they are logged next to the call.',
        excerpt: s.trim().slice(0, 120),
      };
    }
    return null;
  },
};
