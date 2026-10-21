// "Saturday, October 11" when October 11 is a Sunday. Language models carry last year's calendar in their weights
// and write the weekday from memory. Checked in English and Brazilian Portuguese, in text the agent WRITES
// (files, messages, echo/printf, scripts), never in text it reads.

const EN_DAYS = { sunday: 0, sun: 0, monday: 1, mon: 1, tuesday: 2, tue: 2, tues: 2, wednesday: 3, wed: 3, thursday: 4, thu: 4, thur: 4, thurs: 4, friday: 5, fri: 5, saturday: 6, sat: 6 };
const EN_MONTHS = { january: 1, jan: 1, february: 2, feb: 2, march: 3, mar: 3, april: 4, apr: 4, may: 5, june: 6, jun: 6, july: 7, jul: 7, august: 8, aug: 8, september: 9, sep: 9, sept: 9, october: 10, oct: 10, november: 11, nov: 11, december: 12, dec: 12 };
const EN_DAY_NAMES = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const PT_DAY_NAMES = ['domingo', 'segunda-feira', 'terça-feira', 'quarta-feira', 'quinta-feira', 'sexta-feira', 'sábado'];
const PT_MONTHS = { janeiro: 1, fevereiro: 2, março: 3, marco: 3, abril: 4, maio: 5, junho: 6, julho: 7, agosto: 8, setembro: 9, outubro: 10, novembro: 11, dezembro: 12, jan: 1, fev: 2, mar: 3, abr: 4, mai: 5, jun: 6, jul: 7, ago: 8, set: 9, out: 10, nov: 11, dez: 12 };

function ptDay(s) {
  const t = s.toLowerCase().replace(/[.\s-]+feira$/, '').replace(/\.$/, '').replace(/s$/, '').replace(/[áà]/g, 'a').replace(/ç/g, 'c');
  const m = { domingo: 0, dom: 0, segunda: 1, seg: 1, terca: 2, ter: 2, quarta: 3, qua: 3, quinta: 4, qui: 4, sexta: 5, sex: 5, sabado: 6, sab: 6 };
  if (m[t] !== undefined) return m[t];
  const o = t.match(/^([2-6])[ªa]?$/);
  return o ? Number(o[1]) - 1 : null;
}
function enDay(s) {
  const t = s.toLowerCase().replace(/\.$/, '');
  return EN_DAYS[t] ?? null;
}

const PT_DAY_RX = String.raw`(domingos?|segundas?(?:[-\s.]*feiras?)?|ter[çc]as?(?:[-\s.]*feiras?)?|quartas?(?:[-\s.]*feiras?)?|quintas?(?:[-\s.]*feiras?)?|sextas?(?:[-\s.]*feiras?)?|s[áa]bados?|dom\.?|seg\.?|ter\.?|qua\.?|qui\.?|sex\.?|s[áa]b\.?|[2-6]ª(?:[-\s]?feira)?)`;
const PT_MONTH_RX = String.raw`(janeiro|fevereiro|mar[çc]o|abril|maio|junho|julho|agosto|setembro|outubro|novembro|dezembro|jan|fev|mar|abr|mai|jun|jul|ago|set|out|nov|dez)\.?`;
const EN_DAY_RX = String.raw`(sunday|monday|tuesday|wednesday|thursday|friday|saturday|sun|mon|tue|tues|wed|thu|thur|thurs|fri|sat)\.?`;
const EN_MONTH_RX = String.raw`(january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|jun|jul|aug|sep|sept|oct|nov|dec)\.?`;
const SEP = String.raw`[\s,:()]*(?:dia\s+|the\s+)?`;
const ORD = String.raw`(?:st|nd|rd|th)?`;

// Each pattern yields { d, mo, y, name } via its `pick`. Shapes covered (DAY = weekday name, D/M = numbers):
//   pt: "DAY D/M[/YYYY]"  "DAY, D de MONTH[ de YYYY]"  "D/M (DAY)"  "D de MONTH, DAY"
//   en: "DAY, MONTH D[, YYYY]"  "DAY, D MONTH[ YYYY]"  "MONTH D[, YYYY] (DAY)"  "D MONTH[ YYYY] (DAY)"
// English numeric dates (10/11) are ambiguous between D/M and M/D and are not checked.
const PATTERNS = [
  { lang: 'pt', rx: new RegExp(`\\b${PT_DAY_RX}${SEP}(\\d{1,2})/(\\d{1,2})(?:/(\\d{2,4}))?(?!\\d|/)`, 'gi'), pick: (m) => ({ name: m[1], d: +m[2], mo: +m[3], y: m[4] ? +m[4] : 0 }) },
  { lang: 'pt', rx: new RegExp(`\\b${PT_DAY_RX}${SEP}(\\d{1,2})\\s+de\\s+${PT_MONTH_RX}(?:\\s+de\\s+(\\d{4}))?`, 'gi'), pick: (m) => ({ name: m[1], d: +m[2], mo: PT_MONTHS[m[3].toLowerCase().replace(/\.$/, '')], y: m[4] ? +m[4] : 0 }) },
  { lang: 'pt', rx: new RegExp(`(?<![\\d/])(\\d{1,2})/(\\d{1,2})(?:/(\\d{2,4}))?[\\s,]*[(,]?\\s*${PT_DAY_RX}\\b`, 'gi'), pick: (m) => ({ d: +m[1], mo: +m[2], y: m[3] ? +m[3] : 0, name: m[4] }) },
  { lang: 'pt', rx: new RegExp(`(?<![\\d/])(\\d{1,2})\\s+de\\s+${PT_MONTH_RX}(?:\\s+de\\s+(\\d{4}))?[\\s,]*[(,]?\\s*${PT_DAY_RX}\\b`, 'gi'), pick: (m) => ({ d: +m[1], mo: PT_MONTHS[m[2].toLowerCase().replace(/\.$/, '')], y: m[3] ? +m[3] : 0, name: m[4] }) },
  { lang: 'en', rx: new RegExp(`\\b${EN_DAY_RX}${SEP}${EN_MONTH_RX}\\s+(\\d{1,2})${ORD}(?:,?\\s+(\\d{4}))?(?!\\d|:)`, 'gi'), pick: (m) => ({ name: m[1], mo: EN_MONTHS[m[2].toLowerCase().replace(/\.$/, '')], d: +m[3], y: m[4] ? +m[4] : 0 }) },
  { lang: 'en', rx: new RegExp(`\\b${EN_DAY_RX}${SEP}(\\d{1,2})${ORD}\\s+(?:of\\s+)?${EN_MONTH_RX}(?:,?\\s+(\\d{4}))?`, 'gi'), pick: (m) => ({ name: m[1], d: +m[2], mo: EN_MONTHS[m[3].toLowerCase().replace(/\.$/, '')], y: m[4] ? +m[4] : 0 }) },
  { lang: 'en', rx: new RegExp(`\\b${EN_MONTH_RX}\\s+(\\d{1,2})${ORD}(?:,?\\s+(\\d{4}))?[\\s,]*[(,]?\\s*${EN_DAY_RX}\\b`, 'gi'), pick: (m) => ({ mo: EN_MONTHS[m[1].toLowerCase().replace(/\.$/, '')], d: +m[2], y: m[3] ? +m[3] : 0, name: m[4] }) },
  { lang: 'en', rx: new RegExp(`(?<![\\d/])(\\d{1,2})${ORD}\\s+(?:of\\s+)?${EN_MONTH_RX}(?:,?\\s+(\\d{4}))?[\\s,]*[(,]?\\s*${EN_DAY_RX}\\b`, 'gi'), pick: (m) => ({ d: +m[1], mo: EN_MONTHS[m[2].toLowerCase().replace(/\.$/, '')], y: m[3] ? +m[3] : 0, name: m[4] }) },
];

const weekdayOf = (y, m, d) => new Date(Date.UTC(y, m - 1, d, 12)).getUTCDay();
const validDate = (y, m, d) => m >= 1 && m <= 12 && d >= 1 && d <= 31 && new Date(Date.UTC(y, m - 1, d)).getUTCDate() === d;
function candidateYears(y, m, d, now) {
  if (y) return [y < 100 ? 2000 + y : y];
  const a = now.getUTCFullYear();
  const t = Date.UTC(a, m - 1, d);
  const today = Date.UTC(a, now.getUTCMonth(), now.getUTCDate());
  const days = (t - today) / 86400000;
  // No year written: this year; a date more than 45 days in the past may be next year's (December talking about January)
  return days < -45 ? [a, a + 1] : [a];
}
const withoutCode = (s) => String(s).replace(/```[\s\S]*?```/g, ' ').replace(/`[^`\n]*`/g, ' ');

/** All (weekday, date) pairs in `text` whose weekday is wrong. Exported for tests and for other tools. */
export function mismatches(text, now = new Date()) {
  if (!text || !/\d{1,2}/.test(text)) return [];
  const t = withoutCode(text);
  const out = [];
  const seen = new Set();
  for (const p of PATTERNS) {
    p.rx.lastIndex = 0;
    let m;
    while ((m = p.rx.exec(t))) {
      const v = p.pick(m);
      const written = p.lang === 'pt' ? ptDay(v.name) : enDay(v.name);
      if (written === null || !v.mo) continue;
      const years = candidateYears(v.y, v.mo, v.d, now).filter((a) => validDate(a, v.mo, v.d));
      if (!years.length) continue;
      if (years.some((a) => weekdayOf(a, v.mo, v.d) === written)) continue;
      if (!v.y) {
        // A year nearby in the sentence ("In 2025 the meetup was on a Saturday, October 11") makes the pair right for that year.
        const around = t.slice(Math.max(0, m.index - 35), m.index + m[0].length + 35);
        const ctxYears = [...around.matchAll(/\b(20\d\d)\b/g)].map((x) => +x[1]);
        if (ctxYears.some((a) => validDate(a, v.mo, v.d) && weekdayOf(a, v.mo, v.d) === written)) continue;
      }
      const a = years[0];
      const key = `${v.name}|${v.d}/${v.mo}/${a}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const names = p.lang === 'pt' ? PT_DAY_NAMES : EN_DAY_NAMES;
      out.push({ excerpt: m[0].trim(), written: v.name, expected: names[weekdayOf(a, v.mo, v.d)], date: `${a}-${String(v.mo).padStart(2, '0')}-${String(v.d).padStart(2, '0')}` });
    }
  }
  return out;
}

// In commands, only parts that WRITE text count (files, messages, heredocs, echo/printf, inline scripts).
const WRITES_TEXT = /(?:>>?|\btee\b|<<|\becho\b|\bprintf\b|python\d?\s+-c|node\s+-e|Set-Content|Out-File|Add-Content|--text\b|--message\b|--body\b|--data\b|--subject\b|-m\s)/i;
const INTERNAL_FILE = /(?:\.test\.[cm]?js|\.jsonl|\.log|\.csv|CHANGELOG\.md)$/i;

export default {
  id: 'weekday-date-mismatch',
  title: 'Weekday does not match the date',
  tools: /^(?:Bash|PowerShell|mcp__windows-mcp__PowerShell|Write|Edit|MultiEdit)$/,
  incident:
    'On 2026-10-08 a deadline went out in 13 places of a customer-facing page and message set as a Saturday; the date was a Sunday. Only a blind second review caught it. A replay over 37 days of transcripts found the same error in 27 sessions, almost always last year\'s calendar applied to this year.',
  check(input, ctx) {
    let text = '';
    if (input.tool === 'Write' || input.tool === 'Edit' || input.tool === 'MultiEdit') {
      if (INTERNAL_FILE.test(input.file)) return null;
      text = input.text;
    } else {
      if (!WRITES_TEXT.test(input.command)) return null;
      text = input.command;
    }
    const errs = mismatches(text, ctx.now);
    if (!errs.length) return null;
    const e = errs[0];
    return {
      reason: `"${e.excerpt}": ${e.date} is a ${e.expected}${errs.length > 1 ? ` (${errs.length - 1} more)` : ''}. The weekday was written from memory, and memory holds last year's calendar.`,
      fix: `Correct the weekday or the date. Check: \`node -e "console.log(new Date('${e.date}T12:00Z').toUTCString())"\`. If the text quotes the error on purpose, use the override.`,
      excerpt: e.excerpt,
    };
  },
};
