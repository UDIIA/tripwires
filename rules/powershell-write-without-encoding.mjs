import fs from 'node:fs';
import path from 'node:path';
import { segments } from '../src/shell.mjs';

// Windows PowerShell 5.1 writes ANSI by default. pwsh (7+) writes UTF-8 and is left alone.
const WRITES = /\b(Set-Content|Add-Content|Out-File)\b|(?<![-\w])\b(sc|ac)\b(?=\s+-|\s+["'])/i;
const IS_PS_TOOL = (tool) => /^(?:PowerShell|mcp__windows-mcp__PowerShell)$/i.test(String(tool || ''));
const OUT_CMDLET = /\b(?:Write-Output|Write-Host|Write-Verbose|Write-Debug|Write-Warning|Write-Information|echo)\b\s*(?:"(?:[^"\\]|\\.)*"|'[^']*'|[^\s;|]+)/gi;

function hasNonAscii(file) {
  try {
    const buf = fs.readFileSync(file);
    return buf.some((b) => b > 0x7f);
  } catch {
    return false;
  }
}

export default {
  id: 'powershell-write-without-encoding',
  title: 'Set-Content / Add-Content without -Encoding in Windows PowerShell 5.1',
  tools: /^(?:PowerShell|Bash|mcp__windows-mcp__PowerShell)$/,
  platforms: ['win32'],
  incident:
    'On 2026-10-06 a YAML config with accented text was rewritten by `Set-Content` in PowerShell 5.1. It came out in the ANSI code page; the service rejected it ("unacceptable character #x008f") and ran on its fallback config for two minutes before anyone noticed.',
  check(input, ctx) {
    const c = input.command;
    if (!WRITES.test(c)) return null;
    const psTool = IS_PS_TOOL(input.tool);
    for (const seg of segments(c)) {
      if (!psTool && !/\bpowershell(?:\.exe)?\b/i.test(seg)) continue;
      const m = seg.replace(OUT_CMDLET, '').match(WRITES);
      if (!m) continue;
      if (/-Encoding\b|-AsByteStream|-Enc\b/i.test(seg)) continue;
      const cmdlet = m[1] || m[2];
      const accented = /[^\x00-\x7F]/.test(seg);
      const pm = seg.match(/-(?:Path|LiteralPath|FilePath)\s+["']?([^"'\s]+)/i) || seg.match(new RegExp(`${cmdlet}\\s+["']?([^"'\\s-][^"'\\s]*)`, 'i'));
      const target = pm ? pm[1] : '';
      if (accented) return deny(cmdlet, target, 'the same statement carries non-ASCII text');
      if (ctx.fs === false) continue;
      const p = target && path.resolve(input.cwd || process.cwd(), target.replace(/\$env:USERPROFILE/i, process.env.USERPROFILE || ''));
      if (p && fs.existsSync(p) && hasNonAscii(p)) return deny(cmdlet, target, 'the file on disk already has non-ASCII bytes');
    }
    return null;
  },
};

function deny(cmdlet, target, why) {
  return {
    reason: `${cmdlet} in Windows PowerShell 5.1 writes the ANSI code page by default and ${why}. The accented characters will be corrupted.`,
    fix: 'Add `-Encoding utf8` to the write AND to the Get-Content that feeds it (or `-Raw -Encoding utf8`), or edit the bytes from Python (open rb/wb) or with the Edit tool.',
    excerpt: `${cmdlet} ${target}`.trim(),
  };
}
