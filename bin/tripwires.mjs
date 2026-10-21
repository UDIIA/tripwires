#!/usr/bin/env node
// tripwires CLI. `tripwires help` lists the commands.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { loadConfig, trustProject } from '../src/config.mjs';
import { loadRules, evaluate, allowFile } from '../src/engine.mjs';
import { runHook } from '../src/hook.mjs';
import { install, uninstall, status, TARGETS } from '../src/install.mjs';
import { buildReport, renderReport } from '../src/report.mjs';
import { peek } from '../src/peek.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const argv = process.argv.slice(2);
const cmd = argv[0] || 'help';
const flag = (name) => argv.includes(`--${name}`);
const opt = (name, d) => {
  const i = argv.indexOf(`--${name}`);
  return i > 0 && argv[i + 1] !== undefined ? argv[i + 1] : d;
};
const VALUE_OPTS = new Set(['--tool', '--cwd', '--days', '--rule', '--samples', '--because', '--dir', '--key', '--max', '--agent']);
const positional = [];
for (let i = 1; i < argv.length; i++) {
  if (VALUE_OPTS.has(argv[i])) { i++; continue; }
  if (argv[i].startsWith('--')) continue;
  positional.push(argv[i]);
}

const HELP = `tripwires ${pkg.version}: guardrails that fire before the tool runs (Claude Code, Codex CLI)

  tripwires init [--claude] [--codex] [--project] [--dry-run]   install the PreToolUse hook (default: every agent found)
  tripwires uninstall [--claude] [--codex] [--project]          remove it
  tripwires doctor                                              what is installed, which rules load, log size
  tripwires list [--all]                                        rules and the incident behind each one
  tripwires try "<command>" [--tool Bash] [--cwd DIR]           dry-run a command against the rules
  tripwires report [--days 7] [--rule ID] [--samples 6] [--json] what fired, how often, verdict lines to fill in
  tripwires allow <rule-id> --because "<the person's words>"    one-shot pass for the next denial of that rule
  tripwires off <rule-id> | on <rule-id>                        switch a rule off/on in ~/.tripwires/config.json
  tripwires trust [dir]                                         let this project's .tripwires.json load rule code
  tripwires new <rule-id> [--dir ./tripwires-rules]             scaffold a rule file and its test from the template
  tripwires peek <file> [--key a.b] [--max 400]                 read a credential file with every value masked
  tripwires pids <name>                                         list processes by name with PID and command line
  tripwires hook --agent claude|codex                           (used by the installed hook; reads stdin)

Docs: ${pkg.homepage}
`;

async function main() {
  switch (cmd) {
    case 'hook': {
      if (opt('agent')) process.env.TRIPWIRES_AGENT = opt('agent');
      process.exitCode = await runHook();
      return;
    }
    case 'init': {
      const agents = pickAgents();
      const scope = flag('project') ? 'project' : 'global';
      for (const a of agents) {
        const r = install(a, { scope, dryRun: flag('dry-run') });
        console.log(`${a} (${scope}): ${r.changed ? (flag('dry-run') ? 'would write' : 'written') : 'already installed'} → ${r.file}`);
        if (a === 'codex' && r.changed) console.log('  Codex trusts hooks per definition: open Codex, run /hooks and trust the tripwires entries once.');
      }
      if (!agents.length) console.log('No agent found. Pass --claude or --codex, or create ~/.claude or ~/.codex first.');
      return;
    }
    case 'uninstall': {
      const agents = pickAgents();
      const scope = flag('project') ? 'project' : 'global';
      for (const a of agents) {
        const r = uninstall(a, { scope, dryRun: flag('dry-run') });
        console.log(`${a} (${scope}): ${r.changed ? 'removed' : 'not installed'} → ${r.file}`);
      }
      return;
    }
    case 'doctor': {
      const cfg = loadConfig();
      console.log(`tripwires ${pkg.version}, node ${process.version}, ${process.platform}`);
      console.log(`config: ${cfg.sources.length ? cfg.sources.join(', ') : 'defaults (no config file)'}`);
      console.log(`state: ${cfg.stateDir}`);
      for (const s of status()) console.log(`${s.installed ? 'ON ' : 'off'} ${s.agent} ${s.scope}: ${s.file}${s.exists === 'invalid' ? ' (INVALID JSON)' : s.exists ? '' : ' (file absent)'}`);
      const rules = await loadRules(cfg);
      console.log(`rules: ${rules.filter((r) => !r.off).length} active, ${rules.filter((r) => r.off).length} off, ${rules.filter((r) => r.platforms && !r.platforms.includes(process.platform)).length} not for this platform`);
      for (const e of rules.errors) console.log(`  FAILED TO LOAD ${e.file}: ${e.message}`);
      for (const p of cfg.untrustedRules) console.log(`  NOT LOADED (project not trusted; run \`tripwires trust\` there): ${p}`);
      try {
        const st = fs.statSync(path.join(cfg.stateDir, 'log.jsonl'));
        console.log(`log: ${st.size} bytes`);
      } catch {
        console.log('log: empty (nothing has fired yet, or the hook is not installed)');
      }
      return;
    }
    case 'trust': {
      const dir = positional[0] ? path.resolve(positional[0]) : process.cwd();
      const file = trustProject(dir);
      console.log(`${dir} is trusted: its .tripwires.json may now load rule code (${file}). Rule files run inside the hook with your file and environment access; read them first.`);
      return;
    }
    case 'list': {
      const rules = await loadRules(loadConfig(), { strict: true });
      for (const r of rules) {
        const here = !r.platforms || r.platforms.includes(process.platform);
        console.log(`${r.off ? 'off ' : here ? 'ON  ' : 'n/a '} ${r.id}: ${r.title}`);
        if (flag('all')) console.log(`      tools: ${r.tools}${r.platforms ? `  platforms: ${r.platforms.join(',')}` : ''}\n      incident: ${r.incident}\n`);
      }
      if (!flag('all')) console.log('\n--all shows the incident behind each rule.');
      return;
    }
    case 'try': {
      const command = positional[0] || '';
      const tool = opt('tool', 'Bash');
      const cwd = opt('cwd', process.cwd());
      process.env.TRIPWIRES_TEST = '1';
      const r = await evaluate({ tool_name: tool, tool_input: tool === 'Read' ? { file_path: command } : { command }, cwd, session_id: 'try' }, { log: false, probe: true });
      if (!r) {
        console.log('pass');
        return;
      }
      console.log(`DENY\n${r.message}`);
      process.exitCode = 1;
      return;
    }
    case 'report': {
      const cfg = loadConfig();
      const rep = buildReport(cfg.stateDir, { days: Number(opt('days', 7)), rule: opt('rule', null), samples: Number(opt('samples', 6)) });
      console.log(flag('json') ? JSON.stringify(rep, null, 2) : renderReport(rep));
      return;
    }
    case 'allow': {
      const id = positional[0];
      const because = opt('because', '');
      if (!id || !because) {
        console.error('usage: tripwires allow <rule-id> --because "<the person\'s own words>"\nThe words are recorded in the log next to the pass. Do not invent them.');
        process.exitCode = 2;
        return;
      }
      const cfg = loadConfig();
      const f = allowFile(cfg.stateDir, id);
      fs.mkdirSync(path.dirname(f), { recursive: true });
      fs.writeFileSync(f, JSON.stringify({ rule: id, because, at: new Date().toISOString() }, null, 2));
      console.log(`one-shot pass written for ${id}: ${f}\nIt is consumed by the next denial of that rule and recorded in the log with the words.`);
      return;
    }
    case 'off':
    case 'on': {
      const id = positional[0];
      if (!id) {
        console.error(`usage: tripwires ${cmd} <rule-id>`);
        process.exitCode = 2;
        return;
      }
      const file = path.join(loadConfig().stateDir, 'config.json');
      let j = {};
      try {
        j = JSON.parse(fs.readFileSync(file, 'utf8'));
      } catch {
        j = {};
      }
      const off = new Set(Array.isArray(j.off) ? j.off : []);
      if (cmd === 'off') off.add(id);
      else off.delete(id);
      j.off = [...off];
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, JSON.stringify(j, null, 2) + '\n');
      console.log(`${id} is now ${cmd} (${file}). Write down why in your notes: a rule switched off without a reason comes back as the same incident.`);
      return;
    }
    case 'new': {
      const id = positional[0];
      if (!id || !/^[a-z0-9][a-z0-9-]*$/.test(id)) {
        console.error('usage: tripwires new <kebab-case-id> [--dir ./tripwires-rules]');
        process.exitCode = 2;
        return;
      }
      const dir = path.resolve(opt('dir', './tripwires-rules'));
      fs.mkdirSync(dir, { recursive: true });
      const ruleFile = path.join(dir, `${id}.mjs`);
      const testFile = path.join(dir, `${id}.test.mjs`);
      if (fs.existsSync(ruleFile)) {
        console.error(`${ruleFile} exists`);
        process.exitCode = 2;
        return;
      }
      fs.writeFileSync(ruleFile, ruleTemplate(id));
      fs.writeFileSync(testFile, testTemplate(id));
      console.log(`${ruleFile}\n${testFile}\n\nNext: fill in the incident (date, what happened, how often), write the denial from the real command, run \`node --test ${path.relative(process.cwd(), dir)}\`, then add "${path.relative(process.cwd(), dir).replace(/\\/g, '/')}" to "rules" in ~/.tripwires/config.json (or in .tripwires.json plus \`tripwires trust\` here).`);
      return;
    }
    case 'peek': {
      const file = positional[0];
      if (!file) {
        console.error('usage: tripwires peek <file> [--key a.b.c] [--max N]');
        process.exitCode = 2;
        return;
      }
      console.log(peek(file, { max: Number(opt('max', 400)), key: opt('key', null) }));
      return;
    }
    case 'pids': {
      const name = positional[0];
      if (!name) {
        console.error('usage: tripwires pids <name>');
        process.exitCode = 2;
        return;
      }
      console.log(listPids(name));
      return;
    }
    case 'version':
    case '--version':
    case '-v':
      console.log(pkg.version);
      return;
    default:
      console.log(HELP);
  }
}

function pickAgents() {
  const chosen = ['claude', 'codex'].filter((a) => flag(a));
  if (chosen.length) return chosen;
  return Object.keys(TARGETS).filter((a) => fs.existsSync(path.dirname(TARGETS[a].global)));
}

function listPids(name) {
  const me = new Set([process.pid, process.ppid]);
  if (process.platform === 'win32') {
    const ps = `Get-CimInstance Win32_Process | Where-Object { $_.Name -like '*${name.replace(/'/g, "''")}*' -or $_.CommandLine -like '*${name.replace(/'/g, "''")}*' } | Select-Object ProcessId,ParentProcessId,Name,CreationDate,CommandLine | ConvertTo-Json -Compress`;
    const r = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], { encoding: 'utf8', windowsHide: true });
    let rows = [];
    try {
      const j = JSON.parse(r.stdout || '[]');
      rows = Array.isArray(j) ? j : [j];
    } catch {
      return r.stdout || r.stderr || 'no match';
    }
    return rows.map((p) => `${String(p.ProcessId).padStart(7)}  ppid ${String(p.ParentProcessId).padStart(6)}  ${p.Name}${me.has(p.ProcessId) ? '  (this tripwires process)' : ''}\n         ${String(p.CommandLine || '').slice(0, 160)}`).join('\n') || 'no match';
  }
  // No shell: `ps` is run directly and filtered here, so the name cannot carry a command substitution.
  const r = spawnSync('ps', ['-eo', 'pid,ppid,etime,args'], { encoding: 'utf8' });
  const needle = name.toLowerCase();
  const rows = (r.stdout || '').split('\n').slice(1).filter((l) => l.toLowerCase().includes(needle));
  return rows.map((l) => (me.has(Number(l.trim().split(/\s+/)[0])) ? `${l}  (this tripwires process)` : l)).join('\n') || 'no match';
}

function ruleTemplate(id) {
  return `// One rule, one incident. Fill in every field from what actually happened, not from what might.
// Shell helpers (segments, tokens, firstWord, programName, stripFileHeredocs, withoutQuotes) come in ctx.shell,
// so this file needs no import. See https://github.com/UDIIA/tripwires/blob/main/docs/writing-a-rule.md
export default {
  id: '${id}',
  title: 'What the agent did, in six words',
  tools: /^(?:Bash|PowerShell)$/,            // which tool_name values this rule looks at
  // platforms: ['win32'],                   // uncomment when the mistake only exists on one OS
  incident:
    'YYYY-MM-DD HH:MM: what the agent ran, what broke, how it was noticed, how many times it happened before this rule.',
  check(input, ctx) {
    // input.command (Bash/PowerShell), input.file + input.text (Read/Write/Edit), input.cwd, input.session
    // ctx.now, ctx.platform, ctx.stateDir, ctx.fs (false in tests that must not touch the disk)
    const hit = ctx.shell.segments(input.command).find((s) => /PATTERN/.test(s));
    if (!hit) return null;
    return {
      reason: 'Why this command is the mistake, in one or two sentences the agent can verify.',
      fix: 'The command or tool to use instead. Concrete enough to paste.',
      excerpt: hit.trim(),
    };
  },
};
`;
}

function testTemplate(id) {
  return `import { test } from 'node:test';
import assert from 'node:assert/strict';
import rule from './${id}.mjs';

process.env.TRIPWIRES_TEST = '1';
const shell = await import('tripwires/shell').catch(() => import('${pathToFileURL(path.join(ROOT, 'src', 'shell.mjs')).href}'));
const run = (command, tool = 'Bash') => rule.check({ tool, command, file: '', text: '', cwd: process.cwd(), session: 'test', tool_input: { command } }, { now: new Date(), platform: process.platform, stateDir: '', fs: false, shell });

// Every "deny" case is the real command from the incident. Every "pass" case is legitimate work a sloppy regex would block.
test('${id}: denies the incident command', () => {
  assert.ok(run('THE REAL COMMAND'));
});
test('${id}: passes the legitimate neighbour', () => {
  assert.equal(run('A SIMILAR COMMAND THAT IS FINE'), null);
});
`;
}

main().catch((e) => {
  console.error(e && e.stack ? e.stack : String(e));
  process.exitCode = 1;
});
