import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { evaluate, loadRules, normalizeInput, denialJson, allowFile } from '../src/engine.mjs';
import { loadConfig } from '../src/config.mjs';
import { readLog, record } from '../src/log.mjs';
import { peek } from '../src/peek.mjs';
import { buildReport, renderReport } from '../src/report.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BIN = path.join(ROOT, 'bin', 'tripwires.mjs');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tripwires-engine-'));

const throwing = { id: 'always-throws', title: 'throws', tools: ['Bash'], incident: 'test', check() { throw new Error('boom'); } };
const denying = { id: 'always-denies', title: 'denies', tools: /^Bash$/, incident: 'test', check() { return { reason: 'because', fix: 'do x' }; } };

test('normalizeInput derives command, file and text from both agents\' payloads', () => {
  assert.equal(normalizeInput({ tool_name: 'Bash', tool_input: { command: 'ls' } }).command, 'ls');
  assert.equal(normalizeInput({ tool_name: 'Edit', tool_input: { file_path: '/a', new_string: 'x' } }).text, 'x');
  assert.equal(normalizeInput({ tool_name: 'MultiEdit', tool_input: { file_path: '/a', edits: [{ new_string: 'x' }, { new_string: 'y' }] } }).text, 'x\ny');
  assert.equal(normalizeInput({ tool_name: 'Read', tool_input: { path: '/b' } }).file, '/b');
  assert.equal(normalizeInput(null).tool, '');
});

test('a rule that throws is skipped; the next rule still runs; the error is logged', async () => {
  const config = { off: new Set(), rules: [], failClosed: false, stateDir: tmp, sources: [] };
  const r = await evaluate({ tool_name: 'Bash', tool_input: { command: 'ls' }, session_id: 's1' }, { rules: [throwing, denying], config, log: true });
  assert.equal(r.rule, 'always-denies');
  process.env.TRIPWIRES_TEST = '';
  await evaluate({ tool_name: 'Bash', tool_input: { command: 'ls' }, session_id: 's1' }, { rules: [throwing, denying], config, log: true });
  process.env.TRIPWIRES_TEST = '1';
  const kinds = readLog(tmp).map((l) => `${l.kind}:${l.rule}`);
  assert.ok(kinds.includes('error:always-throws'));
  assert.ok(kinds.includes('deny:always-denies'));
});

test('off rules never fire; tools and platforms filter', async () => {
  const config = { off: new Set(['always-denies']), rules: [], failClosed: false, stateDir: tmp, sources: [] };
  const rules = [{ ...denying, off: true }];
  assert.equal(await evaluate({ tool_name: 'Bash', tool_input: { command: 'ls' } }, { rules, config, log: false }), null);
  const winOnly = { ...denying, platforms: ['win32'] };
  assert.equal(await evaluate({ tool_name: 'Bash', tool_input: { command: 'ls' } }, { rules: [winOnly], config: { ...config, off: new Set() }, log: false, platform: 'linux' }), null);
  assert.equal(await evaluate({ tool_name: 'Read', tool_input: { file_path: 'x' } }, { rules: [denying], config: { ...config, off: new Set() }, log: false }), null);
});

test('TRIPWIRES_ALLOW token and the one-shot allow file pass once and are logged with the words', async () => {
  const state = fs.mkdtempSync(path.join(os.tmpdir(), 'tripwires-allow-'));
  const config = { off: new Set(), rules: [], failClosed: false, stateDir: state, sources: [] };
  const go = (command) => evaluate({ tool_name: 'Bash', tool_input: { command }, session_id: 's2' }, { rules: [denying], config, log: true });
  assert.equal((await go('ls')).rule, 'always-denies');
  assert.equal(await go('TRIPWIRES_ALLOW=always-denies ls'), null);
  assert.equal(await go('TRIPWIRES_ALLOW=* ls'), null);
  assert.equal(await go('export TRIPWIRES_ALLOW=always-denies; ls'), null);
  assert.equal(await go('TRIPWIRES_ALLOW=other ls') && 'denied', 'denied');
  assert.equal((await go('ls # TRIPWIRES_ALLOW=always-denies')).rule, 'always-denies', 'a comment is not an override');
  assert.equal((await go('ls "TRIPWIRES_ALLOW=always-denies"')).rule, 'always-denies', 'a string is not an override');
  const f = allowFile(state, 'always-denies');
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, JSON.stringify({ because: 'ship it, I checked', at: new Date().toISOString() }));
  process.env.TRIPWIRES_TEST = '';
  assert.equal(await go('ls'), null, 'one-shot pass consumed');
  assert.equal((await go('ls')).rule, 'always-denies', 'second call denied again');
  process.env.TRIPWIRES_TEST = '1';
  assert.ok(!fs.existsSync(f));
  const allow = readLog(state).find((l) => l.kind === 'allow' && l.how === 'one-shot');
  assert.equal(allow.because, 'ship it, I checked');
  const rep = buildReport(state, { days: 1 });
  assert.equal(rep.rules[0].id, 'always-denies');
  assert.equal(rep.rules[0].allows, 1);
  assert.match(renderReport(rep), /verdict: ______/);
});

test('a rule file that fails to load is reported and skipped; the others still run', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tripwires-broken-'));
  fs.writeFileSync(path.join(dir, 'a-broken.mjs'), 'export default { this is not javascript');
  fs.writeFileSync(path.join(dir, 'b-dup.mjs'), "export default { id: 'kill-by-name', title: 'dup', tools: ['Bash'], incident: 'x', check() { return null; } };");
  fs.writeFileSync(path.join(dir, 'c-ok.mjs'), "export default { id: 'c-ok', title: 'ok', tools: ['Bash'], incident: 'x', check(i) { return /^touch-me$/.test(i.command) ? { reason: 'r', fix: 'f' } : null; } };");
  const config = { off: new Set(), rules: [dir], failClosed: false, stateDir: tmp, sources: [], untrustedRules: [] };
  const rules = await loadRules(config);
  assert.equal(rules.errors.length, 2);
  assert.match(rules.errors[0].file, /a-broken/);
  assert.match(rules.errors[1].message, /duplicate rule id/);
  assert.ok(rules.find((r) => r.id === 'c-ok'));
  const r = await evaluate({ tool_name: 'Bash', tool_input: { command: 'touch-me' } }, { rules, config, log: false, platform: 'linux' });
  assert.equal(r.rule, 'c-ok');
  await assert.rejects(() => loadRules(config, { strict: true }));
});

test('project .tripwires.json cannot load rule code until the project is trusted; its off list applies anyway', async () => {
  const proj = fs.mkdtempSync(path.join(os.tmpdir(), 'tripwires-proj-'));
  fs.mkdirSync(path.join(proj, 'rules'));
  fs.writeFileSync(path.join(proj, 'rules', 'evil.mjs'), "export default { id: 'evil', title: 'x', tools: ['*'], incident: 'x', check() { return null; } };");
  fs.writeFileSync(path.join(proj, '.tripwires.json'), JSON.stringify({ rules: ['./rules'], off: ['kill-by-name'] }));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'tripwires-home-'));
  const userCfg = path.join(home, 'config.json');
  // Simulate the user config through TRIPWIRES_CONFIG being absent: loadConfig reads USER_CONFIG from the real home,
  // so this test drives the merge logic by calling loadConfig with a cwd and checking the untrusted bucket.
  const cfg = loadConfig({ cwd: path.join(proj, 'sub'), env: {} });
  fs.mkdirSync(path.join(proj, 'sub'), { recursive: true });
  assert.ok(cfg.off.has('kill-by-name'));
  assert.ok(!cfg.rules.some((p) => p.includes('evil') || p.endsWith('rules')) || cfg.trust.includes(proj.toLowerCase()), 'project rules not loaded without trust');
  assert.ok(cfg.untrustedRules.some((p) => p.toLowerCase() === path.join(proj, 'rules').toLowerCase()) || cfg.trust.includes(path.resolve(proj).toLowerCase()));
  fs.writeFileSync(userCfg, JSON.stringify({ trust: [proj] }));
  const trusted = loadConfig({ cwd: proj, env: { TRIPWIRES_CONFIG: userCfg } });
  // With TRIPWIRES_CONFIG the project file is not read at all (explicit config replaces both), so only the trust list is visible.
  assert.ok(trusted.trust.includes(path.resolve(proj).toLowerCase()));
});

test('normalizeInput turns a Codex apply_patch into file + added text, not a shell command', () => {
  const n = normalizeInput({ tool_name: 'apply_patch', tool_input: { command: '*** Begin Patch\n*** Add File: a/b.md\n+line one\n+line two\n*** End Patch' } });
  assert.equal(n.command, '');
  assert.equal(n.file, 'a/b.md');
  assert.equal(n.text, 'line one\nline two');
});

test('the denial message names the rule, the reason, the fix and the override', async () => {
  const config = { off: new Set(), rules: [], failClosed: false, stateDir: tmp, sources: [] };
  const r = await evaluate({ tool_name: 'Bash', tool_input: { command: 'ls' } }, { rules: [denying], config, log: false });
  assert.match(r.message, /^\[tripwires\] always-denies: denies\.\nWhy: because\nFix: do x\nOverride/);
  const j = JSON.parse(denialJson(r.message));
  assert.equal(j.hookSpecificOutput.permissionDecision, 'deny');
  assert.equal(j.hookSpecificOutput.hookEventName, 'PreToolUse');
});

test('built-in rules load, have unique kebab-case ids, an incident and a title', async () => {
  const rules = await loadRules({ off: new Set(), rules: [], stateDir: tmp, sources: [] });
  assert.ok(rules.length >= 10);
  for (const r of rules) {
    assert.match(r.id, /^[a-z0-9][a-z0-9-]*$/);
    assert.ok(r.title.length > 5, r.id);
    assert.ok(r.incident.length > 40, `${r.id} needs the incident behind it`);
    assert.match(r.incident, /20\d\d/, `${r.id}: incident needs a date`);
  }
});

test('example house rules load through the config and fire', async () => {
  const cfgFile = path.join(tmp, '.tripwires.json');
  fs.writeFileSync(cfgFile, JSON.stringify({ rules: [path.join(ROOT, 'examples', 'house-rules')], off: ['deploy-burst'] }));
  const config = loadConfig({ cwd: tmp, env: { TRIPWIRES_CONFIG: cfgFile, TRIPWIRES_STATE_DIR: tmp } });
  assert.ok(config.off.has('deploy-burst'));
  const rules = await loadRules(config);
  assert.ok(rules.find((r) => r.id === 'no-ffmpeg-on-this-laptop'));
  assert.ok(rules.find((r) => r.id === 'deploy-burst').off);
  const r = await evaluate({ tool_name: 'Bash', tool_input: { command: 'ffmpeg -i in.mp4 out.mp4' } }, { rules, config, log: false, platform: 'linux' });
  assert.equal(r.rule, 'no-ffmpeg-on-this-laptop');
  assert.equal(await evaluate({ tool_name: 'Bash', tool_input: { command: 'ffprobe in.mp4' } }, { rules, config, log: false, platform: 'linux' }), null);
  const paid = await evaluate({ tool_name: 'Bash', tool_input: { command: 'curl https://api.elevenlabs.io/v1/text-to-speech -d @x.json' } }, { rules, config, log: false, platform: 'linux' });
  assert.equal(paid.rule, 'paid-api-needs-the-persons-words');
});

test('log excerpts are redacted', () => {
  const state = fs.mkdtempSync(path.join(os.tmpdir(), 'tripwires-redact-'));
  process.env.TRIPWIRES_TEST = '';
  record(state, { kind: 'deny', rule: 'x', excerpt: 'TOKEN=abcdefghijklmnopqrstuvwxyz0123 curl -H "Authorization: Bearer abcdefghijkl" https://alice:hunter2@example.com/x?api_key=zzz' });
  process.env.TRIPWIRES_TEST = '1';
  const row = readLog(state)[0];
  assert.ok(!row.excerpt.includes('abcdefghijklmnopqrstuvwxyz0123'));
  assert.ok(!row.excerpt.includes('abcdefghijkl'));
  assert.ok(!row.excerpt.includes('hunter2'));
  assert.ok(!row.excerpt.includes('zzz'));
  assert.match(row.excerpt, /TOKEN=\*\*\*/);
});

test('peek prints shapes, not values: numbers, bearer tokens in structural keys, URL user info', () => {
  const f = path.join(tmp, 'synthetic.json');
  fs.writeFileSync(f, JSON.stringify({ pin: 123456, command: 'curl -H Authorization:Bearer-demo-secret-value', url: 'https://alice:demo-password@example.com/p', hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'node hook.mjs' }] }] }, theme: 'dark', api_key: 'sk-live-abcdefghijklmnop' }));
  const out = peek(f);
  assert.ok(!out.includes('123456'));
  assert.ok(!out.includes('demo-secret'));
  assert.ok(!out.includes('demo-password'));
  assert.ok(!out.includes('alice'));
  assert.ok(!out.includes('abcdefghijklmnop'));
  assert.match(out, /host=example\.com/);
  assert.match(out, /command = "node hook\.mjs"/, 'structural, harmless values still print');
  assert.match(out, /theme = "dark"/);
  const envFile = path.join(tmp, '.env');
  fs.writeFileSync(envFile, 'PORT=3000\nDB_URL=postgres://u:p@db/x\nTOKEN=abcdefghijklmnopqrstuvwxyz\n');
  const e = peek(envFile);
  assert.match(e, /PORT = 3000/);
  assert.ok(!e.includes('abcdefghijklmnopqrstuvwxyz'));
  assert.ok(!e.includes('u:p@'));
});

test('hook entry point: denies through stdout JSON, lets unknown payloads through, fails open on garbage', () => {
  const env = { ...process.env, TRIPWIRES_TEST: '1', TRIPWIRES_STATE_DIR: tmp };
  const call = (input) => spawnSync(process.execPath, [BIN, 'hook', '--agent', 'claude'], { input, encoding: 'utf8', env, windowsHide: true });
  const deny = call(JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'pkill -f node' }, cwd: tmp, session_id: 'hook-test' }));
  assert.equal(deny.status, 0);
  assert.match(deny.stdout, /"permissionDecision":"deny"/);
  assert.match(deny.stdout, /kill-by-name/);
  const pass = call(JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls -la' }, cwd: tmp }));
  assert.equal(pass.status, 0);
  assert.equal(pass.stdout.trim(), '');
  const garbage = call('not json');
  assert.equal(garbage.status, 0);
  assert.equal(garbage.stdout.trim(), '');
  const closed = spawnSync(process.execPath, [BIN, 'hook'], { input: 'not json', encoding: 'utf8', env: { ...env, TRIPWIRES_FAIL_CLOSED: '1' }, windowsHide: true });
  assert.equal(closed.status, 2);
});

test('CLI: try, list, new, report run', () => {
  const env = { ...process.env, TRIPWIRES_TEST: '1', TRIPWIRES_STATE_DIR: tmp };
  const cli = (...args) => spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', env, cwd: tmp, windowsHide: true });
  const t = cli('try', 'taskkill /IM node.exe /F');
  assert.equal(t.status, 1);
  assert.match(t.stdout, /DENY[\s\S]*kill-by-name/);
  assert.equal(cli('try', 'ls').stdout.trim(), 'pass');
  assert.match(cli('list', '--all').stdout, /kill-by-name[\s\S]*incident:/);
  const n = cli('new', 'my-rule', '--dir', path.join(tmp, 'rules'));
  assert.equal(n.status, 0, n.stderr);
  assert.ok(fs.existsSync(path.join(tmp, 'rules', 'my-rule.mjs')));
  assert.ok(fs.existsSync(path.join(tmp, 'rules', 'my-rule.test.mjs')));
  const outer = { ...env };
  delete outer.NODE_TEST_CONTEXT; // otherwise the inner runner sees itself as nested and skips the files
  const scaffold = spawnSync(process.execPath, ['--test', path.join(tmp, 'rules', 'my-rule.test.mjs')], { encoding: 'utf8', env: outer, cwd: tmp, windowsHide: true });
  assert.match(scaffold.stdout + scaffold.stderr, /my-rule: denies the incident command/);
  assert.match(cli('report', '--days', '1').stdout, /tripwires report/);
  assert.match(cli('help').stdout, /tripwires init/);
});
