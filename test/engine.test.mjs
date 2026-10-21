import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { evaluate, loadRules, normalizeInput, denialJson, allowFile } from '../src/engine.mjs';
import { loadConfig } from '../src/config.mjs';
import { readLog } from '../src/log.mjs';
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
  assert.equal(await go('TRIPWIRES_ALLOW=other ls') && 'denied', 'denied');
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
