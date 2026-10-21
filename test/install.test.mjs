import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { install, uninstall, status, TARGETS, hookCommand } from '../src/install.mjs';

process.env.TRIPWIRES_TEST = '1';

test('install merges into Claude settings.json without touching other hooks, idempotently; uninstall removes only ours', () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'tripwires-install-'));
  const file = TARGETS.claude.project(cwd);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const theirs = { matcher: 'Bash', hooks: [{ type: 'command', command: 'node their-hook.mjs' }] };
  fs.writeFileSync(file, JSON.stringify({ permissions: { allow: ['Bash(ls:*)'] }, hooks: { PreToolUse: [theirs], Stop: [{ hooks: [{ type: 'command', command: 'echo bye' }] }] } }));
  const r1 = install('claude', { scope: 'project', cwd });
  assert.equal(r1.changed, true);
  const j = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(j.permissions, { allow: ['Bash(ls:*)'] });
  assert.equal(j.hooks.Stop.length, 1);
  assert.equal(j.hooks.PreToolUse.length, 3);
  assert.deepEqual(j.hooks.PreToolUse[0], theirs);
  assert.match(j.hooks.PreToolUse[1].hooks[0].command, /tripwires\.mjs" hook --agent claude$/);
  assert.ok(fs.existsSync(`${file}.bak-tripwires`));
  const r2 = install('claude', { scope: 'project', cwd });
  assert.equal(r2.changed, false, 'second install is a no-op');
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).hooks.PreToolUse.length, 3);
  assert.equal(status({ cwd }).find((s) => s.agent === 'claude' && s.scope === 'project').installed, true);
  const u = uninstall('claude', { scope: 'project', cwd });
  assert.equal(u.changed, true);
  const after = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(after.hooks.PreToolUse, [theirs]);
  assert.equal(after.hooks.Stop.length, 1);
});

test('a group that holds our handler and someone else\'s keeps theirs on install and uninstall', () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'tripwires-mixed-'));
  const file = TARGETS.claude.project(cwd);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const theirs = { type: 'command', command: 'node their-hook.mjs' };
  const stale = { type: 'command', command: '"/old/node" "/old/tripwires/bin/tripwires.mjs" hook --agent claude' };
  fs.writeFileSync(file, JSON.stringify({ hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [theirs, stale] }] } }));
  install('claude', { scope: 'project', cwd });
  let j = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(j.hooks.PreToolUse[0], { matcher: 'Bash', hooks: [theirs] });
  assert.equal(j.hooks.PreToolUse.length, 3);
  uninstall('claude', { scope: 'project', cwd });
  j = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(j.hooks.PreToolUse, [{ matcher: 'Bash', hooks: [theirs] }]);
});

test('install creates Codex hooks.json under the "hooks" key with commandWindows; dry-run writes nothing', () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'tripwires-codex-'));
  const file = TARGETS.codex.project(cwd);
  const dry = install('codex', { scope: 'project', cwd, dryRun: true });
  assert.equal(dry.changed, true);
  assert.ok(!fs.existsSync(file));
  install('codex', { scope: 'project', cwd });
  const j = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.ok(Array.isArray(j.hooks.PreToolUse));
  assert.equal(j.hooks.PreToolUse.length, 2);
  const h = j.hooks.PreToolUse[0].hooks[0];
  assert.equal(h.type, 'command');
  assert.equal(h.command, h.commandWindows);
  assert.equal(h.command, hookCommand('codex'));
  assert.equal(h.timeout, 10);
});

test('invalid JSON in the target is reported, not overwritten', () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'tripwires-bad-'));
  const file = TARGETS.claude.project(cwd);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, '{ not json');
  assert.throws(() => install('claude', { scope: 'project', cwd }), /not valid JSON/);
  assert.equal(fs.readFileSync(file, 'utf8'), '{ not json');
  assert.equal(status({ cwd }).find((s) => s.agent === 'claude' && s.scope === 'project').exists, 'invalid');
});
