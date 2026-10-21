// Every "deny" case is the real command (or the exact gesture) from an incident. Every "pass" case is legitimate
// work that a sloppy version of the rule blocked, or would block. When a rule denies legitimate work in the field,
// the command goes here first, then the rule gets narrowed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { evaluate, loadRules } from '../src/engine.mjs';

process.env.TRIPWIRES_TEST = '1';
const NOW = new Date('2026-10-19T14:00:00Z');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tripwires-'));
const config = { off: new Set(), rules: [], failClosed: false, stateDir: tmp, sources: [] };
const rules = await loadRules(config);

async function run(tool, tool_input, { platform = 'win32', fsAccess = false, cwd = tmp, now = NOW } = {}) {
  const r = await evaluate({ tool_name: tool, tool_input, cwd, session_id: 'test' }, { rules, config, now, platform, fsAccess, log: false });
  return r ? r.rule : null;
}
const bash = (command, o) => run('Bash', { command }, o);
const ps = (command, o) => run('PowerShell', { command }, o);

const cases = [
  // kill-by-name
  ['kill-by-name', bash('taskkill /IM powershell.exe /F')],
  ['kill-by-name', bash('pkill -f porteira')],
  ['kill-by-name', bash('Get-Process node | Stop-Process -Force')],
  ['kill-by-name', ps('Get-CimInstance Win32_Process -Filter "name=\'node.exe\'" | Invoke-CimMethod -MethodName Terminate')],
  ['kill-by-name', ps('spps -Name node')],
  [null, bash('taskkill /PID 4321 /F')],
  [null, ps('Stop-Process -Id 4321 -Force')],
  [null, ps('Get-Process -Id 4321 | Stop-Process')],
  [null, bash('kill 4321')],
  [null, bash('cat > notes.md <<EOF\nrun pkill -f foo when it hangs\nEOF')],
  // secret-file-read
  ['secret-file-read', bash('cat ~/.claude/settings.json')],
  ['secret-file-read', bash('sed -n 1,40p netlify.toml')],
  ['secret-file-read', bash('grep -n token .env')],
  ['secret-file-read', bash('cat .env.production')],
  ['secret-file-read', bash('Get-Content C:\\Users\\me\\.codex\\auth.json')],
  ['secret-file-read', bash('cat ~/.aws/credentials')],
  ['secret-file-read', bash('cat ~/.ssh/id_ed25519')],
  ['secret-file-read', run('Read', { file_path: 'C:/Users/me/.claude/settings.json' })],
  ['secret-file-read', run('Read', { file_path: '/home/me/app/.env' })],
  [null, run('Read', { file_path: '/home/me/app/.env.example' })],
  [null, run('Read', { file_path: '/home/me/app/src/settings.json' })],
  [null, bash('cat ~/.ssh/id_ed25519.pub')],
  [null, bash('ls -la netlify.toml public | head -5')],
  [null, bash('stat netlify.toml; echo ok; tail -4 /tmp/x')],
  [null, bash('git log -- netlify.toml | awk \'{print $1}\'')],
  [null, bash('grep -c "" .env')],
  [null, bash('grep -l API_KEY .env .env.local')],
  [null, bash('wc -l .env')],
  [null, bash('cat .env.example')],
  [null, bash('tripwires peek .env')],
  // rm-relative-glob-after-cd
  ['rm-relative-glob-after-cd', bash('cd build && rm -rf tmp-*')],
  ['rm-relative-glob-after-cd', bash('cd /srv/app; rm -r cache/*.tmp')],
  [null, bash('cd build && rm -rf /srv/app/build/tmp')],
  [null, bash('rm -rf tmp-*')],
  [null, bash('cd build && rm -f *.log')],
  [null, bash('cd build && node -e "require(\'fs\').rmSync(\'tmp\',{recursive:true,force:true})"')],
  // edit-chained-with-deploy
  ['edit-chained-with-deploy', bash('python fix_toml.py && netlify deploy --prod --dir public')],
  ['edit-chained-with-deploy', bash('sed -i "s/a/b/" public/index.html && netlify deploy --prod')],
  ['edit-chained-with-deploy', bash('cp new.html public/index.html; vercel --prod')],
  ['edit-chained-with-deploy', bash('echo "x" > public/robots.txt && wrangler pages deploy public')],
  [null, bash('cd site && npm run build && netlify deploy --prod --dir dist')],
  [null, bash('node --check public/app.js && netlify deploy --prod')],
  [null, bash('rm -f .netlify/netlify.toml && netlify deploy --prod --dir public')],
  [null, bash('python check_links.py && netlify deploy --prod')],
  [null, bash('git status && netlify deploy --prod')],
  [null, bash('netlify deploy --prod --dir public')],
  // send-scheduled-in-session-cron
  ['send-scheduled-in-session-cron', run('CronCreate', { prompt: 'at 14:00 send the WhatsApp messages to the 10 customers in the list' })],
  ['send-scheduled-in-session-cron', run('ScheduleWakeup', { prompt: 'publish the post to the group at 9am' })],
  ['send-scheduled-in-session-cron', run('CronCreate', { prompt: 'netlify deploy --prod at 18:00' })],
  [null, run('CronCreate', { prompt: 'check the deploy status every 5 minutes and read the logs' })],
  [null, run('ScheduleWakeup', { prompt: 'poll CI for the test results' })],
  // sed-inplace-on-crlf (candidate without disk access; see the fs test below)
  [null, bash('sed -n "s/a/b/p" file.txt')],
  [null, bash('TRIPWIRES_ALLOW=sed-inplace-on-crlf sed -i "s/a/b/" file.txt')],
  // review findings (2026-10-21): text is not code, code is not text
  ['kill-by-name', bash('pkill -f node # TRIPWIRES_ALLOW=kill-by-name')],
  ['kill-by-name', bash('echo "TRIPWIRES_ALLOW=kill-by-name"; pkill -f node')],
  ['kill-by-name', bash('cat > notes.md <<EOF\nstatus: $(pkill -f node)\nEOF')],
  [null, bash("cat > notes.md <<'EOF'\nstatus: $(pkill -f node)\nEOF")],
  [null, bash('echo "pkill -f node"')],
  [null, bash('grep -n "pkill" docs/method.md')],
  ['secret-file-read', bash('cat .env .env.example')],
  ['secret-file-read', bash('tripwires peek .env; cat .env')],
  [null, bash('cp a b; echo "netlify deploy --prod"')],
  [null, bash('wrangler deploy --dry-run')],
  [null, bash('mv a.html x.html && echo "then: netlify deploy --prod"')],
  ['weekday-date-mismatch', run('apply_patch', { command: '*** Begin Patch\n*** Update File: site/page.html\n@@\n-old\n+Doors open Saturday, October 11, 2026\n*** End Patch' })],
  [null, run('apply_patch', { command: '*** Begin Patch\n*** Update File: site/page.html\n@@\n-old\n+Doors open Sunday, October 11, 2026\n*** End Patch' })],
  // tmp-path-to-interpreter (win32)
  ['tmp-path-to-interpreter', bash('python send.py --payload "{\\"file\\": \\"/tmp/contact.json\\"}"')],
  ['tmp-path-to-interpreter', bash('node -e "require(\'fs\').readFileSync(\'/tmp/x.json\')"')],
  ['tmp-path-to-interpreter', bash('MSYS_NO_PATHCONV=1 python x.py /tmp/x.json')],
  [null, bash('python x.py /tmp/x.json')],
  [null, bash('python x.py --out=/tmp/x.json')],
  [null, bash('python x.py > /tmp/out.txt')],
  [null, bash('wsl python3 x.py /tmp/x.json')],
  [null, bash('python x.py /tmp/x.json', { platform: 'linux' })],
  [null, bash('node -e "fs.readFileSync(dir+\'/tmp/x\')"')],
  // powershell-write-without-encoding (win32)
  ['powershell-write-without-encoding', ps('Set-Content config.yaml "ação: sim"')],
  ['powershell-write-without-encoding', bash('powershell -c "Add-Content notas.txt \'João\'"')],
  [null, ps('Set-Content config.yaml "acao: sim" -Encoding utf8')],
  [null, ps('Set-Content config.yaml "plain ascii"')],
  [null, ps('Write-Output "Set-Content is dangerous: ação"')],
  [null, bash('pwsh -c "Set-Content x.txt \'ação\'"')],
  [null, bash('python -c "print(\'Set-Content ação\')"')],
  // weekday-date-mismatch (2026-10-11 is a Sunday; 2026-10-10 is a Saturday)
  ['weekday-date-mismatch', bash('echo "until Saturday, October 11" > notice.txt')],
  ['weekday-date-mismatch', bash('echo "deadline: October 11, 2026 (Saturday)" >> notice.txt')],
  ['weekday-date-mismatch', bash('python send.py --text "até sábado, 11/10"')],
  ['weekday-date-mismatch', run('Write', { file_path: '/site/page.html', content: '<p>Doors open Sat, 11 Oct 2026</p>' })],
  ['weekday-date-mismatch', run('Edit', { file_path: '/site/page.html', new_string: 'quarta, 15 de outubro' })],
  [null, bash('echo "until Saturday, October 10" > notice.txt')],
  [null, bash('echo "Sunday, October 11, 2026" > notice.txt')],
  [null, bash('grep "Saturday, October 11" notice.txt')],
  [null, run('Write', { file_path: '/site/page.html', content: 'In 2025 the meetup was on Saturday, October 11.' })],
  [null, run('Write', { file_path: '/site/page.html', content: 'Saturday, 10/11' })],
  [null, run('Write', { file_path: '/x/dates.test.mjs', content: 'assert("Saturday, October 11")' })],
  [null, run('Write', { file_path: '/site/page.html', content: 'see `Saturday, October 11` in the fixture' })],
  [null, run('Write', { file_path: '/site/page.html', content: 'quinta, 15 de outubro de 2026' })],
  // deploy-burst (state empty, no disk): first deploy passes
  [null, bash('netlify deploy --prod --dir public')],
  [null, bash('echo "run netlify deploy --prod later"')],
  // inline-script-backslash (win32). Inside single quotes bash keeps the backslashes, so a collapsed `\\` changes the
  // program; inside double quotes `\\` becomes `\` either way and nothing breaks (case 88).
  ['inline-script-backslash', bash("python -c 'open(\"C:\\\\Users\\\\me\\\\x.txt\").read()'")],
  ['inline-script-backslash', bash("node -e 'console.log(\"C:\\\\Users\")'")],
  ['inline-script-backslash', bash("printf 'C:\\\\Users\\\\me\\n'")],
  ['inline-script-backslash', bash("python - <<'PY'\nprint(open('C:\\\\Users\\\\me\\\\x.txt').read())\nPY")],
  [null, bash('python -c "open(\'C:\\\\Users\\\\me\\\\x.txt\').read()"')],
  [null, bash('python -c "print(\\"a\\\\d\\")"')],
  [null, bash('echo "rollback\\\\hydra"')],
  [null, bash('python x.py "C:\\\\Users\\\\me"')],
  [null, bash("python -c 'open(\"C:\\\\Users\\\\me\\\\x.txt\").read()'", { platform: 'linux' })],
];

let i = 0;
for (const [expected, promise] of cases) {
  const n = ++i;
  test(`case ${n}: ${expected === null ? 'pass' : 'deny ' + expected}`, async () => {
    assert.equal(await promise, expected);
  });
}

test('sed-inplace-on-crlf: denies a CRLF file inside a git repo, passes an LF file', async () => {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'tripwires-repo-'));
  fs.mkdirSync(path.join(repo, '.git'));
  fs.writeFileSync(path.join(repo, 'crlf.html'), '<p>a</p>\r\n<p>b</p>\r\n');
  fs.writeFileSync(path.join(repo, 'lf.html'), '<p>a</p>\n<p>b</p>\n');
  assert.equal(await bash('sed -i "s/a/b/" crlf.html', { fsAccess: true, cwd: repo }), 'sed-inplace-on-crlf');
  assert.equal(await bash('sed -i "s/a/b/" lf.html', { fsAccess: true, cwd: repo }), null);
  assert.equal(await bash('sed -i "s/a/b/" "crlf.html"', { fsAccess: true, cwd: repo }), 'sed-inplace-on-crlf');
});

test('deploy-burst: the second production deploy of the same target inside 30 minutes is denied', async () => {
  const state = fs.mkdtempSync(path.join(os.tmpdir(), 'tripwires-deploy-'));
  const cfg = { ...config, stateDir: state };
  const go = (minutes, cmd = 'netlify deploy --prod --dir public --site aaaa') =>
    evaluate({ tool_name: 'Bash', tool_input: { command: cmd }, cwd: '/srv/site', session_id: 'test' }, { rules, config: cfg, now: new Date(NOW.getTime() + minutes * 60000), platform: 'linux', fsAccess: true, log: false });
  assert.equal(await go(0), null);
  const second = await go(5);
  assert.equal(second && second.rule, 'deploy-burst');
  assert.equal(await go(5, 'netlify deploy --prod --dir public --site bbbb'), null);
  assert.equal(await go(40), null);
  assert.equal(await go(80), null);
  const fourth = await go(120);
  assert.equal(fourth && fourth.rule, 'deploy-burst');
  assert.match(fourth.message, /3 production deploy attempts today/);
  assert.equal(await go(125, 'netlify deploy --dir public --site aaaa'), null);
  assert.equal(await go(130, 'TRIPWIRES_ALLOW=deploy-burst netlify deploy --prod --site aaaa'), null);
});

test('deploy-burst: a deploy denied by another rule is not recorded; `try` (probe) records nothing', async () => {
  const state = fs.mkdtempSync(path.join(os.tmpdir(), 'tripwires-deploy2-'));
  const cfg = { ...config, stateDir: state };
  const go = (cmd, extra = {}) => evaluate({ tool_name: 'Bash', tool_input: { command: cmd }, cwd: '/srv/site', session_id: 'test' }, { rules, config: cfg, now: NOW, platform: 'linux', fsAccess: true, log: false, ...extra });
  const denied = await go('python fix.py && netlify deploy --prod --site cccc');
  assert.equal(denied.rule, 'edit-chained-with-deploy');
  assert.ok(!fs.existsSync(path.join(state, 'deploys.jsonl')), 'nothing recorded for a denied call');
  assert.equal(await go('netlify deploy --prod --site cccc', { probe: true }), null);
  assert.ok(!fs.existsSync(path.join(state, 'deploys.jsonl')), 'probe records nothing');
  assert.equal(await go('netlify deploy --prod --site cccc'), null, 'first real deploy passes');
  assert.equal(fs.readFileSync(path.join(state, 'deploys.jsonl'), 'utf8').trim().split('\n').length, 1);
});
