import { test } from 'node:test';
import assert from 'node:assert/strict';
import { segments, tokens, heredocs, stripFileHeredocs, firstWord, programName, hasAllowToken, withoutQuotes, withoutComment, redact } from '../src/shell.mjs';

test('segments cuts at | ; && || and newlines, never inside quotes', () => {
  assert.deepEqual(segments('a | b; c && d || e\nf'), ['a ', ' b', ' c ', ' d ', ' e', 'f']);
  assert.deepEqual(segments('grep -nE "from|to" x.toml'), ['grep -nE "from|to" x.toml']);
  assert.deepEqual(segments("echo 'a;b' && ls"), ["echo 'a;b' ", ' ls']);
});

test('tokens keeps quoted strings as one token and flags them', () => {
  assert.deepEqual(tokens('sed -i "s/a b/c/" "my file.txt"'), [{ v: 'sed', q: false }, { v: '-i', q: false }, { v: 's/a b/c/', q: true }, { v: 'my file.txt', q: true }]);
  assert.deepEqual(tokens("x='1 2'"), [{ v: 'x=1 2', q: true }]);
});

test('heredocs and stripFileHeredocs tell data from code', () => {
  const cmd = 'cat > notes.md <<EOF\nrun ffmpeg later\nEOF\npython - <<PY\nimport os\nPY';
  const h = heredocs(cmd);
  assert.equal(h.length, 2);
  assert.equal(h[0].marker, 'EOF');
  assert.equal(h[1].body, 'import os');
  const s = stripFileHeredocs(cmd);
  assert.ok(!s.includes('ffmpeg'));
  assert.ok(s.includes('import os'));
});

test('firstWord strips env assignments and wrappers; programName strips path and extension', () => {
  assert.equal(firstWord('FOO=1 sudo -u me time nohup /usr/bin/ffmpeg -i x'), '/usr/bin/ffmpeg');
  assert.equal(firstWord('cmd /c start "" node x.js'), 'node');
  assert.equal(programName('C:\\tools\\FFmpeg.EXE'), 'ffmpeg');
});

test('hasAllowToken accepts one id, a list, or *, only where an assignment goes', () => {
  assert.ok(hasAllowToken('TRIPWIRES_ALLOW=a ls', 'a'));
  assert.ok(hasAllowToken('TRIPWIRES_ALLOW=a,b ls', 'b'));
  assert.ok(hasAllowToken('$env:TRIPWIRES_ALLOW="*"; ls', 'zzz'));
  assert.ok(hasAllowToken('cd x && TRIPWIRES_ALLOW=a ls', 'a'));
  assert.ok(!hasAllowToken('TRIPWIRES_ALLOW=a ls', 'b'));
  assert.ok(!hasAllowToken('echo TRIPWIRES_ALLOWED=a', 'a'));
  assert.ok(!hasAllowToken('ls # TRIPWIRES_ALLOW=a', 'a'));
  assert.ok(!hasAllowToken('ls --note "TRIPWIRES_ALLOW=a"', 'a'));
  assert.ok(!hasAllowToken('ls TRIPWIRES_ALLOW=a', 'a'));
});

test('withoutComment strips a trailing comment outside quotes', () => {
  assert.equal(withoutComment('ls -la # list'), 'ls -la ');
  assert.equal(withoutComment('echo "# not a comment" # yes'), 'echo "# not a comment" ');
  assert.equal(withoutComment('echo a#b'), 'echo a#b');
});

test('redact hides credential-looking parts', () => {
  const r = redact('API_KEY=abcdefghijklmnopqrstuvwxyz curl -u me:pw https://bob:s3cret@h.io -H "Authorization: Bearer xyzxyzxyzxyz" --token=abc123 ghp_abcdefghijklmnop');
  assert.ok(!r.includes('abcdefghijklmnopqrstuvwxyz'));
  assert.ok(!r.includes('s3cret'));
  assert.ok(!r.includes('xyzxyzxyzxyz'));
  assert.ok(!r.includes('abc123'));
  assert.ok(!r.includes('ghp_abcdefghijklmnop'));
  assert.ok(r.includes('curl'));
});

test('stripFileHeredocs keeps an unquoted heredoc that expands a command', () => {
  assert.ok(stripFileHeredocs('cat > x <<EOF\nrun $(pkill -f node)\nEOF').includes('pkill'));
  assert.ok(!stripFileHeredocs("cat > x <<'EOF'\nrun $(pkill -f node)\nEOF").includes('pkill'));
  assert.ok(!stripFileHeredocs('cat > x <<EOF\nrun pkill -f node later\nEOF').includes('pkill'));
});

test('withoutQuotes blanks string contents', () => {
  assert.equal(withoutQuotes('echo "a > b" > c'), 'echo "" > c');
});
