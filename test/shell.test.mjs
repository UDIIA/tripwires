import { test } from 'node:test';
import assert from 'node:assert/strict';
import { segments, tokens, heredocs, stripFileHeredocs, firstWord, programName, hasAllowToken, withoutQuotes } from '../src/shell.mjs';

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

test('hasAllowToken accepts one id, a list, or *', () => {
  assert.ok(hasAllowToken('TRIPWIRES_ALLOW=a ls', 'a'));
  assert.ok(hasAllowToken('TRIPWIRES_ALLOW=a,b ls', 'b'));
  assert.ok(hasAllowToken('$env:TRIPWIRES_ALLOW="*"; ls', 'zzz'));
  assert.ok(!hasAllowToken('TRIPWIRES_ALLOW=a ls', 'b'));
  assert.ok(!hasAllowToken('echo TRIPWIRES_ALLOWED=a', 'a'));
});

test('withoutQuotes blanks string contents', () => {
  assert.equal(withoutQuotes('echo "a > b" > c'), 'echo "" > c');
});
