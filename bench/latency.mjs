// How the README latency numbers were measured. Run: node bench/latency.mjs
// Spawns the hook the way an agent does (one process per call, JSON on stdin) and compares with bare Node.
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'tripwires.mjs');
const N = Number(process.argv[2] || 12);
const env = { ...process.env, TRIPWIRES_TEST: '1' };

function run(label, args, input) {
  const times = [];
  for (let i = 0; i < N; i++) {
    const t = performance.now();
    spawnSync(process.execPath, args, { input, encoding: 'utf8', env, windowsHide: true });
    times.push(performance.now() - t);
  }
  times.sort((a, b) => a - b);
  console.log(`${label.padEnd(28)} p50=${Math.round(times[Math.floor(N / 2)])} ms  min=${Math.round(times[0])}  max=${Math.round(times[N - 1])}`);
}

const payload = (tool_name, tool_input) => JSON.stringify({ tool_name, tool_input, cwd: process.cwd(), session_id: 'bench' });
console.log(`${N} runs each, ${process.platform}, node ${process.version}`);
run('bare node -e 0', ['-e', '0']);
run('hook: Bash pass', [BIN, 'hook'], payload('Bash', { command: 'ls -la' }));
run('hook: Bash deny', [BIN, 'hook'], payload('Bash', { command: 'pkill -f node' }));
run('hook: Write pass', [BIN, 'hook'], payload('Write', { file_path: 'x/page.html', content: '<p>hello</p>' }));
