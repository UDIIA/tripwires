// Example of a house rule: a constraint that is true for ONE machine and nowhere else.
// Generic guard lists will never carry it; the person whose cursor froze will.
import { segments, firstWord, programName, stripFileHeredocs } from 'tripwires/shell';

export default {
  id: 'no-ffmpeg-on-this-laptop',
  title: 'ffmpeg on the laptop',
  tools: /^(?:Bash|PowerShell)$/,
  incident:
    '2026-10-05 06:57: an ffmpeg encode took two thirds of the CPU with RAM at 87% and froze the cursor of the person working on the machine. Their order the same morning: "video and ffmpeg never on this laptop, however small it looks". Reading metadata (ffprobe) is fine.',
  check(input) {
    const hit = segments(stripFileHeredocs(input.command)).find((s) => programName(firstWord(s)) === 'ffmpeg');
    if (!hit) return null;
    return {
      reason: 'ffmpeg on this laptop froze the person\'s cursor once and they asked for it never to run here again. ffprobe (metadata) is allowed.',
      fix: 'Queue the job for the render machine (`python hdsk.py new ...`) and read the result back; here, only ffprobe or looking at a frame that already exists.',
      excerpt: hit.trim(),
    };
  },
};
