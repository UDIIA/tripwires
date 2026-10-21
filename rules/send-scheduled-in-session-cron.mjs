// Claude Code can schedule work inside the session (CronCreate, ScheduleWakeup). The schedule dies with the session.
const SEND = /\b(?:send|sends|deliver|post|publish|ship|blast|dispatch|notify|email|message|envie|enviar|envia|mande|mandar|manda|dispare|disparar|dispara|publique|publicar|publica|poste|postar|posta)\b/i;
const TARGET = /\b(?:message|messages|whatsapp|email|e-mail|slack|telegram|sms|group|customer|customers|client|clients|user|users|subscriber|subscribers|tweet|post|posts|site|page|campaign|newsletter|batch|mensagem|mensagens|zap|grupo|aluno|alunos|cliente|clientes|lote|campanha|p[áa]gina)\b/i;
// A deploy named as a command or an action, not as a thing to look at ("check the deploy status" passes).
const DEPLOY_ACTION = /(?:netlify\s+deploy\s+--prod|vercel\s+--prod|wrangler\s+(?:deploy|publish)|firebase\s+deploy|fly\s+deploy|\bdeploy\s+(?:the|to|it|now|at)\b|\brun\s+the\s+deploy\b|\bpromote\s+(?:the|to)\b)/i;

export default {
  id: 'send-scheduled-in-session-cron',
  title: 'Outbound send scheduled inside the session',
  tools: /^(?:CronCreate|ScheduleWakeup)$/,
  incident:
    'On 2026-10-09 at 10:13 ten customer messages were queued with an in-session cron for the afternoon. The session was restarted at noon; the cron went with it, nothing was sent, and nothing reported the loss. Two earlier runs lost scheduled deploys the same way.',
  check(input) {
    const ti = input.tool_input;
    const p = String(ti.prompt ?? ti.command ?? ti.instruction ?? JSON.stringify(ti));
    if (!DEPLOY_ACTION.test(p) && !(SEND.test(p) && TARGET.test(p))) return null;
    return {
      reason: 'An in-session schedule disappears on restart, account limit or compaction. Sends, posts and deploys that depend on it are lost silently.',
      fix: 'Schedule outbound work outside the session: a system scheduler (cron, launchd, Task Scheduler) running a script with its own log and dedupe, or a queue the job runner owns. Keep in-session schedules for reads and checks that can be lost.',
      excerpt: p.slice(0, 200),
    };
  },
};
