import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { AuditLog } from "../extensions/audit.ts";
import { autopilotDecision, type AutopilotState } from "../extensions/autopilot.ts";
import type { EngagementSnapshot } from "../extensions/guide.ts";
import redteamExtension from "../extensions/redteam.ts";
import { askFirstReason } from "../extensions/tiers.ts";

function harness(t: { after(fn: () => void): void }) {
  const cwd = mkdtempSync(join(tmpdir(), "pi-auto-"));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  writeFileSync(join(cwd, "redteam.config.json"), JSON.stringify({
    engagement: "Fixture", authorizationExpires: "2099-01-01", targets: ["app.fixture.test", "10.20.0.0/24"], excludeTargets: ["10.20.0.1"], targetSources: [],
    webEndpoints: ["https://app.fixture.test/login", "https://app.fixture.test/api"],
  }));
  const hooks = new Map<string, (...args: any[]) => Promise<any>>();
  const commands = new Map<string, { handler: (...args: any[]) => Promise<any> }>();
  const tools = new Map<string, (...args: any[]) => Promise<any>>();
  const sent: string[] = [];
  redteamExtension({
    registerCommand: (name: string, command: { handler: (...args: any[]) => Promise<any> }) => commands.set(name, command),
    registerTool: (tool: { name: string; execute: (...args: any[]) => Promise<any> }) => tools.set(tool.name, tool.execute),
    on: (event: string, hook: (...args: any[]) => Promise<any>) => hooks.set(event, hook),
    sendUserMessage: (text: string) => { sent.push(text); },
  } as unknown as ExtensionAPI);
  const ui = { answer: true, notices: [] as string[], prompts: [] as string[], details: [] as string[], widget: [] as string[], status: {} as Record<string, string | undefined>, aborted: 0, idle: true };
  const ctx = {
    cwd, hasUI: true, sessionManager: { getSessionId: () => "session-test" },
    isIdle: () => ui.idle, abort: () => { ui.aborted++; },
    ui: {
      confirm: async (title: string, detail: string) => { ui.prompts.push(title); ui.details.push(detail); return ui.answer; },
      select: async () => undefined, notify: (text: string) => { ui.notices.push(text); },
      setStatus: (key: string, value: string | undefined) => { ui.status[key] = value; },
      setWidget: (_key: string, lines: string[]) => { ui.widget = lines; },
    },
  };
  t.after(() => { void hooks.get("session_shutdown")!({ reason: "test" }, ctx); });
  const run = (name: string, args = "") => commands.get(name)!.handler(args, ctx);
  const tool = async (name: string, params: Record<string, unknown>) => (await tools.get(name)!("id", params, undefined, undefined, ctx)) as { details: any };
  let id = 0;
  const bash = (command: string) => hooks.get("tool_call")!({ type: "tool_call", toolName: "bash", toolCallId: `c${++id}`, input: { command } }, ctx) as Promise<{ reason?: string } | undefined>;
  const start = (prompt = sent.at(-1) ?? "go") => { ui.idle = false; return hooks.get("before_agent_start")!({ systemPromptOptions: { sections: {} }, messageType: "user", prompt }, ctx); };
  const settle = (aborted = false) => { ui.idle = true; return hooks.get("agent_settled")!({ aborted }, ctx); };
  const review = (endpoint: string) => tool("redteam_coverage", { operation: "record", subject: { endpoint }, state: "reviewed", outcome: "observed", layer: "application",
    claim: "Login form served", evidence: [{ source: "evidence/x.txt", observation: "HTTP 200" }] });
  return { cwd, ui, sent, run, tool, bash, start, settle, review, hooks, ctx };
}

test("autopilot starts runs by itself and stops when a run makes no progress", async t => {
  const { run, ui, sent, start, settle, review, cwd, hooks, ctx } = harness(t);
  await run("rt-auto");
  assert.match(ui.notices.at(-1)!, /Autopilot: ▷ off[\s\S]*It never answers a prompt for you/);
  await run("rt-auto", "on 99");
  assert.match(ui.notices.at(-1)!, /Usage: \/rt-auto/);
  await run("rt-auto", "on 3");
  assert.deepEqual(ui.prompts, ["Turn on autopilot?"]);
  assert.equal(sent.length, 1);
  assert.match(sent[0], /^\[autopilot run 1 of 3\][\s\S]*2 coverage item\(s\) pending[\s\S]*Do not wait for an answer in this run/);
  assert.match(ui.widget[0], /▶ AUTO 1\/3$/);
  assert.equal(ui.status["redteam-auto"], "▶ AUTO 1/3");

  await start();
  await review("https://app.fixture.test/login");
  await settle();
  assert.equal(sent.length, 2, "progress was recorded, so the next run starts");
  assert.match(sent[1], /^\[autopilot run 2 of 3\][\s\S]*1 coverage item\(s\) pending/);

  await start();
  await settle();
  assert.equal(sent.length, 2, "no progress: no further run");
  assert.match(ui.notices.at(-1)!, /■ AUTOPILOT STOPPED — 2 automatic runs in about 1 min\nWhy: the last run made no recorded progress[\s\S]*DID\n  Coverage 0% → 50% \(1\/2\) · pending 2 → 1[\s\S]*FOUND\n  nothing new[\s\S]*NEEDS YOU\n  ✓ nothing[\s\S]*Autopilot is now off/);
  assert.equal(ui.status["redteam-auto"], undefined);
  assert.doesNotMatch(ui.widget[0], /AUTO/);

  await hooks.get("session_shutdown")!({ reason: "test" }, ctx);
  const audit = new AuditLog(cwd, ".redteam/audit/audit.db");
  t.after(() => audit.close());
  assert.equal(audit.countEvents("autopilot_started"), 1);
  assert.equal(audit.countEvents("autopilot_stopped"), 1);
  const runs = audit.eventsOfTypes(["agent_run_started"]);
  assert.deepEqual(runs.map(event => [event.actor, event.action]), [["extension", "autopilot run 1 of 3"], ["extension", "autopilot run 2 of 3"]]);
});

test("autopilot stops for a severe finding, a refusal, the run limit, an interrupt, and when nothing is left", async t => {
  const { run, ui, sent, start, settle, review, tool, bash } = harness(t);
  const on = async (limit = 5) => { await run("rt-auto", `on ${limit}`); await start(); };

  await on();
  await tool("redteam_findings", { operation: "record", title: "Unauthenticated admin console", status: "validated", affectedSystems: ["https://app.fixture.test/admin"],
    description: "Console answers without a session.", evidence: ["HTTP 200 — evidence/admin.txt"], technicalImpact: 3 });
  await settle();
  assert.match(ui.notices.at(-1)!, /AUTOPILOT STOPPED — 1 automatic run [\s\S]*Why: a severe finding was validated and deserves your attention first: #1\.[\s\S]*FOUND\n  \+ #1 \[validated\] Unauthenticated admin console/);

  await on();
  ui.answer = false;
  assert.match((await bash("curl -X POST https://app.fixture.test/api"))!.reason!, /Denied by the operator \(curl sends a state-changing POST request\)\. Do not retry it in another form/);
  ui.answer = true;
  await review("https://app.fixture.test/login");
  await settle();
  assert.match(ui.notices.at(-1)!, /you answered a confirmation with no/, "a refusal stops autopilot even though progress was made");

  await on();
  for (const target of ["evil.example", "other.example", "third.example"]) await bash(`nmap ${target}`);
  await tool("redteam_tasks", { operation: "add", title: "check" });
  await settle();
  assert.match(ui.notices.at(-1)!, /the guard refused 3 commands in one run/);

  await on(1);
  await tool("redteam_tasks", { operation: "add", title: "another" });
  await settle();
  assert.match(ui.notices.at(-1)!, /Why: the limit of 1 automatic run\(s\) is reached/);

  await on();
  await tool("redteam_tasks", { operation: "add", title: "third" });
  await settle(true);
  assert.match(ui.notices.at(-1)!, /you interrupted the run/);

  await on();
  const before = sent.length;
  await run("rt-pause");
  assert.equal(ui.aborted, 1);
  assert.match(ui.notices.at(-1)!, /■ Paused\. Autopilot off after 1 automatic run\(s\)\. The running agent was interrupted\./);
  await settle(true);
  assert.equal(sent.length, before, "after a pause nothing starts again");
  await run("rt-auto", "last");
  assert.match(ui.notices.at(-1)!, /AUTOPILOT STOPPED[\s\S]*Why: you paused it with \/rt-pause/);

  await on();
  await review("https://app.fixture.test/api");
  await settle();
  assert.match(ui.notices.at(-1)!, /✓ AUTOPILOT FINISHED — 1 automatic run[\s\S]*Why: nothing is left that the agent can do alone/);
  await run("rt-auto", "on");
  assert.match(ui.notices.at(-1)!, /▷ Autopilot not started: nothing is left/);
});

test("the decision never continues past a problem and words the next run from the agent's own recommendation", () => {
  const state: AutopilotState = { limit: 5, runs: 2, baseline: "a" };
  const snapshot: EngagementSnapshot = { engagement: "F", authorizationExpires: "2099-01-01", armed: true, targets: 1, exclusions: 0, routes: 1, scanlensReady: true, pendingProposals: 0, openTasks: 0,
    coverage: { total: 4, pending: 2, reviewed: 2, grouped: 0, waiting: 0, blocked: 0 }, agentNext: [{ label: "Check the VPN portal", instruction: "x", why: "" }] };
  const facts = { aborted: false, blocks: 0, denials: 0, severeFindings: [] };
  const go = autopilotDecision(state, snapshot, facts, "b");
  assert.ok(go.continue && /\[autopilot run 3 of 5\][\s\S]*Your own first recommendation was: Check the VPN portal/.test(go.prompt));
  assert.match((autopilotDecision(state, { ...snapshot, problem: "authorization expired on 2020-01-01" }, facts, "b") as { reason: string }).reason, /authorization expired/);
  assert.equal(autopilotDecision(state, snapshot, facts, "a").continue, false);
  assert.equal(autopilotDecision(state, { ...snapshot, coverage: { ...snapshot.coverage!, pending: 0 }, findings: { suspected: 1, validated: 0, reported: 0 } }, facts, "b").continue, true, "suspected findings are work the agent can do");
});

test("ask-first actions are recognized on the command line", () => {
  const asks: [string, RegExp][] = [
    ["curl -X POST https://a.test/api", /state-changing POST/], ["curl -sS --request=DELETE https://a.test/x", /DELETE/], ["curl -d 'a=1' https://a.test", /request body/],
    ["curl -u admin:pw https://a.test", /credentials/], ["curl -H 'Authorization: Bearer abc' https://a.test", /credentials or a session token/],
    ["timeout 10 bash -c 'curl -X PUT https://a.test/x'", /PUT/], ["wget --post-data=a=1 https://a.test", /state-changing/],
    ["httpx-toolkit -u a.test -x POST", /POST/], ["nmap --script vuln a.test", /intrusive scripts/], ["nmap --script=http-brute -p 80 a.test", /intrusive scripts/],
    ["nmap -T5 a.test", /aggressive rate/], ["masscan 10.0.0.0/24 -p80", /rate limit/], ["hydra -l admin -P list.txt ssh://a.test", /guesses credentials/],
    ["nxc smb 10.0.0.5 -u admin -p pw", /given credentials/], ["smbclient -N -L //10.0.0.5", /null session/], ["ssh admin@a.test", /login attempt/],
    ["sqlmap -u https://a.test/?id=1", /attack payloads/], ["ffuf -u https://a.test/FUZZ -w words.txt", /brute-forces paths/],
    ["nuclei -u https://a.test -as", /-ni is missing/], ["nuclei -u https://a.test -ni -tags rce,dos", /intrusive templates/], ["nuclei -u https://a.test -ni -dast", /fuzzing/],
    ["trufflehog filesystem evidence", /--no-verification is missing/], ["impacket-secretsdump a.test", /authenticated or relay session/],
  ];
  for (const [command, pattern] of asks) assert.match(askFirstReason(command) ?? "", pattern, command);
  for (const command of [
    "curl -sS -I https://a.test/login", "curl -X GET -H 'Accept: application/json' https://a.test/api", "curl --max-time 10 -o out.txt https://a.test/",
    "nmap -sV -p 443 -T3 --script default,safe a.test", "nmap -sV -oX scans/a.xml a.test", "masscan 10.0.0.0/24 -p80 --rate 500", "nxc smb 10.0.0.5",
    "httpx-toolkit -u a.test -sc -title", "nuclei -u https://a.test -as -ni -duc -rl 20 -etags dos,fuzz,intrusive,bruteforce", "trufflehog filesystem evidence --no-verification --no-update",
    "dnsx -l a.test -a -resp", "testssl a.test", "gowitness scan single -u https://a.test", "echo 'curl -X POST is not run here' > notes.txt", "grep -r POST evidence/",
  ]) assert.equal(askFirstReason(command), undefined, command);
});

test("armed checks still ask for ask-first actions, and scope still comes first", async t => {
  const { run, ui, bash } = harness(t);
  await run("rt-arm");
  ui.prompts.length = 0;
  assert.equal(await bash("curl -sS -I https://app.fixture.test/login"), undefined);
  assert.equal(await bash("nmap -sV -p 443 -T3 app.fixture.test"), undefined);
  assert.deepEqual(ui.prompts, [], "ordinary in-scope checks run without a prompt when armed");

  assert.equal(await bash("curl -X POST https://app.fixture.test/api"), undefined, "approved by the operator");
  assert.deepEqual(ui.prompts.splice(0), ["Allow this ask-first action?"]);
  assert.match(ui.details.at(-1)!, /Why you are asked although checks are armed: curl sends a state-changing POST request\./);
  assert.equal(await bash("trufflehog filesystem .redteam/evidence"), undefined);
  assert.deepEqual(ui.prompts.splice(0), ["Allow this ask-first action?"], "asked even though the command names no target");
  assert.equal(await bash("trufflehog filesystem .redteam/evidence --no-verification"), undefined);
  assert.deepEqual(ui.prompts, []);

  assert.match((await bash("curl -X POST https://10.20.0.1/api"))!.reason!, /excluded/);
  assert.match((await bash("nmap --script vuln evil.example"))!.reason!, /evil\.example is unknown/);
  assert.deepEqual(ui.prompts, [], "excluded and unknown targets are refused without asking");
  ui.answer = false;
  assert.match((await bash("nmap --script vuln app.fixture.test"))!.reason!, /Denied by the operator \(nmap runs brute-force, exploit, vulnerability, or other intrusive scripts\)/);
});

test("the agent files questions and keeps working; answers reach it at the next run", async t => {
  const { run, ui, sent, start, settle, review, tool, hooks, ctx } = harness(t);
  await run("rt-auto", "on 5");
  await start();
  const asked = await tool("redteam_ask", { operation: "ask", question: "Is SSO  enforced on the login page?", options: ["Yes, for all users", "No", "Only for staff"], blocks: "endpoint /login" });
  assert.deepEqual([asked.details.recorded, asked.details.id, asked.details.open], [true, 1, 1]);
  assert.equal((await tool("redteam_ask", { operation: "ask", question: "Is SSO enforced on the login page?" })).details.recorded, false, "the same open question is filed once");
  await settle();
  assert.equal(sent.length, 2, "filing a question counts as progress and does not stop the agent");
  assert.match(ui.widget[1], /Needs you 1 /);
  assert.match(ui.widget[2], /^Next: \/rt-answer — Answer the agent's questions/);

  await run("rt-answer");
  assert.match(ui.notices.at(-1)!, /✓ 0 of 1 question\(s\) answered/, "the picker was closed without an answer");
  await run("rt-answer", "1 3");
  assert.match(ui.notices.at(-1)!, /✓ Answered #1: Only for staff\nThe agent receives it at the start of its next run\. 0 question\(s\) still open\./);
  await run("rt-answer", "9 yes");
  assert.match(ui.notices.at(-1)!, /No question #9/);

  const event = { systemPromptOptions: { sections: {} as Record<string, string> }, messageType: "user", prompt: sent.at(-1) };
  await hooks.get("before_agent_start")!(event, ctx);
  assert.match(event.systemPromptOptions.sections.redteam_operating_rules, /OPERATOR ANSWERS since your last run[\s\S]*#1 Q: Is SSO enforced on the login page\? \(waits on this: endpoint \/login\) A: Only for staff/);
  assert.match(event.systemPromptOptions.sections.redteam_operating_rules, /AUTOPILOT is on \(automatic run 2 of 5\)/);
  const again = { systemPromptOptions: { sections: {} as Record<string, string> }, messageType: "user", prompt: "next" };
  await hooks.get("before_agent_start")!(again, ctx);
  assert.doesNotMatch(again.systemPromptOptions.sections.redteam_operating_rules, /OPERATOR ANSWERS/, "an answer is delivered once");

  await tool("redteam_ask", { operation: "ask", question: "May the staging host be restarted during tests?" });
  await review("https://app.fixture.test/login");
  await run("rt-auto", "off");
  assert.match(ui.notices.at(-1)!, /Why: you turned autopilot off\.[\s\S]*1 question filed|2 questions filed/);
  assert.match(ui.notices.at(-1)!, /NEEDS YOU\n  \? 1 question from the agent → \/rt-answer\n {6}#2 May the staging host be restarted during tests\?/);
  await run("rt-tasks");
  assert.match(ui.notices.at(-1)!, /\? 1 question\(s\) from the agent → \/rt-answer/);
});
