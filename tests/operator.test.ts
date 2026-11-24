import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { AuditLog } from "../extensions/audit.ts";
import { boardText, daysLeft, nextActions, overviewText, panelLines, progressBar, steeringPrompts, welcomeText, workflowStages, type EngagementSnapshot } from "../extensions/guide.ts";
import redteamExtension from "../extensions/redteam.ts";

const now = new Date("2026-11-24T12:00:00Z");
const base: EngagementSnapshot = {
  engagement: "Fixture", authorizationExpires: "2027-01-31", armed: false, targets: 4, exclusions: 1, routes: 2,
  scanlensReady: true, pendingProposals: 0, openTasks: 0, discoveryRuns: 1,
  coverage: { total: 10, pending: 4, reviewed: 5, grouped: 1, waiting: 0, blocked: 0 },
};

test("progress bar and expiry countdown are stable at their edges", () => {
  assert.equal(progressBar(0, 0, 4), "░░░░");
  assert.equal(progressBar(1, 2, 4), "██░░");
  assert.equal(progressBar(9, 2, 4), "████");
  assert.equal(daysLeft("2026-11-24", now), 0);
  assert.equal(daysLeft("2026-11-27", now), 3);
  assert.equal(daysLeft("not-a-date", now), undefined);
});

test("next actions follow the engagement stage", () => {
  const first = (snapshot: Partial<EngagementSnapshot>) => nextActions({ ...base, ...snapshot }, now)[0].command;
  assert.equal(first({ problem: "engagement name is missing" }), "/rt-setup");
  assert.equal(first({ problem: "scope has no targets", targets: 0 }), "/rt-start");
  assert.equal(first({ pendingProposals: 2 }), "/rt-proposals");
  assert.equal(first({ coverage: { ...base.coverage!, waiting: 1 } }), "/rt-tasks");
  assert.equal(first({ scanlensReady: false }), "/rt-start");
  assert.equal(first({}), "/rt-steer");
  assert.match(nextActions({ ...base, authorizationExpires: "2026-11-27" }, now)[0].why, /expires in 3 day/);
  assert.ok(nextActions(base, now).some(action => action.command === "/rt-arm"));
  assert.ok(!nextActions({ ...base, armed: true }, now).some(action => action.command === "/rt-arm"));
});

test("workflow checklist marks exactly one current stage and the panel names the next step", () => {
  const stages = workflowStages(base);
  assert.deepEqual(stages.map(stage => stage.mark), ["done", "done", "done", "done", "current", "done", "todo"]);
  assert.equal(workflowStages({ ...base, discoveryRuns: 0 })[3].mark, "current", "an unmapped surface comes before triage");
  assert.equal(nextActions({ ...base, discoveryRuns: 0 }, now)[0].command, "/rt-discover");
  assert.equal(nextActions({ ...base, discoveryRuns: 0, discovery: { used: 0, limit: 50 } }, now)[0].label, "Map the attack surface");
  assert.equal(nextActions({ ...base, pendingEndpoints: 3 }, now)[0].command, "/rt-endpoints");
  assert.match(panelLines({ ...base, discovery: { used: 12, limit: 50 }, pendingEndpoints: 3 }, now).join("\n"), /◆ discovery 38\/50[\s\S]*Proposals 3/);
  assert.equal(workflowStages({ ...base, problem: "authorization expired on 2020-01-01" })[0].mark, "blocked");
  const panel = panelLines(base, now);
  assert.equal(panel.length, 3);
  assert.match(panel[0], /Fixture · authorized to 2027-01-31 \(68d\) · ○ disarmed/);
  assert.match(panel[1], /60% \(6\/10\)/);
  assert.match(panel[2], /^Next: \/rt-steer/);
  assert.match(panelLines({ ...base, armed: true }, now)[0], /● ARMED/);
  assert.match(overviewText(base, now), /▸ 5\. Triage and review coverage/);
});

test("steering puts the most relevant instruction first", () => {
  assert.equal(steeringPrompts({ ...base, coverage: undefined })[0].label, "Start scan triage");
  assert.equal(steeringPrompts(base)[0].label, "Continue the coverage review");
  assert.equal(steeringPrompts({ ...base, coverage: { ...base.coverage!, pending: 0 } })[0].label, "Draft client-facing findings");
  assert.equal(new Set(steeringPrompts(base).map(item => item.label)).size, 8);
  assert.equal(steeringPrompts({ ...base, discoveryRuns: 0, discovery: { used: 0, limit: 50 } })[0].label, "Map the attack surface");
});

test("open-work board separates operator items, agent items, and tracked tasks", () => {
  const text = boardText({
    snapshot: { ...base, pendingProposals: 1, openTasks: 1, coverage: { ...base.coverage!, waiting: 6 } },
    waiting: [{ key: "endpoint:https://a.test/", missing: "owner confirmation" }],
    blocked: [], pending: [{ key: "service:tcp:a.test:443" }],
    proposals: [{ host: "b.test", reason: "seen in certificate" }],
    tasks: [{ id: 3, title: "Ask for VPN access", createdBy: "operator", createdAt: "2026-11-20T10:00:00Z", status: "open" }],
  }, now);
  assert.match(text, /NEEDS YOU\n {2}! 6 coverage item\(s\) wait on a fact from you\n {6}- endpoint:https:\/\/a\.test\/ — needs: owner confirmation\n {6}- … 5 more/);
  assert.match(text, /b\.test — seen in certificate/);
  assert.match(text, /AGENT CAN CONTINUE\n {2}▸ 4 pending coverage item/);
  assert.match(text, /TRACKED TASKS \(1 open\)\n {2}□ #3 \[operator\] Ask for VPN access {2}\(2026-11-20\)/);
});

function harness(t: { after(fn: () => void): void }) {
  const cwd = mkdtempSync(join(tmpdir(), "pi-operator-"));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  const configPath = join(cwd, "redteam.config.json");
  mkdirSync(join(cwd, "targets"));
  writeFileSync(join(cwd, "targets", "hosts.txt"), "listed.fixture.test\n");
  writeFileSync(configPath, JSON.stringify({
    engagement: "Fixture", authorizationExpires: "2099-01-01", targets: ["10.20.0.0/24", "app.fixture.test"],
    excludeTargets: [], targetSources: ["targets"],
  }));
  const hooks = new Map<string, (...args: any[]) => Promise<any>>();
  const commands = new Map<string, { handler: (...args: any[]) => Promise<any> }>();
  const tools = new Map<string, (...args: any[]) => Promise<any>>();
  redteamExtension({
    registerCommand: (name: string, command: { handler: (...args: any[]) => Promise<any> }) => commands.set(name, command),
    registerTool: (tool: { name: string; execute: (...args: any[]) => Promise<any> }) => tools.set(tool.name, tool.execute),
    on: (event: string, hook: (...args: any[]) => Promise<any>) => hooks.set(event, hook),
  } as unknown as ExtensionAPI);
  const ui = {
    answer: true, selection: undefined as string | undefined | ((options: string[]) => string | undefined), typed: undefined as string | undefined,
    notices: [] as string[], confirms: [] as string[], menus: [] as string[][], editor: "", widget: [] as string[],
  };
  const ctx = {
    cwd, hasUI: true, sessionManager: { getSessionId: () => "session-test" },
    waitForIdle: async () => {},
    ui: {
      confirm: async (_title: string, body: string) => { ui.confirms.push(body); return ui.answer; },
      select: async (_title: string, options: string[]) => { ui.menus.push(options); return typeof ui.selection === "function" ? ui.selection(options) : ui.selection; },
      input: async () => ui.typed,
      notify: (text: string) => { ui.notices.push(text); },
      setStatus() {}, setEditorText: (text: string) => { ui.editor = text; },
      setWidget: (_key: string, lines: string[]) => { ui.widget = lines; },
    },
  };
  t.after(() => { void hooks.get("session_shutdown")!({ reason: "test" }, ctx); });
  const run = (name: string, args = "") => commands.get(name)!.handler(args, ctx);
  const config = () => JSON.parse(readFileSync(configPath, "utf8")) as { targets: string[]; excludeTargets: string[] };
  return { cwd, ctx, ui, run, config, tools, hooks };
}

test("rt-onboard adds one exact host after confirmation and rt-offboard removes it again", async t => {
  const { run, ui, config, cwd, hooks, ctx } = harness(t);
  ui.answer = false;
  await run("rt-onboard", "new.fixture.test");
  assert.deepEqual(config().targets, ["10.20.0.0/24", "app.fixture.test"]);
  assert.match(ui.notices.at(-1)!, /was not added/);

  ui.answer = true;
  await run("rt-arm");
  await run("rt-onboard", "New.Fixture.Test.");
  assert.deepEqual(config().targets, ["10.20.0.0/24", "app.fixture.test", "new.fixture.test"]);
  assert.match(ui.notices.at(-1)!, /★ new\.fixture\.test onboarded/);
  assert.match(ui.widget[0], /○ disarmed/, "a scope change disarms active checks");
  await run("rt-targets", "onboarded");
  assert.match(ui.notices.at(-1)!, /★ ONBOARDED {2}new\.fixture\.test/);

  await run("rt-onboard", "10.20.0.0/25");
  assert.match(ui.notices.at(-1)!, /exact hostname or IP/);
  await run("rt-onboard", "app.fixture.test");
  assert.match(ui.notices.at(-1)!, /already in scope/);

  await run("rt-offboard", "new.fixture.test");
  assert.deepEqual(config(), { ...config(), targets: ["10.20.0.0/24", "app.fixture.test"], excludeTargets: [] });
  assert.match(ui.notices.at(-1)!, /⛔ new\.fixture\.test offboarded\./);

  await hooks.get("session_shutdown")!({ reason: "test" }, ctx);
  const audit = new AuditLog(cwd, ".redteam/audit/audit.db");
  t.after(() => audit.close());
  const events = (audit.query({ operation: "target", target: "new.fixture.test" }) as { eventType: string }[]).map(event => event.eventType);
  assert.ok(events.includes("scope_target_onboarded") && events.includes("scope_target_offboarded"));
  assert.equal(audit.verify().valid, true);
});

test("rt-offboard excludes hosts that an inventory file or range still covers", async t => {
  const { run, ui, config } = harness(t);
  await run("rt-offboard", "listed.fixture.test");
  assert.match(ui.confirms.at(-1)!, /still covered by inventory file targets\/hosts\.txt/);
  assert.deepEqual(config().excludeTargets, ["listed.fixture.test"]);

  await run("rt-offboard", "10.20.0.9");
  assert.match(ui.confirms.at(-1)!, /broader range or wildcard rule/);
  assert.deepEqual(config().excludeTargets, ["listed.fixture.test", "10.20.0.9"]);
  assert.deepEqual(config().targets, ["10.20.0.0/24", "app.fixture.test"]);

  await run("rt-offboard", "10.20.0.9");
  assert.match(ui.notices.at(-1)!, /already excluded/);
  await run("rt-onboard", "10.20.0.9");
  assert.match(ui.notices.at(-1)!, /explicitly excluded/);

  ui.selection = options => options.find(option => option === "app.fixture.test");
  await run("rt-offboard");
  assert.deepEqual(ui.menus.at(-1), ["app.fixture.test"], "the picker offers only exact hosts still in scope");
  assert.deepEqual(config().targets, ["10.20.0.0/24"]);
});

test("tasks are tracked by operator and agent and shown on the board and panel", async t => {
  const { run, ui, tools, ctx } = harness(t);
  await run("rt-tasks", "add Ask the client for VPN access");
  assert.match(ui.notices.at(-1)!, /Task #1 added/);
  await tools.get("redteam_tasks")!("id", { operation: "add", title: "Recheck TLS on app after the patch window" }, undefined, undefined, ctx);
  await run("rt-tasks");
  assert.match(ui.notices.at(-1)!, /TRACKED TASKS \(2 open\)\n {2}□ #1 \[operator\] Ask the client for VPN access/);
  assert.match(ui.notices.at(-1)!, /□ #2 \[agent\] Recheck TLS/);
  assert.match(ui.widget[1], /Needs you 2/);

  await run("rt-tasks", "done 1");
  await run("rt-tasks", "all");
  assert.match(ui.notices.at(-1)!, /TRACKED TASKS \(1 open\)/);
  assert.match(ui.notices.at(-1)!, /✓ #1 \[operator\]/);
  await run("rt-tasks", "done 99");
  assert.match(ui.notices.at(-1)!, /No task #99/);
});

test("the menu leads with the next step and dispatches the chosen action; steering fills the editor", async t => {
  const { run, ui } = harness(t);
  ui.selection = options => options.find(option => option.startsWith("Help"));
  await run("rt");
  const menu = ui.menus.at(-1)!;
  assert.match(menu[0], /^▸ Next: /);
  assert.ok(menu.includes("Scope · onboard a target") && menu.includes("Scope · offboard a target") && menu.includes("Run · arm active checks"));
  assert.match(ui.notices.at(-2)!, /Workflow {3}✓ done · ▸ you are here/);
  assert.match(ui.notices.at(-1)!, /operator guide/);

  ui.selection = options => options[1];
  await run("rt-steer");
  assert.match(ui.editor, /\S/);
  assert.match(ui.notices.at(-1)!, /placed in the editor/);
  assert.match(ui.widget.at(-1)!, /^Next: /);
});

test("the welcome message names the folder state and the right first command", () => {
  const fresh = welcomeText({ ...base, engagement: "", problem: "redteam.config.json is missing", targets: 0, scanlensReady: false, coverage: undefined }, "/opt/harness/README.md", now);
  assert.match(fresh, /^Welcome to the Pi red-team harness\nNo engagement is set up in this folder yet \(redteam\.config\.json is missing\)\.\n\n {2}\/rt-start {3}Start here/);
  assert.match(fresh, /Full guide: \/opt\/harness\/README\.md/);
  const running = welcomeText(base, "/opt/harness/README.md", now);
  assert.match(running, /Engagement: Fixture · authorized to 2027-01-31 \(68d\) · 4 target\(s\), 1 excluded\n\n {2}\/rt {9}Start here/);
  assert.match(running, /Active checks are disarmed/);
});
