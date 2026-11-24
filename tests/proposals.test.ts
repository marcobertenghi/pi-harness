import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { AuditLog } from "../extensions/audit.ts";
import redteamExtension from "../extensions/redteam.ts";
import { ProposalStore, proposalHost } from "../extensions/proposals.ts";
import { scopeDecision } from "../extensions/scope.ts";

test("proposals are deduplicated, paginated, and isolated per engagement without changing scope", t => {
  const db = new DatabaseSync(":memory:");
  t.after(() => db.close());
  const store = new ProposalStore(db);
  const scope = ["known.example.test"];
  assert.deepEqual(store.record("project-a", "New.Example.Test.", "Operator capture #1", "Mentioned in certificate data"), {
    host: "new.example.test", recorded: true, authorizationChanged: false,
  });
  assert.equal(store.record("project-a", "new.example.test", "Note #2", "Duplicate").recorded, false);
  assert.equal(store.record("project-a", "192.0.2.5", "Operator note", "Related inventory reference").recorded, true);
  const first = store.list("project-a", 0, 1);
  const second = store.list("project-a", first.nextOffset ?? -1, 1);
  assert.equal(first.nextOffset, 1);
  assert.equal(second.nextOffset, null);
  const entries = [...first.entries, ...second.entries];
  assert.equal(entries.find(entry => entry.host === "new.example.test")?.source, "Operator capture #1");
  assert.equal(store.list("project-b").entries.length, 0);
  for (const { host } of entries) assert.equal(scopeDecision(host, scope, []), "unknown");
});

test("proposal dispositions and operator audit events are committed together", t => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-proposal-disposition-"));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  const audit = new AuditLog(cwd, "audit.db");
  t.after(() => audit.close());
  const host = "related.example.test";
  const context = { sessionId: "s1" };
  audit.proposals.record("engagement", host, "Ref 1", "Related service");
  assert.throws(() => audit.recordProposalDisposition("another", host, "rejected", context), /No such proposal/);
  assert.equal(audit.verify().events, 0);
  audit.recordProposalDisposition("engagement", host, "deferred", context);
  assert.equal(audit.proposals.list("engagement", 0, 20, true).entries.length, 0);
  assert.equal(audit.proposals.list("engagement").entries[0].disposition, "deferred");
  assert.match(JSON.stringify(audit.query({ operation: "target", target: host })), /"action":"deferred"/);
  assert.equal(audit.verify().valid, true);

  const db = new DatabaseSync(audit.dbPath);
  db.exec("CREATE TRIGGER fail_event BEFORE INSERT ON audit_events BEGIN SELECT raise(ABORT, 'test write failure'); END");
  db.close();
  assert.throws(() => audit.recordProposalDisposition("engagement", host, "rejected", context), /test write failure/);
  assert.equal(audit.proposals.list("engagement").entries[0].disposition, "deferred");
});

test("onboarded disposition requires confirmation, appends only the exact host, audits it, and disarms", async t => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-lead-confirmation-"));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  const host = "candidate.example.test";
  const configPath = join(cwd, "redteam.config.json");
  const config = { engagement: "Fixture", authorizationExpires: "2099-01-01", targets: ["existing.example.test"],
    excludeTargets: [], targetSources: [], auditDb: "audit.db" };
  writeFileSync(configPath, JSON.stringify(config));
  const commands = new Map<string, Parameters<ExtensionAPI["registerCommand"]>[1]>();
  const tools: Record<string, (...args: unknown[]) => Promise<unknown>> = {};
  const hooks = new Map<string, (...args: unknown[]) => Promise<void>>();
  redteamExtension({
    registerCommand: (...args: [string, Parameters<ExtensionAPI["registerCommand"]>[1]]) => commands.set(...args),
    registerTool: (tool: { name: string; execute: (...args: unknown[]) => Promise<unknown> }) => { tools[tool.name] = tool.execute; },
    on: (event: string, hook: (...args: unknown[]) => Promise<void>) => hooks.set(event, hook),
  } as unknown as ExtensionAPI);
  let confirm = false;
  const notices: string[] = [];
  const statuses: string[] = [];
  const ctx = { cwd, hasUI: true, sessionManager: { getSessionId: () => "session-test" },
    ui: {
      confirm: async () => confirm,
      notify: (message: string) => notices.push(message),
      setStatus: (_key: string, value: string) => statuses.push(value),
    } };
  t.after(() => hooks.get("session_shutdown")?.({ reason: "quit" }, ctx));
  const handler = commands.get("rt-proposals")!.handler;
  const review = () => handler(`onboarded ${host}`, ctx as unknown as Parameters<typeof handler>[1]);
  await tools.redteam_proposals("id", { operation: "record", host, source: "evidence 1", reason: "related" }, undefined, undefined, ctx);
  await review();
  assert.equal((JSON.parse(readFileSync(configPath, "utf8")) as { targets: string[] }).targets.includes(host), false);

  confirm = true;
  await review();
  const saved = JSON.parse(readFileSync(configPath, "utf8")) as { targets: string[] };
  assert.deepEqual(saved.targets, ["existing.example.test", host]);
  assert.equal(statuses.at(-1), "RT: disarmed");
  assert.match(notices.at(-1) ?? "", /onboarded and now in scope/);
  const audit = new AuditLog(cwd, "audit.db");
  t.after(() => audit.close());
  assert.match(JSON.stringify(audit.query({ operation: "target", target: host })), /proposal_scope_added/);
});

test("rt-proposals without arguments provides an interactive proposal and disposition picker", async t => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-proposal-picker-"));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  const host = "candidate.example.test";
  writeFileSync(join(cwd, "redteam.config.json"), JSON.stringify({
    engagement: "Fixture",
    authorizationExpires: "2099-01-01",
    targets: ["existing.example.test", host],
    excludeTargets: [],
    targetSources: [],
    auditDb: "audit.db",
  }));
  const commands = new Map<string, Parameters<ExtensionAPI["registerCommand"]>[1]>();
  const tools: Record<string, (...args: unknown[]) => Promise<unknown>> = {};
  const hooks = new Map<string, (...args: unknown[]) => Promise<void>>();
  redteamExtension({
    registerCommand: (...args: [string, Parameters<ExtensionAPI["registerCommand"]>[1]]) => commands.set(...args),
    registerTool: (tool: { name: string; execute: (...args: unknown[]) => Promise<unknown> }) => { tools[tool.name] = tool.execute; },
    on: (event: string, hook: (...args: unknown[]) => Promise<void>) => hooks.set(event, hook),
  } as unknown as ExtensionAPI);
  const notices: string[] = [];
  const selectionTitles: string[] = [];
  const confirmationTitles: string[] = [];
  let selectedHost = host;
  const ctx = {
    cwd,
    hasUI: true,
    sessionManager: { getSessionId: () => "session-picker" },
    ui: {
      select: async (title: string, options: string[]) => {
        selectionTitles.push(title);
        return options.find(option => option.includes(selectedHost)) ?? options[0];
      },
      confirm: async (title: string) => {
        confirmationTitles.push(title);
        return title !== "Add exact host to authorized scope?";
      },
      notify: (message: string) => notices.push(message),
    },
  };
  t.after(() => hooks.get("session_shutdown")?.({ reason: "quit" }, ctx));
  await tools.redteam_proposals("id", { operation: "record", host, source: "evidence 1", reason: "related" }, undefined, undefined, ctx);
  const handler = commands.get("rt-proposals")!.handler;
  await handler("", ctx as unknown as Parameters<typeof handler>[1]);
  assert.deepEqual(selectionTitles, ["Review pending scope proposal", `Disposition for ${host}`]);
  assert.match(notices.at(-1) ?? "", new RegExp(`${host} onboarded and now in scope`));

  selectedHost = "unknown.example.test";
  await tools.redteam_proposals("id-2", { operation: "record", host: selectedHost, source: "evidence 2", reason: "related" }, undefined, undefined, ctx);
  await handler("", ctx as unknown as Parameters<typeof handler>[1]);
  assert.equal(confirmationTitles.at(-1), "Add exact host to authorized scope?");
  assert.doesNotMatch(notices.at(-1) ?? "", /Error: Error:/);
});

test("proposals accept only exact hosts and IPs, not paths, ranges, or credentials", () => {
  assert.equal(proposalHost("2001:db8::8"), "2001:db8::8");
  for (const input of ["https://new.example.test/path?token=secret", "*.example.test", "192.0.2.0/24", "foo.test:443", "-arg", "foo.test\nbar.test"]) {
    assert.throws(() => proposalHost(input), /exact hostname or IP/);
  }
});
