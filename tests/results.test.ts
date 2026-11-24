import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { AuditLog } from "../extensions/audit.ts";
import { parseArchiveUrls, type Transport } from "../extensions/discovery.ts";
import { reportGaps } from "../extensions/findings.ts";
import { findingsLabel, nextActions, workflowStages, type EngagementSnapshot } from "../extensions/guide.ts";
import redteamExtension from "../extensions/redteam.ts";

function harness(t: { after(fn: () => void): void }, transport?: Partial<Transport>, passiveSources: string[] = []) {
  const cwd = mkdtempSync(join(tmpdir(), "pi-results-"));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  writeFileSync(join(cwd, "redteam.config.json"), JSON.stringify({
    engagement: "Fixture", authorizationExpires: "2099-01-01", targets: ["app.fixture.test", "*.acme.fixture.test"], excludeTargets: ["secret.acme.fixture.test"],
    targetSources: [], webEndpoints: ["https://app.fixture.test/login"], passiveSources,
  }));
  const requests: { url: string; headers?: Record<string, string> }[] = [];
  const hooks = new Map<string, (...args: any[]) => Promise<any>>();
  const commands = new Map<string, { handler: (...args: any[]) => Promise<any> }>();
  const tools = new Map<string, (...args: any[]) => Promise<any>>();
  redteamExtension({
    registerCommand: (name: string, command: { handler: (...args: any[]) => Promise<any> }) => commands.set(name, command),
    registerTool: (tool: { name: string; execute: (...args: any[]) => Promise<any> }) => tools.set(tool.name, tool.execute),
    on: (event: string, hook: (...args: any[]) => Promise<any>) => hooks.set(event, hook),
  } as unknown as ExtensionAPI, {
    discoveryDelayMs: 0, codeSearchToken: "fixture-token",
    transport: {
      get: async (url, options) => { requests.push({ url, headers: options.headers }); return transport?.get ? transport.get(url, options) : { status: 404, headers: {}, body: "" }; },
      resolve: async name => transport?.resolve ? transport.resolve(name) : [],
    },
  });
  const ui = { notices: [] as string[], widget: [] as string[] };
  const ctx = {
    cwd, hasUI: true, sessionManager: { getSessionId: () => "session-test" },
    ui: {
      confirm: async () => true, select: async () => undefined, notify: (text: string) => { ui.notices.push(text); },
      setStatus: () => {}, setWidget: (_key: string, lines: string[]) => { ui.widget = lines; },
    },
  };
  t.after(() => { void hooks.get("session_shutdown")!({ reason: "test" }, ctx); });
  const run = (name: string, args = "") => commands.get(name)!.handler(args, ctx);
  const tool = async (name: string, params: Record<string, unknown>) => (await tools.get(name)!("id", params, undefined, undefined, ctx)) as { details: any; isError?: boolean };
  const last = () => ui.notices.at(-1)!;
  const closeAudit = () => hooks.get("session_shutdown")!({ reason: "test" }, ctx);
  return { cwd, ui, run, tool, last, requests, closeAudit };
}

const evidence = (cwd: string, ...parts: string[]) => join(cwd, ".redteam", "evidence", ...parts);

test("findings move from suspected to validated to the draft report", async t => {
  const { run, tool, last, ui, cwd, closeAudit } = harness(t);
  const recorded = await tool("redteam_findings", { operation: "record", title: "Exposed  admin\nconsole", affectedSystems: ["https://app.fixture.test/admin"], note: "password=hunter2 seen in page" });
  assert.equal(recorded.details.status, "suspected");
  assert.equal(recorded.details.title, "Exposed admin console");
  assert.doesNotMatch(recorded.details.note, /hunter2/, "secret-looking values are redacted before they are stored");
  assert.deepEqual(recorded.details.missingForReport, ["evidence", "description", "risk", "mitigation", "OSSTMM category", "ratings"]);
  await run("rt-status");
  assert.match(ui.widget[1], /Findings 0✓ 1\?$/);

  await assert.rejects(tool("redteam_findings", { operation: "update", id: 1, status: "validated" }), /cannot be validated without evidence, description/);
  await assert.rejects(tool("redteam_findings", { operation: "record", title: "Guess", status: "validated" }), /needs affected systems, evidence, description/);
  const validated = await tool("redteam_findings", { operation: "update", id: 1, status: "validated", description: "The console answers without authentication.",
    evidence: ["HTTP 200 on /admin without a session — .redteam/evidence/admin.txt"], risk: "Configuration can be read.", mitigation: "It is recommended to require authentication.",
    osstmmCategory: "Exposure", exploitability: 1, technicalImpact: 2, mitigationEffort: 1 });
  assert.deepEqual([validated.details.status, validated.details.missingForReport], ["validated", []]);
  await tool("redteam_findings", { operation: "record", title: "Possible outdated TLS", affectedSystems: ["app.fixture.test:443"] });

  await run("rt-findings");
  assert.match(last(), /VALIDATED · evidence-backed, goes into the report \(1\)\n  ✓ #1 Exposed admin console — https:\/\/app\.fixture\.test\/admin\n\nSUSPECTED · still to validate or dismiss \(1\)\n  \? #2 Possible outdated TLS/);
  await run("rt-findings", "1");
  assert.match(last(), /Finding #1 \[validated\] Exposed admin console[\s\S]*Complete for the report\./);
  await run("rt-findings", "dismiss 2");
  assert.match(last(), /✗ Finding #2 is now dismissed/);
  await assert.rejects(tool("redteam_findings", { operation: "update", id: 2, note: "retry" }), /dismissed by operator decision/);
  await run("rt-findings", "reopen 2");
  await run("rt-findings", "validate 2");
  assert.match(last(), /cannot be validated without evidence, description/, "the operator cannot skip the evidence either");

  await run("rt-report");
  assert.match(last(), /Draft report written: \.redteam\/evidence\/reports\/report-\d{8}-\d{6}\.md\n  1 finding\(s\)[\s\S]*! 1 suspected finding\(s\) are left out of the client part[\s\S]*! 1 coverage item\(s\) are still pending/);
  const file = readdirSync(evidence(cwd, "reports"))[0];
  const report = readFileSync(evidence(cwd, "reports", file), "utf8");
  assert.match(report, /^# Fixture — assessment report \(draft\)/);
  assert.match(report, /\| 1\.1 \| Exposed admin console \| 1 \| Exposure \| 1 \| 2 \| 1 \|/);
  assert.match(report, /### 1\.1 Exposed admin console\n\n\*\*Affected Systems:\*\*\n- https:\/\/app\.fixture\.test\/admin\n\n\*\*Description:\*\* The console answers without authentication\./);
  assert.match(report, /\| endpoint:https:\/\/app\.fixture\.test\/login \| pending \|/);
  assert.match(report, /Audit log: intact, \d+ event\(s\)/);
  assert.match(report, /## 4\. Activity timeline \(UTC\)/);
  const [client, appendix] = report.split("## Internal appendix — remove before delivery");
  assert.doesNotMatch(client, /Possible outdated TLS/, "suspected findings stay out of the client part");
  assert.match(appendix, /- #2 Possible outdated TLS — app\.fixture\.test:443/);

  await closeAudit();
  const audit = new AuditLog(cwd, ".redteam/audit/audit.db");
  t.after(() => audit.close());
  assert.equal(audit.countEvents("finding_recorded"), 2);
  assert.equal(audit.countEvents("report_generated"), 1);
  assert.equal((audit.query({ operation: "artifacts" }) as { actor: string; evidencePath: string }[]).filter(event => event.actor === "operator" && /reports\/report-/.test(event.evidencePath)).length, 1);
  assert.equal(audit.verify().valid, true);
});

test("the credential ledger records locations and tests, never values", async t => {
  const { run, tool, last, cwd } = harness(t);
  const input = { operation: "record", kind: "password", account: "svc-backup", foundAt: "https://app.fixture.test/config.bak" };
  await assert.rejects(tool("redteam_credentials", { ...input, secretLocation: "notes.txt" }), /must be a file under the evidence directory/);
  await assert.rejects(tool("redteam_credentials", { ...input, secretLocation: ".redteam/evidence/loot/svc-backup.txt" }), /does not exist\. Write the value to that file first/);
  mkdirSync(evidence(cwd, "loot"), { recursive: true });
  writeFileSync(evidence(cwd, "loot", "svc-backup.txt"), "Sup3rSecret!\n");
  const first = await tool("redteam_credentials", { ...input, secretLocation: ".redteam/evidence/loot/svc-backup.txt" });
  assert.deepEqual([first.details.recorded, first.details.credential.id], [true, 1]);
  assert.equal((await tool("redteam_credentials", { ...input, secretLocation: ".redteam/evidence/loot/svc-backup.txt" })).details.recorded, false, "the same credential is recorded once");

  await assert.rejects(tool("redteam_credentials", { operation: "test", id: 1, target: "ssh://other.example:22", result: "valid" }), /other\.example is not in scope/);
  await assert.rejects(tool("redteam_credentials", { operation: "test", id: 1, target: "ssh://secret.acme.fixture.test:22", result: "valid" }), /not in scope/);
  await tool("redteam_credentials", { operation: "test", id: 1, target: "ssh://vpn.acme.fixture.test:22", result: "invalid" });
  const tested = await tool("redteam_credentials", { operation: "test", id: 1, target: "ssh://vpn.acme.fixture.test:22", result: "valid", note: "operator approved" });
  assert.deepEqual(tested.details.credential.tests.map((item: { result: string }) => item.result), ["valid"], "the latest result per target replaces the earlier one");

  await run("rt-creds");
  assert.match(last(), /#1 password · svc-backup · found at https:\/\/app\.fixture\.test\/config\.bak\n {6}value in \.redteam\/evidence\/loot\/svc-backup\.txt\n {6}✓ ssh:\/\/vpn\.acme\.fixture\.test:22: valid \(operator approved\)/);
  await run("rt-report");
  await run("rt-handover");
  assert.match(last(), /Handover note written: \.redteam\/evidence\/handover\/handover-[\s\S]*Credentials: 1 recorded, 0 never tested/);
  for (const folder of ["reports", "handover"]) {
    const text = readFileSync(evidence(cwd, folder, readdirSync(evidence(cwd, folder))[0]), "utf8");
    assert.match(text, /svc-backup/);
    assert.doesNotMatch(text, /Sup3rSecret/);
  }
});

test("the handover note carries next steps, open questions, and what was blocked", async t => {
  const { run, tool, last, cwd } = harness(t);
  await tool("redteam_next", { steps: [{ label: "Validate the admin console", instruction: "Validate finding 1 with one GET.", why: "likely entry point" }] });
  await tool("redteam_tasks", { operation: "add", title: "Ask the client for a test account" });
  await tool("redteam_coverage", { operation: "record", subject: { endpoint: "https://app.fixture.test/login" }, state: "waiting_on_operator",
    claim: "Login form present", evidence: [{ source: "operator note", observation: "form seen" }], missingFact: "whether SSO is enforced" });
  await run("rt-handover");
  assert.match(last(), /Where it stands[\s\S]*waiting on operator 1[\s\S]*Do next\n\n1\. \*\*Validate the admin console\*\* — likely entry point\n   Send to the agent: Validate finding 1 with one GET\./);
  const text = readFileSync(evidence(cwd, "handover", readdirSync(evidence(cwd, "handover"))[0]), "utf8");
  assert.match(text, /## Needs the operator\n\n- endpoint:https:\/\/app\.fixture\.test\/login — needs: whether SSO is enforced\n- Task #1 \[agent\] Ask the client for a test account/);
  assert.match(text, /## How to resume\n\n1\. Start Pi in this folder/);
  assert.match(text, /active checks disarmed, discovery off/);
});

test("the guide points at validation and then the report once coverage is done", () => {
  const base: EngagementSnapshot = { engagement: "Fixture", authorizationExpires: "2099-01-01", armed: true, targets: 2, exclusions: 0, routes: 1, scanlensReady: true,
    pendingProposals: 0, openTasks: 0, discoveryRuns: 1, coverage: { total: 4, pending: 0, reviewed: 4, grouped: 0, waiting: 0, blocked: 0 } };
  assert.equal(findingsLabel(base), "Findings 0");
  assert.equal(findingsLabel({ findings: { suspected: 2, validated: 3, reported: 1 } }), "Findings 4✓ 2?");
  assert.equal(nextActions({ ...base, findings: { suspected: 2, validated: 1, reported: 0 } })[0].label, "Validate suspected findings");
  assert.deepEqual([nextActions({ ...base, findings: { suspected: 0, validated: 1, reported: 0 } })[0].command], ["/rt-report"]);
  assert.equal(workflowStages({ ...base, findings: { suspected: 1, validated: 0, reported: 0 } }).at(-1)!.mark, "current");
  assert.equal(workflowStages({ ...base, findings: { suspected: 0, validated: 1, reported: 0 } }).at(-1)!.mark, "done");
  assert.deepEqual(reportGaps({ affectedSystems: ["a"], evidence: ["b"], description: "c", risk: "", mitigation: "m", osstmmCategory: null, exploitability: 1, technicalImpact: 1, mitigationEffort: null } as never),
    ["risk", "OSSTMM category", "ratings"]);
});

test("exposure sources need their own approval, stay tied to scope, and become proposals", async t => {
  assert.deepEqual(parseArchiveUrls(JSON.stringify([["original"], ["http://a.test/x"], ["http://a.test/x"], [7]])), ["http://a.test/x"]);
  assert.deepEqual(parseArchiveUrls("<html>"), []);

  const archive = JSON.stringify([["original"],
    ["http://www.acme.fixture.test:80/old-admin/?token=abc"], ["https://www.acme.fixture.test/logo.png"], ["https://www.acme.fixture.test/"],
    ["https://secret.acme.fixture.test/hidden"], ["https://other.example/x"]]);
  const transport: Partial<Transport> = {
    get: async url => url.startsWith("https://web.archive.org/") ? { status: 200, headers: {}, body: archive }
      : url === "https://acme-backup.s3.amazonaws.com/" ? { status: 200, headers: {}, body: "<ListBucketResult><Contents><Key>db.sql</Key></Contents></ListBucketResult>" }
      : url === "https://acme.s3.amazonaws.com/" ? { status: 403, headers: {}, body: "" }
      : url.startsWith("https://api.github.com/") ? { status: 200, headers: {}, body: JSON.stringify({ total_count: 1, items: [{ path: "deploy/env.sh", html_url: "https://github.com/someone/infra/blob/main/deploy/env.sh", repository: { full_name: "someone/infra" } }] }) }
      : { status: 404, headers: {}, body: "" },
  };
  const blocked = harness(t, transport);
  await blocked.run("rt-discover", "on 100");
  for (const [params, pattern] of [
    [{ operation: "history", domain: "acme.fixture.test" }, /web\.archive\.org is not an approved passive source/],
    [{ operation: "cloud_storage", names: ["acme"] }, /No cloud storage provider is an approved passive source/],
    [{ operation: "code_mentions", domain: "acme.fixture.test" }, /api\.github\.com is not an approved passive source/],
  ] as const) assert.match((await blocked.tool("redteam_discover", params)).details.error, pattern);
  assert.equal(blocked.requests.length, 0, "nothing is sent to a source the operator did not approve");

  const { run, tool, requests } = harness(t, transport, ["web.archive.org", "s3.amazonaws.com", "api.github.com"]);
  await run("rt-discover", "on 100");
  assert.match((await tool("redteam_discover", { operation: "history", domain: "other.example" })).details.error, /other\.example is not in scope/);
  const history = await tool("redteam_discover", { operation: "history", domain: "*.acme.fixture.test" });
  assert.deepEqual(history.details.endpoints, ["http://www.acme.fixture.test/old-admin/"], "queries are dropped, static files and excluded hosts are skipped");
  assert.equal(history.details.proposed.endpoints, 1);
  assert.doesNotMatch(JSON.stringify(history.details), /token=abc|secret\.acme/);

  assert.match((await tool("redteam_discover", { operation: "cloud_storage", names: ["microsoft"] })).details.error, /must be labels taken from in-scope hostnames/);
  const storage = await tool("redteam_discover", { operation: "cloud_storage", names: ["acme"] });
  assert.deepEqual(storage.details.providers, ["s3"], "only approved providers are asked");
  assert.deepEqual(storage.details.found, [
    { provider: "s3", name: "acme", host: "acme.s3.amazonaws.com", state: "exists" },
    { provider: "s3", name: "acme-backup", host: "acme-backup.s3.amazonaws.com", state: "public-listing" },
  ]);
  assert.doesNotMatch(JSON.stringify(storage.details), /db\.sql/, "bucket contents are never returned");
  assert.equal(storage.details.proposed.hosts, 2);

  const code = await tool("redteam_discover", { operation: "code_mentions", domain: "acme.fixture.test" });
  assert.deepEqual(code.details.mentions, [{ repository: "someone/infra", path: "deploy/env.sh", url: "https://github.com/someone/infra/blob/main/deploy/env.sh" }]);
  assert.equal(requests.at(-1)!.headers?.Authorization, "Bearer fixture-token");
  assert.doesNotMatch(JSON.stringify(code.details), /fixture-token/);
  assert.equal(code.details.budget.used, 1 + 14 + 1);
  const proposals = (await tool("redteam_proposals", { operation: "list" })).details.entries as { host: string; configuredScope: string }[];
  assert.deepEqual(proposals.map(entry => [entry.host, entry.configuredScope]).sort(), [["acme-backup.s3.amazonaws.com", "unknown"], ["acme.s3.amazonaws.com", "unknown"]]);
  assert.ok(existsSync(join(blocked.cwd, "redteam.config.json")));
});
