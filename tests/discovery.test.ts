import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { AuditLog } from "../extensions/audit.ts";
import { Budget, discoverSubdomains, discoverVirtualHosts, parseCertificateNames, parseOpenApi, parseRobots, parseSitemap, type DiscoveryContext, type Transport } from "../extensions/discovery.ts";
import redteamExtension from "../extensions/redteam.ts";

test("self-description parsers extract routes and ignore wildcards and junk", () => {
  assert.deepEqual(parseRobots("User-agent: *\nDisallow: /admin/ # private\nAllow: /api/v1\nDisallow: /\nDisallow: /*.pdf$\nSitemap: https://a.test/sitemap-main.xml\n"),
    { paths: ["/admin/", "/api/v1"], sitemaps: ["https://a.test/sitemap-main.xml"] });
  assert.deepEqual(parseSitemap("<urlset><url><loc>https://a.test/x?a=1&amp;b=2</loc></url><url><loc> https://a.test/y </loc></url></urlset>"),
    ["https://a.test/x?a=1&b=2", "https://a.test/y"]);
  assert.deepEqual(parseOpenApi(JSON.stringify({ basePath: "/api", paths: { "/users": {}, "/users/{id}": {}, "x-internal": {} } })), ["/api/users", "/api/users/{id}"]);
  assert.deepEqual(parseOpenApi("<html>not json</html>"), []);
  assert.deepEqual(parseCertificateNames(JSON.stringify([{ name_value: "*.lab.a.test\nwww.a.test", common_name: "A.test" }, { name_value: "bad_name!" }])),
    ["a.test", "lab.a.test", "www.a.test"]);
});

function context(transport: Partial<Transport>, limit = 500, targets = ["*.lab.fixture.test", "app.fixture.test"]): DiscoveryContext {
  return {
    transport: { get: async () => ({ status: 404, headers: {}, body: "" }), resolve: async () => [], ...transport },
    budget: new Budget(limit), delayMs: 0, targets, exclusions: ["secret.lab.fixture.test"], passiveSources: [],
  };
}

test("subdomain discovery stays inside the wildcard, skips exclusions, and discounts wildcard DNS", async () => {
  const asked: string[] = [];
  const found = await discoverSubdomains(context({
    resolve: async name => { asked.push(name); return name.startsWith("api.") || name.startsWith("extra.") ? ["10.0.0.5"] : []; },
  }), "*.lab.fixture.test", ["extra", "secret", "bad label"]);
  assert.deepEqual(found.found.map(item => item.host), ["api.lab.fixture.test", "extra.lab.fixture.test"]);
  assert.ok(asked.every(name => name.endsWith(".lab.fixture.test")) && !asked.includes("secret.lab.fixture.test"));
  assert.equal(found.wildcardDns, undefined);

  const catchAll = await discoverSubdomains(context({ resolve: async () => ["10.9.9.9"] }), "lab.fixture.test");
  assert.deepEqual(catchAll.wildcardDns, ["10.9.9.9"]);
  assert.deepEqual(catchAll.found, [], "names that only match the catch-all answer are not reported");

  await assert.rejects(discoverSubdomains(context({}), "other.test"), /No name under other\.test is in scope/);
  const limited = await discoverSubdomains(context({}, 4), "lab.fixture.test");
  assert.match(limited.stopped!, /budget of 4/);
  assert.ok(limited.tested <= 3);
});

test("virtual-host checks use only in-scope names and report answers that differ from the baseline", async () => {
  const transport: Partial<Transport> = {
    get: async (_url, options) => options.host === "api.lab.fixture.test"
      ? { status: 200, headers: {}, body: "<title>Internal API</title>" } : { status: 404, headers: {}, body: "<title>Not found</title>" },
  };
  const result = await discoverVirtualHosts(context(transport), "https://app.fixture.test", ["api.lab.fixture.test", "www.lab.fixture.test"]);
  assert.deepEqual(result.distinct.map(item => item.host), ["api.lab.fixture.test"]);
  assert.deepEqual(result.same, ["www.lab.fixture.test"]);
  await assert.rejects(discoverVirtualHosts(context(transport), "https://app.fixture.test", ["evil.example"]), /Not in scope: evil\.example/);
  await assert.rejects(discoverVirtualHosts(context(transport), "https://evil.example", ["api.lab.fixture.test"]), /not in scope/);
});

function harness(t: { after(fn: () => void): void }) {
  const cwd = mkdtempSync(join(tmpdir(), "pi-discovery-"));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  const configPath = join(cwd, "redteam.config.json");
  writeFileSync(configPath, JSON.stringify({
    engagement: "Fixture", authorizationExpires: "2099-01-01", targets: ["app.fixture.test", "*.lab.fixture.test"], excludeTargets: [], targetSources: [],
  }));
  const requests: string[] = [];
  const pages: Record<string, string> = {
    "https://app.fixture.test/robots.txt": "Disallow: /admin/\nSitemap: https://app.fixture.test/sitemap-extra.xml\n",
    "https://app.fixture.test/sitemap.xml": "<loc>https://app.fixture.test/pricing</loc><loc>https://partner.example/landing</loc>",
    "https://app.fixture.test/sitemap-extra.xml": "<loc>https://app.fixture.test/blog/first</loc>",
    "https://app.fixture.test/openapi.json": JSON.stringify({ paths: { "/api/users": {} } }),
    "https://crt.sh/?q=%25.lab.fixture.test&output=json": JSON.stringify([{ name_value: "git.lab.fixture.test\nlab.fixture.test" }]),
  };
  const transport: Transport = {
    get: async url => { requests.push(url); return pages[url] ? { status: 200, headers: {}, body: pages[url] } : { status: 404, headers: {}, body: "" }; },
    resolve: async name => name === "api.lab.fixture.test" ? ["10.0.0.5"] : [],
  };
  const hooks = new Map<string, (...args: any[]) => Promise<any>>();
  const commands = new Map<string, { handler: (...args: any[]) => Promise<any> }>();
  const tools = new Map<string, (...args: any[]) => Promise<any>>();
  redteamExtension({
    registerCommand: (name: string, command: { handler: (...args: any[]) => Promise<any> }) => commands.set(name, command),
    registerTool: (tool: { name: string; execute: (...args: any[]) => Promise<any> }) => tools.set(tool.name, tool.execute),
    on: (event: string, hook: (...args: any[]) => Promise<any>) => hooks.set(event, hook),
  } as unknown as ExtensionAPI, { transport, discoveryDelayMs: 0 });
  const ui = { answer: true, notices: [] as string[], prompts: [] as string[], widget: [] as string[] };
  const ctx = {
    cwd, hasUI: true, sessionManager: { getSessionId: () => "session-test" },
    ui: {
      confirm: async (title: string) => { ui.prompts.push(title); return ui.answer; },
      select: async () => undefined, notify: (text: string) => { ui.notices.push(text); }, setStatus() {},
      setWidget: (_key: string, lines: string[]) => { ui.widget = lines; },
    },
  };
  t.after(() => { void hooks.get("session_shutdown")!({ reason: "test" }, ctx); });
  const run = (name: string, args = "") => commands.get(name)!.handler(args, ctx);
  const tool = async (name: string, params: Record<string, unknown>) => (await tools.get(name)!("id", params, undefined, undefined, ctx)) as { details: any; isError?: boolean };
  let id = 0;
  const bash = (command: string) => hooks.get("tool_call")!({ type: "tool_call", toolName: "bash", toolCallId: `c${++id}`, input: { command } }, ctx) as Promise<{ reason?: string } | undefined>;
  const config = () => JSON.parse(readFileSync(configPath, "utf8")) as { webEndpoints?: string[]; passiveSources?: string[]; targets: string[] };
  return { cwd, ctx, ui, run, tool, bash, config, requests, hooks };
}

test("discovery needs operator arming, records findings as proposals, and accepted routes become coverage", async t => {
  const { run, tool, ui, config, requests, cwd, hooks, ctx } = harness(t);
  const refused = await tool("redteam_discover", { operation: "well_known", origin: "https://app.fixture.test" });
  assert.equal(refused.isError, true);
  assert.match(refused.details.error, /Discovery mode is off/);
  assert.equal(requests.length, 0);

  await run("rt-discover", "on 40");
  assert.match(ui.notices.at(-1)!, /◆ Discovery mode on with a budget of 40/);
  assert.match(ui.widget[0], /◆ discovery 40\/40/);

  const outside = await tool("redteam_discover", { operation: "well_known", origin: "https://partner.example" });
  assert.match(outside.details.error, /partner\.example is not in scope/);
  assert.equal(requests.length, 0, "an out-of-scope origin is never contacted");

  const found = await tool("redteam_discover", { operation: "well_known", origin: "https://app.fixture.test/login" });
  assert.deepEqual(found.details.endpoints, [
    "https://app.fixture.test/admin/", "https://app.fixture.test/api/users", "https://app.fixture.test/blog/first",
    "https://app.fixture.test/openapi.json", "https://app.fixture.test/pricing",
  ]);
  assert.deepEqual(found.details.otherHosts, ["partner.example"]);
  assert.deepEqual(found.details.proposed.hosts, 1);
  assert.deepEqual(found.details.proposed.endpoints, 5);
  assert.equal(found.details.budget.used, 11, "ten well-known files plus one sitemap from robots.txt");
  assert.ok(requests.every(url => url.startsWith("https://app.fixture.test/")));

  const names = await tool("redteam_discover", { operation: "subdomains", domain: "lab.fixture.test" });
  assert.deepEqual(names.details.found.map((item: { host: string }) => item.host), ["api.lab.fixture.test"]);
  assert.equal(names.details.budget.remaining, 0, "the wordlist is larger than what was left of the budget");
  assert.match(names.details.stopped, /budget of 40/);
  assert.match((await tool("redteam_discover", { operation: "status" })).details.discoveryMode, /off/, "an exhausted budget turns discovery off");

  await run("rt-endpoints");
  await run("rt-tasks");
  assert.match(ui.notices.at(-1)!, /! 5 discovered route\(s\) to decide → \/rt-endpoints/);
  await run("rt-endpoints", "reject https://app.fixture.test/pricing");
  await run("rt-endpoints", "accept all");
  assert.deepEqual(config().webEndpoints?.length, 4);
  assert.match(ui.notices.at(-1)!, /✓ 4 route\(s\) accepted/);
  assert.deepEqual(config().targets, ["app.fixture.test", "*.lab.fixture.test"], "accepting routes never changes host scope");
  const coverage = await tool("redteam_coverage", { operation: "list", state: "pending" });
  assert.equal(coverage.details.matched, 4);
  const hosts = (await tool("redteam_proposals", { operation: "list" })).details.entries as { host: string; configuredScope: string }[];
  assert.deepEqual(hosts.map(entry => [entry.host, entry.configuredScope]).sort(), [["api.lab.fixture.test", "included"], ["partner.example", "unknown"]]);

  await hooks.get("session_shutdown")!({ reason: "test" }, ctx);
  const audit = new AuditLog(cwd, ".redteam/audit/audit.db");
  t.after(() => audit.close());
  assert.equal(audit.countEvents("discovery_run"), 3);
  assert.equal(audit.countEvents("endpoint_proposals_accepted"), 1);
  assert.equal(audit.verify().valid, true);
});

test("passive sources need operator approval; discovery mode then covers them within the budget", async t => {
  const { run, tool, bash, ui, config } = harness(t);
  const lookup = "curl -s 'https://crt.sh/?q=%25.lab.fixture.test&output=json'";
  assert.match((await bash(lookup))!.reason!, /crt\.sh is unknown/);
  await run("rt-discover", "on 5");
  assert.match((await tool("redteam_discover", { operation: "certificates", domain: "lab.fixture.test" })).details.error, /not an approved passive source/);

  await run("rt-discover", "allow crt.sh");
  assert.deepEqual(config().passiveSources, ["crt.sh"]);
  ui.prompts.length = 0;
  ui.answer = false;
  assert.match((await bash(lookup))!.reason!, /denied by operator/);
  assert.deepEqual(ui.prompts, ["Allow one passive lookup?"], "approving a source disarms discovery, so the lookup asks");

  ui.answer = true;
  await run("rt-discover", "on 3");
  ui.prompts.length = 0;
  assert.equal(await bash(lookup), undefined);
  assert.deepEqual(ui.prompts, [], "discovery mode covers approved passive sources");
  const names = await tool("redteam_discover", { operation: "certificates", domain: "*.lab.fixture.test" });
  assert.deepEqual(names.details.inScope, ["git.lab.fixture.test"]);
  assert.deepEqual(names.details.outsideScope, ["lab.fixture.test"]);
  assert.equal(names.details.budget.used, 2, "the shell lookup and the tool lookup share one budget");
  assert.match((await bash("curl https://crt.sh/ https://evil.example/"))!.reason!, /evil\.example is unknown/);
});

test("the agent can propose routes only on hosts that are already in scope", async t => {
  const { tool } = harness(t);
  const record = (endpoint: string) => tool("redteam_proposals", { operation: "record_endpoint", endpoint, source: "login page link", reason: "linked admin console" });
  assert.equal((await record("https://app.fixture.test/console?token=abc#x")).details.endpoint, "https://app.fixture.test/console");
  assert.equal((await record("https://app.fixture.test/console")).details.recorded, false);
  await assert.rejects(record("https://evil.example/console"), /not in scope/);
  await assert.rejects(record("https://app.fixture.test/files/*"), /without credentials or wildcards/);
  assert.equal((await tool("redteam_proposals", { operation: "list_endpoints" })).details.entries.length, 1);
});
