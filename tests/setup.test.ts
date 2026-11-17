import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, existsSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setupConfig, validScopeRule } from "../extensions/setup.ts";
import { authorizationError, loadConfig, loadTargetSources } from "../extensions/scope.ts";

type SetupContext = Parameters<typeof setupConfig>[0];
function fixture(t: test.TestContext, inputs: (string | undefined)[], confirms = [true, true], hasUI = true) {
  const cwd = mkdtempSync(join(tmpdir(), "pi-setup-"));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  const notices: string[] = [];
  const titles: string[] = [];
  const ctx = { cwd, hasUI, ui: {
    input: async (title: string) => { titles.push(title); assert.ok(inputs.length, `Unexpected question: ${title}`); return inputs.shift(); },
    confirm: async (title: string) => { titles.push(title); assert.ok(confirms.length); return confirms.shift(); },
    notify: (text: string) => { notices.push(text); },
  } } as unknown as SetupContext;
  return { ctx, notices, titles, path: join(cwd, "redteam.config.json") };
}
const answers = () => ["Customer authorization ABC-123", "2099-12-31", "192.0.2.0/24", "192.0.2.1", "-", "", "", "", ""];

test("setup gathers reviewed config, uses path defaults, and warns about missing DB", async (t) => {
  const f = fixture(t, answers());
  assert.equal(await setupConfig(f.ctx), true);
  const result = loadConfig(f.ctx.cwd);
  assert.equal(result.error, undefined);
  assert.equal(authorizationError(result.config, 1), undefined);
  assert.deepEqual(result.config.targetSources, []);
  assert.deepEqual(result.config.excludeTargets, ["192.0.2.1"]);
  assert.equal(result.config.scanlensDb, "scanlens.db");
  assert.ok(f.notices.some((text) => text.includes("Database not found")));
  assert.ok(f.notices.some((text) => text.includes("remain disarmed")));
});

test("setup saves an empty default inventory, then picks up targets added later", async (t) => {
  const f = fixture(t, ["Assessment", "2099-12-31", "", "", "", "", "", "", ""]);
  assert.equal(await setupConfig(f.ctx), true);
  const { config } = loadConfig(f.ctx.cwd);
  assert.deepEqual(config.targetSources, ["targets"]);
  assert.equal(existsSync(join(f.ctx.cwd, "targets")), true);
  assert.equal(authorizationError(config, 0), "scope has no targets");
  assert.ok(f.notices.some((text) => text.includes("Authorization stays INVALID")));
  writeFileSync(join(f.ctx.cwd, "targets", "approved.txt"), "192.0.2.42\n");
  const inventory = loadTargetSources(f.ctx.cwd, config.targetSources);
  assert.deepEqual(inventory.targets, ["192.0.2.42"]);
  assert.equal(authorizationError(config, inventory.targets.length), undefined);
});

test("empty custom inventory path can be saved without creating or reading raw scans", async (t) => {
  const f = fixture(t, ["Assessment", "2099-12-31", "", "", "approved-inventory", "", "", "", ""]);
  assert.equal(await setupConfig(f.ctx), true);
  assert.deepEqual(loadConfig(f.ctx.cwd).config.targetSources, ["approved-inventory"]);
  assert.equal(existsSync(join(f.ctx.cwd, "approved-inventory")), false);
  assert.ok(f.notices.some((text) => text.includes("target source not found")));
});

test("example copies are invalid even when unexpired, and wizard removes sample scope", async (t) => {
  const f = fixture(t, answers());
  const example = JSON.parse(readFileSync(new URL("../redteam.config.example.json", import.meta.url), "utf8"));
  example.authorizationExpires = "2099-12-31";
  writeFileSync(f.path, JSON.stringify(example));
  assert.match(authorizationError(loadConfig(f.ctx.cwd).config, 3)!, /example/);
  assert.equal(await setupConfig(f.ctx), true);
  assert.deepEqual(loadConfig(f.ctx.cwd).config.targets, ["192.0.2.0/24"]);
});

test("cancellation at a question or final review never writes", async (t) => {
  const missing = fixture(t, [undefined]);
  assert.equal(await setupConfig(missing.ctx), false);
  assert.equal(existsSync(missing.path), false);
  const existing = fixture(t, answers(), [true, false]);
  writeFileSync(existing.path, "{}");
  assert.equal(await setupConfig(existing.ctx), false);
  assert.equal(readFileSync(existing.path, "utf8"), "{}");
});

test("noninteractive setup does not prompt or write", async (t) => {
  const f = fixture(t, [], [], false);
  assert.equal(await setupConfig(f.ctx), false);
  assert.equal(existsSync(f.path), false);
  assert.match(f.notices[0], /interactive UI/);
});

test("wizard retries invalid dates and scope rules", async (t) => {
  const f = fixture(t, ["Assessment", "2099-02-30", "2000-01-01", "2099-12-31", "https://invalid.test/path", "192.0.2.2", "", "", "", "", "", ""]);
  assert.equal(await setupConfig(f.ctx), true);
  assert.ok(f.notices.some((text) => text.includes("invalid")));
  assert.ok(f.notices.some((text) => text.includes("expired")));
  assert.ok(f.notices.some((text) => text.includes("no URLs")));
});

test("scope syntax validation is local and bounded to supported syntax", () => {
  for (const rule of ["192.0.2.1", "192.0.2.0/24", "::1", "server.internal", "*.internal.test"]) assert.equal(validScopeRule(rule), true, rule);
  for (const rule of ["192.0.2.0/33", "999.2.3.4", "::1/64", "host:443", "https://host.test", "*", "-bad.test"]) assert.equal(validScopeRule(rule), false, rule);
});

test("malformed field types fail closed instead of crashing later", (t) => {
  const f = fixture(t, []);
  for (const value of [null, [], { engagement: 42 }, { targets: "192.0.2.2" }, { auditDb: false }]) {
    writeFileSync(f.path, JSON.stringify(value));
    assert.match(loadConfig(f.ctx.cwd).error!, /invalid configuration/);
  }
});
