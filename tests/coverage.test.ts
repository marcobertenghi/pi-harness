import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { AuditLog } from "../extensions/audit.ts";
import type { CoverageScope, Review } from "../extensions/coverage.ts";
import { loadScanInventory, scanInventory } from "../extensions/coverage-inventory.ts";

const route = "https://web.example.test/one";
const peer = "https://web.example.test/two";
const wildcard = "https://web.example.test/family/*";
const excluded = "https://excluded.example.test/route";
const scope: CoverageScope = { key: "engagement-a", endpoints: [route, peer, wildcard, excluded], targets: ["*.example.test"], exclusions: ["excluded.example.test"] };
const observed: Review = { state: "reviewed", outcome: "observed", claim: "Authentication challenge returned", evidence: [{ source: "Operator capture 1", observation: "HTTP 401" }] };

function fixture(t: { after(callback: () => void): void }) {
  const dir = mkdtempSync(join(tmpdir(), "pi-coverage-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return () => new AuditLog(dir, "audit.db");
}

test("coverage persists across sessions, includes unseen routes, and isolates engagements", t => {
  const open = fixture(t);
  const audit = open();
  assert.equal(audit.coverage.view(scope).counts.pending, 3);
  assert.equal(audit.coverage.view(scope).counts.blocked, 1);
  audit.coverage.record(scope, { endpoint: `${route}?token=discarded` }, observed);
  audit.coverage.record(scope, { host: "web.example.test", port: 443, transport: "tcp" }, {
    ...observed, outcome: "advisory_candidate", missingFact: "Affected build cannot be identified from the banner",
  });
  audit.close();

  const reopened = open();
  t.after(() => reopened.close());
  const view = reopened.coverage.view(scope, { state: "reviewed", limit: 1 });
  assert.equal(view.counts.reviewed, 2);
  assert.equal(view.nextOffset, 1);
  assert.equal(JSON.stringify(view).includes("discarded"), false);
  assert.equal(reopened.coverage.view(scope, { outcome: "advisory_candidate" }).matched, 1);
  assert.equal(reopened.coverage.view({ ...scope, key: "engagement-b" }).counts.reviewed, 0);
  assert.equal(reopened.coverage.view({ ...scope, endpoints: [peer] }).total, 2);
});

test("grouping requires a recorded representative and becomes pending when evidence no longer qualifies", t => {
  const audit = fixture(t)();
  t.after(() => audit.close());
  const store = audit.coverage;
  const group: Review = { state: "grouped", claim: "Same application and auth boundary", representative: route, evidence: observed.evidence };
  assert.throws(() => store.record(scope, { endpoint: peer }, group), /representative/);
  store.record(scope, { endpoint: route }, observed);
  store.record(scope, { endpoint: peer }, group);
  assert.equal(store.view(scope).counts.grouped, 1);
  const changedScope = { ...scope, endpoints: [peer] };
  assert.equal(store.view(changedScope).counts.pending, 1);
  store.record(scope, { endpoint: route }, { ...observed, outcome: "unresolved_from_outside", missingFact: "Application ownership" });
  assert.equal(store.view(scope).counts.grouped, 0);
});

test("coverage cannot expand wildcard paths, ignore exclusions, or mark unsupported conclusions", t => {
  const audit = fixture(t)();
  t.after(() => audit.close());
  const store = audit.coverage;
  assert.throws(() => store.record(scope, { endpoint: wildcard.replace("*", "new") }, observed), /configured/);
  assert.throws(() => store.record(scope, { endpoint: wildcard }, observed), /wildcard/);
  assert.throws(() => store.record(scope, { endpoint: excluded }, observed), /scope/);
  assert.throws(() => store.record(scope, { endpoint: route }, { ...observed, evidence: [] }), /sourced/);
  assert.throws(() => store.record(scope, { endpoint: route }, { ...observed, outcome: "unresolved_from_outside" }), /missing fact/);
});

test("reconciliation counts untouched services and keeps gateway evidence separate", t => {
  const audit = fixture(t)();
  t.after(() => audit.close());
  const store = audit.coverage;
  const current = { ...scope, targets: [...scope.targets, "192.0.2.0/24"], exclusions: [...scope.exclusions, "192.0.2.9"] };
  const raw = JSON.stringify([
    { ip: "192.0.2.1", hostname: "web.example.test", port: 443, protocol: "tcp" },
    { ip: "192.0.2.1", hostname: null, port: 443, protocol: "tcp" },
    { ip: "198.51.100.2", hostname: "web.example.test", port: 53, protocol: "udp" },
    { ip: "192.0.2.5", hostname: "excluded.example.test", port: 443, protocol: "tcp" },
    { ip: "192.0.2.9", hostname: "web.example.test", port: 443, protocol: "tcp" },
    { ip: "198.51.100.3", hostname: "unrelated.test", port: 443, protocol: "tcp" },
    { ip: "https://invalid.test", port: 443, protocol: "tcp" },
  ]);
  const scanned = scanInventory(raw, current);
  assert.deepEqual(scanned, { services: [
    { host: "192.0.2.1", port: 443, transport: "tcp" },
    { host: "web.example.test", port: 53, transport: "udp" },
  ], truncated: false, invalidRows: 1 });
  store.record(current, scanned.services[0], { ...observed, layer: "gateway_only" });
  const view = store.view(current, { scanned: scanned.services, state: "pending", scanlensOnly: true });
  assert.equal(view.scannedCounts?.reviewed, 1);
  assert.equal(view.scannedCounts?.pending, 1);
  assert.deepEqual(view.entries.map(entry => entry.subject), [scanned.services[1]]);
  assert.equal(store.view(current, { layer: "gateway_only" }).matched, 1);
  assert.equal(store.view(current).total, current.endpoints.length + 1, "reconciliation did not persist seeded services");
});

test("inventory flags truncation", () => {
  const row = { ip: "192.0.2.1", hostname: "web.example.test", port: 443, protocol: "tcp" };
  assert.equal(scanInventory(JSON.stringify(Array(20_001).fill(row)), scope).truncated, true);
});

test("fixed Scanlens query reads only open supported services from a synthetic database", async t => {
  if (spawnSync("scanlens", ["--version"]).status !== 0) { t.skip("Scanlens not installed"); return; }
  const dir = mkdtempSync(join(tmpdir(), "pi-scanlens-inventory-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const db = new DatabaseSync(join(dir, "scans.db"));
  db.exec(`CREATE TABLE v_services(ip TEXT, hostname TEXT, port INTEGER, protocol TEXT, state TEXT);
    INSERT INTO v_services VALUES ('192.0.2.1', 'web.example.test', 443, 'TCP', 'open'),
    ('192.0.2.1', 'web.example.test', 22, 'tcp', 'closed'), ('192.0.2.1', 'web.example.test', 0, 'tcp', 'open');`);
  db.close();
  const result = await loadScanInventory(dir, "scans.db", scope);
  assert.deepEqual(result.services, [{ host: "web.example.test", port: 443, transport: "tcp" }]);
  await assert.rejects(loadScanInventory(dir, "missing.db", scope), /missing/);
});
