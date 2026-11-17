import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  authorizationError,
  isActiveNetworkCommand,
  loadTargetSources,
  matchesWebEndpoint,
  mentionsRawScan,
  normalizeWebEndpoint,
  obviousTargets,
  scopeDecision,
} from "../extensions/scope.ts";

test("scope supports exact hosts, wildcard domains, CIDRs, and exclusions", () => {
  const includes = ["10.20.0.0/24", "app.example.test", "*.lab.example.test"];
  assert.equal(scopeDecision("10.20.0.42", includes, []), "included");
  assert.equal(scopeDecision("https://app.example.test/login", includes, []), "included");
  assert.equal(scopeDecision("db.lab.example.test", includes, []), "included");
  assert.equal(scopeDecision("lab.example.test", includes, []), "unknown");
  assert.equal(scopeDecision("10.20.0.1", includes, ["10.20.0.1"]), "excluded");
  assert.equal(scopeDecision("10.21.0.1", includes, []), "unknown");
});

test("target sources read text inventory and refuse raw scans", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-redteam-"));
  mkdirSync(join(cwd, "targets"));
  writeFileSync(join(cwd, "targets", "scope.txt"), "# approved\n10.0.0.1\napp.example.test, 10.0.0.0/24\nhttps://App.Example.Test/health?full=1#section\nhttps://api.example.test/rest/v1/*\nhttps://user:secret@ignored.example.test/private\n");
  writeFileSync(join(cwd, "targets", "raw.nessus"), "do not read me");
  const result = loadTargetSources(cwd, ["targets"]);
  assert.deepEqual(result.targets.sort(), ["10.0.0.0/24", "10.0.0.1", "api.example.test", "app.example.test"]);
  assert.deepEqual(result.webEndpoints.sort(), [
    "https://api.example.test/rest/v1/*",
    "https://app.example.test/health",
  ]);
  assert.match(result.warnings.join("\n"), /refused raw scan file/);
  assert.match(result.warnings.join("\n"), /credential-bearing endpoint/);
});

test("web endpoint normalization accepts only credential-free HTTP(S) URLs", () => {
  assert.equal(normalizeWebEndpoint("https://APP.example.test/a/*#fragment"), "https://app.example.test/a/*");
  assert.equal(normalizeWebEndpoint("http://app.example.test"), "http://app.example.test/");
  assert.equal(normalizeWebEndpoint("ftp://app.example.test/file"), "");
  assert.equal(normalizeWebEndpoint("https://user:secret@app.example.test/private"), "");
  assert.equal(normalizeWebEndpoint("app.example.test/path"), "");
  assert.equal(matchesWebEndpoint("https://api.example.test/rest/v1/items/42?token=ignored", "https://api.example.test/rest/v1/*"), true);
  assert.equal(matchesWebEndpoint("https://other.example.test/rest/v1/items/42", "https://api.example.test/rest/v1/*"), false);
  assert.equal(matchesWebEndpoint("https://api.example.test/rest/v2/items/42", "https://api.example.test/rest/v1/*"), false);
});

test("authorization must be named, scoped, dated, and current", () => {
  const base = {
    engagement: "Lab",
    authorizationExpires: "2030-01-01",
    targets: [], excludeTargets: [], targetSources: [], scanlensDb: "scanlens.db",
    evidenceDir: ".redteam/evidence", toolsDir: ".redteam/tools", auditDb: ".redteam/audit/audit.db",
  };
  assert.equal(authorizationError(base, 1, new Date("2029-01-01T00:00:00Z")), undefined);
  assert.match(authorizationError(base, 0, new Date("2029-01-01T00:00:00Z"))!, /no targets/);
  assert.match(authorizationError(base, 1, new Date("2031-01-01T00:00:00Z"))!, /expired/);
});

test("guards recognize active tools and raw scan references", () => {
  assert.equal(isActiveNetworkCommand("nmap -sV 10.0.0.1"), true);
  assert.equal(isActiveNetworkCommand("sudo nmap -sV 10.0.0.1"), true);
  assert.equal(isActiveNetworkCommand("printf hello"), false);
  assert.equal(mentionsRawScan("cat scans/client.nessus"), true);
  assert.equal(mentionsRawScan("less scans/client.gnmap"), true);
  assert.equal(mentionsRawScan("scanlens summary --db scanlens.db"), false);
  assert.deepEqual(obviousTargets("nmap app.example.test"), ["app.example.test"]);
  assert.deepEqual(obviousTargets("ffuf -w /usr/share/wordlists/common.txt -u https://app.example.test/FUZZ"), ["app.example.test"]);
});
