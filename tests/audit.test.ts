import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";
import { AuditLog, redact } from "../extensions/audit.ts";

test("audit appends queryable events and verifies its hash chain", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-redteam-audit-"));
  const audit = new AuditLog(cwd, ".redteam/audit/audit.db");
  const scopeHash = audit.recordScope({
    engagement: "Test",
    authorizationExpires: "2030-01-01",
    included: ["10.0.0.1"],
    excluded: [],
    configHash: "sha256:test",
  });
  const first = audit.append({
    eventType: "tool_requested",
    sessionId: "session-1",
    actor: "agent",
    target: "10.0.0.1",
    tool: "bash",
    action: "nmap 10.0.0.1",
    status: "requested",
    scopeHash,
  });
  audit.append({
    eventType: "tool_completed",
    sessionId: "session-1",
    actor: "agent",
    target: "10.0.0.1",
    tool: "bash",
    status: "completed",
    scopeHash,
  });

  assert.equal(first, 1);
  const target = audit.query({ operation: "target", target: "10.0.0.1" }) as unknown[];
  assert.equal(target.length, 2);
  assert.deepEqual(audit.query({ operation: "verify" }), {
    valid: true,
    events: 2,
    finalHash: (target[0] as { eventHash: string }).eventHash,
  });
  const scopes = audit.query({ operation: "scope" }) as unknown[];
  assert.equal(scopes.length, 1);
  audit.close();
});

test("audit verification detects modified events", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-redteam-tamper-"));
  const dbPath = join(cwd, ".redteam", "audit", "audit.db");
  const audit = new AuditLog(cwd, dbPath);
  audit.append({ eventType: "session_started", sessionId: "s1", status: "started" });
  audit.close();
  const db = new DatabaseSync(dbPath);
  db.prepare("UPDATE audit_events SET payload_json = ? WHERE id = 1").run("{}");
  db.close();
  const reopened = new AuditLog(cwd, dbPath);
  const verification = reopened.query({ operation: "verify" }) as { valid: boolean; error: string };
  assert.equal(verification.valid, false);
  assert.match(verification.error, /invalid event hash/);
  reopened.close();
});

test("audit redacts common command secrets", () => {
  const value = redact("curl -H 'Authorization: Bearer abc123' --password hunter2 https://user:pass@example.test/");
  assert.doesNotMatch(value, /abc123|hunter2|:pass@/);
  assert.match(value, /\[REDACTED\]/);
});

test("audit identifies artifacts only inside a workspace root", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-redteam-artifact-"));
  const root = join(cwd, ".redteam", "tools");
  mkdirSync(root, { recursive: true });
  const path = join(root, "check.py");
  writeFileSync(path, "print('ok')\n");
  const audit = new AuditLog(cwd, ".redteam/audit/audit.db");
  const artifact = await audit.artifact(path, root);
  assert.equal(artifact?.path, "check.py");
  assert.equal(artifact?.size, 12);
  assert.equal(await audit.artifact(join(cwd, "outside.py"), root), undefined);
  audit.close();
});
