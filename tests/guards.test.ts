import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { AuditLog, redact } from "../extensions/audit.ts";
import redteamExtension from "../extensions/redteam.ts";
import { obviousTargets, scopeDecision } from "../extensions/scope.ts";
import { isActiveNetworkCommand, networkReferences, referencesProtectedPath } from "../extensions/shell.ts";

test("IPv4 ranges honor exclusions and need full coverage by included addresses", () => {
  const included = ["10.20.0.0/24", "10.30.0.0/25", "10.30.0.128/25", "192.0.2.7"];
  const excluded = ["10.20.0.1"];
  const cases: Array<[string, ReturnType<typeof scopeDecision>]> = [
    ["10.20.0.0/24", "excluded"], // contains the excluded address
    ["10.20.0.*", "excluded"],
    ["10.20.0.0/23", "excluded"],
    ["10.20.0.128/25", "included"], // subnet of an included CIDR
    ["10.20.0.2-254", "included"],
    ["10.20.0.5,6", "included"],
    ["10.30.0.0/24", "included"], // covered by two adjacent included CIDRs
    ["192.0.2.7", "included"],
    ["192.0.2.7-8", "unknown"],
    ["10.21.0.0/24", "unknown"],
    ["999.1.1.1", "unknown"],
    ["10.*.*.*", "unknown"], // too broad to evaluate; fails closed
  ];
  for (const [target, expected] of cases) assert.equal(scopeDecision(target, included, excluded), expected, target);
});

test("target extraction sees ranges, bare host paths, UNC shares, IPv6, and non-HTTP URLs", () => {
  const cases: Array<[string, string[]]> = [
    ["nmap 10.0.0.1-254", ["10.0.0.1-254"]],
    ["nmap 10.0.0.*", ["10.0.0.*"]],
    ["nmap 10.0.0.1,2,3", ["10.0.0.1,2,3"]],
    ["nmap 10.0.0.0/25", ["10.0.0.0/25"]],
    ["curl https://in.scope.test/ evil.example/steal", ["in.scope.test", "evil.example"]],
    ["curl evil.example/admin", ["evil.example"]],
    ["smbclient //evil.example/share", ["evil.example"]],
    ["nmap -6 fe80::1 in.scope.test", ["fe80::1", "in.scope.test"]],
    ["curl http://ok.test@evil.example/", ["evil.example"]],
    ["curl ftp://files.example/x", ["files.example"]],
    ["ffuf -w /usr/share/wordlists/common.txt -u https://app.example.test/FUZZ", ["app.example.test"]],
  ];
  for (const [command, expected] of cases) assert.deepEqual(obviousTargets(command), expected, command);
});

test("active-command detection follows wrappers, shell structure, and a wider tool list", () => {
  const active = [
    "timeout 5 curl http://x.test", "sudo -n nmap 10.0.0.1", "sudo -u root nmap 10.0.0.1", "env A=1 curl x.test", "A=1 curl x.test",
    "time nmap 10.0.0.1", "xargs nmap < hosts", "echo hi\nnmap 10.0.0.1", "if true; then nmap 10.0.0.1; fi", "(nmap 10.0.0.1)",
    "echo $(curl x.test)", 'echo "$(curl x.test)"', "echo `curl x.test`", "bash -c 'nmap 10.0.0.1'", "/usr/bin/nmap 10.0.0.1",
    "ping 10.0.0.1", "ssh root@10.0.0.1", "dig x.test", "ncat 10.0.0.1 80", "socat - TCP:10.0.0.1:80", "telnet 10.0.0.1",
    "httpx -u x.test", "testssl.sh x.test", "echo > /dev/tcp/10.0.0.1/80", "openssl s_client -connect x.test:443",
  ];
  const inactive = [
    "printf hello", 'echo "curl is fun"', "grep -r curl tools/", "git commit -m 'add nmap wrapper'",
    "openssl x509 -in cert.pem", "ls | sort", "scanlens summary --db scanlens.db",
  ];
  for (const command of active) assert.equal(isActiveNetworkCommand(command), true, command);
  for (const command of inactive) assert.equal(isActiveNetworkCommand(command), false, command);
});

test("unrecognized commands expose their URLs and IP literals; local file utilities do not", () => {
  assert.deepEqual(networkReferences("python3 tools/probe.py https://app.test/x"), ["app.test"]);
  assert.deepEqual(networkReferences("T=10.0.0.9; ./scan.sh $T"), ["10.0.0.9"]);
  assert.deepEqual(networkReferences(`python3 -c "import socket; socket.create_connection(('10.9.9.9', 80))"`), ["10.9.9.9"]);
  assert.deepEqual(networkReferences("grep 10.0.0.5 notes.md"), []);
  assert.deepEqual(networkReferences("mkdir -p .redteam/evidence/10.0.0.5"), []);
});

test("audit path guard resists globs, directory changes, quoting, and parent deletion", () => {
  const guarded = (command: string) => referencesProtectedPath(command, "/work", ".redteam/audit/audit.db");
  for (const command of [
    "sqlite3 .redteam/audit/audit.db", "cd .redteam && sqlite3 aud*/audit.db", "cd .redteam && cd audit && rm *",
    "cat .redteam/./audit/x", "cat .red'team'/audit/x", "ls .redteam/a*", "rm -rf .redteam", "rm -rf .red*",
    "mv .redteam /tmp/x", "tar czf x.tgz -C .redteam audit", "find . -name '*.py' -delete",
  ]) assert.equal(guarded(command), true, command);
  for (const command of [
    "ls .redteam/evidence", "cat .redteam/evidence/notes.md", "rm .redteam/evidence/old.txt", "npm audit",
    "rm tmp/*", "find . -name '*.py'", "ls -la",
  ]) assert.equal(guarded(command), false, command);
});

test("redaction covers credential flags, header schemes, and secret-named variables without eating ports", () => {
  const secrets: Array<[string, string]> = [
    ["curl -u admin:hunter2 https://x.test", "hunter2"],
    ["nxc smb 10.0.0.1 -u bob -p 'Passw0rd!' --shares", "Passw0rd!"],
    ["nxc smb 10.0.0.1 -u bob -H aad3b435:31d6cfe0", "31d6cfe0"],
    ["sshpass -p hunter2 ssh a@b", "hunter2"],
    ["mysql -phunter2 -h db", "hunter2"],
    ["smbclient //h/s -U bob%hunter2", "hunter2"],
    ["secretsdump.py corp/admin:S3cret@10.0.0.1", "S3cret"],
    ["impacket-psexec -hashes aad3:31d6 a@b", "31d6"],
    ["curl -H 'Authorization: Token abc123'", "abc123"],
    ["export AWS_SECRET_ACCESS_KEY=abc123", "abc123"],
    [`{"password": "hunter2", "user": "bob"}`, "hunter2"],
  ];
  for (const [text, secret] of secrets) {
    assert.ok(!redact(text).includes(secret), text);
    assert.match(redact(text), /\[REDACTED\]/, text);
  }
  for (const text of ["nmap -p 80,443 10.0.0.1", "ssh -p 2222 a@b", "hydra -l admin -P wordlist.txt"]) assert.equal(redact(text), text);
});

function harness(t: { after(fn: () => void): void }, config: Record<string, unknown> = {}) {
  const cwd = mkdtempSync(join(tmpdir(), "pi-guards-"));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  writeFileSync(join(cwd, "redteam.config.json"), JSON.stringify({
    engagement: "Fixture", authorizationExpires: "2099-01-01", targets: ["10.20.0.0/24", "app.fixture.test"],
    excludeTargets: ["10.20.0.1"], targetSources: [], ...config,
  }));
  const hooks = new Map<string, (...args: any[]) => Promise<any>>();
  const commands = new Map<string, { handler: (...args: any[]) => Promise<any> }>();
  redteamExtension({
    registerCommand: (name: string, command: { handler: (...args: any[]) => Promise<any> }) => commands.set(name, command),
    registerTool: () => {},
    on: (event: string, hook: (...args: any[]) => Promise<any>) => hooks.set(event, hook),
  } as unknown as ExtensionAPI);
  const prompts: string[] = [];
  const state = { answer: false };
  const ctx = {
    cwd, hasUI: true, sessionManager: { getSessionId: () => "session-test" },
    ui: {
      confirm: async (title: string) => { prompts.push(title); return state.answer; },
      notify() {}, setStatus() {},
    },
  };
  t.after(() => { void hooks.get("session_shutdown")!({ reason: "test" }, ctx); });
  let id = 0;
  const call = (toolName: string, input: Record<string, unknown>) => {
    const event = { type: "tool_call", toolName, toolCallId: `call-${++id}`, input };
    return hooks.get("tool_call")!(event, ctx).then((result) => ({ result, event }));
  };
  const bash = (command: string) => call("bash", { command }).then(({ result }) => result as { block?: boolean; reason?: string } | undefined);
  return { cwd, ctx, hooks, commands, prompts, state, call, bash };
}

test("bash guard blocks excluded ranges, unknown targets, and wrapped tools, even when armed", async t => {
  const { bash, commands, ctx, state, prompts } = harness(t);
  state.answer = true;
  await commands.get("rt-arm")!.handler("", ctx);
  prompts.length = 0;

  assert.match((await bash("nmap 10.20.0.0/24"))!.reason!, /10\.20\.0\.0\/24 is excluded/);
  assert.match((await bash("nmap 10.20.0.1-50"))!.reason!, /excluded/);
  assert.match((await bash("timeout 5 curl https://app.fixture.test/ evil.example/steal"))!.reason!, /evil\.example is unknown/);
  assert.match((await bash("echo ok\nnmap 10.21.0.5"))!.reason!, /10\.21\.0\.5 is unknown/);
  assert.match((await bash("python3 tools/probe.py http://10.20.0.1/"))!.reason!, /excluded/);
  assert.equal(await bash("nmap 10.20.0.128/25"), undefined);
  assert.equal(await bash("sudo -n nmap 10.20.0.2-254"), undefined);
  assert.equal(await bash("python3 tools/probe.py https://app.fixture.test/health"), undefined);
  assert.equal(await bash("grep 10.20.0.1 notes.md"), undefined);
  assert.equal(await bash("python3 -m http.server --bind 127.0.0.1"), undefined);
  assert.deepEqual(prompts, [], "armed in-scope commands and local commands do not prompt");
});

test("commands naming out-of-scope hosts need operator approval that arming does not grant", async t => {
  const { bash, commands, ctx, state, prompts } = harness(t);
  state.answer = true;
  await commands.get("rt-arm")!.handler("", ctx);
  prompts.length = 0;

  state.answer = false;
  assert.match((await bash("git clone https://github.com/example/tool .redteam/tools/tool"))!.reason!, /denied by the operator/);
  state.answer = true;
  assert.equal(await bash("git clone https://github.com/example/tool .redteam/tools/tool"), undefined);
  assert.deepEqual(prompts, ["Allow command naming hosts outside scope?", "Allow command naming hosts outside scope?"]);

  (ctx as { hasUI: boolean }).hasUI = false;
  assert.match((await bash("python3 fetch.py https://other.example/x"))!.reason!, /no operator UI/);
});

test("file tools cannot reach the audit directory or raw scan files", async t => {
  const { call, bash } = harness(t);
  for (const tool of ["read", "grep", "find", "ls"]) {
    const { result } = await call(tool, { path: ".redteam/audit", pattern: "x" });
    assert.match(result.reason, /append-only/, tool);
  }
  assert.match((await call("grep", { pattern: "x", path: "scan.nessus" })).result.reason, /Raw scan files/);
  assert.match((await call("grep", { pattern: "x", glob: "*.nessus" })).result.reason, /Search globs/);
  assert.match((await call("grep", { pattern: "x", glob: "scans/*" })).result.reason, /Search globs/);
  assert.equal((await call("grep", { pattern: "x", glob: "*.{ts,md}" })).result, undefined);
  const open = await call("grep", { pattern: "x" });
  assert.equal(open.result, undefined);
  assert.equal(open.event.input.glob, "!*.{nessus,nmap,gnmap,xml}");
  assert.match((await bash("cd .redteam && sqlite3 aud*/audit.db .dump"))!.reason!, /append-only/);
  assert.match((await bash("rm -rf .redteam"))!.reason!, /append-only/);
});

test("evidence written or removed by a shell command is hashed into the audit trail", async t => {
  const { cwd, ctx, hooks } = harness(t);
  const evidence = join(cwd, ".redteam", "evidence");
  mkdirSync(evidence, { recursive: true });
  writeFileSync(join(evidence, "old.txt"), "old");
  const run = async (id: string, effect: () => void) => {
    await hooks.get("tool_execution_start")!({ toolName: "bash", toolCallId: id, args: { command: "true" } }, ctx);
    effect();
    await hooks.get("tool_execution_end")!({ toolName: "bash", toolCallId: id, result: {}, isError: false, durationMs: 1 }, ctx);
  };
  await run("a", () => writeFileSync(join(evidence, "scan.txt"), "open ports"));
  await run("b", () => rmSync(join(evidence, "old.txt")));
  await hooks.get("session_shutdown")!({ reason: "test" }, ctx);

  const audit = new AuditLog(cwd, ".redteam/audit/audit.db");
  t.after(() => audit.close());
  const artifacts = audit.query({ operation: "artifacts" }) as Array<{ eventType: string; evidencePath: string; contentHash: string | null; toolCallId: string }>;
  assert.deepEqual(artifacts.map(item => [item.eventType, item.evidencePath, item.toolCallId]).reverse(), [
    ["artifact_modified", join(".redteam", "evidence", "scan.txt"), "a"],
    ["artifact_removed", join(".redteam", "evidence", "old.txt"), "b"],
  ]);
  assert.match(artifacts.at(-1)!.contentHash!, /^sha256:[0-9a-f]{64}$/);
  assert.equal(audit.verify().valid, true);
});
