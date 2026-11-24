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
    "trufflehog github --org=someorg", "trufflehog git https://github.com/a/b",
    "httpx -u x.test", "testssl.sh x.test", "echo > /dev/tcp/10.0.0.1/80", "openssl s_client -connect x.test:443",
  ];
  const inactive = [
    "printf hello", 'echo "curl is fun"', "grep -r curl tools/", "git commit -m 'add nmap wrapper'",
    "trufflehog filesystem .redteam/evidence",
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

test("the agent cannot change the files that define scope, but can still read them", async t => {
  const { call, bash, cwd } = harness(t, { targetSources: ["targets"] });
  mkdirSync(join(cwd, "targets"));
  writeFileSync(join(cwd, "targets", "hosts.txt"), "10.20.0.7\n");
  for (const [tool, path] of [["write", "redteam.config.json"], ["edit", "targets/hosts.txt"], ["write", "targets/extra.txt"]]) {
    assert.match((await call(tool, { path, content: "x" })).result.reason, /operator-controlled/, `${tool} ${path}`);
  }
  for (const command of [
    "echo 10.99.0.1 >> targets/hosts.txt", "printf x >targets/new.txt", "cd targets && echo 10.99.0.1 > hosts.txt", "sed -i s/a/b/ redteam.config.json",
    "cp /tmp/list.txt targets/extra.txt", "rm targets/hosts.txt", "mv targets/hosts.txt /tmp/", "tee -a targets/hosts.txt",
  ]) assert.match((await bash(command))!.reason!, /operator-controlled/, command);
  for (const command of ["cat targets/hosts.txt", "wc -l targets/hosts.txt", "cp targets/hosts.txt .redteam/evidence/hosts-copy.txt", "echo note > .redteam/evidence/note.txt"]) {
    assert.equal(await bash(command), undefined, command);
  }
  assert.equal((await call("read", { path: "targets/hosts.txt" })).result, undefined);
});

test("arming stays until the operator disarms, except when scope changes under a running agent", async t => {
  const { bash, commands, hooks, ctx, state, prompts, cwd } = harness(t, { targetSources: ["targets"] });
  const notices: string[] = [];
  (ctx.ui as { notify: (text: string) => void }).notify = text => { notices.push(text); };
  mkdirSync(join(cwd, "targets"));
  const inventory = join(cwd, "targets", "hosts.txt");
  writeFileSync(inventory, "10.30.0.1\n");
  state.answer = true;
  await commands.get("rt-arm")!.handler("", ctx);
  prompts.length = 0;

  // The operator edits the inventory between runs: noticed, reported, still armed.
  writeFileSync(inventory, "10.30.0.1\n10.30.0.2\n");
  assert.equal(await bash("nmap 10.30.0.2"), undefined);
  assert.deepEqual(prompts, []);
  assert.match(notices.at(-1)!, /Scope changed: .* → 4 target\(s\).*stay ● ARMED/);

  // A reload or session switch keeps it; a fresh Pi process does not.
  await commands.get("rt-status")!.handler("", ctx);
  await hooks.get("session_start")!({ reason: "reload" }, ctx);
  assert.ok(notices.some(text => /Kept from before the reload: active checks ● ARMED/.test(text)));
  assert.equal(await bash("nmap 10.30.0.2"), undefined);
  assert.deepEqual(prompts, []);

  // The same change while the agent is running disarms as a precaution.
  await hooks.get("before_agent_start")!({ systemPromptOptions: { sections: {} }, messageType: "user", prompt: "go" }, ctx);
  writeFileSync(inventory, "10.30.0.1\n10.30.0.2\n10.30.0.3\n");
  state.answer = false;
  assert.match((await bash("nmap 10.30.0.3"))!.reason!, /denied by operator/);
  assert.deepEqual(prompts, ["Allow one active check?"]);
  assert.ok(notices.some(text => /Scope changed while the agent was running.*DISARMED/.test(text)));

  state.answer = true;
  await hooks.get("agent_settled")!({ aborted: false }, ctx);
  await commands.get("rt-arm")!.handler("", ctx);
  await hooks.get("session_start")!({ reason: "startup" }, ctx);
  prompts.length = 0;
  state.answer = false;
  assert.match((await bash("nmap 10.30.0.2"))!.reason!, /denied by operator/, "a fresh Pi process starts disarmed");
});

test("purpose-built tools are scope-checked on the hostnames they are given", async t => {
  const { customToolTargets } = await import("../extensions/shell.ts");
  const targets = (command: string) => customToolTargets(command, "/work", ".redteam/tools");
  assert.deepEqual(targets("python3 .redteam/tools/probe.py --host vpn.acme.test --port 443 --out .redteam/evidence/vpn.json"), ["vpn.acme.test"]);
  assert.deepEqual(targets("./.redteam/tools/sweep.sh mail.acme.test 10.0.0.7").sort(), ["10.0.0.7", "mail.acme.test"]);
  assert.deepEqual(targets("timeout 30 .redteam/tools/bin/check app.acme.test"), ["app.acme.test"]);
  assert.deepEqual(targets("python3 .redteam/tools/parse.py .redteam/evidence/app.acme.test-headers.txt"), [], "a file name is not a target");
  assert.deepEqual(targets("cat .redteam/tools/notes-app.acme.test.md"), [], "reading a tool file is local");
  assert.deepEqual(targets(`python3 -c "import os.path; print(os.path.sep)"`), [], "one-liners outside the tools directory are not parsed for hostnames");
  for (const tool of ["wafw00f app.test", "ssh-audit app.test", "ike-scan 10.0.0.1", "swaks --to a@app.test --server app.test", "whois app.test", "theHarvester -d app.test", "httpx-toolkit -u app.test"]) {
    assert.equal(isActiveNetworkCommand(tool), true, tool);
  }

  const { bash, commands, ctx, state, prompts } = harness(t);
  state.answer = false;
  assert.match((await bash("python3 .redteam/tools/probe.py app.fixture.test"))!.reason!, /denied by operator/, "disarmed: an in-scope run of an own tool asks first");
  assert.deepEqual(prompts.splice(0), ["Allow one active check?"]);
  assert.match((await bash("python3 .redteam/tools/probe.py evil.example"))!.reason!, /outside the configured scope was denied/);
  state.answer = true;
  await commands.get("rt-arm")!.handler("", ctx);
  prompts.length = 0;
  assert.equal(await bash("python3 .redteam/tools/probe.py app.fixture.test --timeout 5"), undefined);
  assert.deepEqual(prompts, [], "armed: an in-scope run of an own tool needs no prompt");
  assert.match((await bash("python3 .redteam/tools/probe.py 10.20.0.1"))!.reason!, /excluded/);
});

test("the tool check lists what is installed, what is missing, and one install command", async () => {
  const { installCommand, toolboxBrief, toolboxStatus, toolboxText } = await import("../extensions/toolbox.ts");
  const status = toolboxStatus(name => !["nuclei", "nxc", "go", "httpx-toolkit"].includes(name));
  assert.deepEqual(status.missing.map(tool => tool.name), ["nxc", "httpx-toolkit", "nuclei", "go"]);
  assert.equal(installCommand(status.missing), "sudo apt update && sudo apt install -y netexec httpx-toolkit nuclei golang-go");
  const text = toolboxText(status, true);
  assert.match(text, /○ Web\n {4}installed: whatweb, [^\n]*\n {4}missing:   httpx-toolkit, nuclei\n {4}note: httpx-toolkit — ProjectDiscovery httpx/);
  assert.match(text, /✓ Core\n/);
  assert.match(text, /Recommended first:\n  sudo apt update && sudo apt install -y nuclei httpx-toolkit netexec\n/);
  const { toolPlaybook } = await import("../extensions/toolbox.ts");
  const playbook = toolPlaybook(toolboxStatus(() => true), ".redteam/evidence").join("\n");
  assert.match(playbook, /^TOOL PLAYBOOK:[\s\S]*1\. subfinder[\s\S]*2\. dnsx[\s\S]*3\. httpx-toolkit[\s\S]*nuclei -u URL1 -u URL2 -as -ni -duc[\s\S]*trufflehog filesystem DIR --no-verification/);
  assert.match(toolPlaybook(toolboxStatus(() => true), "e", { nucleiTemplates: false }).join("\n"), /templates are not: tell the operator under NEED to run `nuclei -ut` once/);
  assert.doesNotMatch(toolPlaybook(status, "e").join("\n"), /nuclei —|nxc —|httpx-toolkit —/, "tools that are not installed are not mentioned");
  assert.deepEqual(toolPlaybook(toolboxStatus(() => false), "e"), []);
  for (const command of ["dnsx -l a.fixture.test,b.fixture.test -a -resp -silent", "httpx-toolkit -u app.fixture.test -sc -title", "nuclei -u https://app.fixture.test -as -ni", "nxc smb 10.0.0.5", "subfinder -d fixture.test -silent"]) {
    assert.equal(isActiveNetworkCommand(command), true, command);
  }
  assert.match(toolboxBrief(status), /^Installed assessment tools: scanlens, curl,[^\n]*\. Not installed: nxc, httpx-toolkit, nuclei, go\.$/);
  assert.match(toolboxText(toolboxStatus(() => true), false), /Nothing is missing\./);
  assert.equal(toolboxStatus(name => name !== "curl").categories[0].essential, true);
});

test("only nmap may write a raw scan file, and only into the agent's scans folder", async t => {
  const { ownScanOutput } = await import("../extensions/shell.ts");
  const own = (command: string) => ownScanOutput(command, "/work", ".redteam/evidence/scans");
  assert.equal(own("nmap -sV -p 443 -oX .redteam/evidence/scans/app.xml -oN .redteam/evidence/scans/app.txt app.fixture.test"), true);
  assert.equal(own("sudo -n nmap -oX /work/.redteam/evidence/scans/a.xml 10.0.0.1"), true);
  for (const command of [
    "nmap -oX scan.xml app.fixture.test", "nmap -oX .redteam/evidence/scans/../../../client.xml app.fixture.test",
    "cat .redteam/evidence/scans/app.xml", "nmap -iL .redteam/evidence/scans/app.xml", "curl -o .redteam/evidence/scans/app.xml https://app.fixture.test/",
    "nmap -oX .redteam/evidence/scans/a.xml 10.0.0.1; cat client.nessus", "nmap -oX .redteam/evidence/scans/a.xml 10.0.0.1 && cat $(ls *.xml)",
    "nmap -oN .redteam/evidence/scans/app.txt app.fixture.test",
  ]) assert.equal(own(command), false, command);

  const { bash, commands, ctx, state, call } = harness(t);
  state.answer = true;
  await commands.get("rt-arm")!.handler("", ctx);
  assert.equal(await bash("nmap -sV -oX .redteam/evidence/scans/app.xml -oN .redteam/evidence/scans/app.txt app.fixture.test"), undefined);
  assert.match((await bash("nmap -oX out.xml app.fixture.test"))!.reason!, /Raw scan files are prohibited[\s\S]*one exception is nmap writing -oX into \.redteam\/evidence\/scans\//);
  assert.match((await bash("cat .redteam/evidence/scans/app.xml"))!.reason!, /Raw scan files are prohibited/);
  assert.match((await bash("nmap -oX .redteam/evidence/scans/x.xml 10.20.0.1"))!.reason!, /excluded/, "the scope check still applies");
  assert.match((await call("write", { path: ".redteam/evidence/scans/fake.xml", content: "<nmaprun/>" })).result.reason, /written by a scanner, never by hand/);
  assert.match((await call("read", { path: ".redteam/evidence/scans/app.xml" })).result.reason, /Raw scan files/);
});

test("screenshots of in-scope pages follow arming; other hosts are refused", async t => {
  const shot = (url: string) => `timeout 60 chromium --headless --disable-gpu --ignore-certificate-errors --window-size=1366,900 --screenshot=.redteam/evidence/screenshots/app.fixture.test_443_login.png ${url}`;
  const { bash, commands, ctx, state, prompts } = harness(t);
  state.answer = false;
  assert.match((await bash(shot("https://app.fixture.test/login")))!.reason!, /denied by operator/);
  assert.deepEqual(prompts.splice(0), ["Allow one active check?"]);
  state.answer = true;
  await commands.get("rt-arm")!.handler("", ctx);
  prompts.length = 0;
  assert.equal(await bash(shot("https://app.fixture.test/login")), undefined);
  assert.deepEqual(prompts, []);
  assert.match((await bash(shot("https://evil.example/")))!.reason!, /evil\.example is unknown/);
  assert.match((await bash("chromium --headless --screenshot=.redteam/evidence/screenshots/x.png"))!.reason!, /Could not identify an explicit/);
});
