import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import redteamExtension from "../extensions/redteam.ts";
import { loadTargetSources } from "../extensions/scope.ts";
import { preflight, scaffoldInventory, startText, TEMPLATE } from "../extensions/start.ts";

function folder(t: { after(fn: () => void): void }) {
  const cwd = mkdtempSync(join(tmpdir(), "pi-start-"));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  return cwd;
}
const valid = { engagement: "Fixture", authorizationExpires: "2099-01-01", targets: [], excludeTargets: [], targetSources: ["targets"] };

test("an empty folder gets a checklist that starts with setup and names every location", t => {
  const cwd = folder(t);
  const facts = preflight(cwd);
  const result = startText(facts);
  assert.equal(result.ready, false);
  assert.equal(result.remaining, 3);
  assert.match(result.text, /▸ 1\. Describe the engagement\n {5}No redteam\.config\.json in this folder yet\.\n {5}The setup wizard \(\/rt-setup, offered by \/rt-start\) asks four things/);
  assert.match(result.text, /○ 2\. Add the authorized targets\n {5}Put one or more \.txt, \.list, or \.csv files in the targets\/ folder\./);
  assert.ok(result.text.includes(`Engagement folder: ${cwd}`));
  assert.ok(result.text.includes(`scanlens import /path/to/your/scans --db "${join(cwd, "scanlens.db")}"`));
  assert.match(result.text, /○ 4\. Decide on discovery {2}\(optional\)/);
});

test("the checklist follows what is in the folder, and the template file adds no scope", t => {
  const cwd = folder(t);
  writeFileSync(join(cwd, "redteam.config.json"), JSON.stringify(valid));
  let facts = preflight(cwd);
  assert.match(startText(facts).text, /✓ 1\. Describe the engagement\n {5}Fixture · authorized to 2099-01-01/);
  assert.match(startText(facts).text, /▸ 2\. Add the authorized targets/);

  const file = scaffoldInventory(facts)!;
  assert.equal(readFileSync(file, "utf8"), TEMPLATE);
  assert.deepEqual(loadTargetSources(cwd, ["targets"]).targets, [], "every template line is a comment");
  assert.equal(scaffoldInventory(preflight(cwd)), undefined, "an existing inventory file is never overwritten");

  writeFileSync(file, `${TEMPLATE}192.0.2.10\n*.lab.fixture.test\nhttps://app.fixture.test/api/orders\n`);
  mkdirSync(join(cwd, "scans"));
  writeFileSync(join(cwd, "scans", "client.nessus"), "");
  facts = preflight(cwd);
  const open = startText(facts);
  assert.match(open.text, /✓ 2\. Add the authorized targets\n {5}3 target\(s\) and 1 priority route\(s\) loaded\.\n {5}targets\/targets\.txt: 3 target\(s\), 1 priority route\(s\)/);
  assert.match(open.text, /▸ 3\. Import the scan results/);
  assert.match(open.text, /! 1 raw scan file\(s\) are inside this folder: scans\/client\.nessus/);
  assert.match(open.text, /Your scope has 1 wildcard domain\(s\)/);
  assert.equal(open.remaining, 1);

  writeFileSync(join(cwd, "scanlens.db"), "");
  const done = startText(preflight(cwd));
  assert.equal(done.ready, true);
  assert.match(done.text, /Setup is complete\. Run \/rt for the menu/);
});

test("rt-start offers the wizard, then the template, then reports what is left", async t => {
  const cwd = folder(t);
  const commands = new Map<string, { handler: (...args: any[]) => Promise<any> }>();
  const hooks = new Map<string, (...args: any[]) => Promise<any>>();
  redteamExtension({
    registerCommand: (name: string, command: { handler: (...args: any[]) => Promise<any> }) => commands.set(name, command),
    registerTool: () => {}, on: (event: string, hook: (...args: any[]) => Promise<any>) => hooks.set(event, hook),
  } as unknown as ExtensionAPI);
  const answers = ["Authorization ABC-123", "2099-12-31", "", "", "", "", "", "", ""];
  const confirms: string[] = [];
  const notices: string[] = [];
  const ctx = {
    cwd, hasUI: true, sessionManager: { getSessionId: () => "session-test" }, waitForIdle: async () => {},
    ui: {
      confirm: async (title: string) => { confirms.push(title); return true; },
      input: async () => answers.shift(), select: async () => undefined,
      notify: (text: string) => { notices.push(text); }, setStatus() {}, setWidget() {},
    },
  };
  t.after(() => { void hooks.get("session_shutdown")!({ reason: "test" }, ctx); });
  await commands.get("rt-start")!.handler("", ctx);
  assert.deepEqual(confirms.filter(title => /wizard now|target file/.test(title)), ["Run the setup wizard now?", "Create a target file to fill in?"]);
  assert.ok(existsSync(join(cwd, "redteam.config.json")) && existsSync(join(cwd, "targets", "targets.txt")));
  assert.match(notices.at(-1)!, /✓ 1\. Describe the engagement\n {5}Authorization ABC-123/);
  assert.match(notices.at(-1)!, /▸ 2\. Add the authorized targets/);
  assert.match(notices.at(-1)!, /2 step\(s\) left/);
});
