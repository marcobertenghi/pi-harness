import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { existsSync, mkdirSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { isIP } from "node:net";
import { authorizationError, DEFAULT_CONFIG, isExampleConfig, loadConfig, loadTargetSources, type RedteamConfig } from "./scope.ts";

// No network access: setup only gathers operator answers and writes the reviewed config.
export function validScopeRule(rule: string): boolean {
  if (isIP(rule)) return true;
  if (rule.includes("/")) {
    const [ip, bits, extra] = rule.split("/");
    return extra === undefined && isIP(ip) === 4 && /^\d+$/.test(bits ?? "") && Number(bits) <= 32;
  }
  const host = rule.replace(/^\*\./, "");
  return host.length <= 253 && host.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)) && !/^\d+(?:\.\d+)*$/.test(host);
}

export async function setupConfig(ctx: Pick<ExtensionContext, "cwd" | "hasUI" | "ui">): Promise<boolean> {
  if (!ctx.hasUI) {
    ctx.ui.notify("Setup requires an interactive UI. Run Pi interactively and use /rt-setup, or configure redteam.config.json manually. Active checks remain blocked until authorization is valid.", "warning");
    return false;
  }
  const loaded = loadConfig(ctx.cwd);
  const original = existsSync(loaded.path) ? readFileSync(loaded.path, "utf8") : undefined;
  const seed = loaded.error || isExampleConfig(loaded.config) ? DEFAULT_CONFIG : loaded.config;
  const draft: RedteamConfig = { ...seed, targets: [...seed.targets], excludeTargets: [...seed.excludeTargets], targetSources: [...seed.targetSources] };
  const cancelled = () => {
    ctx.ui.notify("Setup cancelled; configuration was not changed. Use /rt-setup to start again. Arming is unchanged.", "info");
    return false;
  };
  async function ask(title: string, initial: string, validate: (value: string) => string | undefined): Promise<string | undefined> {
    while (true) {
      const defaultValue = initial && validate("") ? initial : "";
      const answer = await ctx.ui.input(defaultValue ? `${title} — Enter keeps: ${defaultValue}` : title, initial);
      if (answer === undefined) return undefined;
      const value = answer.trim() || defaultValue;
      const error = validate(value);
      if (!error) return value;
      ctx.ui.notify(error, "warning");
    }
  }
  const required = (value: string) => value ? undefined : "Please supply a value (Escape cancels setup).";
  if (!await ctx.ui.confirm("Set up red-team engagement?", "Only enter scope covered by your written authorization. This wizard does not grant permission to test. Escape cancels without saving; arming is unchanged.")) return cancelled();
  const name = await ask("1/8 — What is the engagement / written authorization reference?", seed.engagement, (value) => required(value) ?? (value === "Example authorized assessment" ? "Replace the example engagement label." : undefined));
  if (name === undefined) return cancelled();
  draft.engagement = name;
  const expiry = await ask("2/8 — When does authorization expire? YYYY-MM-DD (inclusive, UTC)", seed.authorizationExpires, (value) => authorizationError({ ...draft, authorizationExpires: value, targets: [] }, 1));
  if (expiry === undefined) return cancelled();
  draft.authorizationExpires = expiry;
  for (const [key, title] of [
    ["targets", "3/8 — Explicitly authorized IPs, hosts, IPv4 CIDRs or *.domains (comma/space separated; blank if using inventory)"],
    ["excludeTargets", "4/8 — Excluded targets (same syntax; blank for none). Exclusions always win."],
  ] as const) {
    const answer = await ask(title, seed[key].join(", "), (value) => {
      const rules = value.split(/[\s,]+/).filter(Boolean);
      return rules.every(validScopeRule) ? undefined : "Use exact IPs/hostnames, IPv4 CIDRs, or *.domain rules; no URLs, paths, or port numbers.";
    });
    if (answer === undefined) return cancelled();
    draft[key] = answer.split(/[\s,]+/).filter(Boolean);
  }
  // The source is explicit in the question and final review; never infer targets from a directory name.
  const sources = await ask("5/8 — Approved inventory files/directories (comma separated). Enter keeps the default; '-' means none. Files must contain targets, not raw scans. You may populate the directory after setup.", seed.targetSources.join(", ") || "targets", required);
  if (sources === undefined) return cancelled();
  draft.targetSources = sources === "-" ? [] : sources.split(",").map((value) => value.trim()).filter(Boolean);
  const inventory = loadTargetSources(ctx.cwd, draft.targetSources);
  const problem = authorizationError(draft, draft.targets.length + inventory.targets.length);
  for (const warning of inventory.warnings) ctx.ui.notify(warning, "warning");
  if (problem && problem !== "scope has no targets") {
    ctx.ui.notify(`Cannot save: ${problem}. Run /rt-setup again with real authorized scope.`, "error");
    return false;
  }
  const pendingScope = problem === "scope has no targets";
  if (pendingScope) ctx.ui.notify("Setup can be saved with no targets yet. Authorization stays INVALID and active checks stay blocked until you add authorized IPs/hostnames to a .txt, .list, or .csv inventory file, or add explicit targets with /rt-setup. A directory path alone is not target scope.", "warning");
  const db = await ask("6/8 — Path to the scanlens SQLite database (not a raw scan file)", seed.scanlensDb, (value) => required(value) ?? (/\.(?:nessus|nmap|xml)$/i.test(value) ? "Choose a scanlens database, not a raw scan file." : undefined));
  if (db === undefined) return cancelled();
  draft.scanlensDb = db;
  for (const key of ["evidenceDir", "toolsDir", "auditDb"] as const) {
    const value = await ask(`7/8 — Where to keep ${key === "auditDb" ? "the audit log database" : key === "toolsDir" ? "scripts and tools the agent creates" : "evidence"} (the default is fine for most engagements)`, seed[key], required);
    if (value === undefined) return cancelled();
    draft[key] = value;
  }
  const database = resolve(ctx.cwd, draft.scanlensDb);
  const ready = existsSync(database) && statSync(database).isFile();
  if (!ready) ctx.ui.notify(`Database not found at ${database}. Import scans with scanlens outside the agent or supply an existing database before triage.`, "warning");
  const review = `${JSON.stringify(draft, null, 2)}\n\nInventory hosts: ${inventory.targets.join(", ") || "(none)"}\n\nPriority web endpoints (${inventory.webEndpoints.length}):\n${inventory.webEndpoints.map((endpoint) => `- ${endpoint}`).join("\n") || "(none)"}\n${pendingScope ? "SETUP INCOMPLETE: no targets yet; authorization remains INVALID and active checks are blocked.\n" : ""}${draft.targetSources.includes("targets") ? "The default targets/ directory will be created if missing.\n" : ""}\nConfirm that this scope is covered by your written authorization. Save ${loaded.path}${original === undefined ? "" : " (replace existing configuration)"}? Active checks will NOT be armed.`;
  if (!await ctx.ui.confirm("8/8 — Review and save", review)) return cancelled();
  const current = existsSync(loaded.path) ? readFileSync(loaded.path, "utf8") : undefined;
  if (current !== original) throw new Error("Configuration changed during setup; nothing saved. Run /rt-setup again.");
  if (draft.targetSources.includes("targets")) mkdirSync(resolve(ctx.cwd, "targets"), { recursive: true });
  writeFileSync(loaded.path, `${JSON.stringify(draft, null, 2)}\n`, { mode: 0o600, flag: original === undefined ? "wx" : "w" });
  ctx.ui.notify(`Saved ${loaded.path}. Arming is unchanged. ${pendingScope ? "Add authorized targets to an inventory file (one IP/hostname or IPv4 CIDR per line), then run /rt-status. Scope is reread automatically; no wizard restart is required." : ready ? "Use /rt-status, then /skill:redteam to begin scan triage." : "Configure/import the scanlens database before triage."} Use /rt-arm only when ready to approve active checks.`, "info");
  return true;
}
