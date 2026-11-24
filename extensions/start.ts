import { existsSync, mkdirSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { delimiter, extname, isAbsolute, join, relative, resolve } from "node:path";
import { authorizationError, loadConfig, loadTargetSources, type RedteamConfig } from "./scope.ts";

// The guided entry point: inspect the engagement folder, say what is ready and
// what is missing, and give the exact file location or command for each gap.

export interface Preflight {
  cwd: string;
  config: RedteamConfig;
  configExists: boolean;
  /** Configuration or authorization problem other than an empty scope. */
  configProblem?: string;
  inventory: { source: string; path: string; exists: boolean; files: { name: string; targets: number; routes: number }[] }[];
  targets: number;
  routes: number;
  scanDatabase: { path: string; exists: boolean };
  scanlensInstalled: boolean;
  /** Raw scan files lying inside the engagement folder, where the agent works. */
  rawScans: string[];
  wildcards: number;
}

const NO_TARGETS = "scope has no targets";
const INVENTORY_EXTENSIONS = new Set([".txt", ".list", ".csv"]);
const RAW_SCAN_EXTENSIONS = new Set([".nessus", ".nmap", ".gnmap"]);
export const TEMPLATE_NAME = "targets.txt";
export const TEMPLATE = `# Authorized targets for this engagement, one per line.
# Only list what the written authorization covers. Lines starting with # are ignored.
#
#   192.0.2.10                    one address
#   192.0.2.0/24                  an IPv4 range
#   app.client.example            one hostname
#   *.lab.client.example          every name under a domain
#   https://app.client.example/api/v1/orders    a priority route (its host joins the scope)
#
# Do not put credentials, commands, or scan output in this file.
`;

function onPath(command: string): boolean {
  return (process.env.PATH ?? "").split(delimiter).some((directory) => directory && existsSync(join(directory, command)));
}

function inventoryFiles(path: string): string[] {
  try {
    if (statSync(path).isFile()) return [path];
    return readdirSync(path, { withFileTypes: true }).filter((entry) => entry.isFile() && INVENTORY_EXTENSIONS.has(extname(entry.name).toLowerCase()))
      .map((entry) => join(path, entry.name)).sort();
  } catch {
    return [];
  }
}

function rawScanFiles(cwd: string): string[] {
  const found: string[] = [];
  const visit = (directory: string, depth: number) => {
    let entries;
    try { entries = readdirSync(directory, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (found.length >= 20) return;
      if (entry.isFile() && RAW_SCAN_EXTENSIONS.has(extname(entry.name).toLowerCase())) found.push(relative(cwd, join(directory, entry.name)));
      else if (entry.isDirectory() && depth < 1 && !entry.name.startsWith(".") && entry.name !== "node_modules") visit(join(directory, entry.name), depth + 1);
    }
  };
  visit(cwd, 0);
  return found.sort();
}

export function preflight(cwd: string, now = new Date()): Preflight {
  const loaded = loadConfig(cwd);
  const { config } = loaded;
  const merged = loadTargetSources(cwd, config.targetSources);
  const targets = new Set([...config.targets, ...merged.targets]).size;
  const problem = loaded.error ?? authorizationError(config, targets, now);
  const scanPath = resolve(cwd, config.scanlensDb);
  return {
    cwd, config,
    configExists: existsSync(loaded.path),
    configProblem: problem === NO_TARGETS ? undefined : problem,
    inventory: config.targetSources.map((source) => {
      const path = isAbsolute(source) ? source : resolve(cwd, source);
      return {
        source, path, exists: existsSync(path),
        files: inventoryFiles(path).map((file) => {
          const content = loadTargetSources(cwd, [file]);
          return { name: relative(cwd, file) || file, targets: content.targets.length, routes: content.webEndpoints.length };
        }),
      };
    }),
    targets,
    routes: new Set([...merged.webEndpoints, ...config.webEndpoints]).size,
    scanDatabase: { path: scanPath, exists: existsSync(scanPath) },
    scanlensInstalled: onPath("scanlens"),
    rawScans: rawScanFiles(cwd),
    wildcards: [...config.targets, ...merged.targets].filter((target) => target.startsWith("*.")).length,
  };
}

// Paths inside the engagement folder read better relative to it.
function shown(facts: Preflight, path: string): string {
  const rel = relative(facts.cwd, path);
  return rel && !rel.startsWith("..") && !isAbsolute(rel) ? `${rel}/` : path;
}

export function importCommand(facts: Preflight): string {
  return `scanlens import /path/to/your/scans --db ${JSON.stringify(facts.scanDatabase.path)}`;
}

/** The numbered setup checklist with, for every open step, exactly what to do. */
export function startText(facts: Preflight): { text: string; ready: boolean; remaining: number } {
  const lines: string[] = [];
  let step = 0;
  let remaining = 0;
  let currentShown = false;
  const add = (done: boolean, title: string, detail: string[], optional = false) => {
    const mark = done ? "✓" : optional ? "○" : currentShown ? "○" : "▸";
    if (!done && !optional) { remaining++; currentShown = true; }
    lines.push(`${mark} ${++step}. ${title}${optional && !done ? "  (optional)" : ""}`, ...detail.map((line) => `     ${line}`));
  };

  add(!facts.configProblem && facts.configExists, "Describe the engagement",
    facts.configProblem || !facts.configExists
      ? [facts.configExists ? `Problem: ${facts.configProblem}` : "No redteam.config.json in this folder yet.",
        "The setup wizard (/rt-setup, offered by /rt-start) asks four things: the authorization",
        "reference, the expiry date, targets you want to type in directly, and exclusions.",
        "The remaining questions are file locations with working defaults: press Enter."]
      : [`${facts.config.engagement} · authorized to ${facts.config.authorizationExpires} · ${facts.config.excludeTargets.length} exclusion(s)`]);

  const firstDirectory = facts.inventory[0];
  const fileLines = facts.inventory.flatMap((source) => source.files.map((file) => `${file.name}: ${file.targets} target(s), ${file.routes} priority route(s)`));
  add(facts.targets > 0, "Add the authorized targets",
    facts.targets > 0
      ? [`${facts.targets} target(s) and ${facts.routes} priority route(s) loaded.`, ...fileLines,
        ...(facts.config.targets.length ? [`redteam.config.json: ${facts.config.targets.length} target(s) entered in setup`] : []),
        "Add more any time: edit the files above, or /rt-onboard HOST for a single host."]
      : [firstDirectory
          ? `Put one or more .txt, .list, or .csv files in the ${shown(facts, firstDirectory.path)} folder.`
          : "No inventory folder is configured; add one with /rt-setup or use /rt-onboard HOST.",
        "One target per line: an IP, a hostname, an IPv4 range, *.domain, or a full https:// URL",
        "for a route that deserves its own review. Files are reread automatically; no restart needed.",
        ...(firstDirectory ? [`/rt-start can create ${join(firstDirectory.source, TEMPLATE_NAME)} with the format explained.`] : [])]);

  add(facts.scanDatabase.exists, "Import the scan results",
    facts.scanDatabase.exists
      ? [`Scan database found: ${facts.scanDatabase.path}`]
      : [...(facts.scanlensInstalled ? [] : ["scanlens is not on your PATH; install it first."]),
        "In a normal terminal (not through the agent), run:",
        `  ${importCommand(facts)}`,
        "Point it at the folder holding your .nessus and Nmap XML files. Keep those files outside",
        "this engagement folder: the agent works from the database and must not read raw scans."]);

  if (facts.rawScans.length) {
    lines.push(`  ! ${facts.rawScans.length} raw scan file(s) are inside this folder: ${facts.rawScans.slice(0, 3).join(", ")}${facts.rawScans.length > 3 ? ", …" : ""}`,
      "     Move them elsewhere after importing. The agent is blocked from reading them, but they do not belong in its workspace.");
  }

  add(facts.config.passiveSources.length > 0, "Decide on discovery",
    facts.config.passiveSources.length
      ? [`Approved passive sources: ${facts.config.passiveSources.join(", ")}. Start a run with /rt-discover on.`]
      : ["Discovery lets the agent look for hosts and routes beyond your list, within a request",
        `budget (default ${facts.config.discoveryBudget}). Turn it on with /rt-discover on once the steps above are done.`,
        ...(facts.wildcards ? [`Your scope has ${facts.wildcards} wildcard domain(s), which is where subdomain discovery applies.`] : []),
        "/rt-discover allow crt.sh additionally permits certificate-log lookups; these disclose",
        "in-scope domain names to that service, so check the rules of engagement first."], true);

  const ready = remaining === 0;
  return {
    ready, remaining,
    text: [
      "Getting started",
      `Engagement folder: ${facts.cwd}`,
      "✓ done · ▸ do this now · ○ later",
      "",
      ...lines,
      "",
      ready
        ? "Setup is complete. Run /rt for the menu, or /rt-steer → Start scan triage to begin."
        : `${remaining} step(s) left. Run /rt-start again at any time to see where you are.`,
    ].join("\n"),
  };
}

/** Creates the first inventory folder and a commented template file. Returns the file path, or undefined if nothing was created. */
export function scaffoldInventory(facts: Preflight): string | undefined {
  const first = facts.inventory[0];
  if (!first || facts.targets > 0 || first.files.length) return undefined;
  if (first.exists && !statSync(first.path).isDirectory()) return undefined;
  mkdirSync(first.path, { recursive: true });
  const file = join(first.path, TEMPLATE_NAME);
  writeFileSync(file, TEMPLATE, { flag: "wx", mode: 0o600 });
  return file;
}
