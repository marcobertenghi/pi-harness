import { isIP } from "node:net";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { extname, isAbsolute, join, relative, resolve } from "node:path";

export interface RedteamConfig {
  engagement: string;
  authorizationExpires: string;
  targets: string[];
  excludeTargets: string[];
  targetSources: string[];
  scanlensDb: string;
  evidenceDir: string;
  toolsDir: string;
  auditDb: string;
  /** Priority web endpoints accepted from proposals. Their hosts must already be in scope. */
  webEndpoints: string[];
  /** Third-party hosts the operator approved for passive lookups (for example crt.sh). */
  passiveSources: string[];
  /** Requests the discovery tool may send per arming. */
  discoveryBudget: number;
}

export const DEFAULT_CONFIG: RedteamConfig = {
  engagement: "",
  authorizationExpires: "",
  targets: [],
  excludeTargets: [],
  targetSources: ["targets"],
  scanlensDb: "scanlens.db",
  evidenceDir: ".redteam/evidence",
  toolsDir: ".redteam/tools",
  auditDb: ".redteam/audit/audit.db",
  webEndpoints: [],
  passiveSources: [],
  discoveryBudget: 300,
};

export function loadConfig(cwd: string): { config: RedteamConfig; path: string; error?: string } {
  const path = join(cwd, "redteam.config.json");
  if (!existsSync(path)) return { config: { ...DEFAULT_CONFIG }, path, error: "redteam.config.json is missing" };
  try {
    const value = JSON.parse(readFileSync(path, "utf8")) as Partial<RedteamConfig>;
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("expected a configuration object");
    for (const key of ["engagement", "authorizationExpires", "scanlensDb", "evidenceDir", "toolsDir", "auditDb"] as const) {
      if (value[key] !== undefined && (typeof value[key] !== "string" || !value[key]!.trim())) throw new Error(`${key} must be a non-empty string`);
    }
    if (value.discoveryBudget !== undefined && (!Number.isInteger(value.discoveryBudget) || value.discoveryBudget < 1 || value.discoveryBudget > 5000)) {
      throw new Error("discoveryBudget must be a whole number from 1 to 5000");
    }
    for (const key of ["targets", "excludeTargets", "targetSources", "webEndpoints", "passiveSources"] as const) {
      if (value[key] !== undefined && (!Array.isArray(value[key]) || !value[key]!.every((item) => typeof item === "string"))) throw new Error(`${key} must be an array of strings`);
    }
    return {
      path,
      config: {
        ...DEFAULT_CONFIG,
        ...value,
        targets: strings(value.targets),
        excludeTargets: strings(value.excludeTargets),
        targetSources: strings(value.targetSources ?? DEFAULT_CONFIG.targetSources),
        webEndpoints: [...new Set(strings(value.webEndpoints).map(normalizeWebEndpoint).filter(Boolean))],
        passiveSources: [...new Set(strings(value.passiveSources).map(normalizeTarget).filter(Boolean))],
      },
    };
  } catch (error) {
    return { config: { ...DEFAULT_CONFIG }, path, error: `invalid configuration: ${String(error)}` };
  }
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

const ALLOWED_TARGET_EXTENSIONS = new Set([".txt", ".list", ".csv"]);
const RAW_SCAN_EXTENSIONS = new Set([".nessus", ".nmap", ".gnmap", ".xml"]);

export interface TargetSourceDetail {
  source: string;
  targets: string[];
  webEndpoints: string[];
}

export interface TargetSourceInventory {
  targets: string[];
  webEndpoints: string[];
  warnings: string[];
  sourceDetails: TargetSourceDetail[];
}

export function loadTargetSources(cwd: string, sources: string[]): TargetSourceInventory {
  const targets = new Set<string>();
  const webEndpoints = new Set<string>();
  const warnings: string[] = [];
  const sourceDetails: TargetSourceDetail[] = [];
  for (const source of sources) {
    const path = isAbsolute(source) ? source : resolve(cwd, source);
    if (!existsSync(path)) {
      warnings.push(`target source not found: ${source}`);
      continue;
    }
    collectTargetPath(cwd, path, targets, webEndpoints, warnings, sourceDetails);
  }
  return { targets: [...targets], webEndpoints: [...webEndpoints], warnings, sourceDetails };
}

function collectTargetPath(cwd: string, path: string, targets: Set<string>, webEndpoints: Set<string>, warnings: string[], sourceDetails: TargetSourceDetail[]): void {
  const stat = statSync(path);
  if (stat.isDirectory()) {
    for (const name of readdirSync(path)) collectTargetPath(cwd, join(path, name), targets, webEndpoints, warnings, sourceDetails);
    return;
  }
  const extension = extname(path).toLowerCase();
  if (RAW_SCAN_EXTENSIONS.has(extension)) {
    warnings.push(`refused raw scan file: ${path}`);
    return;
  }
  if (!ALLOWED_TARGET_EXTENSIONS.has(extension)) return;
  const fileTargets = new Set<string>();
  const fileEndpoints = new Set<string>();
  for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
    const clean = line.replace(/#.*$/, "").trim();
    if (!clean) continue;
    for (const token of clean.split(/[\s,]+/)) {
      const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(token);
      const endpoint = normalizeWebEndpoint(token);
      if (endpoint) {
        webEndpoints.add(endpoint);
        fileEndpoints.add(endpoint);
      } else if (hasScheme) {
        warnings.push(`ignored unsupported or credential-bearing endpoint in ${path}`);
        continue;
      }
      const normalized = normalizeTarget(endpoint || token);
      if (normalized) {
        targets.add(normalized);
        fileTargets.add(normalized);
      }
    }
  }
  if (fileTargets.size || fileEndpoints.size) {
    const rel = relative(cwd, path);
    sourceDetails.push({
      source: rel && !rel.startsWith("..") && !isAbsolute(rel) ? rel : path,
      targets: [...fileTargets],
      webEndpoints: [...fileEndpoints],
    });
  }
}

export function normalizeWebEndpoint(value: string): string {
  if (!/^https?:\/\//i.test(value.trim())) return "";
  try {
    const endpoint = new URL(value.trim());
    if (!['http:', 'https:'].includes(endpoint.protocol) || endpoint.username || endpoint.password || !endpoint.hostname) return "";
    endpoint.hostname = endpoint.hostname.toLowerCase();
    endpoint.search = "";
    endpoint.hash = "";
    return endpoint.toString();
  } catch {
    return "";
  }
}

export function matchesWebEndpoint(value: string, ruleValue: string): boolean {
  const valueNormalized = normalizeWebEndpoint(value);
  const ruleNormalized = normalizeWebEndpoint(ruleValue);
  if (!valueNormalized || !ruleNormalized) return false;
  const valueUrl = new URL(valueNormalized);
  const ruleUrl = new URL(ruleNormalized);
  if (valueUrl.origin !== ruleUrl.origin) return false;
  const pattern = ruleUrl.pathname
    .split("*")
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${pattern}$`).test(valueUrl.pathname);
}

export function normalizeTarget(value: string): string {
  let target = value.trim().toLowerCase();
  if (!target) return "";
  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(target)) target = new URL(target).hostname;
  } catch {
    return "";
  }
  target = target.replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (!isIP(target) && target.includes(":")) target = target.split(":", 1)[0];
  return target;
}

function ipv4Number(ip: string): number | undefined {
  if (isIP(ip) !== 4) return undefined;
  return ip.split(".").reduce((value, octet) => (value * 256 + Number(octet)) >>> 0, 0);
}

type Interval = [number, number];
const MAX_OCTET_COMBINATIONS = 4096;

// One nmap-style octet: "*", "7", "1-20", "1-" (to 255), or a comma list of those.
function octetRanges(text: string): Interval[] | undefined {
  const ranges: Interval[] = [];
  for (const piece of text.split(",").filter(Boolean)) {
    if (piece === "*") { ranges.push([0, 255]); continue; }
    const match = /^(\d{1,3})(?:(-)(\d{1,3})?)?$/.exec(piece);
    if (!match) return undefined;
    const low = Number(match[1]);
    const high = match[2] ? Number(match[3] ?? 255) : low;
    if (low > 255 || high > 255 || low > high) return undefined;
    ranges.push([low, high]);
  }
  return ranges.length ? ranges : undefined;
}

function mergeIntervals(intervals: Interval[]): Interval[] {
  const merged: Interval[] = [];
  for (const [low, high] of [...intervals].sort((a, b) => a[0] - b[0])) {
    const last = merged.at(-1);
    if (last && low <= last[1] + 1) last[1] = Math.max(last[1], high);
    else merged.push([low, high]);
  }
  return merged;
}

/**
 * Address ranges covered by an IPv4 expression: a plain address, a CIDR, or
 * nmap octet syntax (10.0.0.1-254, 10.0.0.*, 10.0.0.1,2,3). Returns undefined
 * for anything that is not IPv4-shaped and "invalid" for IPv4-shaped text that
 * cannot be evaluated, so callers can fail closed.
 */
export function ipv4Intervals(value: string): Interval[] | "invalid" | undefined {
  const match = /^([\d*][\d*,-]*(?:\.[\d*][\d*,-]*){3})(?:\/(\d{1,2}))?$/.exec(value);
  if (!match) return undefined;
  if (match[2] !== undefined) {
    const base = ipv4Number(match[1]);
    const bits = Number(match[2]);
    if (base === undefined || bits > 32) return "invalid";
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    const low = (base & mask) >>> 0;
    return [[low, (low | (~mask >>> 0)) >>> 0]];
  }
  const octets = match[1].split(".").map(octetRanges);
  if (octets.some((ranges) => !ranges)) return "invalid";
  const [first, second, third, fourth] = (octets as Interval[][]).map((ranges, index) =>
    index === 3 ? ranges : ranges.flatMap(([low, high]) => Array.from({ length: high - low + 1 }, (_, offset) => [low + offset, low + offset] as Interval)));
  if (first.length * second.length * third.length > MAX_OCTET_COMBINATIONS) return "invalid";
  const intervals: Interval[] = [];
  for (const [a] of first) for (const [b] of second) for (const [c] of third) {
    const prefix = ((a * 256 + b) * 256 + c) * 256;
    for (const [low, high] of fourth) intervals.push([prefix + low, prefix + high]);
  }
  return mergeIntervals(intervals);
}

function ruleIntervals(rules: string[]): Interval[] {
  return mergeIntervals(rules.flatMap((rule) => {
    const intervals = ipv4Intervals(normalizeTarget(rule));
    return Array.isArray(intervals) ? intervals : [];
  }));
}

export function matchesScope(targetValue: string, ruleValue: string): boolean {
  const target = normalizeTarget(targetValue);
  const rule = normalizeTarget(ruleValue);
  if (!target || !rule) return false;
  if (rule.includes("/")) {
    const wanted = ipv4Intervals(target);
    const allowed = ipv4Intervals(rule);
    return Array.isArray(wanted) && Array.isArray(allowed)
      && wanted.every(([low, high]) => allowed.some(([from, to]) => from <= low && high <= to));
  }
  if (rule.startsWith("*.")) {
    const suffix = rule.slice(1);
    return target.endsWith(suffix) && target !== suffix.slice(1);
  }
  return target === rule;
}

/**
 * Exclusions win. An IPv4 range (CIDR or nmap octet syntax) is excluded when it
 * overlaps any excluded address, and included only when every address in it is
 * covered by the included addresses and CIDRs.
 */
export function scopeDecision(target: string, includes: string[], excludes: string[]): "included" | "excluded" | "unknown" {
  const wanted = ipv4Intervals(normalizeTarget(target));
  if (wanted === "invalid") return "unknown";
  if (wanted) {
    const excluded = ruleIntervals(excludes);
    if (wanted.some(([low, high]) => excluded.some(([from, to]) => low <= to && from <= high))) return "excluded";
    const included = ruleIntervals(includes);
    return wanted.every(([low, high]) => included.some(([from, to]) => from <= low && high <= to)) ? "included" : "unknown";
  }
  if (excludes.some((rule) => matchesScope(target, rule))) return "excluded";
  return includes.some((rule) => matchesScope(target, rule)) ? "included" : "unknown";
}

export function isExampleConfig(config: RedteamConfig): boolean {
  return config.engagement.trim() === "Example authorized assessment"
    || config.targets.some((target) =>
      ["app.example.test", "*.lab.example.test"].includes(target.trim().toLowerCase()));
}

export function authorizationError(config: RedteamConfig, targetCount: number, now = new Date()): string | undefined {
  if (isExampleConfig(config)) return "configuration contains example values; run /rt-setup";
  if (!config.engagement.trim()) return "engagement name is missing";
  if (targetCount === 0) return "scope has no targets";
  if (!/^\d{4}-\d{2}-\d{2}$/.test(config.authorizationExpires)) return "authorizationExpires must be YYYY-MM-DD";
  const end = new Date(`${config.authorizationExpires}T23:59:59Z`);
  if (Number.isNaN(end.valueOf()) || end.toISOString().slice(0, 10) !== config.authorizationExpires) return "authorizationExpires is invalid";
  if (now.valueOf() > end.valueOf()) return `authorization expired on ${config.authorizationExpires}`;
  return undefined;
}

export function mentionsRawScan(command: string): boolean {
  return /(?:^|[\s'"`])[^\s'"`]*\.(?:nessus|nmap|gnmap|xml)(?:[\s'"`]|$)/i.test(command);
}

const IPV4_EXPRESSION = /(?<![\w.])(?:[\d*][\d*,-]*\.){3}[\d*][\d*,-]*(?:\/\d{1,2})?(?![\w.])/g;
const IPV6_LITERAL = /(?<![\w:.])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:.])/gi;
const URL_REFERENCE = /\b[a-z][a-z0-9+.-]*:\/\/[^\s'"`]+/gi;

/** Unambiguous network references: URLs of any scheme and IP literals or ranges. */
export function explicitTargets(text: string): string[] {
  const found = new Set<string>();
  for (const match of text.matchAll(URL_REFERENCE)) {
    if (/^file:/i.test(match[0])) continue;
    // An unparseable URL stays in the list as-is so it is blocked as unknown.
    found.add(normalizeTarget(match[0]) || match[0]);
  }
  for (const match of text.matchAll(IPV4_EXPRESSION)) found.add(match[0].replace(/[,-]+$/, ""));
  for (const match of text.matchAll(IPV6_LITERAL)) {
    if (isIP(match[0]) === 6) found.add(match[0].toLowerCase());
  }
  return [...found];
}

export function isLoopbackTarget(target: string): boolean {
  return target === "localhost" || target === "::1" || target === "0.0.0.0" || /^127(?:\.\d{1,3}){3}$/.test(target);
}

export function obviousTargets(command: string): string[] {
  const found = new Set<string>(explicitTargets(command));
  // UNC-style //host/share, as used by smbclient.
  for (const match of command.matchAll(/(?<![\w:\/.])\/\/([a-z0-9][a-z0-9.-]*)/gi)) {
    const value = normalizeTarget(match[1]);
    if (value) found.add(value);
  }
  // Conservatively recognize dotted DNS names, with or without a trailing path.
  // Names preceded by a slash are excluded to avoid treating
  // /usr/share/wordlists/common.txt as a network target.
  for (const match of command.matchAll(/(?<![\/\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,62})\.)+[a-z][a-z0-9-]{0,62}(?![\w.-])/gi)) {
    const value = normalizeTarget(match[0]);
    if (value && !/\.(?:txt|list|csv|json|yaml|yml|xml|nessus|nmap)$/i.test(value)) found.add(value);
  }
  return [...found];
}
