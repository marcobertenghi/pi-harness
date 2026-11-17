import { isIP } from "node:net";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { extname, isAbsolute, join, resolve } from "node:path";

export interface RedteamConfig {
  engagement: string;
  authorizationExpires: string;
  targets: string[];
  excludeTargets: string[];
  targetSources: string[];
  scanlensDb: string;
  evidenceDir: string;
  toolsDir: string;
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
};

export function loadConfig(cwd: string): { config: RedteamConfig; path: string; error?: string } {
  const path = join(cwd, "redteam.config.json");
  if (!existsSync(path)) return { config: { ...DEFAULT_CONFIG }, path, error: "redteam.config.json is missing" };
  try {
    const value = JSON.parse(readFileSync(path, "utf8")) as Partial<RedteamConfig>;
    return {
      path,
      config: {
        ...DEFAULT_CONFIG,
        ...value,
        targets: strings(value.targets),
        excludeTargets: strings(value.excludeTargets),
        targetSources: strings(value.targetSources ?? DEFAULT_CONFIG.targetSources),
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
const RAW_SCAN_EXTENSIONS = new Set([".nessus", ".nmap", ".xml"]);

export function loadTargetSources(cwd: string, sources: string[]): { targets: string[]; warnings: string[] } {
  const targets = new Set<string>();
  const warnings: string[] = [];
  for (const source of sources) {
    const path = isAbsolute(source) ? source : resolve(cwd, source);
    if (!existsSync(path)) {
      warnings.push(`target source not found: ${source}`);
      continue;
    }
    collectTargetPath(path, targets, warnings);
  }
  return { targets: [...targets], warnings };
}

function collectTargetPath(path: string, targets: Set<string>, warnings: string[]): void {
  const stat = statSync(path);
  if (stat.isDirectory()) {
    for (const name of readdirSync(path)) collectTargetPath(join(path, name), targets, warnings);
    return;
  }
  const extension = extname(path).toLowerCase();
  if (RAW_SCAN_EXTENSIONS.has(extension)) {
    warnings.push(`refused raw scan file: ${path}`);
    return;
  }
  if (!ALLOWED_TARGET_EXTENSIONS.has(extension)) return;
  for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
    const clean = line.replace(/#.*$/, "").trim();
    if (!clean) continue;
    for (const token of clean.split(/[\s,]+/)) {
      const normalized = normalizeTarget(token);
      if (normalized) targets.add(normalized);
    }
  }
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

function inCidr(target: string, cidr: string): boolean {
  const [network, bitsText] = cidr.split("/");
  const ip = ipv4Number(target);
  const base = ipv4Number(network);
  const bits = Number(bitsText);
  if (ip === undefined || base === undefined || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ip & mask) === (base & mask);
}

export function matchesScope(targetValue: string, ruleValue: string): boolean {
  const target = normalizeTarget(targetValue);
  const rule = normalizeTarget(ruleValue);
  if (!target || !rule) return false;
  if (rule.includes("/")) return inCidr(target, rule);
  if (rule.startsWith("*.")) {
    const suffix = rule.slice(1);
    return target.endsWith(suffix) && target !== suffix.slice(1);
  }
  return target === rule;
}

export function scopeDecision(target: string, includes: string[], excludes: string[]): "included" | "excluded" | "unknown" {
  if (excludes.some((rule) => matchesScope(target, rule))) return "excluded";
  return includes.some((rule) => matchesScope(target, rule)) ? "included" : "unknown";
}

export function authorizationError(config: RedteamConfig, targetCount: number, now = new Date()): string | undefined {
  if (!config.engagement.trim()) return "engagement name is missing";
  if (targetCount === 0) return "scope has no targets";
  if (!/^\d{4}-\d{2}-\d{2}$/.test(config.authorizationExpires)) return "authorizationExpires must be YYYY-MM-DD";
  const end = new Date(`${config.authorizationExpires}T23:59:59Z`);
  if (Number.isNaN(end.valueOf())) return "authorizationExpires is invalid";
  if (now.valueOf() > end.valueOf()) return `authorization expired on ${config.authorizationExpires}`;
  return undefined;
}

export function mentionsRawScan(command: string): boolean {
  return /(?:^|[\s'"`])[^\s'"`]*\.(?:nessus|nmap|xml)(?:[\s'"`]|$)/i.test(command);
}

export function isActiveNetworkCommand(command: string): boolean {
  return /(?:^|[;&|]\s*|\b(?:sudo|env|timeout)\s+)(?:[\w./-]+\/)?(?:nmap|masscan|rustscan|nikto|gobuster|ffuf|feroxbuster|dirb|nuclei|sqlmap|hydra|medusa|netexec|nxc|crackmapexec|smbclient|rpcclient|enum4linux(?:-ng)?|ldapsearch|snmpwalk|whatweb|curl|wget|nc|netcat|openssl\s+s_client|msfconsole)\b/i.test(command.trim());
}

export function obviousTargets(command: string): string[] {
  const found = new Set<string>();
  for (const match of command.matchAll(/\bhttps?:\/\/[^\s'"`]+/gi)) {
    const value = normalizeTarget(match[0]);
    if (value) found.add(value);
  }
  for (const match of command.matchAll(/(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?(?![\w.])/g)) {
    const value = normalizeTarget(match[0]);
    if (value) found.add(value);
  }
  // Conservatively recognize dotted DNS names. Paths are excluded to avoid
  // treating /usr/share/wordlists/common.txt as a network target.
  for (const match of command.matchAll(/(?<![\/\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,62})\.)+[a-z][a-z0-9-]{0,62}(?![\/\w.-])/gi)) {
    const value = normalizeTarget(match[0]);
    if (value && !/\.(?:txt|list|csv|json|yaml|yml|xml|nessus|nmap)$/i.test(value)) found.add(value);
  }
  return [...found];
}
