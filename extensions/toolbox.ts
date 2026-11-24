import { accessSync, constants } from "node:fs";
import { delimiter, join } from "node:path";

// The tools an external assessment draws on, by purpose. Used to tell the
// operator what is missing on this machine and the agent what it can rely on.

export interface ToolEntry { name: string; package?: string; note?: string }
export interface ToolCategory { title: string; essential?: boolean; tools: ToolEntry[] }

export const TOOLBOX: ToolCategory[] = [
  { title: "Core", essential: true, tools: [
    { name: "scanlens" }, { name: "curl" }, { name: "jq" }, { name: "openssl" }, { name: "dig", package: "bind9-dnsutils" },
    { name: "whois" }, { name: "ncat" }, { name: "git" }, { name: "python3" },
  ] },
  { title: "Ports and services", tools: [
    { name: "nmap" }, { name: "masscan" }, { name: "naabu" }, { name: "ssh-audit" }, { name: "ike-scan" }, { name: "snmpwalk", package: "snmp" },
    { name: "smbclient" }, { name: "nxc", package: "netexec" }, { name: "enum4linux-ng" }, { name: "ldapsearch", package: "ldap-utils" }, { name: "swaks" },
  ] },
  { title: "Web", tools: [
    { name: "httpx-toolkit", note: "ProjectDiscovery httpx; plain `httpx` on Kali is a different Python client" },
    { name: "whatweb" }, { name: "wafw00f" }, { name: "nuclei" }, { name: "nikto" }, { name: "ffuf" }, { name: "feroxbuster" }, { name: "gobuster" },
    { name: "katana" }, { name: "arjun" }, { name: "sqlmap" }, { name: "wpscan" },
  ] },
  { title: "TLS", tools: [{ name: "testssl", package: "testssl.sh" }, { name: "sslscan" }, { name: "sslyze" }] },
  { title: "DNS and names", tools: [
    { name: "subfinder" }, { name: "amass" }, { name: "dnsx" }, { name: "massdns" }, { name: "dnsrecon" }, { name: "theHarvester", package: "theharvester" },
  ] },
  { title: "Exposure and leaks", tools: [
    { name: "gau", package: "getallurls" }, { name: "trufflehog" }, { name: "gitleaks" }, { name: "s3scanner" }, { name: "cloud_enum", package: "cloud-enum" }, { name: "shodan", package: "python3-shodan" },
  ] },
  { title: "Screenshots", tools: [{ name: "gowitness" }, { name: "chromium" }] },
  { title: "Building your own tools", tools: [
    { name: "python3" }, { name: "pip", package: "python3-pip" }, { name: "pipx" }, { name: "go", package: "golang-go" }, { name: "gcc" }, { name: "make" }, { name: "node", package: "nodejs" },
  ] },
];

export function onPath(command: string, path = process.env.PATH ?? ""): boolean {
  return path.split(delimiter).filter(Boolean).some((directory) => {
    try { accessSync(join(directory, command), constants.X_OK); return true; } catch { return false; }
  });
}

export interface ToolboxStatus { categories: { title: string; essential: boolean; installed: string[]; missing: ToolEntry[] }[]; installed: string[]; missing: ToolEntry[] }

export function toolboxStatus(available: (command: string) => boolean = onPath): ToolboxStatus {
  const categories = TOOLBOX.map((category) => ({
    title: category.title, essential: category.essential === true,
    installed: category.tools.filter((tool) => available(tool.name)).map((tool) => tool.name),
    missing: category.tools.filter((tool) => !available(tool.name)),
  }));
  const unique = <T>(items: T[], key: (item: T) => string) => [...new Map(items.map((item) => [key(item), item])).values()];
  return { categories, installed: unique(categories.flatMap((category) => category.installed), (name) => name),
    missing: unique(categories.flatMap((category) => category.missing), (tool) => tool.name) };
}

export function installCommand(missing: ToolEntry[]): string {
  return `sudo apt update && sudo apt install -y ${[...new Set(missing.map((tool) => tool.package ?? tool.name))].join(" ")}`;
}

export function toolboxText(status: ToolboxStatus, wordlists: boolean): string {
  const lines = status.categories.flatMap((category) => [
    `${category.missing.length ? (category.essential ? "✗" : "○") : "✓"} ${category.title}`,
    ...(category.installed.length ? [`    installed: ${category.installed.join(", ")}`] : []),
    ...(category.missing.length ? [`    missing:   ${category.missing.map((tool) => tool.name).join(", ")}`] : []),
    ...category.missing.filter((tool) => tool.note).map((tool) => `    note: ${tool.name} — ${tool.note}`),
  ]);
  return [
    `Tools on this machine — ${status.installed.length} installed, ${status.missing.length} missing`,
    "",
    ...lines,
    `${wordlists ? "✓" : "○"} Wordlists`,
    `    ${wordlists ? "/usr/share/seclists found" : "/usr/share/seclists not found (package seclists)"}`,
    "",
    ...(status.missing.length
      ? ["Install what is missing (run it yourself; the agent does not install system packages):", `  ${installCommand(status.missing)}`]
      : ["Nothing is missing."]),
    "",
    "The agent is told which of these are installed. Where a tool is missing or none fits, it writes its own under the tools directory.",
  ].join("\n");
}

/** One line for the agent: what it can rely on, and what is absent so it does not try. */
export function toolboxBrief(status: ToolboxStatus): string {
  return `Installed assessment tools: ${status.installed.join(", ") || "none detected"}. Not installed: ${status.missing.map((tool) => tool.name).join(", ") || "nothing"}.${
    status.missing.some((tool) => tool.name === "httpx-toolkit") ? "" : " Use httpx-toolkit for ProjectDiscovery httpx; plain httpx is a different Python client."}`;
}
