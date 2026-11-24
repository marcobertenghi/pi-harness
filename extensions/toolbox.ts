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

/** The additions that widen the agent's reach the most, in order. Shown first when they are missing. */
export const RECOMMENDED = ["nuclei", "httpx-toolkit", "subfinder", "dnsx", "nxc", "gowitness", "trufflehog"];

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
    ...(status.missing.some((tool) => RECOMMENDED.includes(tool.name))
      ? ["Recommended first:", `  ${installCommand(RECOMMENDED.flatMap((name) => status.missing.filter((tool) => tool.name === name)))}`, ""]
      : []),
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

const TEMPLATE_DIRECTORIES = ["nuclei-templates", ".local/nuclei-templates", ".local/share/nuclei-templates"];

export function nucleiTemplatesInstalled(home = process.env.HOME ?? ""): boolean {
  return [...TEMPLATE_DIRECTORIES.map((directory) => join(home, directory)), "/usr/share/nuclei-templates"].some((directory) => {
    try { accessSync(directory, constants.R_OK); return true; } catch { return false; }
  });
}

/**
 * How the agent is to use the installed tools: in what order, for which
 * question, and with which limits. Only installed tools are mentioned.
 */
export function toolPlaybook(status: ToolboxStatus, evidenceDir: string, options: { nucleiTemplates?: boolean } = {}): string[] {
  const has = (name: string) => status.installed.includes(name);
  const recon = `${evidenceDir}/recon`;
  const steps: string[] = [];
  if (has("subfinder")) steps.push(`subfinder — names under an in-scope domain from passive sources. It sends the domain to third parties, so run it only while discovery mode is on: subfinder -d DOMAIN -silent -o ${recon}/subfinder-DOMAIN.txt. Names covered by an authorized wildcard are yours to work on; every other name goes to redteam_proposals and is not resolved or contacted.`);
  if (has("dnsx")) steps.push(`dnsx — which in-scope names exist and where they point: dnsx -l NAME1,NAME2 -a -cname -resp -silent -duc -rl 50 -o ${recon}/dnsx-BATCH.txt. A CNAME to a third-party service that no longer answers is a takeover lead: record it as a suspected finding.`);
  if (has("httpx-toolkit")) steps.push(`httpx-toolkit — what answers on the web, for many hosts in one pass: httpx-toolkit -u HOST1,HOST2 -sc -title -td -server -location -ct -cl -ip -silent -duc -rl 20 -t 10 -j -o ${recon}/httpx-BATCH.jsonl. Use the result to rank endpoints (admin and login pages, unusual technology, redirects) and to choose what to screenshot and scan.`);
  if (has("nmap")) steps.push("nmap — ports, services, and versions where scan data is missing or thin, as described under SCANNING.");
  if (has("nxc")) steps.push("nxc — what an exposed SMB, LDAP, WinRM, RDP, MSSQL, SSH, or FTP service reveals without credentials: nxc smb HOST (likewise ldap, winrm, rdp, mssql, ssh, ftp). It reports host name, domain, OS, and signing. Null or anonymous sessions and every use of a credential need the operator's approval first; never spray or guess passwords.");
  if (has("testssl") || has("sslscan")) steps.push(`${has("testssl") ? "testssl" : "sslscan"} — TLS configuration of a service that matters, once per distinct server, not per route.`);
  if (has("nuclei")) steps.push(options.nucleiTemplates === false
    ? "nuclei — installed, but its templates are not: tell the operator under NEED to run `nuclei -ut` once, and do not run it until then."
    : `nuclei — known vulnerabilities and misconfigurations, aimed by what httpx-toolkit and the scans found, not sprayed at everything: nuclei -u URL1 -u URL2 -as -ni -duc -rl 20 -c 5 -etags dos,fuzz,intrusive,bruteforce -o ${recon}/nuclei-BATCH.txt, or -tags TECHNOLOGY for a specific product. Always pass -ni and the excluded tags. A hit is a lead: record it as a suspected finding and validate it independently before calling it validated.`);
  if (has("trufflehog")) steps.push("trufflehog — secrets in files you already collected under the evidence directory: trufflehog filesystem DIR --no-verification --no-update. Always pass --no-verification: without it the tool tries each credential against its live service. Values go to the loot folder and the credential ledger, never into a reply.");
  if (!steps.length) return [];
  return [
    "TOOL PLAYBOOK: use the installed tools deliberately, in this order, each for the question it answers. Before a run, know which question it settles; after it, read the output, record what it established in coverage or findings, and decide the next step from the result rather than running the next tool by habit.",
    ...steps.map((step, index) => `${index + 1}. ${step}`),
    `Rules for all of them: pass targets on the command line, at most about 20 per run, never through a list file, because the scope guard reads the command line and blocks a network tool that names no target. Keep the rate limits shown or lower. Write output under ${recon} and cite it. Do not repeat a run whose answer you already have, and do not run a tool only because it is installed. When two tools disagree, say so and settle it with a third observation.`,
  ];
}
