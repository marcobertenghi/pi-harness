import { shellSegments } from "./shell.ts";

// The ask-first tier. Arming removes the prompt for ordinary in-scope checks;
// the actions recognized here always go to the operator, armed or not, because
// they change state, use a credential, or are intrusive by nature. Recognition
// reads the command line, like the rest of the guard: it covers the usual forms
// of known tools, not what a purpose-built script does internally.

const name = (word: string | undefined) => (word ?? "").split("/").pop()!.toLowerCase();
const has = (words: string[], ...flags: string[]) => words.some((word) => flags.some((flag) => word === flag || word.startsWith(`${flag}=`)));
/** Value of an option given as `-x value`, `--long value`, `--long=value`, or `-xvalue`. */
function option(words: string[], ...flags: string[]): string | undefined {
  for (const [index, word] of words.entries()) {
    for (const flag of flags) {
      if (word === flag) return words[index + 1] ?? "";
      if (word.startsWith(`${flag}=`)) return word.slice(flag.length + 1);
      if (!flag.startsWith("--") && flag.length === 2 && word.startsWith(flag) && word.length > 2) return word.slice(2);
    }
  }
  return undefined;
}

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
// Tools whose normal use is a login attempt or an authenticated session.
const LOGIN_CLIENTS = new Set(["ssh", "scp", "sftp", "sshpass", "telnet", "ftp", "tftp", "xfreerdp", "rdesktop", "evil-winrm", "mysql", "psql", "mongosh", "redis-cli"]);
const CREDENTIAL_ATTACKS = new Set(["hydra", "medusa", "kerbrute", "ncrack", "patator", "crowbar"]);
const AUTH_OPTIONAL = new Set(["nxc", "netexec", "crackmapexec", "cme", "smbmap", "enum4linux", "enum4linux-ng", "certipy", "bloodhound-python", "ldapdomaindump"]);
const INTRUSIVE_TOOLS = new Set(["sqlmap", "commix", "dalfox", "wapiti", "msfconsole", "responder", "hping3", "nikto", "wpscan"]);
const PATH_BRUTE_FORCE = new Set(["ffuf", "gobuster", "feroxbuster", "dirb", "dirsearch", "wfuzz", "arjun"]);
const NMAP_INTRUSIVE = /\b(?:brute|dos|exploit|intrusive|vuln|fuzzer|malware|external)\b|-brute\b|\*/i;
const NUCLEI_INTRUSIVE = /\b(?:dos|fuzz|fuzzing|intrusive|bruteforce|brute-force|exploit|rce)\b/i;
const ALL_TOOLS = new Set([...LOGIN_CLIENTS, ...CREDENTIAL_ATTACKS, ...AUTH_OPTIONAL, ...INTRUSIVE_TOOLS, ...PATH_BRUTE_FORCE,
  "curl", "wget", "httpx-toolkit", "nmap", "masscan", "zmap", "nuclei", "smbclient", "rpcclient", "ldapsearch", "trufflehog"]);

// Commands that run another command given in their arguments.
const RUNNERS = new Set(["sudo", "doas", "env", "timeout", "time", "nice", "ionice", "nohup", "stdbuf", "setsid", "xargs", "parallel", "exec", "command", "eval", "watch",
  "proxychains", "proxychains4", "torsocks", "bash", "sh", "zsh", "dash", "ksh", "if", "then", "else", "elif", "while", "until", "do", "!", "{"]);

/** Index of the command word: past variable assignments. */
function commandIndex(words: string[]): number {
  let index = 0;
  while (index < words.length && /^\w+=/.test(words[index])) index++;
  return index;
}

function segmentReason(words: string[]): string | undefined {
  const first = commandIndex(words);
  const known = (word: string) => ALL_TOOLS.has(name(word)) || name(word).startsWith("impacket-");
  // The tool is the command itself, or follows a runner such as sudo or timeout.
  const start = known(words[first] ?? "") ? first : RUNNERS.has(name(words[first])) ? words.findIndex((word, index) => index > first && known(word)) : -1;
  if (start < 0) return undefined;
  const tool = name(words[start]);
  const args = words.slice(start + 1);
  if (tool.startsWith("impacket-")) return `${tool} opens an authenticated or relay session`;
  if (CREDENTIAL_ATTACKS.has(tool)) return `${tool} guesses credentials and can lock accounts`;
  if (LOGIN_CLIENTS.has(tool)) return `${tool} is a login attempt against the target`;
  if (INTRUSIVE_TOOLS.has(tool)) return `${tool} sends attack payloads or a large volume of probes`;
  if (PATH_BRUTE_FORCE.has(tool)) return `${tool} brute-forces paths or parameters`;
  if (AUTH_OPTIONAL.has(tool) && has(args, "-u", "-p", "-H", "--hashes", "-k", "--kerberos", "--use-kcache", "--local-auth")) return `${tool} is given credentials to try`;
  if (tool === "smbclient" || tool === "rpcclient") {
    if (has(args, "-U", "--user", "-N", "--no-pass", "-A", "--authentication-file", "--pw-nt-hash")) return `${tool} opens a session (credentials or a null session)`;
  }
  if (tool === "ldapsearch" && has(args, "-D", "-w", "-W", "-y", "-Y")) return "ldapsearch binds with credentials";
  if (tool === "curl") {
    const method = option(args, "-X", "--request")?.toUpperCase();
    if (method && !SAFE_METHODS.has(method)) return `curl sends a state-changing ${method} request`;
    if (has(args, "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii", "--json", "-F", "--form", "--form-string", "-T", "--upload-file")
      || args.some((word) => /^-[a-zA-Z]*[dFT]$/.test(word) && !word.startsWith("--"))) return "curl sends a request body";
    if (has(args, "-u", "--user", "--oauth2-bearer", "--negotiate", "--ntlm", "-E", "--cert") || args.some((word) => /^(?:authorization|cookie|x-api-key)\s*:/i.test(word))) {
      return "curl sends credentials or a session token";
    }
  }
  if (tool === "wget") {
    const method = option(args, "--method")?.toUpperCase();
    if ((method && !SAFE_METHODS.has(method)) || has(args, "--post-data", "--post-file", "--body-data", "--body-file")) return "wget sends a state-changing request";
    if (has(args, "--user", "--password", "--http-user", "--http-password") || args.some((word) => /^--header=(?:authorization|cookie)\s*:/i.test(word))) return "wget sends credentials";
  }
  if (tool === "httpx-toolkit") {
    const method = option(args, "-x")?.toUpperCase();
    if (method && method.split(",").some((item) => !SAFE_METHODS.has(item.trim()))) return `httpx-toolkit sends ${method} requests`;
    if (has(args, "-body")) return "httpx-toolkit sends a request body";
  }
  if (tool === "nmap") {
    const scripts = [option(args, "--script"), option(args, "--script-args"), option(args, "--script-args-file")].filter((value) => value !== undefined).join(" ");
    if (scripts && NMAP_INTRUSIVE.test(scripts)) return "nmap runs brute-force, exploit, vulnerability, or other intrusive scripts";
    if (has(args, "-T5", "-T4", "--min-rate") || args.includes("insane") || args.includes("aggressive")) return "nmap runs at an aggressive rate";
  }
  if (tool === "masscan" || tool === "zmap") {
    const rate = Number(option(args, "--rate", "-r", "--max-rate"));
    if (!Number.isFinite(rate) || rate > 1000) return `${tool} runs without a rate limit of 1000 packets per second or less`;
  }
  if (tool === "nuclei") {
    if (has(args, "-dast", "-fuzz", "-itags", "-include-tags", "-code", "-headless")) return "nuclei runs fuzzing, code, or normally excluded templates";
    const chosen = [option(args, "-tags"), option(args, "-t", "-templates"), option(args, "-id", "-template-id")].filter(Boolean).join(" ");
    if (chosen && NUCLEI_INTRUSIVE.test(chosen)) return "nuclei is pointed at intrusive templates";
    if (!has(args, "-ni", "-no-interactsh")) return "nuclei runs with outside interaction servers enabled (-ni is missing)";
  }
  if (tool === "trufflehog" && !has(args, "--no-verification")) return "trufflehog would try each found credential against its live service (--no-verification is missing)";
  return undefined;
}

/**
 * Why a command belongs to the ask-first tier, or undefined when it does not.
 * The operator is asked for each such command even while checks are armed.
 */
export function askFirstReason(command: string, depth = 0): string | undefined {
  for (const words of shellSegments(command)) {
    const direct = segmentReason(words);
    if (direct) return direct;
    // A quoted command string handed to a shell or wrapper.
    for (const word of RUNNERS.has(name(words[commandIndex(words)])) ? words : []) {
      if (depth < 3 && /\s/.test(word)) {
        const nested = askFirstReason(word, depth + 1);
        if (nested) return nested;
      }
    }
  }
  return undefined;
}
