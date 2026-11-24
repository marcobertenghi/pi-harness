import { basename, dirname, isAbsolute, relative, resolve } from "node:path";
import { explicitTargets, obviousTargets } from "./scope.ts";

// Heuristic shell inspection for the command guards. This is not a sandbox: it
// recognizes common command shapes and fails closed where a shape is ambiguous.

const ACTIVE_TOOLS = new Set([
  "nmap", "masscan", "rustscan", "zmap", "naabu", "nikto", "gobuster", "ffuf", "feroxbuster", "dirb", "dirsearch", "wfuzz",
  "nuclei", "sqlmap", "wpscan", "whatweb", "httpx", "katana", "hydra", "medusa", "kerbrute", "netexec", "nxc", "crackmapexec",
  "smbclient", "smbmap", "rpcclient", "rpcinfo", "showmount", "enum4linux", "enum4linux-ng", "ldapsearch", "ldapdomaindump",
  "snmpwalk", "onesixtyone", "nbtscan", "arp-scan", "curl", "wget", "aria2c", "lynx", "w3m", "nc", "netcat", "ncat", "socat",
  "telnet", "ftp", "tftp", "ssh", "scp", "sftp", "sshpass", "evil-winrm", "xfreerdp", "rdesktop", "ping", "ping6", "fping",
  "hping3", "traceroute", "tracepath", "mtr", "dig", "nslookup", "host", "dnsrecon", "dnsenum", "amass", "subfinder",
  "testssl", "testssl.sh", "sslscan", "sslyze", "msfconsole", "responder", "certipy", "bloodhound-python",
  "redis-cli", "mysql", "psql", "mongosh",
  "wafw00f", "ssh-audit", "ike-scan", "swaks", "smtp-user-enum", "whois", "theharvester", "shodan", "dnsx", "massdns", "puredns",
  "httpx-toolkit", "arjun", "gau", "waybackurls", "hakrawler", "gowitness", "eyewitness", "aquatone", "s3scanner", "cloud_enum",
  "chromium", "chromium-browser", "google-chrome", "firefox", "cutycapt", "wkhtmltoimage",
  "nmblookup", "snmp-check", "snmpget", "ntpq", "ldapwhoami", "wapiti", "commix", "dalfox", "tlsx", "asnmap", "fierce", "sublist3r",
]);

// Commands that run another command given in their arguments.
const WRAPPERS = new Set([
  "sudo", "doas", "su", "env", "timeout", "time", "nice", "ionice", "nohup", "stdbuf", "unbuffer", "setsid", "flock",
  "xargs", "parallel", "exec", "command", "builtin", "eval", "watch", "script", "strace", "ltrace", "proxychains",
  "proxychains4", "torsocks", "docker", "podman", "find", "bash", "sh", "zsh", "dash", "ksh",
  "if", "then", "else", "elif", "while", "until", "do", "!", "{",
]);

// Commands that only touch local files, so an address in their arguments is not a network contact.
const LOCAL_COMMANDS = new Set([
  "echo", "printf", "cat", "ls", "mkdir", "rmdir", "touch", "cp", "mv", "rm", "head", "tail", "grep", "egrep", "fgrep", "rg",
  "wc", "sort", "uniq", "cut", "tr", "tee", "jq", "sed", "awk", "diff", "cmp", "cd", "pwd", "date", "sleep", "true", "false",
  "test", "[", "[[", "export", "unset", "sha256sum", "md5sum", "file", "stat", "basename", "dirname", "chmod", "less",
  "more", "column", "nl", "seq", "read", "set", "local", "declare", "type", "which", "scanlens", "fi", "done",
]);

const NETWORK_DEVICE = /\/dev\/(?:tcp|udp)\/|\/inet[46]?\/(?:tcp|udp)\//;
const ASSIGNMENT = /^\w+=/;

/** Splits a command line into simple commands, each a list of words with quotes removed. */
export function shellSegments(command: string): string[][] {
  const segments: string[][] = [];
  let words: string[] = [];
  let word = "";
  let open = false;
  const endWord = () => { if (open) words.push(word); word = ""; open = false; };
  const endSegment = () => { endWord(); if (words.length) segments.push(words); words = []; };
  for (let index = 0; index < command.length; index++) {
    const char = command[index];
    if (char === "\\") {
      if (command[index + 1] === "\n") index++;
      else if (index + 1 < command.length) { word += command[++index]; open = true; }
    } else if (char === "'" || char === '"') {
      open = true;
      for (index++; index < command.length && command[index] !== char; index++) {
        if (char === '"' && command[index] === "\\" && index + 1 < command.length) index++;
        word += command[index];
      }
    } else if (";&|\n()`".includes(char)) endSegment();
    else if (/\s/.test(char)) endWord();
    else { word += char; open = true; }
  }
  endSegment();
  return segments;
}

// The command itself plus the text after each command substitution, so that a
// substitution inside double quotes is inspected as a command of its own.
function commandTexts(command: string): string[] {
  const texts = [command];
  for (const match of command.matchAll(/\$\(|<\(|`/g)) texts.push(command.slice(match.index + match[0].length));
  return texts;
}

function toolName(word: string | undefined): string {
  return (word ?? "").split("/").pop()!.toLowerCase();
}

function commandWord(words: string[]): number {
  let index = 0;
  while (index < words.length && ASSIGNMENT.test(words[index])) index++;
  return index;
}

function isActiveTool(name: string, words: string[]): boolean {
  if (name === "openssl") return words.includes("s_client");
  // Scanning a local folder is local work; every other source reaches a network service.
  if (name === "trufflehog") return !words.includes("filesystem");
  return ACTIVE_TOOLS.has(name) || name.startsWith("impacket-");
}

function segmentIsActive(words: string[], depth: number): boolean {
  const start = commandWord(words);
  const name = toolName(words[start]);
  if (isActiveTool(name, words)) return true;
  if (!WRAPPERS.has(name)) return false;
  // A wrapper may take options and operands before the wrapped command, so any
  // later word naming an active tool counts, as does a quoted command string.
  return words.slice(start + 1).some((word) =>
    /[\s;&|]/.test(word) ? depth < 4 && isActive(word, depth + 1) : isActiveTool(toolName(word), words));
}

function isActive(command: string, depth: number): boolean {
  if (NETWORK_DEVICE.test(command)) return true;
  return commandTexts(command).some((text) => shellSegments(text).some((words) => segmentIsActive(words, depth)));
}

/** True when the command runs a recognized network tool, directly or through a wrapper, subshell, or substitution. */
export function isActiveNetworkCommand(command: string): boolean {
  return isActive(command.trim(), 0);
}

/**
 * URLs and IP literals named by commands that are not plainly local file
 * utilities. Used to gate tools the active list does not know about, such as a
 * purpose-built script or an interpreter one-liner.
 */
export function networkReferences(command: string): string[] {
  const found = new Set<string>();
  for (const text of commandTexts(command)) {
    for (const words of shellSegments(text)) {
      const name = toolName(words[commandWord(words)]);
      if (name && LOCAL_COMMANDS.has(name)) continue;
      for (const target of explicitTargets(words.join(" "))) found.add(target);
    }
  }
  return [...found];
}

/**
 * Hostnames, URLs, and addresses passed as arguments to a script or binary kept
 * in the tools directory. A purpose-built tool is scope-checked like a known one,
 * so writing a tool never becomes a way around the scope guard.
 */
export function customToolTargets(command: string, cwd: string, toolsDir: string): string[] {
  const root = resolve(cwd, toolsDir);
  const found = new Set<string>();
  for (const text of commandTexts(command)) {
    for (const words of shellSegments(text)) {
      const start = commandWord(words);
      if (LOCAL_COMMANDS.has(toolName(words[start]))) continue;
      const tool = words.findIndex((word, index) => index >= start && !word.startsWith("-") && /[\w/]/.test(word) && isWithin(root, resolve(cwd, word)) && resolve(cwd, word) !== root);
      if (tool < 0) continue;
      for (const target of obviousTargets(words.slice(tool + 1).join(" "))) found.add(target);
    }
  }
  return [...found];
}

const RAW_SCAN_WORD = /\.(?:nessus|nmap|gnmap|xml)$/i;

/**
 * True when every raw scan file the command names is XML output that nmap itself
 * writes (-oX) into the agent's own scans directory. That is the one case where
 * a command may name a raw scan file: the result is imported, never read directly.
 */
export function ownScanOutput(command: string, cwd: string, scansDir: string): boolean {
  let outputs = 0;
  for (const words of shellSegments(command)) {
    for (const [index, word] of words.entries()) {
      if (!RAW_SCAN_WORD.test(word)) continue;
      const scanner = words.slice(0, index).some((item) => toolName(item) === "nmap");
      if (!scanner || words[index - 1] !== "-oX" || !isWithin(resolve(cwd, scansDir), resolve(cwd, word))) return false;
      outputs++;
    }
  }
  // Substitutions and quoted command strings are not unpacked here, so they fail closed.
  return outputs > 0 && !/\$\(|<\(|`/.test(command) && (command.match(/\.(?:nessus|nmap|gnmap|xml)(?![\w.])/gi) ?? []).length === outputs;
}

const FILE_WRITERS = new Set([
  "tee", "sed", "rm", "mv", "cp", "touch", "truncate", "dd", "install", "ln", "chmod", "chown", "rsync", "shred", "unlink", "patch",
  "vi", "vim", "nano", "ed",
]);
// For these, only the last operand is written to.
const COPY_COMMANDS = new Set(["cp", "rsync", "install", "ln"]);

/**
 * True when a command appears to create, change, or delete one of the protected
 * files or anything inside a protected directory. Reading them stays allowed,
 * so `nmap -iL targets/hosts.txt` passes while `echo x >> targets/hosts.txt` does not.
 */
export function writesProtectedPath(command: string, cwd: string, protectedPaths: string[]): boolean {
  const segments = commandTexts(command).flatMap(shellSegments);
  // A `cd` into a protected directory makes later relative names resolve inside it.
  const entered = segments.filter((words) => ["cd", "pushd"].includes(toolName(words[0])) && words[1])
    .map((words) => resolve(cwd, words[1])).filter((path) => protectedPaths.some((target) => isWithin(target, path)));
  for (const words of segments) {
    const names = words.map(toolName);
    const redirects = words.some((word) => /^\d*>/.test(word));
    const writers = names.filter((name) => FILE_WRITERS.has(name));
    if (!redirects && !writers.length) continue;
    const copyOnly = !redirects && writers.every((name) => COPY_COMMANDS.has(name));
    for (const raw of copyOnly ? words.slice(-1) : words) {
      const word = raw.replace(/^\d*>+&?/, "").replace(/^--?[\w-]+=/, "");
      if (!word || word.startsWith("-")) continue;
      const bases = [cwd, ...entered];
      for (const base of bases) {
        const path = resolve(base, word);
        if (protectedPaths.some((target) => isWithin(target, path))) return true;
        if (/[*?[]/.test(word) && protectedPaths.some((target) => globPattern(word).test(relative(cwd, target)) || globPattern(word).test(basename(target)))) return true;
      }
    }
  }
  return false;
}

function globPattern(glob: string): RegExp {
  const body = glob
    .replace(/[.+^${}()|\\]/g, "\\$&")
    .replace(/\*\*/g, "\u0000")
    .replace(/\*/g, "[^/]*")
    .replace(/\u0000/g, ".*")
    .replace(/\?/g, "[^/]");
  try { return new RegExp(`^${body}$`); } catch { return /^$/; }
}

function isWithin(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

/**
 * True when a shell command appears to touch the protected file or its
 * directory: by literal path, by its file name, through a glob, after a `cd`
 * toward it, or by deleting or moving a parent directory.
 */
export function referencesProtectedPath(command: string, cwd: string, configuredFile: string): boolean {
  const file = resolve(cwd, configuredFile);
  const directory = dirname(file);
  const unquoted = command.replace(/['"\\]/g, "").replace(/\/(?:\.?\/)+/g, "/");
  const literals = [configuredFile, file, directory, basename(file)];
  if (dirname(configuredFile) !== ".") literals.push(dirname(configuredFile));
  if (literals.some((path) => unquoted.includes(path))) return true;

  // Parents of the protected directory, up to and including the working directory.
  const parents: string[] = [];
  if (isWithin(cwd, directory)) {
    for (let path = dirname(directory); isWithin(cwd, path); path = dirname(path)) {
      parents.push(path);
      if (path === dirname(path)) break;
    }
  }
  const segments = commandTexts(command).flatMap(shellSegments);
  const words = segments.flat();
  const names = new Set(words.map(toolName));
  const destructive = ["rm", "mv", "shred", "truncate", "unlink", "rmdir"].some((name) => names.has(name))
    || (names.has("find") && words.some((word) => ["-delete", "-exec", "-execdir", "-ok"].includes(word)));
  // After a directory change, relative words may resolve from a parent of the protected directory.
  const changesDirectory = ["cd", "pushd", "chdir"].some((name) => names.has(name)) || words.includes("-C");
  const bases = changesDirectory ? [cwd, ...parents.filter((path) => path !== cwd)] : [cwd];

  for (const raw of words) {
    const word = (raw.startsWith("-") && raw.includes("=") ? raw.slice(raw.indexOf("=") + 1) : raw).replace(/\/+$/, "") || "/";
    if (word.startsWith("-")) continue;
    for (const base of bases) {
      if (/[*?[]/.test(word)) {
        const pattern = globPattern(word);
        const matches = (path: string) => pattern.test(path) || pattern.test(relative(base, path)) || pattern.test(`./${relative(base, path)}`);
        if (matches(file) || matches(directory) || (destructive && parents.some(matches))) return true;
      } else {
        const path = resolve(base, word);
        if (isWithin(directory, path) || (destructive && parents.includes(path))) return true;
      }
    }
  }
  return false;
}
