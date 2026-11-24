# Minimal red-team agent for Pi

A scope-aware, operator-supervised red-team workflow for [Pi](https://github.com/earendil-works/pi) and `scanlens`.

The package adds:

- a red-team skill for scan-first triage, safe validation, and evidence-based reporting;
- a `security-findings` skill for English/German client-facing findings, OSSTMM classification, and management summaries;
- `redteam_scope`, which resolves explicit scope and approved target inventories;
- a constrained `scanlens` wrapper that queries imported scan data without opening raw scans;
- `redteam_audit`, a query interface for the append-only, hash-chained activity log;
- `redteam_coverage`, a resumable black-box evidence queue;
- a `/rt` operator menu and status panel, plus `/rt-setup`, `/rt-status`, `/rt-onboard`, `/rt-offboard`, `/rt-steer`, `/rt-tasks`, `/rt-discover`, `/rt-endpoints`, `/rt-arm`, `/rt-disarm`, `/rt-log`, `/rt-coverage`, `/rt-targets`, `/rt-progress`, and `/rt-admin` commands;
- gates for authorization expiry, target scope, exclusions, raw scan access, and active network checks;
- dedicated `.redteam/evidence` and `.redteam/tools` workspaces.

This is not an autonomous exploitation framework. Written authorization and operator oversight remain mandatory. The harness does not permit persistence, destructive actions, denial of service, uncontrolled credential attacks, or bypassing scope and approval controls.

## Requirements

- Node.js **22.19 or newer**;
- Pi installed and available as `pi`;
- `scanlens` installed and available on `PATH`;
- written authorization with an expiry date and explicit target scope;
- an interactive Pi session for the setup wizard and approval dialogs.

Quick checks:

```bash
node --version
pi --version
scanlens --help
```

The package does not install `scanlens`, import scans, or grant authorization.

## Quick start

### 1. Install development dependencies

From the package root:

```bash
npm install
npm test
npm run check
```

### 2. Load the package

For one Pi invocation without changing settings:

```bash
pi -e .
```

Or register it as a project-local Pi package:

```bash
pi install --local .
```

A local install writes a package declaration under `.pi/settings.json`. Pi loads project packages only after project trust is granted. Use `pi list` to confirm configured packages. If Pi is already running, use `/reload` after installation or source changes.

### 3. Start with `/rt-start`

In a new engagement folder, run:

```text
/rt-start
```

It inspects the folder and prints a numbered checklist: describe the engagement, add the authorized targets, import the scan results, and (optionally) decide on discovery. For each open step it gives the exact folder to put files in or the command to run, including the `scanlens import` command with this folder's database path. If there is no valid configuration it offers to run the setup wizard, and if no target file exists it offers to create a commented template that adds no scope until you fill it in. Run it again at any time to see what is left; the sections below describe each step in detail.

### 3a. The setup wizard

If `redteam.config.json` is missing, invalid, expired, or still contains example values, the extension automatically offers setup. You can start it explicitly at any time:

```text
/rt-setup
```

The wizard asks for:

1. engagement or written-authorization reference;
2. authorization expiry in `YYYY-MM-DD` form, inclusive in UTC;
3. explicit included targets;
4. exclusions;
5. approved target inventory files or directories;
6. the `scanlens` database path;
7. evidence, tools, and audit paths;
8. final operator review and confirmation.

Setup performs no network access and imports no scans. It never arms active checks and leaves arming as you set it. Escape, a declined confirmation, or an error before saving leaves the existing configuration unchanged.

### 4. Add authorized targets

You can enter targets directly in the wizard or place them in `.txt`, `.list`, or simple `.csv` files under the configured inventory directory. The default is `targets/`.

Example `targets/approved.txt`:

```text
# Only targets covered by written authorization
10.20.0.0/24
app.example.test
*.lab.example.test
```

Use exact IPs, hostnames, IPv4 CIDRs, wildcard subdomains, or absolute HTTP(S) URLs. Do not put commands or credentials in target inventory files.

For an HTTP(S) URL, the hostname is added to scope and the complete URL path is preserved as a **priority web endpoint**. This matters when a scanner covers only the host or root service. `/rt-status` reports the endpoint count, and `redteam_scope` returns the normalized endpoint list for explicit route-level review. URL query strings and fragments are removed to avoid importing tokens or other sensitive values; credential-bearing or unsupported URLs are rejected. A `*` in a path is a route-family marker, not permission to brute-force or automatically expand paths.

A directory name is only a place to look for inventory—it is not scope by itself. The wizard can save configuration before the directory contains targets, but authorization remains invalid and active checks remain blocked until at least one authorized target is loaded. Inventory is reread automatically; after adding targets, run `/rt-status` without rerunning setup or reloading.

The inventory question defaults to `targets/`. Press Enter to accept it or enter `-` to configure no inventory sources. The wizard creates the default directory if needed; custom directories remain operator-managed.

### 5. Import scans outside the agent

Set `scanlensDb` to an existing scanlens SQLite database. Raw Nessus and Nmap files must stay outside the agent workflow. Import them directly as the human operator:

```bash
scanlens import --help
scanlens import /path/to/operator-controlled/scans
```

The default database path is `scanlens.db` in the package root. Missing scan data does not prevent saving setup, but scan triage cannot proceed until the database exists.

Never ask Pi to read raw `.nessus`, `.nmap`, `.gnmap`, or Nmap XML files. Use `scanlens` queries instead.

### 6. Start an engagement

Inside Pi:

```text
/rt-status
/skill:redteam triage the current engagement
```

You can also use a normal request such as:

```text
Carry out the authorized red-team engagement according to the red-team workflow.
```

The skill begins by checking authorization and scope, querying `scanlens guide` and `scanlens summary`, and ranking a short hypothesis queue. For external perimeter reviews it also makes a dedicated pass over informational Nessus results (`scanlens` tool: `operation: "findings"`, `severity: "info"`) and the service inventory, even when no vulnerabilities were flagged. For each priority service it records corroboration, a material evidence gap for the operator, or why further collection would not change the conclusion.

## Operator commands

| Command | Purpose |
|---|---|
| `/rt` | Open the menu: workflow checklist, recommended next steps, and every operator action. |
| `/rt-start` | Guided start: checks the engagement folder, offers the setup wizard and a target-file template, and lists what is still missing with the exact location or command. |
| `/rt-help` | Show the operator guide with all commands grouped by purpose. |
| `/rt-setup` | Run the interactive configuration wizard. Never arms active checks. |
| `/rt-tools` | Check which assessment tools are installed on this machine, by purpose, and print one command that installs the rest. |
| `/rt-status` | Show authorization, the workflow checklist, and what to do next. |
| `/rt-onboard HOST` | Add one exact host or IP to scope after confirming written authorization. |
| `/rt-offboard [HOST]` | Take one exact host out of scope: removes an explicit target, or adds an exclusion when an inventory file or range still covers it. |
| `/rt-discover` | Show discovery status: mode, remaining budget, approved passive sources, authorized wildcards and ranges. |
| `/rt-discover on [BUDGET]` / `off` | Let the agent send up to BUDGET bounded discovery requests (default `discoveryBudget`), or stop discovery. |
| `/rt-discover allow HOST` / `deny HOST` | Approve or remove a third-party passive source such as `crt.sh`. |
| `/rt-endpoints [all]` | Review routes discovered on in-scope hosts; `accept`, `defer`, or `reject` a URL or `all`. |
| `/rt-steer` | Pick a ready-made instruction for the agent; it is placed in the editor for review before sending. |
| `/rt-tasks [all]` | Open-work board: what needs the operator, what the agent can continue, and tracked tasks. |
| `/rt-tasks add TEXT` / `done ID` / `reopen ID` | Track, close, or reopen a follow-up task. |
| `/rt-findings [all]` | Findings register grouped by status: validated, suspected, reported. `/rt-findings ID` shows one in the house format. |
| `/rt-findings validate\|report\|dismiss\|reopen ID` | Record your decision on one finding. Validating needs affected systems, a description, and evidence. |
| `/rt-creds` | Captured credentials: account, where found, which evidence file holds the value, and where it was tried. |
| `/rt-report` | Write a draft client report to `evidenceDir/reports/` from the findings register, coverage, and audit log. |
| `/rt-handover` | Write a handover note to `evidenceDir/handover/`: state, next steps, open questions, findings, and what did not work. |
| `/rt-arm` | After operator confirmation, allow in-scope active checks for the current runtime. |
| `/rt-disarm` | Immediately return to per-command approval mode. |
| `/rt-log` | Show the 20 most recent audit events. |
| `/rt-log failures` | Show recent failed or blocked actions. |
| `/rt-log target 10.20.0.42` | Show audit activity for one target. |
| `/rt-log verify` | Verify the audit hash chain. |
| `/rt-coverage` | Show current coverage counts. Add a state, e.g. `/rt-coverage pending`, for a sample. |
| `/rt-coverage reconcile [state]` | Include open in-scope Scanlens services, even if they have never been reviewed. |
| `/rt-proposals [all]` | Open an interactive proposal and disposition picker; `all` also includes previously reviewed proposals. |
| `/rt-proposals deferred\|rejected\|onboarded HOST` | Directly confirm and record a lead decision; onboarding can add only the confirmed exact host. |
| `/rt-targets [all\|onboarded\|baseline\|routes]` | Show effective host scope and a separate source-attributed list of exact priority URLs/full paths. |
| `/rt-progress` | Reconcile coverage and show completion, open items, missing facts, pending proposals, and resolution guidance. |
| `/rt-admin` | Open an interactive administration menu for scope and progress views. |
| `/skill:redteam …` | Invoke the red-team workflow explicitly. |
| `/skill:security-findings …` | Draft, revise, classify, or summarise client-facing findings. |

The model-facing tools are normally called by the agent rather than typed as slash commands.

## Operator guide

A three-line panel above the editor is always visible in interactive mode and refreshes after every `/rt` command, agent run, and tracking-tool call:

```text
RT ▸ Fixture · authorized to 2027-01-31 (68d) · ○ disarmed · ◇ discovery off
Scope 4 target(s), 1 excluded · Coverage ███████░░░░░ 60% (6/10) · pending 4 · Needs you 2 · Proposals 1 · Findings 3✓ 2?
Next: /rt-proposals — Review scope proposals (1 host(s) proposed by the agent await your decision) · /rt opens the menu
```

`/rt` is the entry point. It prints a numbered workflow checklist (`✓` done, `▸` you are here, `○` later, `✗` blocked), lists what you can do next with the reason for each, and opens a menu that leads with those recommendations and can start every other action. `/rt-status` prints the same checklist without the menu.

Changing scope during an engagement:

- `/rt-onboard HOST` adds one exact host or IP. It asks you to confirm that written authorization covers it, appends only that host to `targets`, and records a `scope_target_onboarded` audit event. `/rt-targets` then marks it `★ ONBOARDED`.
- `/rt-offboard HOST` takes one exact host out. An explicit target is removed from `targets`; a host that an inventory file, CIDR, or wildcard still covers is added to `excludeTargets` instead, because inventory files are never edited. The confirmation dialog states which of the two will happen. Evidence and coverage notes are kept.
- `/rt-proposals` decides hosts the agent proposed. Ranges, wildcards, and removing an exclusion still go through `/rt-setup`.

Steering: `/rt-steer` offers instructions such as "Start scan triage", "Continue the coverage review", "Report where we stand", and "Pause active work", ordered by relevance to the current stage. The chosen text goes into the editor, so you can edit it before pressing Enter. A message sent while the agent is working is delivered as steering; Escape interrupts it.

Objective and reporting: the agent's standing orders are to drive coverage to 100% and pending to 0, working through pending items in batches without asking whether to continue, and to park what it cannot settle as waiting on the operator, unresolved from outside, or blocked. It reports as a short operator brief ending in four fixed lines (`STATUS`, `FOUND`, `NEED`, `NEXT`), with detail in evidence files. Before ending a run it publishes its recommended next steps through the `redteam_next` tool; they appear at the top of `/rt-steer` as "★ Agent recommends", and the first one becomes the panel's "Next:" line once nothing is waiting on you. The panel also shows the pending count next to the coverage percentage.

Tracking: `/rt-tasks` separates work that needs you (configuration problems, an expiring authorization, coverage items waiting on a fact, pending proposals) from work the agent can continue (pending and blocked coverage) and lists tracked tasks. You add tasks with `/rt-tasks add TEXT`; the agent adds and closes its own through the `redteam_tasks` tool. Tasks are stored per engagement in the audit database, and every add, close, and reopen is an audit event. Tasks are notes and never change scope or authorization.

## Findings, credentials, report, and handover

**Findings register.** The agent records every plausible issue with the `redteam_findings` tool as soon as it sees it, as `suspected`, and fills in the house-format fields (affected systems, description, evidence, risk, mitigation, OSSTMM category, three ratings) as evidence arrives. A finding can only become `validated` once affected systems, a description, and at least one evidence line exist; that rule applies to you as well. Only you mark a finding `reported` or `dismissed`, and the agent cannot edit either until you reopen it. The panel shows `Findings 3✓ 2?` (validated or reported, and suspected), and suspected findings keep the last workflow stage open.

**Credential ledger.** When the agent finds a credential, hash, token, or key, it writes the value to a file under `evidenceDir/loot/` and records the account, where it was found, and that file's path with `redteam_credentials`. The ledger holds no secret values, so `/rt-creds`, the report, and the handover can list it safely. Each attempt to use a credential is recorded per target with its result (`valid`, `invalid`, `locked_out`, `error`), which shows where a credential was already tried and where it was not. A test against a host outside scope cannot be recorded. Trying a credential remains an active check that you approve.

**Draft report.** `/rt-report` writes `report-YYYYMMDD-HHMMSS.md`. It contains a findings table and each validated finding in the house format, the scope, coverage counts with every item that was not fully reviewed and why, an activity timeline from the audit log, and the audit chain's integrity result and final hash. An internal appendix at the end lists suspected findings, the credential ledger, and open items; remove it before delivery. The command lists what still stands between the draft and a deliverable: validated findings with missing fields, suspected findings, pending coverage. The report is in English and is a draft: it assembles what was recorded and writes no new text, so use `/rt-steer` → "Complete the findings register" first and `/skill:security-findings` for the management summary.

**Handover.** `/rt-handover` writes a note for a colleague or a fresh session: where the engagement stands, the agent's recommended next steps with the exact instruction to send, what waits on the operator, findings and credentials, coverage items that are blocked, recent blocked or denied actions, the last instructions given to the agent, and how to resume.

## Attack-surface discovery

The harness reviews what it was given in depth; discovery widens what it is given. Everything discovery finds is a proposal, and nothing enters scope or coverage until the operator accepts it.

**Routes.** The agent records routes it sees on in-scope hosts (links, redirects, API descriptions) with `redteam_proposals` `record_endpoint`. `/rt-endpoints` lists them; accepting a route adds the exact URL to `webEndpoints` in `redteam.config.json`, which makes it a priority endpoint and opens a pending coverage item. The host must already be in scope, so accepting routes never widens host scope.

**Discovery mode.** `/rt-discover on [BUDGET]` arms the `redteam_discover` tool for a fixed number of requests. It is separate from `/rt-arm`, turns off when the budget is used, and every run is a `discovery_run` audit event. The tool offers four bounded operations against the client's own surface:

| Operation | What it sends | Where results go |
|---|---|---|
| `well_known` | Ten fixed GETs per in-scope origin (`robots.txt`, `sitemap.xml`, `security.txt`, OpenID and API descriptions) plus up to three same-origin sitemaps. No redirect following. | Routes → `/rt-endpoints`; linked foreign hosts → `/rt-proposals` |
| `subdomains` | DNS lookups for about 110 common labels (plus up to 200 supplied by the agent) under an authorized wildcard. Detects catch-all DNS. Excluded names are skipped. | Resolving names → `/rt-proposals` (already in scope) |
| `certificates` | One query to `crt.sh` for an in-scope domain, only if `crt.sh` is an approved passive source. The names returned are not contacted. | In-scope and unknown names → `/rt-proposals` |
| `vhosts` | One GET per in-scope name against an in-scope origin, compared with a baseline for an unknown name. | Reported to the agent only |

Requests are sent sequentially with a short delay, or five at a time for DNS.

**Exposure sources.** Three further operations ask third parties what they know about the client. None of them contacts the client's systems, and each needs its own approved passive source:

| Operation | Passive source to approve | What it sends | Where results go |
|---|---|---|---|
| `history` | `web.archive.org` | One query for URLs the web archive has seen under an in-scope domain. Query strings are dropped, static files are skipped. | Routes on in-scope hosts → `/rt-endpoints`; unknown hosts → `/rt-proposals` |
| `cloud_storage` | `s3.amazonaws.com`, `storage.googleapis.com`, `blob.core.windows.net` | For up to four names, each of which must be a label of an in-scope hostname, 14 variants (`name`, `name-backup`, `name-dev`, …) per approved provider: one unauthenticated request each, or a DNS lookup for Azure. Reports only whether the name exists and whether it lists publicly. Contents are never read. | Existing names → `/rt-proposals`, marked "ownership not verified" |
| `code_mentions` | `api.github.com` | One search of public code for an in-scope domain. Needs a token in the `RT_GITHUB_TOKEN` environment variable, set before starting Pi; the token is never logged or shown to the agent. | Repository and file path, reported to the agent only |

A storage name that exists does not prove the client owns it; decide that before anything else touches it. Archived URLs may be gone. Leaked-credential databases are not queried: the usable ones need a paid key and proof of domain ownership, so bring those results in as an operator-supplied evidence file.

**Passive sources.** A third-party lookup discloses in-scope names to that party, so each source needs `/rt-discover allow HOST`. An approved source is neither in scope nor unknown: a shell command that queries it runs without a prompt while discovery mode is on (charged to the same budget) and asks for one confirmation otherwise. Unapproved third-party hosts stay blocked for recognized network tools.

**Ranges.** Host sweeps of authorized CIDRs use an ordinary in-scope scanner under `/rt-arm`; they are not part of the discovery budget.

Limits: discovery does not crawl pages, brute-force paths with wordlists, or follow redirects, and its subdomain list is small by design. Supply larger candidate lists yourself if the rules of engagement call for them.

## Administration dashboard

Use `/rt-admin` as the entry point for routine engagement administration. `/rt-targets` lists every effective included host or scope rule, marks proposal additions with `★ ONBOARDED`, shows baseline targets separately, and displays exclusions. It then lists the configured priority HTTP(S) endpoints—including complete paths and wildcard route-family markers—in a distinct section grouped by their inventory source file, such as `targets/targets_fqdm.txt`. `/rt-targets routes` shows only this route inventory, while `/rt-targets onboarded` and `/rt-targets baseline` provide compact host-oriented views.

`/rt-progress` reconciles configured routes and saved evidence with the local Scanlens service inventory. It reports evidence completion as `reviewed + grouped` divided by total known coverage, while keeping pending, operator-dependent, and blocked work open. It includes a bounded sample of open keys and their recorded missing facts, pending proposal names, and commands that resolve each administrative queue. A percentage is a coverage indicator, not a security score or claim that the assessed systems are vulnerability-free.

## Black-box coverage

Ask Pi to review coverage from existing Scanlens records, advisory information, audit history, and operator-provided captures. For example: “Resume the black-box evidence review. Which routes are still pending, and which advisory candidates lack an externally verifiable prerequisite?”

`redteam_coverage` supports `list`, `reconcile`, and `record`. `list` combines configured routes with saved assessments. `reconcile` also reads the existing Scanlens inventory and shows open TCP/UDP service identities that have no matching assessment as pending. Set `scanlensOnly: true` with `reconcile` to page through just those inventoried services. Reconciliation matches exact host, port, and transport (preferring an included scan IP over its hostname) and never infers DNS or application equivalence. Truncation or invalid identity rows are reported rather than silently treated as complete coverage.

Use `record` to replace the latest assessment. Tag the evidence layer as `gateway_only`, `application`, `service`, or `unknown`; gateway-only evidence does not establish application behaviour. Use state, outcome, or layer filters to inspect gaps. A grouped route must cite a shared application and authentication boundary and refer to a reviewed, exact route on the same origin. If the representative no longer qualifies, the grouped route returns to pending.

Review outcomes are `observed`, `inferred`, `advisory_candidate`, and `unresolved_from_outside`. Keep them separate from work states (`pending`, `reviewed`, `waiting_on_operator`, `grouped`, `blocked`). Cite each observation's source and record counterevidence where relevant. An `advisory_candidate` is not a confirmed vulnerability.

The queue is stored in a separate, mutable table in the configured audit database, keyed by project directory and engagement name. Tool activity is audited, but the coverage rows themselves are not part of the hash chain. The coverage tool runs locally, does not scan or schedule checks, and stores short evidence references and observations rather than raw captures or secrets. In internal notes, document attack-path hypotheses one link at a time with prerequisites and evidence; an unverified required link keeps the path hypothetical. Reload Pi after updating the package.

## Kali tool awareness

`/rt-tools` checks this machine against the tools an external assessment draws on, grouped by purpose (core, ports and services, web, TLS, DNS and names, exposure and leaks, screenshots, and what is needed to build tools), and prints a single `apt install` command for whatever is missing. The agent receives the same installed and missing lists in its operating rules, so it does not probe for tools or call ones that are absent. It never installs system packages; that stays with you.

The agent is told to write its own tool, without asking, when no installed tool fits, one is missing, or the output is too coarse: a script or small program under `toolsDir`, with targets passed as command-line arguments, the engagement's limits, and output under `evidenceDir`. A script or binary run from `toolsDir` is scope-checked on the hostnames, URLs, and addresses in its arguments, the same as a recognized tool: excluded targets are blocked, in-scope targets follow arming, and unknown hosts ask you. Targets hard-coded inside a script or read from a file are not visible to that check, which is why the agent is instructed to pass them as arguments.

The red-team skill names `scanlens` for existing scanner evidence, `jq` and `diff` for local comparison, and `openssl x509` for saved certificates. It identifies `curl` and OpenSSL as options for operator-directed HTTP/TLS metadata collection. Tool availability does not grant authorization; live activity remains under human supervision. Only the core group is required; everything else widens what the agent can do.

## Client-facing findings

Use `/skill:security-findings` with evidence-backed notes or an existing draft. The skill applies the house format (affected systems, title, description, evidence, risk, mitigation, OSSTMM category, and three numeric ratings) without adding an overall severity label. Affected assets must be exact and evidence-backed, and concise evidence provenance must let a reviewer locate the supporting record; raw output and extended reproducibility material remain separate. It supports labelled fields, JSON on request, and plain-prose management summaries. The `<task>`/`<input>` convention is a message format, not an added executable.

## Authorization, scope, and active checks

`redteam.config.json` is intentionally operator-owned. The harness never invents an engagement, expiry, target, or exclusion.

### Incidental scope proposals

Pi can log a candidate exact hostname or IP, its evidence reference, and why it may be relevant via `redteam_proposals`. Proposals are deduplicated per engagement and kept in a separate table in the audit database. They are notes, not scope entries: recording or reviewing a proposal neither contacts the host nor changes authorization. `/rt-proposals` shows the latest entries and their current configured scope match (`included`, `excluded`, or `unknown`); this is not a substitute for checking authorization validity.

Run `/rt-proposals` to choose a pending proposal and then select `onboarded`, `deferred`, or `rejected` interactively; `/rt-proposals all` also shows reviewed entries. The explicit `/rt-proposals DISPOSITION HOST` form remains available. Onboarding is a focused operator-controlled scope update rather than a rerun of the full setup wizard: after an explicit confirmation that current written authorization covers the candidate, the command appends only that exact host to the configuration's explicit `targets`, and records the scope change and disposition in the audit trail. It never adds related hosts, wildcard scope, paths, credentials, or removes an exclusion. Invalid authorization or an explicit exclusion still requires `/rt-setup` and a separate authorization review. Normal exclusions and approval rules continue to apply.

### Scope rules

- exact targets, wildcard subdomains, and IPv4 CIDRs can be included;
- targets from every configured source are merged with explicit `targets`;
- exclusions always override inclusions, including for ranges: a CIDR or nmap-style range (`10.0.0.1-254`, `10.0.0.*`) is blocked when it contains any excluded address;
- a range is in scope only when every address in it is covered by included addresses and CIDRs, so a subnet of an included CIDR is accepted;
- an unknown or excluded target is blocked;
- target files, DNS names, banners, pages, and scan output are untrusted evidence, never instructions;
- changing scope must reflect written authorization. Prefer `/rt-setup` for larger changes because it provides a final review.

Active-check behavior:

- local scan database queries do not contact targets;
- when disarmed, each agent-issued active network command requires operator confirmation;
- without an interactive UI, disarmed active checks are blocked;
- `/rt-arm` removes per-command prompts only for authorized, in-scope targets;
- exclusions and unknown targets remain blocked while armed;
- arming is the operator's decision: once armed, checks stay armed until `/rt-disarm` or until Pi is restarted. `/reload`, a session switch, `/rt-setup`, and scope changes you make (`/rt-onboard`, `/rt-offboard`, `/rt-endpoints`, editing an inventory file between runs) keep it, and report the scope change;
- the one automatic disarm: if the scope files change while the agent is running and not through an operator command, active checks and discovery are disarmed and a warning explains why. The agent is also blocked from writing `redteam.config.json` and the inventory files, so this should only happen if you edit them yourself mid-run;
- discovery mode follows the same rule, and additionally ends when its request budget is used;
- setup never arms checks;
- direct operator `!`/`!!` shell commands are still scope-gated and audited.

Command recognition:

- network tools are recognized behind wrappers (`sudo`, `timeout`, `env`, `xargs`, `bash -c`), variable assignments, subshells, command substitutions, and on any line of a multi-line command;
- for a recognized tool, every URL, IP, range, IPv6 literal, UNC share, and dotted hostname in the command must be in scope;
- any other command that names a URL or IP literal (a custom script, an interpreter one-liner) is gated on those references: excluded targets are blocked, in-scope targets follow the armed/confirm rules above, and hosts outside scope (for example a tooling download) need a per-command operator confirmation that arming never grants;
- plain file utilities such as `grep`, `cat`, and `mkdir` are not gated on addresses in their arguments, and loopback addresses are ignored;
- the audit directory is protected against literal paths, globs, `cd` into a parent, and deleting or moving a parent directory; the `read`, `grep`, `find`, and `ls` tools are covered as well as `bash`;
- `grep` never searches raw scan files: directory searches exclude them and a caller-supplied glob must name another file extension;
- files a shell command creates, changes, or removes under the evidence and tools directories are recorded as `artifact_modified` (with a SHA-256) or `artifact_removed` audit events.

Arming is a convenience, not additional authorization. Shell recognition is heuristic, not a network sandbox: bare single-label hostnames, targets read from files or variables, and network code inside scripts are not visible to it. Keep the operator responsible for verifying the actual destinations and scope of live activity.

## Configuration reference

Example schema: [`redteam.config.example.json`](redteam.config.example.json).

| Field | Meaning |
|---|---|
| `engagement` | Non-empty engagement or written-authorization label. |
| `authorizationExpires` | Inclusive UTC end date in `YYYY-MM-DD` form. |
| `targets` | Exact IPs/hosts, IPv4 CIDRs, or wildcard subdomains. |
| `excludeTargets` | Targets that are always blocked, even if also included. |
| `targetSources` | Approved `.txt`, `.list`, or `.csv` inventory files/directories. Hostnames define scope; HTTP(S) URLs also become priority web endpoints. |
| `webEndpoints` | Exact priority routes accepted from discovery. Their hosts must already be in scope. |
| `passiveSources` | Third-party hosts approved for passive lookups: `crt.sh`, `web.archive.org`, `api.github.com`, and the cloud storage hosts listed under exposure sources. |
| `discoveryBudget` | Default number of requests per `/rt-discover on` (1–5000, default 300). |
| `scanlensDb` | Existing scanlens SQLite database path. |
| `evidenceDir` | Notes, captured responses, and reproducibility records. The harness writes `reports/` and `handover/` here, and the agent keeps captured secret values in `loot/`. |
| `toolsDir` | Purpose-built scripts, source trees, builds, temporary wordlists, and tool-generated artifacts. |
| `auditDb` | Append-only SQLite activity database queried only through `redteam_audit`. |

Relative paths resolve from the current project directory.

## Workspace and evidence

Default layout:

```text
.redteam/
├── audit/
│   └── audit.db
├── evidence/
└── tools/
```

For each active validation, evidence should record:

- UTC time;
- exact target and service;
- hypothesis and minimum evidence needed;
- bounded command or tool invocation;
- exact result;
- interpretation and confidence;
- next safe hypothesis.

Use existing system tools before creating a helper. Every purpose-built script, downloaded source tree, compiled utility, temporary wordlist, and generated tool artifact belongs under `toolsDir`. Keep engagement evidence under `evidenceDir`. Stop once impact is sufficiently demonstrated; do not collect unnecessary sensitive data.

The repository `.gitignore` excludes the real config, target inventories, scan databases, raw scan files, `.redteam/`, environment files, and common private-key formats. Verify `git status --ignored` before every commit, especially when using custom paths outside the defaults.

## Scan workflow

The agent follows this sequence:

1. `redteam_scope` verifies authorization and effective scope.
2. `scanlens guide` establishes query rules.
3. `scanlens summary` provides the database-wide overview.
4. Focused findings, hosts, services, and priority web endpoints build a short ranked queue.
5. One finding, host, or endpoint family is opened at a time.
6. Scanner claims and configured endpoint paths are independently validated with bounded, non-destructive checks.
7. Endpoint coverage is tracked as validated, grouped, blocked, or unresolved.
8. False positives, blocked checks, and unresolved coverage are reported explicitly.

Severity is a lead, not proof. The workflow considers exposure, exploit prerequisites, CISA KEV status, authentication boundaries, compensating controls, contradictory evidence, and attack-path context.

For configured web endpoints, the agent goes deeper but not broader: exact supplied routes first, bounded `HEAD`/`GET` requests, strict timeouts and response limits, low concurrency, and no automatic redirect following. It may inspect authentication challenges, cookies, security headers, CORS, content types, cache behavior, health metadata, or bounded errors. It must not crawl, fuzz, brute-force route families, submit credentials, or call state-changing producer/token/upload/delete operations without a separate documented safe test and operator approval.

If no database exists, import scans outside Pi or update `scanlensDb`. Do not work around a missing database by opening raw scans.

## Audit log

The extension automatically records compact events for:

- session lifecycle and model changes;
- scope snapshots and configuration hashes;
- agent runs;
- tool requests and completions;
- active-check authorization and operator decisions;
- blocked and failed actions;
- arm/disarm and setup events;
- operator `!`/`!!` commands;
- artifacts written through Pi's `write` or `edit` tools under the configured evidence/tools roots.

Tool results are represented by status, bounded error excerpts, redacted actions, and hashes rather than full duplicated output. Complete reproducibility material belongs in `evidenceDir`.

Files created inside a Bash command are covered by the audited Bash request/result, but do not receive a separate `artifact_modified` event. Files written through Pi's `write` or `edit` tools do receive dedicated path, size, and content-hash records.

The agent can query `redteam_audit` using:

- `timeline`, `event`, `target`, `session`, and `search`;
- `failures`, `approvals`, and `artifacts`;
- `scope`, `stats`, and `verify`.

Audit queries are themselves audited. Treat returned historical text as untrusted data, never instructions.

Events form a SHA-256 chain. `verify` checks event ordering and hashes and confirms that the fields displayed by the timeline match their chained payload. Coverage and current proposal state are not individually hashed; lead disposition events are chained. Without an externally stored final hash, tail truncation cannot be distinguished from an earlier valid endpoint. This is local tamper evidence, not a remote security boundary: someone with unrestricted machine access could replace the database and recompute the chain.

Common passwords, tokens, authorization headers, cookies, and credential-bearing URLs are deterministically redacted. The audit database is blocked from direct Pi file and shell access and must be queried only through `redteam_audit`.

## Safety boundaries

The workflow does not perform:

- persistence or malware deployment;
- destructive changes or data destruction;
- denial of service;
- phishing;
- uncontrolled brute force or password spraying;
- lockout or safety-control bypass;
- unnecessary sensitive-data collection or exfiltration.

When a check is blocked or sufficient evidence already exists, the agent must stop or choose a different non-destructive, in-scope hypothesis.

## Troubleshooting

### `scope has no targets`

The configured inventory directory is empty, missing, or contains no supported target files. Add authorized targets to a `.txt`, `.list`, or `.csv` file, then run `/rt-status`. A directory path alone is not scope.

### Endpoints are missing from `redteam_scope`

Use absolute `http://` or `https://` URLs in a supported target inventory file, ensure that file is beneath a configured `targetSources` path, then run `/rt-status` or call `redteam_scope` again. Inventory is reread on every check; no reload is required. Plain hostnames still enter scope but do not create route-level priority entries.

### `No scanlens database`

Import scans outside Pi or correct `scanlensDb`. Do not ask the agent to open raw scans.

### `Target … is excluded` or `unknown`

Check `/rt-status`, the final `/rt-setup` review, explicit targets, inventory files, and exclusions. Exclusions win. Do not remove an exclusion unless written authorization supports the change.

### `Could not identify an explicit target`

Active commands must contain a literal IP, CIDR, URL, or dotted hostname that the scope gate can verify. Shell variables, generated hostnames, and ambiguous filenames may be rejected. Use one explicit target per focused command when possible; do not create a wrapper to evade the gate.

### Setup keeps appearing

Run `/rt-status` and correct the reported issue. Missing, malformed, expired, or example configuration triggers setup. A saved configuration with only an empty inventory shows a reminder instead of repeatedly forcing the wizard.

### An internal hostname does not resolve

Confirm the exact authorized name and whether an approved VPN or split-DNS environment is required. Never guess alternate hostnames; update scope first if a different name is authorized.

### Active checks unexpectedly require approval

Only `/rt-disarm`, a Pi restart, or a scope-file change made while the agent was running reset arming; the last one shows a warning and an `active_checks_disarmed` event with action `scope-change-during-run` in `/rt-log`. Run `/rt-status`, then `/rt-arm` if the engagement is still authorized.

## Development

Run before committing:

```bash
npm test
npm run check
git diff --check
git status --short --ignored
```

The extension does not parse arbitrary shell syntax perfectly. Scope enforcement is defense in depth, not a substitute for correct written authorization and human oversight.
