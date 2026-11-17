# Minimal red-team agent for Pi

A small Pi package that adds:

- a red-team skill with a scanlens-first triage and validation workflow;
- `redteam_scope`, a tool that merges explicit scope with plain-text target inventories;
- `scanlens`, a constrained wrapper around the installed CLI;
- a dedicated `.redteam/tools` workspace for all purpose-built assessment tooling;
- `/rt-status`, `/rt-arm`, and `/rt-disarm`;
- scope, authorization-expiry, raw-scan, and operator-confirmation gates for active checks.

It is deliberately an operator-supervised assessment assistant, not an autonomous exploitation framework. `/rt-arm` lasts only for the current session. It never overrides exclusions.

## Setup

```bash
cp redteam.config.example.json redteam.config.json
$EDITOR redteam.config.json
mkdir -p targets
# Put approved inventory in .txt, .list, or .csv files under targets/.
```

Set `scanlensDb` to an existing scanlens database. Keep Nessus/Nmap raw files outside the agent workflow. To create the database, import them directly with scanlens as the human operator:

```bash
scanlens import --help
scanlens import /path/to/operator-controlled/scans
```

Do not ask Pi to inspect those raw files.

Install dependencies for development and run checks:

```bash
npm install
npm test
npm run check
```

Try without installing:

```bash
pi -e .
```

Or install as a project-local package:

```bash
pi install --local .
```

Restart Pi or use `/reload`, then invoke `/skill:redteam` or ask Pi to triage the engagement. Run `/rt-status` first. Active network commands require per-command confirmation until the operator runs `/rt-arm`.

## Configuration

`redteam.config.json` is intentionally operator-owned:

- `engagement`: non-empty authorization/engagement label;
- `authorizationExpires`: UTC end date in `YYYY-MM-DD` form;
- `targets`: exact IPs/hosts, IPv4 CIDRs, or wildcard subdomains such as `*.lab.example.test`;
- `excludeTargets`: always takes precedence;
- `targetSources`: files or directories containing approved target inventory;
- `scanlensDb`: path to the scanlens SQLite database;
- `evidenceDir`: where the workflow keeps notes and engagement evidence;
- `toolsDir`: the dedicated location for scripts, helper utilities, downloaded source, builds, temporary wordlists, and tool-generated artifacts.

The default workspace layout is:

```text
.redteam/
├── evidence/
└── tools/
```

Custom assessment tools must not be scattered elsewhere in the repository or installed globally. The agent is instructed to prefer installed system tools and keep new helpers small and auditable.

Target source content and scan output are treated as untrusted data. Raw `.nessus`, `.nmap`, and `.xml` reads are blocked. XML is blocked conservatively because Nmap commonly uses it; use a separate Pi session if unrelated XML development is needed.

## Typical flow

1. `/rt-status`
2. `/skill:redteam triage the current engagement`
3. Pi calls `redteam_scope`.
4. Pi calls `scanlens guide`, `scanlens summary`, then focused queries.
5. Pi ranks hypotheses and performs least-invasive independent validation.
6. The operator approves each active check or explicitly uses `/rt-arm`.

The extension does not attempt to parse arbitrary shell syntax perfectly. Scope checks are defense in depth; written authorization and human oversight remain mandatory.
