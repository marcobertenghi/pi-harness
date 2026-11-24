import type { Credential } from "./credentials.ts";
import { reportGaps, type Finding } from "./findings.ts";

// Pure text builders for the two operator documents: the draft client report
// and the handover note. Both are generated from recorded data only.

export interface CoverageRow { key: string; state: string; outcome?: string; layer?: string; note?: string }
export interface TimelineEvent { timestampUtc: string; eventType: string; actor: string; status: string; target: string | null; action: string | null; summary: string | null }

export interface EngagementRecord {
  engagement: string;
  authorizationExpires: string;
  generatedAt: Date;
  scope: { targets: string[]; exclusions: string[]; routes: number };
  coverage: { total: number; counts: Record<string, number>; rows: CoverageRow[]; truncated: number };
  findings: Finding[];
  credentials: Credential[];
  tasks: { id: number; title: string; createdBy: string }[];
  proposals: { hosts: number; routes: number };
  nextSteps: { label: string; instruction: string; why: string }[];
  timeline: TimelineEvent[];
  audit: { valid: boolean; events: number; finalHash?: string; error?: string };
  armed: boolean;
  discovery?: { used: number; limit: number };
}

const cell = (value: string) => value.replace(/\|/g, "\\|").replace(/\s+/g, " ").trim();
const stamp = (value: string) => value.slice(0, 16).replace("T", " ");
const RATING = ["–", "1", "2", "3"];
const rate = (value: number | null) => RATING[value ?? 0];

function percent(record: EngagementRecord): string {
  const { counts, total } = record.coverage;
  const done = (counts.reviewed ?? 0) + (counts.grouped ?? 0);
  return total ? `${Math.round((done / total) * 100)}% (${done}/${total})` : "nothing recorded";
}

function findingBlock(finding: Finding, number: string): string[] {
  const gaps = reportGaps(finding);
  return [
    `### ${number} ${finding.title}`,
    "",
    ...(gaps.length ? [`> Incomplete: ${gaps.join(", ")} missing (register entry #${finding.id}).`, ""] : []),
    "**Affected Systems:**",
    ...(finding.affectedSystems.length ? finding.affectedSystems.map((system) => `- ${system}`) : ["- Not established"]),
    "",
    `**Description:** ${finding.description || "—"}`,
    "",
    "**Evidence:**",
    ...(finding.evidence.length ? finding.evidence.map((item) => `- ${item}`) : ["- —"]),
    "",
    `**Risk:** ${finding.risk || "—"}`,
    "",
    `**Mitigation:** ${finding.mitigation || "—"}`,
    "",
    `**OSSTMM category:** ${finding.osstmmCategory ?? "–"} · **Exploitability:** ${rate(finding.exploitability)} · **Technical impact:** ${rate(finding.technicalImpact)} · **Mitigation effort:** ${rate(finding.mitigationEffort)}`,
    "",
  ];
}

// Events worth a line in the client timeline, with a plain label. Finding and credential
// events are left out: they would name unvalidated findings and accounts.
export const TIMELINE_EVENTS: Record<string, string> = {
  session_started: "Session started",
  active_checks_armed: "Active checks armed",
  active_checks_disarmed: "Active checks disarmed",
  discovery_armed: "Discovery mode on",
  discovery_run: "Discovery run",
  scope_target_onboarded: "Target added to scope",
  scope_target_offboarded: "Target removed from scope",
  proposal_scope_added: "Proposed host added to scope",
  endpoint_proposals_accepted: "Discovered routes accepted",
  passive_source_approved: "Passive source approved",
  agent_run_started: "Agent run",
};

/** Draft client report. Suspected findings and credentials are listed apart, and no secret value appears. */
export function reportMarkdown(record: EngagementRecord): string {
  const client = record.findings.filter((finding) => finding.status === "validated" || finding.status === "reported");
  const suspected = record.findings.filter((finding) => finding.status === "suspected");
  const { counts } = record.coverage;
  const open = record.coverage.rows.filter((row) => row.state !== "reviewed" && row.state !== "grouped");
  return [
    `# ${record.engagement} — assessment report (draft)`,
    "",
    "> DRAFT generated from the harness records. Review every statement before it reaches a client.",
    "",
    `- Generated: ${record.generatedAt.toISOString().slice(0, 16).replace("T", " ")} UTC`,
    `- Authorization valid to: ${record.authorizationExpires}`,
    `- Scope: ${record.scope.targets.length} target rule(s), ${record.scope.exclusions.length} exclusion(s), ${record.scope.routes} priority route(s)`,
    `- Coverage: ${percent(record)} · pending ${counts.pending ?? 0} · waiting on client ${counts.waiting_on_operator ?? 0} · blocked ${counts.blocked ?? 0}`,
    `- Findings: ${client.length} validated, ${suspected.length} not validated`,
    `- Audit log: ${record.audit.valid ? `intact, ${record.audit.events} event(s), final hash ${record.audit.finalHash ?? "n/a"}` : `INTEGRITY CHECK FAILED (${record.audit.error ?? "unknown"})`}`,
    "",
    "## 1. Findings",
    "",
    ...(client.length ? [
      "| # | Title | Affected | OSSTMM | Exploitability | Technical impact | Mitigation effort |",
      "|---|---|---|---|---|---|---|",
      ...client.map((finding, index) => `| 1.${index + 1} | ${cell(finding.title)} | ${finding.affectedSystems.length} | ${finding.osstmmCategory ?? "–"} | ${rate(finding.exploitability)} | ${rate(finding.technicalImpact)} | ${rate(finding.mitigationEffort)} |`),
      "",
      "Ratings: exploitability 1 easy – 3 hard; technical impact 1 low – 3 severe; mitigation effort 1 low – 3 high.",
      "",
      ...client.flatMap((finding, index) => findingBlock(finding, `1.${index + 1}`)),
    ] : ["No validated findings are recorded.", ""]),
    "## 2. Scope",
    "",
    "**In scope:**",
    ...(record.scope.targets.length ? record.scope.targets.slice(0, 200).map((target) => `- ${target}`) : ["- (none)"]),
    ...(record.scope.targets.length > 200 ? [`- … ${record.scope.targets.length - 200} more`] : []),
    "",
    "**Excluded:**",
    ...(record.scope.exclusions.length ? record.scope.exclusions.map((target) => `- ${target}`) : ["- (none)"]),
    "",
    "## 3. Coverage",
    "",
    "Coverage states what was reviewed against evidence. It is not a claim that reviewed systems are free of vulnerabilities.",
    "",
    "| State | Items |",
    "|---|---|",
    ...Object.entries(counts).map(([state, count]) => `| ${state.replace(/_/g, " ")} | ${count} |`),
    "",
    ...(open.length ? [
      "### Not fully reviewed",
      "",
      "| Item | State | Reason or missing fact |",
      "|---|---|---|",
      ...open.map((row) => `| ${cell(row.key)} | ${row.state.replace(/_/g, " ")} | ${cell(row.note ?? "") || "–"} |`),
      "",
    ] : []),
    "### Reviewed",
    "",
    "| Item | State | Outcome | Evidence layer |",
    "|---|---|---|---|",
    ...record.coverage.rows.filter((row) => row.state === "reviewed" || row.state === "grouped")
      .map((row) => `| ${cell(row.key)} | ${row.state} | ${(row.outcome ?? "–").replace(/_/g, " ")} | ${(row.layer ?? "unknown").replace(/_/g, " ")} |`),
    ...(record.coverage.rows.some((row) => row.state === "reviewed" || row.state === "grouped") ? [] : ["| (none yet) | – | – | – |"]),
    ...(record.coverage.truncated ? ["", `${record.coverage.truncated} further item(s) are not listed; see /rt-coverage.`] : []),
    "",
    "## 4. Activity timeline (UTC)",
    "",
    "| Time | Event | Detail |",
    "|---|---|---|",
    ...(record.timeline.length ? [] : ["| – | No session activity recorded | – |"]),
    ...record.timeline.map((event) => `| ${stamp(event.timestampUtc)} | ${TIMELINE_EVENTS[event.eventType] ?? event.eventType} | ${cell(event.eventType === "agent_run_started" ? "" : [event.target, event.action, event.summary].filter(Boolean).join(" — ")).slice(0, 160) || "–"} |`),
    "",
    "## Internal appendix — remove before delivery",
    "",
    "### Findings not validated",
    "",
    ...(suspected.length ? suspected.map((finding) => `- #${finding.id} ${finding.title} — ${finding.affectedSystems.join(", ") || "affected systems not established"}`) : ["- (none)"]),
    "",
    "### Credentials captured",
    "",
    "Values are not stored in the harness; each entry names the evidence file that holds it.",
    "",
    ...(record.credentials.length ? [
      "| # | Kind | Account | Found at | Value kept in | Tested |",
      "|---|---|---|---|---|---|",
      ...record.credentials.map((item) => `| ${item.id} | ${item.kind} | ${cell(item.account)} | ${cell(item.foundAt)} | ${cell(item.secretLocation)} | ${cell(item.tests.map((test) => `${test.target}: ${test.result.replace(/_/g, " ")}`).join("; ")) || "not tested"} |`),
    ] : ["- (none)"]),
    "",
    "### Open items",
    "",
    ...(record.tasks.length ? record.tasks.map((task) => `- Task #${task.id} [${task.createdBy}] ${task.title}`) : ["- No open tasks"]),
    `- ${record.proposals.hosts} proposed host(s) and ${record.proposals.routes} discovered route(s) undecided`,
    "",
  ].join("\n");
}

export interface HandoverExtras {
  /** What the operator asked for in recent runs, oldest first. */
  runs: TimelineEvent[];
  /** Recent blocked or failed actions, oldest first. */
  failures: TimelineEvent[];
  waiting: CoverageRow[];
  blocked: CoverageRow[];
  reportPath?: string;
}

/** Handover note: enough for a colleague or a fresh session to continue without rereading the log. */
export function handoverMarkdown(record: EngagementRecord, extras: HandoverExtras): string {
  const { counts } = record.coverage;
  const byStatus = (status: Finding["status"]) => record.findings.filter((finding) => finding.status === status);
  const findingLine = (finding: Finding) => `- #${finding.id} ${finding.title} — ${finding.affectedSystems.slice(0, 3).join(", ") || "affected systems not established"}${finding.note ? ` (${finding.note})` : ""}`;
  const untested = record.credentials.filter((item) => !item.tests.length);
  return [
    `# ${record.engagement} — handover`,
    "",
    `Written ${record.generatedAt.toISOString().slice(0, 16).replace("T", " ")} UTC. Everything below comes from the harness records in this folder.`,
    "",
    "## Where it stands",
    "",
    `- Coverage ${percent(record)} · pending ${counts.pending ?? 0} · waiting on operator ${counts.waiting_on_operator ?? 0} · blocked ${counts.blocked ?? 0}`,
    `- Findings: ${byStatus("validated").length} validated, ${byStatus("suspected").length} suspected, ${byStatus("reported").length} reported`,
    `- Credentials: ${record.credentials.length} recorded, ${untested.length} never tested`,
    `- Undecided: ${record.proposals.hosts} proposed host(s), ${record.proposals.routes} discovered route(s) · ${record.tasks.length} open task(s)`,
    `- Authorization valid to ${record.authorizationExpires} · scope ${record.scope.targets.length} target rule(s), ${record.scope.exclusions.length} excluded`,
    `- When this was written: active checks ${record.armed ? "armed" : "disarmed"}, discovery ${record.discovery ? `on (${record.discovery.limit - record.discovery.used} request(s) left)` : "off"}. A new Pi process starts disarmed with discovery off.`,
    "",
    "## Do next",
    "",
    ...(record.nextSteps.length
      ? record.nextSteps.map((step, index) => `${index + 1}. **${step.label}**${step.why ? ` — ${step.why}` : ""}\n   Send to the agent: ${step.instruction}`)
      : ["The agent has not recorded next steps. Run `/rt` for the suggested next action."]),
    "",
    "## Needs the operator",
    "",
    ...(extras.waiting.length ? extras.waiting.map((row) => `- ${row.key} — needs: ${row.note || "see /rt-tasks"}`) : ["- No coverage item is waiting on a fact"]),
    ...record.tasks.map((task) => `- Task #${task.id} [${task.createdBy}] ${task.title}`),
    "",
    "## Findings",
    "",
    "**Validated**",
    ...(byStatus("validated").length ? byStatus("validated").map(findingLine) : ["- (none)"]),
    "",
    "**Suspected, still to validate**",
    ...(byStatus("suspected").length ? byStatus("suspected").map(findingLine) : ["- (none)"]),
    "",
    "## Credentials",
    "",
    ...(record.credentials.length
      ? record.credentials.map((item) => `- #${item.id} ${item.kind} for ${item.account}, found at ${item.foundAt}, value in ${item.secretLocation} — ${item.tests.map((test) => `${test.target}: ${test.result.replace(/_/g, " ")}`).join("; ") || "not tested"}`)
      : ["- (none)"]),
    "",
    "## Tried and did not work",
    "",
    ...(extras.blocked.length ? extras.blocked.map((row) => `- Blocked: ${row.key}${row.note ? ` — ${row.note}` : ""}`) : []),
    ...(extras.failures.length
      ? extras.failures.map((event) => `- ${stamp(event.timestampUtc)} ${event.status}: ${[event.action, event.summary].filter(Boolean).join(" — ").replace(/\s+/g, " ").slice(0, 200)}`)
      : extras.blocked.length ? [] : ["- Nothing blocked or failed is on record"]),
    "",
    "## Recent instructions to the agent",
    "",
    ...(extras.runs.length ? extras.runs.map((event) => `- ${stamp(event.timestampUtc)} ${(event.summary ?? "").replace(/\s+/g, " ").slice(0, 200)}`) : ["- (none)"]),
    "",
    "## How to resume",
    "",
    "1. Start Pi in this folder and run `/rt` for the current state.",
    "2. Run `/rt-arm` and `/rt-discover on` again if the work needs them.",
    "3. Send the agent: `Read the latest handover note under the evidence directory, check redteam_scope, redteam_findings and redteam_coverage, then continue with the first step under \"Do next\".`",
    ...(extras.reportPath ? [`4. The last draft report is ${extras.reportPath}.`] : []),
    "",
  ].join("\n");
}
