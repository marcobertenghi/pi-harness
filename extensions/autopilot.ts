import type { EngagementSnapshot } from "./guide.ts";

// Autopilot: the harness starts the agent's next run by itself while there is
// work the agent can do alone. Every stop condition is decided here, from
// recorded state, never by the agent.

export interface AutopilotState {
  /** Maximum number of runs the harness may start by itself. */
  limit: number;
  /** Runs started by the harness so far. */
  runs: number;
  /** Progress signature when the last run started. */
  baseline?: string;
  /** Where the engagement stood when autopilot was turned on, for the digest. */
  origin?: Standing;
  startedAt?: number;
  /** Guard refusals and operator denials over all automatic runs. */
  totals?: { blocks: number; denials: number };
}

/** A point-in-time count of what the digest compares. */
export interface Standing {
  done: number; total: number; pending: number; waiting: number; blocked: number;
  findingIds: number[]; credentials: number; proposals: number; questions: number;
}

export interface DigestDetails {
  now: Standing;
  /** Findings recorded or changed since autopilot started. */
  findings: { id: number; title: string; status: string; isNew: boolean }[];
  openQuestions: { id: number; question: string }[];
  nextSteps: string[];
}

/** What happened during the run that just ended. */
export interface RunFacts {
  aborted: boolean;
  /** Commands the guard refused during the run. */
  blocks: number;
  /** Prompts the operator answered with no during the run. */
  denials: number;
  /** Validated findings with severe technical impact recorded during the run. */
  severeFindings: string[];
}

export const AUTOPILOT_DEFAULT_RUNS = 10;
export const AUTOPILOT_MAX_RUNS = 50;
const BLOCK_LIMIT = 3;

/** Changes whenever the agent closed, found, or proposed something. */
export function progressSignature(snapshot: EngagementSnapshot, extra: { credentials: number; proposals: number; tasks: number; questions?: number }): string {
  const coverage = snapshot.coverage;
  const findings = snapshot.findings;
  return JSON.stringify([
    coverage ? [coverage.total, coverage.pending, coverage.reviewed, coverage.grouped, coverage.waiting, coverage.blocked] : null,
    findings ? [findings.suspected, findings.validated, findings.reported] : null,
    extra.credentials, extra.proposals, extra.tasks, extra.questions ?? 0,
  ]);
}

export function autopilotLabel(state: AutopilotState | undefined): string {
  return state ? `▶ AUTO ${state.runs}/${state.limit}` : "▷ auto off";
}

export type AutopilotDecision = { continue: true; prompt: string } | { continue: false; reason: string; done?: boolean };

/** Decides, after a run has ended, whether the harness starts another one. */
export function autopilotDecision(state: AutopilotState, snapshot: EngagementSnapshot, facts: RunFacts, signature: string): AutopilotDecision {
  const coverage = snapshot.coverage;
  const pending = coverage?.pending ?? 0;
  const suspected = snapshot.findings?.suspected ?? 0;
  if (facts.aborted) return { continue: false, reason: "you interrupted the run" };
  if (snapshot.problem) return { continue: false, reason: `authorization or configuration problem: ${snapshot.problem}` };
  if (facts.denials) return { continue: false, reason: "you answered a confirmation with no, so the agent waits for your direction" };
  if (facts.severeFindings.length) return { continue: false, reason: `a severe finding was validated and deserves your attention first: ${facts.severeFindings.join("; ")}` };
  if (facts.blocks >= BLOCK_LIMIT) return { continue: false, reason: `the guard refused ${facts.blocks} commands in one run, which suggests the agent is working against a limit` };
  if (!coverage) return { continue: false, reason: "no coverage has been recorded yet; start the first run yourself with /rt-steer" };
  if (!pending && !suspected) return { continue: false, done: true, reason: "nothing is left that the agent can do alone: no pending coverage and no suspected findings" };
  if (state.baseline !== undefined && state.baseline === signature) return { continue: false, reason: "the last run made no recorded progress (no coverage item closed, no finding, proposal, credential, or task recorded)" };
  if (state.runs >= state.limit) return { continue: false, reason: `the limit of ${state.limit} automatic run(s) is reached` };
  const next = snapshot.agentNext?.[0];
  return {
    continue: true,
    prompt: [
      `[autopilot run ${state.runs + 1} of ${state.limit}] The operator is not watching each step. Continue toward the objective: ${pending} coverage item(s) pending, ${suspected} suspected finding(s) to validate.`,
      next ? `Your own first recommendation was: ${next.label}. Do that, unless something more valuable is now open.` : "Take the most valuable pending items first.",
      "Do not wait for an answer in this run. If a step needs the operator (a fact, a preference, a decision), file it with redteam_ask, record the affected item as waiting_on_operator, and move on to work that does not depend on it. If a command is refused, do not retry it in another form: record why and move on. End with the usual operator brief and redteam_next.",
    ].join(" "),
  };
}

const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? "" : "s"}`;

/** One screen for the operator when autopilot stops: what it did, what it found, what it needs. */
export function digestText(state: AutopilotState, decision: { reason: string; done?: boolean }, details: DigestDetails, now = Date.now()): string {
  const origin = state.origin ?? details.now;
  const current = details.now;
  const minutes = state.startedAt ? Math.max(1, Math.round((now - state.startedAt) / 60_000)) : undefined;
  const percent = (standing: Standing) => standing.total ? Math.round((standing.done / standing.total) * 100) : 0;
  const fresh = details.findings.filter((finding) => finding.isNew);
  const changed = details.findings.filter((finding) => !finding.isNew);
  const needs = [
    ...(details.openQuestions.length ? [`  ? ${plural(details.openQuestions.length, "question")} from the agent → /rt-answer`, ...details.openQuestions.slice(0, 4).map((item) => `      #${item.id} ${item.question}`)] : []),
    ...(current.waiting ? [`  ! ${plural(current.waiting, "coverage item")} waiting on a fact from you → /rt-tasks`] : []),
    ...(current.proposals ? [`  ! ${plural(current.proposals, "proposed host or route")} to decide → /rt-proposals, /rt-endpoints`] : []),
    ...(details.findings.some((finding) => finding.status === "suspected") ? ["  ! suspected findings to confirm or dismiss → /rt-findings"] : []),
  ];
  return [
    `${decision.done ? "✓ AUTOPILOT FINISHED" : "■ AUTOPILOT STOPPED"} — ${plural(state.runs, "automatic run")}${minutes ? ` in about ${minutes} min` : ""}`,
    `Why: ${decision.reason}.`,
    "",
    "DID",
    `  Coverage ${percent(origin)}% → ${percent(current)}% (${current.done}/${current.total}) · pending ${origin.pending} → ${current.pending} · blocked ${current.blocked}`,
    `  ${plural(Math.max(0, current.credentials - origin.credentials), "credential")} recorded · ${plural(Math.max(0, current.proposals - origin.proposals), "new proposal")} · ${plural(Math.max(0, current.questions - origin.questions), "question")} filed`,
    ...(state.totals && (state.totals.blocks || state.totals.denials) ? [`  ${plural(state.totals.blocks, "command")} refused by the guard, ${state.totals.denials} declined by you → /rt-log failures`] : []),
    "",
    "FOUND",
    ...(fresh.length || changed.length
      ? [...fresh.map((finding) => `  + #${finding.id} [${finding.status}] ${finding.title}`), ...changed.map((finding) => `  ~ #${finding.id} now ${finding.status}: ${finding.title}`)]
      : ["  nothing new"]),
    "",
    "NEEDS YOU",
    ...(needs.length ? needs : ["  ✓ nothing"]),
    "",
    "NEXT",
    ...(details.nextSteps.length ? details.nextSteps.slice(0, 3).map((step, index) => `  ${index + 1}. ${step}`) : ["  /rt for the suggested next action"]),
    "",
    "Autopilot is now off. /rt-auto on starts it again · /rt-auto last shows this digest again · /rt-handover writes the full note.",
  ].join("\n");
}
