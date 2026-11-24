// Operator guidance: pure text builders for the engagement panel, the workflow
// checklist, next-step suggestions, the open-work board, and steering prompts.

export interface EngagementSnapshot {
  engagement: string;
  /** Authorization or configuration problem, if any. */
  problem?: string;
  authorizationExpires: string;
  armed: boolean;
  targets: number;
  exclusions: number;
  routes: number;
  scanlensReady: boolean;
  coverage?: { total: number; pending: number; reviewed: number; grouped: number; waiting: number; blocked: number };
  pendingProposals: number;
  openTasks: number;
  /** Discovered routes waiting for review. */
  pendingEndpoints?: number;
  /** Completed or failed discovery runs recorded in the audit log. */
  discoveryRuns?: number;
  /** Request budget while discovery mode is on. */
  discovery?: { used: number; limit: number };
  /** Authorized wildcard rules, which are where subdomain discovery applies. */
  wildcards?: number;
  /** The agent's own recommendations for what to do next, best first. */
  agentNext?: { label: string; instruction: string; why: string }[];
  /** Questions the agent filed that the operator has not answered. */
  openQuestions?: number;
  /** Automatic runs used and allowed while autopilot is on. */
  autopilot?: { runs: number; limit: number };
  /** Findings register counts. */
  findings?: { suspected: number; validated: number; reported: number };
  /** Entries in the credential ledger. */
  credentials?: number;
}

export interface NextAction { command: string; label: string; why: string }

export function progressBar(done: number, total: number, width = 20): string {
  const filled = total > 0 ? Math.round((Math.min(done, total) / total) * width) : 0;
  return `${"█".repeat(filled)}${"░".repeat(width - filled)}`;
}

export function daysLeft(expires: string, now = new Date()): number | undefined {
  const end = new Date(`${expires}T23:59:59Z`).valueOf();
  return Number.isNaN(end) ? undefined : Math.floor((end - now.valueOf()) / 86_400_000);
}

function completion(snapshot: EngagementSnapshot) {
  const coverage = snapshot.coverage;
  const done = coverage ? coverage.reviewed + coverage.grouped : 0;
  const total = coverage?.total ?? 0;
  return { done, total, percent: total ? Math.round((done / total) * 100) : 0 };
}

const NO_TARGETS = "scope has no targets";

/** Ordered suggestions, most urgent first. Never empty. */
export function nextActions(snapshot: EngagementSnapshot, now = new Date()): NextAction[] {
  const actions: NextAction[] = [];
  const coverage = snapshot.coverage;
  if (snapshot.problem === NO_TARGETS) {
    actions.push({ command: "/rt-start", label: "Add the authorized targets", why: "scope is empty: /rt-start shows where the target files go, or use /rt-onboard HOST for a single host" });
  } else if (snapshot.problem) {
    actions.push({ command: "/rt-setup", label: "Fix the engagement configuration", why: snapshot.problem });
  }
  const remaining = daysLeft(snapshot.authorizationExpires, now);
  if (!snapshot.problem && remaining !== undefined && remaining <= 7) {
    actions.push({ command: "/rt-setup", label: "Check the authorization window", why: `authorization expires in ${remaining} day(s)` });
  }
  if (snapshot.pendingProposals) {
    actions.push({ command: "/rt-proposals", label: "Review scope proposals", why: `${snapshot.pendingProposals} host(s) proposed by the agent await your decision` });
  }
  if (snapshot.pendingEndpoints) {
    actions.push({ command: "/rt-endpoints", label: "Review discovered routes", why: `${snapshot.pendingEndpoints} route(s) found on in-scope hosts await your decision` });
  }
  if (snapshot.openQuestions) {
    actions.push({ command: "/rt-answer", label: "Answer the agent's questions", why: `${snapshot.openQuestions} question(s) filed while it kept working` });
  }
  if (coverage?.waiting) {
    actions.push({ command: "/rt-tasks", label: "Answer open questions", why: `${coverage.waiting} coverage item(s) wait on a fact only you can supply` });
  }
  if (snapshot.openTasks) {
    actions.push({ command: "/rt-tasks", label: "Work the task list", why: `${snapshot.openTasks} tracked task(s) are open` });
  }
  if (!snapshot.problem && !snapshot.discoveryRuns) {
    actions.push(snapshot.discovery
      ? { command: "/rt-steer", label: "Map the attack surface", why: `discovery mode is on with ${snapshot.discovery.limit - snapshot.discovery.used} request(s) left and nothing has run yet` }
      : { command: "/rt-discover", label: "Map the attack surface", why: "no discovery has run: turn on bounded discovery to find hosts and routes beyond the supplied list" });
  }
  if (!snapshot.problem) {
    if (!snapshot.scanlensReady) {
      actions.push({ command: "/rt-start", label: "Import scan data", why: "no Scanlens database yet: /rt-start shows the exact import command" });
    } else if (snapshot.agentNext?.length) {
      const top = snapshot.agentNext[0];
      actions.push({ command: "/rt-steer", label: top.label, why: `agent recommends${top.why ? `: ${top.why}` : ""}` });
    } else if (!coverage || completion(snapshot).done === 0) {
      actions.push({ command: "/rt-steer", label: "Start scan triage", why: "scan data is ready and nothing has been reviewed yet" });
    } else if (coverage.pending) {
      actions.push({ command: "/rt-steer", label: "Drive coverage to 100%", why: `${coverage.pending} item(s) still pending` });
    } else if (snapshot.findings?.suspected) {
      actions.push({ command: "/rt-steer", label: "Validate suspected findings", why: `${snapshot.findings.suspected} finding(s) are neither validated nor dismissed` });
    } else {
      actions.push({ command: "/rt-report", label: "Write the draft report", why: `no pending coverage items remain; ${snapshot.findings?.validated ?? 0} validated finding(s) on record` });
    }
    if (!snapshot.armed && snapshot.scanlensReady && coverage?.pending) {
      actions.push({ command: "/rt-arm", label: "Arm active checks", why: "optional: skips the per-command prompt for in-scope targets" });
    }
  }
  if (!actions.length) actions.push({ command: "/rt-status", label: "Review status", why: "nothing is waiting" });
  return actions;
}

export type StageMark = "done" | "current" | "todo" | "blocked";

export function workflowStages(snapshot: EngagementSnapshot): { mark: StageMark; title: string; detail: string }[] {
  const { done, total, percent } = completion(snapshot);
  const coverage = snapshot.coverage;
  const configured = !snapshot.problem || snapshot.problem === NO_TARGETS;
  const raw: [boolean, string, string, boolean?][] = [
    [configured, "Configure the engagement", configured ? snapshot.engagement : `${snapshot.problem} → /rt-setup`, !configured],
    [snapshot.targets > 0, "Load authorized targets",
      snapshot.targets > 0 ? `${snapshot.targets} target(s), ${snapshot.exclusions} excluded, ${snapshot.routes} priority route(s)` : "add an inventory file or /rt-onboard HOST"],
    [snapshot.scanlensReady, "Import scan data", snapshot.scanlensReady ? "Scanlens database found" : "import scans with scanlens outside the agent"],
    [(snapshot.discoveryRuns ?? 0) > 0, "Map the attack surface",
      snapshot.discoveryRuns ? `${snapshot.discoveryRuns} discovery run(s); /rt-discover for more`
        : snapshot.discovery ? "discovery mode is on → /rt-steer → Map the attack surface" : "/rt-discover on allows bounded discovery of new hosts and routes"],
    [total > 0 && coverage?.pending === 0, "Triage and review coverage",
      total ? `${percent}% (${done}/${total}) → /rt-steer to continue, /rt-tasks for open items` : "/rt-steer → Start scan triage"],
    [snapshot.pendingProposals + (snapshot.pendingEndpoints ?? 0) === 0, "Decide discovered hosts and routes",
      [snapshot.pendingProposals ? `${snapshot.pendingProposals} host(s) → /rt-proposals` : "", snapshot.pendingEndpoints ? `${snapshot.pendingEndpoints} route(s) → /rt-endpoints` : ""].filter(Boolean).join(" · ") || "none pending"],
    [total > 0 && coverage?.pending === 0 && !coverage.waiting && !snapshot.openTasks && !snapshot.findings?.suspected, "Close open items and report",
      `${(coverage?.waiting ?? 0) + snapshot.openTasks} item(s) need you → /rt-tasks · ${snapshot.findings?.suspected ?? 0} suspected finding(s) → /rt-findings · then /rt-report`],
  ];
  let currentAssigned = false;
  return raw.map(([complete, title, detail, blocked]) => {
    let mark: StageMark = complete ? "done" : blocked ? "blocked" : "todo";
    if (mark === "todo" && !currentAssigned) { mark = "current"; currentAssigned = true; }
    if (mark === "blocked") currentAssigned = true;
    return { mark, title, detail };
  });
}

const MARKS: Record<StageMark, string> = { done: "✓", current: "▸", todo: "○", blocked: "✗" };

function authorizationLine(snapshot: EngagementSnapshot, now: Date): string {
  if (snapshot.problem) return `⚠ ${snapshot.problem}`;
  const remaining = daysLeft(snapshot.authorizationExpires, now);
  return `authorized to ${snapshot.authorizationExpires}${remaining === undefined ? "" : remaining <= 7 ? ` (⚠ ${remaining}d left)` : ` (${remaining}d)`}`;
}

/** Always states the discovery mode, on or off, so the operator never has to remember it. */
export function discoveryLabel(snapshot: Pick<EngagementSnapshot, "discovery">): string {
  return snapshot.discovery
    ? `◆ DISCOVERY ON ${snapshot.discovery.limit - snapshot.discovery.used}/${snapshot.discovery.limit} left`
    : "◇ discovery off";
}

/** Validated and suspected findings at a glance. */
export function findingsLabel(snapshot: Pick<EngagementSnapshot, "findings">): string {
  const findings = snapshot.findings;
  return `Findings ${findings ? `${findings.validated + findings.reported}✓ ${findings.suspected}?` : "0"}`;
}

/** Compact always-visible panel: identity, safety state, progress, and the next step. */
export function panelLines(snapshot: EngagementSnapshot, now = new Date()): string[] {
  const { done, total, percent } = completion(snapshot);
  const next = nextActions(snapshot, now)[0];
  const coverage = snapshot.coverage;
  const open = (coverage?.waiting ?? 0) + snapshot.openTasks + (snapshot.openQuestions ?? 0);
  return [
    `RT ▸ ${snapshot.engagement || "no engagement"} · ${authorizationLine(snapshot, now)} · ${snapshot.armed ? "● ARMED" : "○ disarmed"} · ${discoveryLabel(snapshot)}${snapshot.autopilot ? ` · ▶ AUTO ${snapshot.autopilot.runs}/${snapshot.autopilot.limit}` : ""}`,
    `Scope ${snapshot.targets} target(s), ${snapshot.exclusions} excluded · Coverage ${progressBar(done, total, 12)} ${total ? `${percent}% (${done}/${total})` : "not started"} · pending ${coverage?.pending ?? 0} · Needs you ${open} · Proposals ${snapshot.pendingProposals + (snapshot.pendingEndpoints ?? 0)} · ${findingsLabel(snapshot)}`,
    `Next: ${next.command} — ${next.label} (${next.why}) · /rt opens the menu`,
  ];
}

export function overviewText(snapshot: EngagementSnapshot, now = new Date()): string {
  const stages = workflowStages(snapshot).map((stage, index) => `  ${MARKS[stage.mark]} ${index + 1}. ${stage.title} — ${stage.detail}`);
  const next = nextActions(snapshot, now).map((action, index) => `  ${index === 0 ? "▸" : "·"} ${action.command.padEnd(14)} ${action.label} — ${action.why}`);
  return [
    `${snapshot.engagement || "No engagement configured"} — ${authorizationLine(snapshot, now)}`,
    `Active checks: ${snapshot.armed ? "● ARMED (in-scope commands run without a prompt)" : "○ disarmed (each active command asks you first)"}`,
    `Discovery: ${snapshot.discovery ? `◆ ON (${snapshot.discovery.limit - snapshot.discovery.used} of ${snapshot.discovery.limit} request(s) left)` : "◇ off (/rt-discover on allows bounded discovery)"}`,
    "",
    "Workflow   ✓ done · ▸ you are here · ○ later · ✗ blocked",
    ...stages,
    "",
    "What you can do next",
    ...next,
  ].join("\n");
}

export const HELP_TEXT = [
  "Red-team harness — operator guide",
  "",
  "START",
  "  /rt-start           Guided start: checks the folder, runs setup, says what goes where",
  "  /rt                 Menu: where you are, what is next, every action",
  "  /rt-status          Workflow checklist and next steps",
  "  /rt-setup           Engagement wizard (name, expiry, scope, paths)",
  "  /rt-tools           Which assessment tools are installed, and how to add the rest",
  "",
  "SCOPE",
  "  /rt-targets         Everything in scope, exclusions, priority routes",
  "  /rt-onboard HOST    Add one exact host or IP (confirms written authorization)",
  "  /rt-offboard HOST   Take one host out of scope (removes it or excludes it)",
  "  /rt-proposals       Decide on hosts the agent proposed or discovered",
  "  /rt-endpoints       Decide on routes discovered on in-scope hosts",
  "",
  "DISCOVER",
  "  /rt-discover        Discovery status: budget, passive sources, wildcards",
  "  /rt-discover on [N] Let the agent send up to N bounded discovery requests",
  "  /rt-discover off    Stop discovery",
  "  /rt-discover allow HOST   Approve a passive source such as crt.sh (deny removes it)",
  "",
  "RUN",
  "  /rt-steer           Pick a ready-made instruction for the agent",
  "  /rt-auto on [RUNS]  Autopilot: the harness starts the agent's next runs by itself",
  "  /rt-auto off        Stop starting runs · /rt-auto last shows the last digest",
  "  /rt-pause           Stop autopilot and interrupt the running agent at once",
  "  /rt-arm             Allow in-scope active checks without a prompt",
  "  /rt-disarm          Back to one prompt per active command",
  "",
  "TRACK",
  "  /rt-tasks           Open work: what needs you, what the agent can continue",
  "  /rt-tasks add TEXT  Track a task · /rt-tasks done ID closes it",
  "  /rt-answer          Answer questions the agent filed while it kept working",
  "  /rt-progress        Completion reconciled with the scan inventory",
  "  /rt-coverage        Coverage counts by state",
  "",
  "RESULTS",
  "  /rt-findings        Findings register: validated, suspected, reported",
  "  /rt-findings validate|report|dismiss|reopen ID   Decide on one finding",
  "  /rt-creds           Captured credentials: where kept, where tried",
  "  /rt-report          Write the draft client report to the evidence folder",
  "  /rt-handover        Write a handover note for a colleague or a new session",
  "",
  "AUDIT",
  "  /rt-log             Recent events · /rt-log failures · /rt-log verify",
  "",
  "While the agent works: type a message to steer it, Escape to interrupt.",
  "A command blocked by the guard explains why; scope and exclusions always win.",
].join("\n");

export interface SteeringPrompt { label: string; prompt: string; why?: string; fromAgent?: boolean }

/**
 * Standing orders for the agent: what it works toward and how it reports. The
 * operator decides quickly from a short brief; detail belongs in evidence files.
 */
export function operatorBriefRules(snapshot: EngagementSnapshot): string[] {
  const coverage = snapshot.coverage;
  const done = coverage ? coverage.reviewed + coverage.grouped : 0;
  const total = coverage?.total ?? 0;
  const standing = coverage
    ? `coverage ${total ? Math.round((done / total) * 100) : 0}% (${done}/${total}), pending ${coverage.pending}, waiting on operator ${coverage.waiting}, blocked ${coverage.blocked}`
    : "nothing recorded yet";
  return [
    `OBJECTIVE: drive coverage to 100% and pending to 0. Current standing: ${standing}. Work toward this on your own initiative in every run: take pending items in batches, most valuable first, and keep going without asking whether to continue. Stop only when nothing is pending, when you need something only the operator can give, or when a guard blocks you.`,
    "No item may stay pending because it is hard. If outside evidence cannot settle it, record it as unresolved_from_outside, or as waiting_on_operator with the exact missing fact; if scope or a gateway prevents it, record it as blocked with the reason. Never mark an item reviewed without evidence in order to raise the percentage. When 100% is not reachable, get as close as the evidence allows and say in one line what holds the rest.",
    "REPORTING: the operator is steering a live operation and must be able to decide in seconds. Write an operator brief, not a report. No preamble, no restating the request, no narration of method, no raw tool output, no closing recap. Put detail in an evidence file and cite its path. Unless the operator asks for depth, keep the whole reply under about 15 lines and end every run with exactly this block:",
    "STATUS  coverage N% (done/total) · pending N · waiting N · blocked N",
    "FOUND   up to three one-line items, most severe first, each with its evidence path; or \"nothing new\"",
    "NEED    each decision or fact required from the operator, one line each; or \"nothing\"",
    "NEXT    up to three numbered next steps, best first, each one line with its expected gain",
    "FINDINGS: record every plausible issue in redteam_findings the moment you see it (status suspected), and move it to validated once affected systems, description, and evidence are established. The operator's report is generated from that register, so a finding that exists only in a reply is lost. FOUND lines cite the register number, e.g. \"#4 Exposed admin console\".",
    "CREDENTIALS: when you come across a credential, hash, token, or key, write the value to a file under the evidence directory's loot folder and record it with redteam_credentials, never in a reply, a finding, or a task. Check that ledger before proposing reuse. Trying a credential is an active check that needs the operator's explicit approval each time.",
    "Before you end a run, call redteam_next with those next steps: a short label, the instruction the operator would send you, and the expected gain. They appear in the operator's /rt-steer menu, so write each instruction so it can be sent as-is. Put first the route with the best expected gain toward the objective, preferring steps that close pending items or confirm a plausible compromise path.",
  ];
}

/** The agent's own recommendations first, then the ready-made instructions. */
export function steeringPrompts(snapshot: EngagementSnapshot): SteeringPrompt[] {
  const recommended = (snapshot.agentNext ?? []).map((step) => ({ label: step.label, prompt: step.instruction, why: step.why, fromAgent: true }));
  return [...recommended, ...builtInPrompts(snapshot)];
}

function builtInPrompts(snapshot: EngagementSnapshot): SteeringPrompt[] {
  const prompts: SteeringPrompt[] = [
    { label: "Start scan triage",
      prompt: "Start scan triage for this engagement. Check redteam_scope, then use scanlens: guide, summary, and narrowed findings/hosts/services queries. Give me a prioritized list of plausible compromise paths with the evidence for each, and record coverage as you go. Do not run active checks yet." },
    { label: "Map the attack surface",
      prompt: "Map the attack surface with redteam_discover. Check its status first; if discovery mode is off, stop and tell me to run /rt-discover on. Otherwise run well_known on each in-scope web origin, subdomains on each authorized wildcard domain, certificates on each in-scope domain if a certificate source is approved, and vhosts where several in-scope names share a server. Watch the budget, then summarize the new hosts and routes that await my review in /rt-proposals and /rt-endpoints." },
    { label: "Drive coverage to 100%, pending to 0",
      prompt: "Drive coverage to 100% and pending to 0. Work through the pending items from redteam_coverage in batches, most valuable first, and record an outcome for each. Do not stop to ask whether to continue: keep going until nothing is pending or you need something only I can give. Park what you cannot resolve as waiting on me or unresolved from outside, with the missing fact. Report as an operator brief." },
    { label: "Review priority web endpoints",
      prompt: "Review the configured priority web endpoints one by one: exact routes only, bounded HEAD/GET requests, no crawling or brute forcing. Record coverage for each and summarize what you observed." },
    { label: "Screenshot the web endpoints",
      prompt: "Take one screenshot of every in-scope web endpoint that has none yet under the evidence screenshots folder: the priority endpoints from redteam_scope first, then the root page of each in-scope web service in scanlens. Look at each one, and record in coverage what the page is (login form, admin console, default page, error, placeholder) with the screenshot path as a source. Record anything that stands out, such as an exposed admin or default install page, in redteam_findings as suspected. Report as an operator brief with a count per page type." },
    { label: "Validate the top finding",
      prompt: "List redteam_findings, take the most severe suspected finding and validate it with the least invasive check. Say in one line what the check is before running it, save the evidence, and update the register: validated with its evidence, or a note saying why it looks like a false positive so I can dismiss it." },
    { label: "Report where we stand",
      prompt: "Give me a status report: what has been reviewed, what is still pending or blocked, what you need from me, and the three most useful next steps. Use redteam_coverage, redteam_tasks, and redteam_audit, not memory." },
    { label: "Complete the findings register",
      prompt: "Bring the findings register to report quality. For every validated finding in redteam_findings, fill in what missingForReport lists (risk, mitigation, OSSTMM category, ratings) following the security-findings skill, with exact affected systems and evidence that cites a file or record. For every suspected finding, either validate it from existing evidence or note why it cannot be confirmed. Do not paste the findings into the reply: tell me the counts and that /rt-report is ready." },
    { label: "Go through the open questions with me",
      prompt: "List every coverage item in state waiting_on_operator (redteam_coverage) and every open task (redteam_tasks), numbered, each with the exact fact or decision you need from me. Then ask me about them one at a time. After each answer, update the coverage record with the new outcome or close the task, and tell me what changed. If I say I cannot supply a fact, record the item as unresolved from outside." },
    { label: "Pause active work",
      prompt: "Stop running active checks now. Summarize what you were doing, what completed, and what remains, then wait for my instruction." },
  ];
  // Put the most relevant instruction first.
  const preferred = snapshot.discovery && !snapshot.discoveryRuns ? 1
    : !snapshot.coverage || snapshot.coverage.reviewed + snapshot.coverage.grouped === 0 ? 0 : snapshot.coverage.pending ? 2 : 7;
  return [prompts[preferred], ...prompts.filter((_, index) => index !== preferred)];
}

export interface BoardInput {
  snapshot: EngagementSnapshot;
  waiting: { key: string; missing?: string }[];
  blocked: { key: string; reason?: string }[];
  pending: { key: string }[];
  proposals: { host: string; reason: string }[];
  endpoints?: string[];
  tasks: { id: number; title: string; createdBy: string; createdAt: string; status: string }[];
  showClosed?: boolean;
}

function sample<T>(items: T[], total: number, render: (item: T) => string): string[] {
  return [...items.map((item) => `      - ${render(item)}`), ...(total > items.length ? [`      - … ${total - items.length} more`] : [])];
}

export function boardText(input: BoardInput, now = new Date()): string {
  const { snapshot } = input;
  const coverage = snapshot.coverage;
  const { done, total, percent } = completion(snapshot);
  const needsYou: string[] = [];
  if (snapshot.problem) needsYou.push(`  ! Configuration: ${snapshot.problem} → /rt-setup`);
  const remaining = daysLeft(snapshot.authorizationExpires, now);
  if (!snapshot.problem && remaining !== undefined && remaining <= 7) needsYou.push(`  ! Authorization expires in ${remaining} day(s) → /rt-setup`);
  if (snapshot.openQuestions) needsYou.push(`  ? ${snapshot.openQuestions} question(s) from the agent → /rt-answer`);
  if (coverage?.waiting) {
    needsYou.push(`  ! ${coverage.waiting} coverage item(s) wait on a fact from you → /rt-steer → Go through the open questions with me`,
      ...sample(input.waiting, coverage.waiting, (item) => `${item.key}${item.missing ? ` — needs: ${item.missing}` : ""}`));
  }
  if (input.proposals.length) {
    needsYou.push(`  ! ${snapshot.pendingProposals} scope proposal(s) to decide → /rt-proposals`,
      ...sample(input.proposals, snapshot.pendingProposals, (item) => `${item.host} — ${item.reason}`));
  }
  if (snapshot.pendingEndpoints) {
    needsYou.push(`  ! ${snapshot.pendingEndpoints} discovered route(s) to decide → /rt-endpoints`, ...sample(input.endpoints ?? [], snapshot.pendingEndpoints, (item) => item));
  }
  const agent: string[] = [];
  if (coverage?.pending) {
    agent.push(`  ▸ ${coverage.pending} pending coverage item(s) → /rt-steer`, ...sample(input.pending, coverage.pending, (item) => item.key));
  }
  if (snapshot.findings?.suspected) agent.push(`  ▸ ${snapshot.findings.suspected} suspected finding(s) to validate → /rt-steer → Validate the top finding · /rt-findings`);
  if (coverage?.blocked) {
    agent.push(`  ▸ ${coverage.blocked} blocked item(s): review scope or an approved vantage point`,
      ...sample(input.blocked, coverage.blocked, (item) => `${item.key}${item.reason ? ` — ${item.reason}` : ""}`));
  }
  const open = input.tasks.filter((task) => task.status === "open");
  const listed = input.showClosed ? input.tasks : open;
  const ownTasks = open.length ? [`  ! ${open.length} tracked task(s) are open: do them, then /rt-tasks done ID (listed below)`] : [];
  needsYou.push(...ownTasks);
  const tasks = listed.map((task) => `  ${task.status === "open" ? "□" : "✓"} #${task.id} [${task.createdBy}] ${task.title}  (${task.createdAt.slice(0, 10)})`);
  return [
    `${snapshot.engagement || "No engagement"} — open work`,
    `Coverage  ${progressBar(done, total)}  ${total ? `${percent}% (${done}/${total} reviewed or grouped)` : "nothing recorded yet"}`,
    "",
    "NEEDS YOU",
    ...(needsYou.length ? needsYou : ["  ✓ nothing is waiting on you"]),
    "",
    "AGENT CAN CONTINUE",
    ...(agent.length ? agent : ["  ✓ no pending or blocked coverage items, no suspected findings"]),
    "",
    `TRACKED TASKS (${open.length} open)`,
    ...(tasks.length ? tasks : ["  (none)"]),
    "",
    "Add: /rt-tasks add TEXT · Close: /rt-tasks done ID · Reopen: /rt-tasks reopen ID · Include closed: /rt-tasks all",
  ].join("\n");
}

/** Shown once when a session starts: what this is, the state of this folder, and where to begin. */
export function welcomeText(snapshot: EngagementSnapshot, readmePath: string, now = new Date()): string {
  const configured = Boolean(snapshot.engagement) && (!snapshot.problem || snapshot.problem === NO_TARGETS);
  const state = !configured
    ? `No engagement is set up in this folder yet${snapshot.problem ? ` (${snapshot.problem})` : ""}.`
    : `Engagement: ${snapshot.engagement} · ${authorizationLine(snapshot, now)} · ${snapshot.targets} target(s), ${snapshot.exclusions} excluded`;
  const first = !configured || snapshot.targets === 0 || !snapshot.scanlensReady
    ? "  /rt-start   Start here: checks this folder and walks you through what is missing"
    : "  /rt         Start here: where you are, what is next, and every action";
  const second = first.includes("/rt-start")
    ? "  /rt         Menu: where you are, what is next, and every action"
    : "  /rt-start   Setup check: what this folder contains and what is missing";
  return [
    "Welcome to the Pi red-team harness",
    state,
    "",
    first,
    second,
    "  /rt-help    All commands on one page",
    `  Full guide: ${readmePath}`,
    "",
    snapshot.armed
      ? "Active checks are ● ARMED: in-scope commands run without a prompt until you run /rt-disarm. Scope and exclusions always win."
      : "Active checks are disarmed: every command that contacts a target asks you first. /rt-arm keeps them armed until you run /rt-disarm.",
  ].join("\n");
}
