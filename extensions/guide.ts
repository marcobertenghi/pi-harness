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
    actions.push({ command: "/rt-onboard", label: "Add an authorized target", why: "scope is empty: onboard an exact host, or add an inventory file under the configured target sources" });
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
      actions.push({ command: "/rt-help", label: "Import scan data", why: "no Scanlens database yet: import scans outside the agent, then start triage" });
    } else if (!coverage || completion(snapshot).done === 0) {
      actions.push({ command: "/rt-steer", label: "Start scan triage", why: "scan data is ready and nothing has been reviewed yet" });
    } else if (coverage.pending) {
      actions.push({ command: "/rt-steer", label: "Continue the coverage review", why: `${coverage.pending} item(s) still pending` });
    } else {
      actions.push({ command: "/rt-steer", label: "Write up findings", why: "no pending coverage items remain" });
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
    [total > 0 && coverage?.pending === 0 && !coverage.waiting && !snapshot.openTasks, "Close open items and report",
      `${(coverage?.waiting ?? 0) + snapshot.openTasks} item(s) need you → /rt-tasks`],
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

/** Compact always-visible panel: identity, safety state, progress, and the next step. */
export function panelLines(snapshot: EngagementSnapshot, now = new Date()): string[] {
  const { done, total, percent } = completion(snapshot);
  const next = nextActions(snapshot, now)[0];
  const coverage = snapshot.coverage;
  const open = (coverage?.waiting ?? 0) + snapshot.openTasks;
  return [
    `RT ▸ ${snapshot.engagement || "no engagement"} · ${authorizationLine(snapshot, now)} · ${snapshot.armed ? "● ARMED" : "○ disarmed"}${snapshot.discovery ? ` · ◆ discovery ${snapshot.discovery.limit - snapshot.discovery.used}/${snapshot.discovery.limit}` : ""}`,
    `Scope ${snapshot.targets} target(s), ${snapshot.exclusions} excluded · Coverage ${progressBar(done, total, 12)} ${total ? `${percent}% (${done}/${total})` : "not started"} · Needs you ${open} · Proposals ${snapshot.pendingProposals + (snapshot.pendingEndpoints ?? 0)}`,
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
  "  /rt                 Menu: where you are, what is next, every action",
  "  /rt-status          Workflow checklist and next steps",
  "  /rt-setup           Engagement wizard (name, expiry, scope, paths)",
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
  "  /rt-arm             Allow in-scope active checks without a prompt",
  "  /rt-disarm          Back to one prompt per active command",
  "",
  "TRACK",
  "  /rt-tasks           Open work: what needs you, what the agent can continue",
  "  /rt-tasks add TEXT  Track a task · /rt-tasks done ID closes it",
  "  /rt-progress        Completion reconciled with the scan inventory",
  "  /rt-coverage        Coverage counts by state",
  "",
  "AUDIT",
  "  /rt-log             Recent events · /rt-log failures · /rt-log verify",
  "",
  "While the agent works: type a message to steer it, Escape to interrupt.",
  "A command blocked by the guard explains why; scope and exclusions always win.",
].join("\n");

export interface SteeringPrompt { label: string; prompt: string }

export function steeringPrompts(snapshot: EngagementSnapshot): SteeringPrompt[] {
  const prompts: SteeringPrompt[] = [
    { label: "Start scan triage",
      prompt: "Start scan triage for this engagement. Check redteam_scope, then use scanlens: guide, summary, and narrowed findings/hosts/services queries. Give me a prioritized list of plausible compromise paths with the evidence for each, and record coverage as you go. Do not run active checks yet." },
    { label: "Map the attack surface",
      prompt: "Map the attack surface with redteam_discover. Check its status first; if discovery mode is off, stop and tell me to run /rt-discover on. Otherwise run well_known on each in-scope web origin, subdomains on each authorized wildcard domain, certificates on each in-scope domain if a certificate source is approved, and vhosts where several in-scope names share a server. Watch the budget, then summarize the new hosts and routes that await my review in /rt-proposals and /rt-endpoints." },
    { label: "Continue the coverage review",
      prompt: "Continue the coverage review. Use redteam_coverage to list pending items, take the next batch, and record an outcome for each from existing evidence. Tell me which items need a fact from me." },
    { label: "Review priority web endpoints",
      prompt: "Review the configured priority web endpoints one by one: exact routes only, bounded HEAD/GET requests, no crawling or brute forcing. Record coverage for each and summarize what you observed." },
    { label: "Validate the top finding",
      prompt: "Take the highest-priority unvalidated finding and validate it with the least invasive check. Explain the check before running it, save evidence, and record the result." },
    { label: "Report where we stand",
      prompt: "Give me a status report: what has been reviewed, what is still pending or blocked, what you need from me, and the three most useful next steps. Use redteam_coverage, redteam_tasks, and redteam_audit, not memory." },
    { label: "Draft client-facing findings",
      prompt: "Draft client-facing findings for everything validated so far, following the security-findings skill. List anything that still lacks evidence separately." },
    { label: "Pause active work",
      prompt: "Stop running active checks now. Summarize what you were doing, what completed, and what remains, then wait for my instruction." },
  ];
  // Put the most relevant instruction first.
  const preferred = snapshot.discovery && !snapshot.discoveryRuns ? 1
    : !snapshot.coverage || snapshot.coverage.reviewed + snapshot.coverage.grouped === 0 ? 0 : snapshot.coverage.pending ? 2 : 6;
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
  if (coverage?.waiting) {
    needsYou.push(`  ! ${coverage.waiting} coverage item(s) wait on a fact from you`,
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
  if (coverage?.blocked) {
    agent.push(`  ▸ ${coverage.blocked} blocked item(s): review scope or an approved vantage point`,
      ...sample(input.blocked, coverage.blocked, (item) => `${item.key}${item.reason ? ` — ${item.reason}` : ""}`));
  }
  const open = input.tasks.filter((task) => task.status === "open");
  const listed = input.showClosed ? input.tasks : open;
  const tasks = listed.map((task) => `  ${task.status === "open" ? "□" : "✓"} #${task.id} [${task.createdBy}] ${task.title}  (${task.createdAt.slice(0, 10)})`);
  return [
    `${snapshot.engagement || "No engagement"} — open work`,
    `Coverage  ${progressBar(done, total)}  ${total ? `${percent}% (${done}/${total} reviewed or grouped)` : "nothing recorded yet"}`,
    "",
    "NEEDS YOU",
    ...(needsYou.length ? needsYou : ["  ✓ nothing is waiting on you"]),
    "",
    "AGENT CAN CONTINUE",
    ...(agent.length ? agent : ["  ✓ no pending or blocked coverage items"]),
    "",
    `TRACKED TASKS (${open.length} open)`,
    ...(tasks.length ? tasks : ["  (none)"]),
    "",
    "Add: /rt-tasks add TEXT · Close: /rt-tasks done ID · Reopen: /rt-tasks reopen ID · Include closed: /rt-tasks all",
  ].join("\n");
}
