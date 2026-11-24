import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { AuditLog } from "./audit.ts";
import { states, type CoverageScope } from "./coverage.ts";
import { loadScanInventory } from "./coverage-inventory.ts";
import { progressBar } from "./guide.ts";
import { normalizeTarget, scopeDecision, type TargetSourceDetail } from "./scope.ts";

type AdminScope = CoverageScope & {
  engagement: string;
  authorizationExpires: string;
  authorizationProblem?: string;
  scanlensDb: string;
  sourceDetails: TargetSourceDetail[];
};

type Proposal = {
  host: string;
  disposition: "pending" | "deferred" | "rejected" | "onboarded";
  reason: string;
};

type CommandContext = {
  cwd: string;
  hasUI: boolean;
  ui: {
    notify(message: string, level?: "info" | "warning" | "error"): void;
    select(title: string, options: string[]): Promise<string | undefined>;
  };
  sessionManager: { getSessionId(): string };
};

export function targetOverview(scope: Pick<AdminScope, "targets" | "exclusions" | "endpoints">, proposals: Proposal[]) {
  const onboarded = new Set(proposals.filter(item => item.disposition === "onboarded").map(item => normalizeTarget(item.host)));
  const rows = scope.targets.map(target => {
    const normalized = normalizeTarget(target);
    const endpointCount = scope.endpoints.filter(endpoint => scopeDecision(endpoint, [target], []) === "included").length;
    return {
      target,
      status: onboarded.has(normalized) ? "onboarded" as const : "baseline" as const,
      endpointCount,
    };
  }).sort((a, b) => Number(b.status === "onboarded") - Number(a.status === "onboarded") || a.target.localeCompare(b.target));
  return {
    rows,
    onboarded: rows.filter(row => row.status === "onboarded").length,
    baseline: rows.filter(row => row.status === "baseline").length,
    exclusions: [...scope.exclusions].sort(),
  };
}

export function progressOverview(view: ReturnType<AuditLog["coverage"]["view"]>, pendingProposals: Proposal[]) {
  const completed = view.counts.reviewed + view.counts.grouped;
  const open = view.counts.pending + view.counts.waiting_on_operator + view.counts.blocked;
  const percent = view.total ? Math.round((completed / view.total) * 100) : 100;
  const actions: string[] = [];
  if (view.counts.pending) actions.push(`${view.counts.pending} pending item(s): collect a distinct evidence source or record why the question cannot be resolved externally.`);
  if (view.counts.waiting_on_operator) actions.push(`${view.counts.waiting_on_operator} item(s) waiting on the operator: provide the recorded missing fact, approved vantage point, or owner artifact.`);
  if (view.counts.blocked) actions.push(`${view.counts.blocked} blocked item(s): review gateway restrictions, scope, or an approved alternate vantage point.`);
  if (pendingProposals.length) actions.push(`${pendingProposals.length} pending scope proposal(s): review with /rt-proposals.`);
  if (!actions.length) actions.push("No open coverage or proposal actions are currently recorded.");
  return { completed, open, percent, actions };
}

export function registerAdministration(
  pi: ExtensionAPI,
  getAudit: (ctx: { cwd: string; sessionManager: { getSessionId(): string } }) => AuditLog,
  getScope: (cwd: string) => AdminScope,
  registerCommand: ExtensionAPI["registerCommand"] = pi.registerCommand.bind(pi),
) {
  function proposals(audit: AuditLog, scope: AdminScope, pendingOnly: boolean) {
    return audit.proposals.list(scope.key, 0, 10_000, pendingOnly).entries as Proposal[];
  }

  async function showTargets(ctx: CommandContext, filter = "all") {
    const scope = getScope(ctx.cwd);
    const overview = targetOverview(scope, proposals(getAudit(ctx), scope, false));
    const rows = overview.rows.filter(row => filter === "all" || row.status === filter);
    const lines = rows.map(row => `${row.status === "onboarded" ? "★ ONBOARDED" : "· BASELINE "}  ${row.target}${row.endpointCount ? `  (${row.endpointCount} priority route${row.endpointCount === 1 ? "" : "s"})` : ""}`);
    const showHosts = filter !== "routes";
    const showRoutes = filter === "all" || filter === "routes";
    const excluded = showHosts && filter === "all" && overview.exclusions.length
      ? ["", `Excluded (${overview.exclusions.length}):`, ...overview.exclusions.map(target => `⛔ EXCLUDED   ${target}`)] : [];
    const routeSources = scope.sourceDetails.filter(source => source.webEndpoints.length);
    const routeLines = showRoutes ? [
      "",
      `Priority web endpoints with full paths (${scope.endpoints.length} unique):`,
      ...(routeSources.length ? routeSources.flatMap(source => [
        `SOURCE ${source.source}  (${source.webEndpoints.length} route${source.webEndpoints.length === 1 ? "" : "s"})`,
        ...source.webEndpoints.map(endpoint => `  ↳ ${endpoint}`),
      ]) : scope.endpoints.map(endpoint => `  ↳ ${endpoint}`)),
    ] : [];
    ctx.ui.notify([
      `${scope.engagement} — scope overview`,
      `Included host/rules: ${overview.rows.length} · baseline: ${overview.baseline} · onboarded: ${overview.onboarded} · excluded: ${overview.exclusions.length} · priority routes: ${scope.endpoints.length}`,
      "Legend: ★ added through proposal onboarding · · configured/inventory baseline · ⛔ excluded · ↳ exact priority route",
      ...(showHosts ? ["", "Included hosts and scope rules:", ...(lines.length ? lines : [`No ${filter} targets.`]), ...excluded] : []),
      ...routeLines,
      "",
      "Change scope: /rt-onboard HOST adds one exact host · /rt-offboard HOST takes one out · /rt-proposals decides agent proposals · /rt-setup for ranges, wildcards, and exclusions",
    ].join("\n"), "info");
  }

  async function showProgress(ctx: CommandContext) {
    const scope = getScope(ctx.cwd);
    const audit = getAudit(ctx);
    let scanned: Awaited<ReturnType<typeof loadScanInventory>> | undefined;
    let scanWarning: string | undefined;
    try { scanned = await loadScanInventory(ctx.cwd, scope.scanlensDb, scope); }
    catch (error) { scanWarning = error instanceof Error ? error.message : String(error); }
    const view = audit.coverage.view(scope, { scanned: scanned?.services });
    const pending = proposals(audit, scope, true);
    const progress = progressOverview(view, pending);
    const samples: string[] = [];
    for (const state of ["pending", "waiting_on_operator", "blocked"] as const) {
      const page = audit.coverage.view(scope, { state, scanned: scanned?.services, limit: 4 });
      if (!page.entries.length) continue;
      samples.push("", `${state.replaceAll("_", " ")} — next items:`);
      for (const entry of page.entries) {
        const missing = entry.review?.missingFact ?? entry.reason;
        samples.push(`- ${entry.key}${missing ? ` — resolve with: ${missing}` : ""}`);
      }
      if (page.nextOffset !== null) samples.push(`- … ${page.matched - page.entries.length} more`);
    }
    const proposalLines = pending.length
      ? ["", "Pending proposals:", ...pending.slice(0, 5).map(item => `- ${item.host} — ${item.reason}`), ...(pending.length > 5 ? [`- … ${pending.length - 5} more`] : [])]
      : [];
    ctx.ui.notify([
      `${scope.engagement} — engagement progress`,
      `Authorization: ${scope.authorizationProblem ? `INVALID — ${scope.authorizationProblem}` : `valid through ${scope.authorizationExpires}`}`,
      `Evidence completion: ${progressBar(progress.completed, view.total)} ${progress.percent}% (${progress.completed}/${view.total}); open: ${progress.open}`,
      `Coverage: ${states.map(state => `${state} ${view.counts[state]}`).join(" · ")} · gateway-only ${view.gatewayOnly}`,
      `Pending proposals: ${pending.length}`,
      ...(scanWarning ? [`Scanlens reconciliation unavailable: ${scanWarning}`] : [`Reconciled Scanlens services: ${scanned?.services.length ?? 0}${scanned?.truncated ? " (truncated)" : ""}`]),
      "",
      "Recommended actions:",
      ...progress.actions.map(action => `- ${action}`),
      ...samples,
      ...proposalLines,
      "",
      "Commands: /rt-tasks (open work board) · /rt-steer (instruct the agent) · /rt-coverage reconcile pending · /rt-proposals · /rt-targets",
    ].join("\n"), scope.authorizationProblem ? "error" : progress.open || pending.length ? "warning" : "info");
  }

  registerCommand("rt-targets", {
    description: "Show all scoped targets and highlight proposal-onboarded systems",
    handler: async (args, ctx) => {
      const filter = args.trim() || "all";
      if (!["all", "onboarded", "baseline", "routes"].includes(filter)) return ctx.ui.notify("Usage: /rt-targets [all|onboarded|baseline|routes]", "error");
      try { await showTargets(ctx as CommandContext, filter); }
      catch (error) { ctx.ui.notify(error instanceof Error ? error.message : String(error), "error"); }
    },
  });

  registerCommand("rt-progress", {
    description: "Show engagement completion, open items, missing facts, and next administrative actions",
    handler: async (_args, ctx) => {
      try { await showProgress(ctx as CommandContext); }
      catch (error) { ctx.ui.notify(error instanceof Error ? error.message : String(error), "error"); }
    },
  });

  registerCommand("rt-admin", {
    description: "Open the red-team administration dashboard",
    handler: async (_args, ctx) => {
      if (!ctx.hasUI) return ctx.ui.notify("/rt-admin requires an interactive UI. Use /rt-targets or /rt-progress.", "error");
      const choice = await ctx.ui.select("Red-team administration", [
        "Scope overview — all targets and onboarded highlights",
        "Engagement progress — open items and resolution guidance",
        "Pending proposals — open proposal review",
      ]);
      if (!choice) return;
      if (choice.startsWith("Scope")) return showTargets(ctx as CommandContext);
      if (choice.startsWith("Engagement")) return showProgress(ctx as CommandContext);
      ctx.ui.notify("Run /rt-proposals to review pending proposals interactively.", "info");
    },
  });
}
