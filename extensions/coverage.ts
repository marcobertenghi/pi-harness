import type { DatabaseSync } from "node:sqlite";
import { isIP } from "node:net";
import { normalizeTarget, normalizeWebEndpoint, scopeDecision } from "./scope.ts";

export const outcomes = ["observed", "inferred", "advisory_candidate", "unresolved_from_outside"] as const;
export const states = ["pending", "reviewed", "waiting_on_operator", "grouped", "blocked"] as const;
export type Outcome = typeof outcomes[number];
export type State = typeof states[number];
export const layers = ["gateway_only", "application", "service", "unknown"] as const;
export type Layer = typeof layers[number];
export type ServiceSubject = { host: string; port: number; transport: "tcp" | "udp" };
export type Subject = { endpoint: string } | ServiceSubject;
export interface Review {
  state: Exclude<State, "pending">;
  outcome?: Outcome;
  claim: string;
  evidence: { source: string; observation: string }[];
  counterevidence?: string;
  missingFact?: string;
  representative?: string;
  layer?: Layer;
}

export interface CoverageScope {
  key: string;
  endpoints: string[];
  targets: string[];
  exclusions: string[];
}

type Entry = { key: string; subject: Subject; state: State; review?: Review; updatedAt?: string; reason?: string; inScanlens?: true };

type ViewOptions = { state?: State; outcome?: Outcome; layer?: Layer; offset?: number; limit?: number; scanned?: ServiceSubject[]; scanlensOnly?: boolean };

export function serviceSubject(value: { host: string; port: unknown; transport: unknown }): ServiceSubject {
  const host = value.host.trim().toLowerCase().replace(/\.$/, "");
  const { port, transport } = value;
  if ((!isIP(host) && (normalizeTarget(host) !== host || host.length > 253 || !host.split(".").every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)))) ||
    typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535 ||
    (transport !== "tcp" && transport !== "udp")) throw new Error("Use a concrete hostname or IP, port, and transport.");
  return { host, port, transport };
}

function serviceKey({ host, port, transport }: ServiceSubject) { return `service:${transport}:${host}:${port}`; }

function endpointKey(endpoint: string) { return `endpoint:${endpoint}`; }

function subjectKey(subject: Subject, scope: CoverageScope): { key: string; subject: Subject; host: string } {
  if ("endpoint" in subject) {
    const endpoint = normalizeWebEndpoint(subject.endpoint);
    if (!scope.endpoints.includes(endpoint)) throw new Error("Use a configured priority endpoint (wildcards are not expanded).");
    return { key: endpointKey(endpoint), subject: { endpoint }, host: endpoint };
  }
  const service = serviceSubject(subject);
  return { key: serviceKey(service), subject: service, host: service.host };
}

export class CoverageStore {
  constructor(private readonly db: DatabaseSync) {
    db.exec(`CREATE TABLE IF NOT EXISTS coverage_entries (
      engagement_key TEXT NOT NULL,
      subject_key TEXT NOT NULL,
      subject_json TEXT NOT NULL,
      review_json TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      PRIMARY KEY (engagement_key, subject_key)
    )`);
  }

  record(scope: CoverageScope, subject: Subject, review: Review): { key: string; updatedAt: string } {
    const entry = subjectKey(subject, scope);
    if (scopeDecision(entry.host, scope.targets, scope.exclusions) !== "included") throw new Error("Coverage subject is not in current scope.");
    if (!review.claim.trim()) throw new Error("A claim or reason is required.");
    if (review.evidence.some(item => !item.source.trim() || !item.observation.trim())) throw new Error("Evidence needs both a source and an observation.");
    if (review.outcome && review.outcome !== "unresolved_from_outside" && !review.evidence.length) throw new Error("A sourced observation is required for this outcome.");
    if ("endpoint" in entry.subject && new URL(entry.subject.endpoint).pathname.includes("*") && review.outcome === "observed") throw new Error("An observation cannot cover a wildcard path directly.");
    if (review.state === "reviewed" && !review.outcome) throw new Error("Reviewed entries need an outcome.");
    if ((review.state === "waiting_on_operator" || review.outcome === "unresolved_from_outside" || review.outcome === "advisory_candidate") && !review.missingFact?.trim()) throw new Error("Record the missing fact that would change the conclusion.");
    if (review.state === "grouped") {
      if (!("endpoint" in entry.subject) || !review.representative || !review.evidence.length) throw new Error("Grouping requires a representative route and evidence of a shared application and authentication boundary.");
      const rep = this.representative(scope, entry.subject.endpoint, review.representative);
      if (!rep) throw new Error("The representative must be a different, exact, in-scope route on the same origin with a recorded observation.");
      review = { ...review, representative: rep };
    } else if (review.representative) throw new Error("Only grouped entries can name a representative.");
    const updatedAt = new Date().toISOString();
    this.db.prepare(`INSERT INTO coverage_entries VALUES (?, ?, ?, ?, ?)
      ON CONFLICT (engagement_key, subject_key) DO UPDATE SET review_json = excluded.review_json, updated_at = excluded.updated_at`)
      .run(scope.key, entry.key, JSON.stringify(entry.subject), JSON.stringify(review), updatedAt);
    return { key: entry.key, updatedAt };
  }

  private representative(scope: CoverageScope, endpoint: string, proposed: string): string | undefined {
    const rep = normalizeWebEndpoint(proposed);
    if (!rep || rep === endpoint || new URL(rep).pathname.includes("*") || new URL(rep).origin !== new URL(endpoint).origin ||
        !scope.endpoints.includes(rep) || scopeDecision(rep, scope.targets, scope.exclusions) !== "included") return;
    const row = this.db.prepare("SELECT review_json FROM coverage_entries WHERE engagement_key = ? AND subject_key = ?").get(scope.key, endpointKey(rep));
    const review = row && JSON.parse(String(row.review_json)) as Review;
    if (review && review.state === "reviewed" && review.outcome === "observed") return rep;
  }

  view(scope: CoverageScope, options: ViewOptions = {}) {
    const entries = new Map<string, Entry>();
    for (const endpoint of scope.endpoints) {
      const key = endpointKey(endpoint);
      const included = scopeDecision(endpoint, scope.targets, scope.exclusions) === "included";
      entries.set(key, { key, subject: { endpoint }, state: included ? "pending" : "blocked",
        ...(included ? {} : { reason: "Outside current scope" }) });
    }
    for (const row of this.db.prepare("SELECT * FROM coverage_entries WHERE engagement_key = ? ORDER BY subject_key").iterate(scope.key)) {
      const subject = JSON.parse(String(row.subject_json)) as Subject;
      const key = String(row.subject_key);
      if ("endpoint" in subject ? entries.get(key)?.state !== "pending" : scopeDecision(subject.host, scope.targets, scope.exclusions) !== "included") continue;
      const review = JSON.parse(String(row.review_json)) as Review;
      const invalidGroup = "endpoint" in subject && review.state === "grouped" && !this.representative(scope, subject.endpoint, review.representative ?? "");
      entries.set(key, { key, subject, state: invalidGroup ? "pending" : review.state, review, updatedAt: String(row.updated_at),
        ...(invalidGroup ? { reason: "Representative no longer supports grouping; reassess" } : {}) });
    }
    for (const subject of options.scanned ?? []) {
      if (scopeDecision(subject.host, scope.targets, scope.exclusions) !== "included") continue;
      const key = serviceKey(subject);
      entries.set(key, { ...(entries.get(key) ?? { key, subject, state: "pending" }), inScanlens: true });
    }
    const counts = Object.fromEntries(states.map(state => [state, 0]));
    const scannedCounts = Object.fromEntries(states.map(state => [state, 0]));
    let gatewayOnly = 0;
    const matching: Entry[] = [];
    for (const entry of entries.values()) {
      counts[entry.state]++;
      if (entry.inScanlens) scannedCounts[entry.state]++;
      const review = entry.state === "pending" ? undefined : entry.review;
      if (review?.layer === "gateway_only") gatewayOnly++;
      if ((!options.scanlensOnly || entry.inScanlens) && (!options.state || entry.state === options.state) &&
          (!options.outcome || review?.outcome === options.outcome) &&
          (!options.layer || (review?.layer ?? "unknown") === options.layer)) matching.push(entry);
    }
    const offset = options.offset ?? 0;
    const page = matching.slice(offset, offset + (options.limit ?? 20));
    return { counts, gatewayOnly, ...(options.scanned && { scannedCounts }), total: entries.size, matched: matching.length,
      nextOffset: offset + page.length < matching.length ? offset + page.length : null, entries: page };
  }
}
