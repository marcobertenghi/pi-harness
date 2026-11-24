import { isIP } from "node:net";
import type { DatabaseSync } from "node:sqlite";
import { normalizeWebEndpoint } from "./scope.ts";

export const dispositions = ["deferred", "rejected", "onboarded"] as const;
export type Disposition = typeof dispositions[number];

export function proposalHost(value: string): string {
  const host = value.trim().toLowerCase().replace(/\.$/, "");
  if (isIP(host)) return host;
  if (host.length > 253 || !host.split(".").every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw new Error("Use one exact hostname or IP, without URLs, ports, wildcards, or ranges.");
  }
  return host;
}

export class ProposalStore {
  constructor(private readonly db: DatabaseSync) {
    db.exec(`CREATE TABLE IF NOT EXISTS target_proposals (
      engagement_key TEXT NOT NULL,
      host TEXT NOT NULL,
      source TEXT NOT NULL,
      reason TEXT NOT NULL,
      proposed_at TEXT NOT NULL,
      PRIMARY KEY (engagement_key, host)
    );
    CREATE TABLE IF NOT EXISTS target_proposal_dispositions (
      engagement_key TEXT NOT NULL,
      host TEXT NOT NULL,
      disposition TEXT NOT NULL,
      reviewed_at TEXT NOT NULL,
      PRIMARY KEY (engagement_key, host),
      FOREIGN KEY (engagement_key, host) REFERENCES target_proposals (engagement_key, host)
    )`);
  }

  record(key: string, candidate: string, source: string, reason: string) {
    const host = proposalHost(candidate);
    if (!source.trim() || !reason.trim()) throw new Error("A source reference and reason are required.");
    const result = this.db.prepare(`INSERT INTO target_proposals VALUES (?, ?, ?, ?, ?)
      ON CONFLICT (engagement_key, host) DO NOTHING`).run(key, host, source, reason, new Date().toISOString());
    return { host, recorded: Number(result.changes) === 1, authorizationChanged: false };
  }

  setDisposition(key: string, candidate: string, disposition: Disposition) {
    const host = proposalHost(candidate);
    if (!dispositions.includes(disposition)) throw new Error("Unknown proposal disposition.");
    if (!this.db.prepare("SELECT 1 FROM target_proposals WHERE engagement_key = ? AND host = ?").get(key, host)) {
      throw new Error("No such proposal in this engagement.");
    }
    const reviewedAt = new Date().toISOString();
    this.db.prepare(`INSERT INTO target_proposal_dispositions VALUES (?, ?, ?, ?)
      ON CONFLICT (engagement_key, host) DO UPDATE SET disposition = excluded.disposition, reviewed_at = excluded.reviewed_at`)
      .run(key, host, disposition, reviewedAt);
    return { host, disposition, reviewedAt };
  }

  list(key: string, offset = 0, limit = 20, pendingOnly = false) {
    const rows = this.db.prepare(`SELECT p.host, p.source, p.reason, p.proposed_at AS proposedAt,
      coalesce(d.disposition, 'pending') AS disposition, d.reviewed_at AS reviewedAt FROM target_proposals p
      LEFT JOIN target_proposal_dispositions d USING (engagement_key, host)
      WHERE p.engagement_key = ? ${pendingOnly ? "AND d.disposition IS NULL" : ""}
      ORDER BY p.proposed_at DESC, p.host LIMIT ? OFFSET ?`).all(key, limit + 1, offset);
    return {
      entries: rows.slice(0, limit) as { host: string; source: string; reason: string; proposedAt: string; disposition: Disposition | "pending"; reviewedAt: string | null }[],
      nextOffset: rows.length > limit ? offset + limit : null,
    };
  }
}

export const endpointDispositions = ["accepted", "deferred", "rejected"] as const;
export type EndpointDisposition = typeof endpointDispositions[number];
export interface EndpointProposal { endpoint: string; source: string; reason: string; proposedAt: string; disposition: EndpointDisposition | "pending"; reviewedAt: string | null }

/** One exact, credential-free HTTP(S) URL without wildcards; query strings and fragments are dropped. */
export function proposalEndpoint(value: string): string {
  const endpoint = normalizeWebEndpoint(value);
  if (!endpoint || endpoint.length > 2048 || new URL(endpoint).pathname.includes("*")) {
    throw new Error("Use one exact http(s) URL without credentials or wildcards.");
  }
  return endpoint;
}

/** Routes discovered on in-scope hosts, waiting for the operator to make them priority endpoints. */
export class EndpointProposalStore {
  constructor(private readonly db: DatabaseSync) {
    db.exec(`CREATE TABLE IF NOT EXISTS endpoint_proposals (
      engagement_key TEXT NOT NULL,
      endpoint TEXT NOT NULL,
      source TEXT NOT NULL,
      reason TEXT NOT NULL,
      proposed_at TEXT NOT NULL,
      disposition TEXT,
      reviewed_at TEXT,
      PRIMARY KEY (engagement_key, endpoint)
    )`);
  }

  record(key: string, candidate: string, source: string, reason: string) {
    const endpoint = proposalEndpoint(candidate);
    if (!source.trim() || !reason.trim()) throw new Error("A source reference and reason are required.");
    const result = this.db.prepare(`INSERT INTO endpoint_proposals (engagement_key, endpoint, source, reason, proposed_at) VALUES (?, ?, ?, ?, ?)
      ON CONFLICT (engagement_key, endpoint) DO NOTHING`).run(key, endpoint, source, reason, new Date().toISOString());
    return { endpoint, recorded: Number(result.changes) === 1, scopeChanged: false };
  }

  setDisposition(key: string, candidate: string, disposition: EndpointDisposition) {
    const endpoint = proposalEndpoint(candidate);
    const reviewedAt = new Date().toISOString();
    const result = this.db.prepare("UPDATE endpoint_proposals SET disposition = ?, reviewed_at = ? WHERE engagement_key = ? AND endpoint = ?")
      .run(disposition, reviewedAt, key, endpoint);
    if (Number(result.changes) !== 1) throw new Error("No such endpoint proposal in this engagement.");
    return { endpoint, disposition, reviewedAt };
  }

  list(key: string, offset = 0, limit = 20, pendingOnly = false) {
    const rows = this.db.prepare(`SELECT endpoint, source, reason, proposed_at AS proposedAt, coalesce(disposition, 'pending') AS disposition,
      reviewed_at AS reviewedAt FROM endpoint_proposals WHERE engagement_key = ? ${pendingOnly ? "AND disposition IS NULL" : ""}
      ORDER BY endpoint LIMIT ? OFFSET ?`).all(key, limit + 1, offset) as unknown as EndpointProposal[];
    return { entries: rows.slice(0, limit), nextOffset: rows.length > limit ? offset + limit : null };
  }

  pendingCount(key: string): number {
    return Number((this.db.prepare("SELECT count(*) AS n FROM endpoint_proposals WHERE engagement_key = ? AND disposition IS NULL").get(key) as { n: number }).n);
  }
}
