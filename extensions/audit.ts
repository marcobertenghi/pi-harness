import { createHash } from "node:crypto";
import { createReadStream, existsSync, mkdirSync, statSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { CoverageStore } from "./coverage.ts";
import { EndpointProposalStore, ProposalStore, type Disposition } from "./proposals.ts";
import { TaskStore } from "./tasks.ts";
import { NextStepStore } from "./nextsteps.ts";
import { FindingStore } from "./findings.ts";
import { CredentialStore } from "./credentials.ts";

export interface AuditEvent {
  timestampUtc?: string;
  eventType: string;
  sessionId: string;
  actor?: "operator" | "agent" | "extension" | "system";
  toolCallId?: string;
  target?: string;
  tool?: string;
  action?: string;
  status: string;
  durationMs?: number;
  summary?: string;
  details?: unknown;
  contentHash?: string;
  evidencePath?: string;
  scopeHash?: string;
}

export interface ScopeSnapshot {
  engagement: string;
  authorizationExpires: string;
  included: string[];
  excluded: string[];
  configHash: string;
}

export interface AuditQuery {
  operation: "timeline" | "event" | "target" | "session" | "search" | "failures" | "approvals" | "artifacts" | "scope" | "verify" | "stats";
  id?: number;
  target?: string;
  sessionId?: string;
  search?: string;
  since?: string;
  until?: string;
  limit?: number;
}

const CREDENTIAL_TOOLS = "nxc|netexec|crackmapexec|cme|hydra|medusa|sshpass|evil-winrm|smbmap|kerbrute|certipy|ldapdomaindump|bloodhound-python|mysql|mysqldump|impacket-[\\w-]+|[\\w-]+\\.py";
const SECRET_VALUE = "(?:'[^']*'|\"[^\"]*\"|[^\\s'\"`]+)";

const SECRET_PATTERNS: Array<[RegExp, string]> = [
  // Authorization header with any scheme (Bearer, Basic, Token, ...) or none.
  [/(authorization["']?\s*[:=]\s*["']?(?:[a-z-]+\s+)?)[^\s'"`]+/gi, "$1[REDACTED]"],
  // KEY=value, KEY: value and "key": "value" where the name mentions a secret.
  [/([\w-]*(?:api[_-]?key|token|secret|password|passwd|pwd|credential)[\w-]*["']?\s*[=:]\s*["']?)[^\s'"`,}]+/gi, "$1[REDACTED]"],
  [new RegExp(`(--(?:password|passwd|pass|token|api-?key|secret|hash|hashes)(?:=|\\s+))${SECRET_VALUE}`, "gi"), "$1[REDACTED]"],
  [new RegExp(`(\\s-hashes\\s+)${SECRET_VALUE}`, "gi"), "$1[REDACTED]"],
  // user:password pairs: curl -u, proxy users, and user:password@host.
  [/(\s(?:-u|--user|--proxy-user)(?:\s+|=)["']?[^\s:'"]+:)[^\s'"]+/g, "$1[REDACTED]"],
  [/(\s-U\s+["']?[^\s%'"]+%)[^\s'"]+/g, "$1[REDACTED]"],
  [/(\s\/p:)[^\s'"]+/g, "$1[REDACTED]"],
  [/([a-z][a-z0-9+.-]*:\/\/[^\s/:]+:)[^@\s/]+@/gi, "$1[REDACTED]@"],
  [/(\b[\w.-]+\/[\w.$-]+:)[^@\s'"]+(@[\w.-]+)/g, "$1[REDACTED]$2"],
  // -p / -H values, only on command lines of tools where they carry a password or hash.
  [new RegExp(`(\\b(?:${CREDENTIAL_TOOLS})\\b[^\\n;|&]*?\\s-[pH](?:\\s+|=)?)${SECRET_VALUE}`, "g"), "$1[REDACTED]"],
  [/((?:cookie|set-cookie)\s*:\s*)[^\r\n]+/gi, "$1[REDACTED]"],
];

export function redact(value: string): string {
  return SECRET_PATTERNS.reduce((text, [pattern, replacement]) => text.replace(pattern, replacement), value);
}

export function bounded(value: string, max = 2048): string {
  const clean = redact(value);
  return clean.length <= max ? clean : `${clean.slice(0, max)}… [truncated ${clean.length - max} chars]`;
}

export function hashText(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}


function safeJson(value: unknown, max = 8192): string {
  let text: string;
  try {
    text = JSON.stringify(value, (_key, item) => {
      if (typeof item === "bigint") return item.toString();
      if (item instanceof Uint8Array) return `[binary ${item.byteLength} bytes]`;
      return item;
    });
  } catch {
    text = JSON.stringify({ serializationError: true, value: String(value) });
  }
  const clean = redact(text);
  return clean.length <= max
    ? clean
    : JSON.stringify({ truncated: true, excerpt: clean.slice(0, max), omittedCharacters: clean.length - max });
}

function parseDetails(value: unknown): unknown {
  if (!value) return undefined;
  try { return JSON.parse(String(value)); } catch { return { parseError: true, excerpt: bounded(String(value), 1024) }; }
}

function eventFields(row: Record<string, unknown>) {
  return {
    timestampUtc: row.timestamp_utc,
    eventType: row.event_type,
    sessionId: row.session_id,
    actor: row.actor,
    toolCallId: row.tool_call_id,
    target: row.target,
    tool: row.tool,
    action: row.action,
    status: row.status,
    durationMs: row.duration_ms,
    summary: row.summary,
    detailsJson: row.details_json,
    contentHash: row.content_hash,
    evidencePath: row.evidence_path,
    scopeHash: row.scope_hash,
  };
}

function rowObject(row: Record<string, unknown>) {
  const { detailsJson, ...fields } = eventFields(row);
  return { id: Number(row.id), ...fields, details: parseDetails(detailsJson), eventHash: row.event_hash };
}

export class AuditLog {
  readonly dbPath: string;
  private readonly db: DatabaseSync;
  private coverageStore?: CoverageStore;
  private proposalStore?: ProposalStore;
  private taskStore?: TaskStore;

  private endpointProposalStore?: EndpointProposalStore;

  get endpointProposals(): EndpointProposalStore {
    return this.endpointProposalStore ??= new EndpointProposalStore(this.db);
  }

  countEvents(eventType: string): number {
    return Number((this.db.prepare("SELECT count(*) AS n FROM audit_events WHERE event_type = ?").get(eventType) as { n: number }).n);
  }

  /** Events of the given types, oldest first, for the report timeline and the handover. */
  eventsOfTypes(eventTypes: string[], limit = 200): { timestampUtc: string; eventType: string; actor: string; status: string; target: string | null; action: string | null; summary: string | null }[] {
    if (!eventTypes.length) return [];
    const rows = this.db.prepare(`SELECT timestamp_utc AS timestampUtc, event_type AS eventType, actor, status, target, action, summary
      FROM audit_events WHERE event_type IN (${eventTypes.map(() => "?").join(", ")}) ORDER BY id DESC LIMIT ?`).all(...eventTypes, Math.max(1, Math.min(limit, 2000)));
    return (rows as unknown as ReturnType<AuditLog["eventsOfTypes"]>).reverse();
  }

  private findingStore?: FindingStore;

  get findings(): FindingStore {
    return this.findingStore ??= new FindingStore(this.db);
  }

  private credentialStore?: CredentialStore;

  get credentials(): CredentialStore {
    return this.credentialStore ??= new CredentialStore(this.db);
  }

  private nextStepStore?: NextStepStore;

  get nextSteps(): NextStepStore {
    return this.nextStepStore ??= new NextStepStore(this.db);
  }

  get tasks(): TaskStore {
    return this.taskStore ??= new TaskStore(this.db);
  }

  get proposals(): ProposalStore {
    return this.proposalStore ??= new ProposalStore(this.db);
  }

  get coverage(): CoverageStore {
    return this.coverageStore ??= new CoverageStore(this.db);
  }

  constructor(cwd: string, configuredPath: string) {
    this.dbPath = isAbsolute(configuredPath) ? configuredPath : resolve(cwd, configuredPath);
    mkdirSync(dirname(this.dbPath), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(this.dbPath);
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit_events (
        id INTEGER PRIMARY KEY,
        timestamp_utc TEXT NOT NULL,
        event_type TEXT NOT NULL,
        session_id TEXT NOT NULL,
        actor TEXT NOT NULL,
        tool_call_id TEXT,
        target TEXT,
        tool TEXT,
        action TEXT,
        status TEXT NOT NULL,
        duration_ms INTEGER,
        summary TEXT,
        details_json TEXT,
        content_hash TEXT,
        evidence_path TEXT,
        scope_hash TEXT,
        payload_json TEXT NOT NULL,
        previous_hash TEXT,
        event_hash TEXT NOT NULL UNIQUE
      );
      CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_events(timestamp_utc);
      CREATE INDEX IF NOT EXISTS idx_audit_target_time ON audit_events(target, timestamp_utc);
      CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_events(session_id, id);
      CREATE INDEX IF NOT EXISTS idx_audit_type_status ON audit_events(event_type, status);
      CREATE TABLE IF NOT EXISTS scope_snapshots (
        scope_hash TEXT PRIMARY KEY,
        timestamp_utc TEXT NOT NULL,
        engagement TEXT NOT NULL,
        authorization_expires TEXT NOT NULL,
        included_json TEXT NOT NULL,
        excluded_json TEXT NOT NULL,
        config_hash TEXT NOT NULL
      );
    `);
  }

  close(): void {
    this.db.close();
  }

  append(event: AuditEvent): number {
    return this.transaction(() => this.appendEvent(event));
  }

  recordProposalDisposition(key: string, candidate: string, disposition: Disposition, context: Pick<AuditEvent, "sessionId" | "scopeHash">) {
    const proposals = this.proposals;
    return this.transaction(() => {
      const decision = proposals.setDisposition(key, candidate, disposition);
      this.appendEvent({ ...context, eventType: "target_proposal_disposition", actor: "operator", target: decision.host,
        status: "completed", action: disposition, timestampUtc: decision.reviewedAt,
        summary: disposition === "onboarded" ? "Proposal marked onboarded; host is in configured scope" : "Proposal disposition recorded; scope unchanged" });
      return decision;
    });
  }

  private transaction<T>(work: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = work();
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  private appendEvent(event: AuditEvent): number {
    const payload = {
      timestampUtc: event.timestampUtc ?? new Date().toISOString(),
      eventType: event.eventType,
      sessionId: event.sessionId,
      actor: event.actor ?? "extension",
      toolCallId: event.toolCallId ?? null,
      target: event.target ?? null,
      tool: event.tool ?? null,
      action: event.action ? bounded(event.action, 4096) : null,
      status: event.status,
      durationMs: event.durationMs ?? null,
      summary: event.summary ? bounded(event.summary, 2048) : null,
      detailsJson: event.details === undefined ? null : safeJson(event.details),
      contentHash: event.contentHash ?? null,
      evidencePath: event.evidencePath ?? null,
      scopeHash: event.scopeHash ?? null,
    };
    const payloadJson = JSON.stringify(payload);
    const previous = this.db.prepare("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").get() as
      | { event_hash: string }
      | undefined;
    const previousHash = previous?.event_hash ?? null;
    const eventHash = hashText(`${previousHash ?? "GENESIS"}\n${payloadJson}`);
    const result = this.db.prepare(`
      INSERT INTO audit_events (
        timestamp_utc, event_type, session_id, actor, tool_call_id, target, tool, action, status,
        duration_ms, summary, details_json, content_hash, evidence_path, scope_hash,
        payload_json, previous_hash, event_hash
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      payload.timestampUtc, payload.eventType, payload.sessionId, payload.actor, payload.toolCallId,
      payload.target, payload.tool, payload.action, payload.status, payload.durationMs, payload.summary,
      payload.detailsJson, payload.contentHash, payload.evidencePath, payload.scopeHash,
      payloadJson, previousHash, eventHash,
    );
    return Number(result.lastInsertRowid);
  }

  recordScope(snapshot: ScopeSnapshot): string {
    const normalized = {
      engagement: snapshot.engagement,
      authorizationExpires: snapshot.authorizationExpires,
      included: [...snapshot.included].sort(),
      excluded: [...snapshot.excluded].sort(),
      configHash: snapshot.configHash,
    };
    const scopeHash = hashText(JSON.stringify(normalized));
    this.db.prepare(`
      INSERT OR IGNORE INTO scope_snapshots
      (scope_hash, timestamp_utc, engagement, authorization_expires, included_json, excluded_json, config_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      scopeHash, new Date().toISOString(), normalized.engagement, normalized.authorizationExpires,
      JSON.stringify(normalized.included), JSON.stringify(normalized.excluded), normalized.configHash,
    );
    return scopeHash;
  }

  query(input: AuditQuery): unknown {
    const limit = Math.max(1, Math.min(input.limit ?? 100, 500));
    if (input.operation === "verify") return this.verify();
    if (input.operation === "stats") {
      return {
        total: Number((this.db.prepare("SELECT count(*) AS n FROM audit_events").get() as { n: number }).n),
        byType: this.db.prepare("SELECT event_type AS eventType, count(*) AS count FROM audit_events GROUP BY event_type ORDER BY count DESC").all(),
        byStatus: this.db.prepare("SELECT status, count(*) AS count FROM audit_events GROUP BY status ORDER BY count DESC").all(),
      };
    }
    if (input.operation === "scope") {
      return this.db.prepare("SELECT scope_hash AS scopeHash, timestamp_utc AS timestampUtc, engagement, authorization_expires AS authorizationExpires, included_json AS included, excluded_json AS excluded, config_hash AS configHash FROM scope_snapshots ORDER BY timestamp_utc DESC LIMIT ?").all(limit);
    }
    if (input.operation === "event") {
      if (!input.id) throw new Error("id is required for event queries");
      const row = this.db.prepare("SELECT * FROM audit_events WHERE id = ?").get(input.id) as Record<string, unknown> | undefined;
      return row ? rowObject(row) : null;
    }

    const clauses: string[] = [];
    const values: Array<string | number> = [];
    if (input.since) { clauses.push("timestamp_utc >= ?"); values.push(input.since); }
    if (input.until) { clauses.push("timestamp_utc <= ?"); values.push(input.until); }
    if (input.operation === "target" || input.target) {
      if (!input.target) throw new Error("target is required for target queries");
      clauses.push("(target = ? OR ',' || target || ',' LIKE ?)");
      values.push(input.target, `%,${input.target},%`);
    }
    if (input.operation === "session" || input.sessionId) {
      if (!input.sessionId) throw new Error("sessionId is required for session queries");
      clauses.push("session_id = ?"); values.push(input.sessionId);
    }
    if (input.operation === "search") {
      if (!input.search) throw new Error("search is required for search queries");
      clauses.push("(summary LIKE ? OR action LIKE ? OR details_json LIKE ?)");
      const term = `%${input.search}%`;
      values.push(term, term, term);
    }
    if (input.operation === "failures") clauses.push("status IN ('failed', 'blocked', 'denied', 'aborted')");
    if (input.operation === "approvals") clauses.push("event_type IN ('operator_approved', 'operator_denied', 'active_checks_armed', 'active_checks_disarmed')");
    if (input.operation === "artifacts") clauses.push("event_type IN ('artifact_modified', 'artifact_removed')");
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    const rows = this.db.prepare(`SELECT * FROM audit_events ${where} ORDER BY id DESC LIMIT ?`).all(...values, limit) as Record<string, unknown>[];
    return rows.map(rowObject);
  }

  verify(): { valid: boolean; events: number; error?: string; finalHash?: string } {
    const events = Number(this.db.prepare("SELECT count(*) AS n FROM audit_events").get()!.n);
    let previous: string | null = null;
    let id = 0;
    for (const row of this.db.prepare("SELECT * FROM audit_events ORDER BY id").iterate()) {
      if (row.id !== ++id) return { valid: false, events, error: `unexpected event ID ${row.id}; expected ${id}` };
      if (row.previous_hash !== previous) return { valid: false, events, error: `broken previous hash at event ${row.id}` };
      const expected = hashText(`${previous ?? "GENESIS"}\n${row.payload_json}`);
      if (expected !== row.event_hash) return { valid: false, events, error: `invalid event hash at event ${row.id}` };
      if (JSON.stringify(eventFields(row)) !== row.payload_json) return { valid: false, events, error: `displayed fields differ from chained payload at event ${row.id}` };
      previous = expected;
    }
    return { valid: true, events: id, finalHash: previous ?? undefined };
  }

  async artifact(path: string, workspaceRoot: string): Promise<{ path: string; size: number; hash: string } | undefined> {
    const absolute = resolve(path);
    if (!existsSync(absolute) || !statSync(absolute).isFile()) return undefined;
    const rel = relative(workspaceRoot, absolute);
    if (rel.startsWith("..")) return undefined;
    const stat = statSync(absolute);
    const digest = createHash("sha256");
    await new Promise<void>((resolvePromise, reject) => {
      const stream = createReadStream(absolute);
      stream.on("data", (chunk) => digest.update(chunk));
      stream.on("error", reject);
      stream.on("end", resolvePromise);
    });
    return { path: rel, size: stat.size, hash: `sha256:${digest.digest("hex")}` };
  }
}
