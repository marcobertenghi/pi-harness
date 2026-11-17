import { createHash } from "node:crypto";
import { createReadStream, existsSync, mkdirSync, statSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

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

const SECRET_PATTERNS: Array<[RegExp, string]> = [
  [/(authorization\s*:\s*(?:bearer|basic)\s+)[^\s'"`]+/gi, "$1[REDACTED]"],
  [/((?:api[_-]?key|token|secret|password|passwd|pwd)\s*[=:]\s*)[^\s'"`]+/gi, "$1[REDACTED]"],
  [/(--(?:password|passwd|token|api-key|secret)(?:=|\s+))[^\s'"`]+/gi, "$1[REDACTED]"],
  [/([a-z][a-z0-9+.-]*:\/\/[^\s/:]+:)[^@\s/]+@/gi, "$1[REDACTED]@"],
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

function rowObject(row: Record<string, unknown>) {
  return {
    id: Number(row.id),
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
    details: parseDetails(row.details_json),
    contentHash: row.content_hash,
    evidencePath: row.evidence_path,
    scopeHash: row.scope_hash,
    eventHash: row.event_hash,
  };
}

export class AuditLog {
  readonly dbPath: string;
  private readonly db: DatabaseSync;

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
    this.db.exec("BEGIN IMMEDIATE");
    try {
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
      this.db.exec("COMMIT");
      return Number(result.lastInsertRowid);
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
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
    if (input.operation === "artifacts") clauses.push("event_type = 'artifact_modified'");
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    const rows = this.db.prepare(`SELECT * FROM audit_events ${where} ORDER BY id DESC LIMIT ?`).all(...values, limit) as Record<string, unknown>[];
    return rows.map(rowObject);
  }

  verify(): { valid: boolean; events: number; error?: string; finalHash?: string } {
    const rows = this.db.prepare("SELECT id, payload_json, previous_hash, event_hash FROM audit_events ORDER BY id").all() as Array<{
      id: number; payload_json: string; previous_hash: string | null; event_hash: string;
    }>;
    let previous: string | null = null;
    for (const row of rows) {
      if (row.previous_hash !== previous) return { valid: false, events: rows.length, error: `broken previous hash at event ${row.id}` };
      const expected = hashText(`${previous ?? "GENESIS"}\n${row.payload_json}`);
      if (expected !== row.event_hash) return { valid: false, events: rows.length, error: `invalid event hash at event ${row.id}` };
      previous = row.event_hash;
    }
    return { valid: true, events: rows.length, finalHash: previous ?? undefined };
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
