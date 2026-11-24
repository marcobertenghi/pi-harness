import type { DatabaseSync } from "node:sqlite";

export interface Task { id: number; title: string; createdBy: "operator" | "agent"; createdAt: string; status: "open" | "done"; closedAt: string | null }

/** Engagement-scoped follow-up list. Tasks are notes: they never grant scope or authorization. */
export class TaskStore {
  constructor(private readonly db: DatabaseSync) {
    db.exec(`CREATE TABLE IF NOT EXISTS engagement_tasks (
      id INTEGER PRIMARY KEY,
      engagement_key TEXT NOT NULL,
      title TEXT NOT NULL,
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open',
      closed_at TEXT
    )`);
  }

  add(key: string, title: string, createdBy: Task["createdBy"]): Task {
    const clean = title.replace(/[\p{C}\p{Zl}\p{Zp}]+/gu, " ").trim();
    if (!clean) throw new Error("A task needs a short description.");
    if (clean.length > 300) throw new Error("Keep the task description under 300 characters.");
    const createdAt = new Date().toISOString();
    const result = this.db.prepare("INSERT INTO engagement_tasks (engagement_key, title, created_by, created_at) VALUES (?, ?, ?, ?)")
      .run(key, clean, createdBy, createdAt);
    return { id: Number(result.lastInsertRowid), title: clean, createdBy, createdAt, status: "open", closedAt: null };
  }

  setStatus(key: string, id: number, status: Task["status"]): Task {
    const closedAt = status === "done" ? new Date().toISOString() : null;
    const result = this.db.prepare("UPDATE engagement_tasks SET status = ?, closed_at = ? WHERE engagement_key = ? AND id = ?").run(status, closedAt, key, id);
    if (Number(result.changes) !== 1) throw new Error(`No task #${id} in this engagement.`);
    return this.list(key, true).find((task) => task.id === id)!;
  }

  list(key: string, includeClosed = false): Task[] {
    return this.db.prepare(`SELECT id, title, created_by AS createdBy, created_at AS createdAt, status, closed_at AS closedAt
      FROM engagement_tasks WHERE engagement_key = ? ${includeClosed ? "" : "AND status = 'open'"} ORDER BY status DESC, id`).all(key) as unknown as Task[];
  }
}
