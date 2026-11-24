import type { DatabaseSync } from "node:sqlite";

export interface NextStep { label: string; instruction: string; why: string; createdAt: string }

const clean = (value: string, max: number) => value.replace(/[\p{C}\p{Zl}\p{Zp}]+/gu, " ").trim().slice(0, max);

/**
 * The agent's current recommendations for what to do next, shown to the
 * operator in /rt-steer. Each set replaces the previous one. These are
 * suggestions for the operator to review, never instructions or authorization.
 */
export class NextStepStore {
  constructor(private readonly db: DatabaseSync) {
    db.exec(`CREATE TABLE IF NOT EXISTS next_steps (
      engagement_key TEXT NOT NULL,
      position INTEGER NOT NULL,
      label TEXT NOT NULL,
      instruction TEXT NOT NULL,
      why TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (engagement_key, position)
    )`);
  }

  replace(key: string, steps: { label: string; instruction: string; why?: string }[]): NextStep[] {
    const createdAt = new Date().toISOString();
    const rows = steps.slice(0, 4)
      .map((step) => ({ label: clean(step.label, 70), instruction: clean(step.instruction, 600), why: clean(step.why ?? "", 140), createdAt }))
      .filter((step) => step.label && step.instruction);
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("DELETE FROM next_steps WHERE engagement_key = ?").run(key);
      const insert = this.db.prepare("INSERT INTO next_steps VALUES (?, ?, ?, ?, ?, ?)");
      rows.forEach((step, position) => insert.run(key, position, step.label, step.instruction, step.why, createdAt));
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
    return rows;
  }

  list(key: string): NextStep[] {
    return this.db.prepare("SELECT label, instruction, why, created_at AS createdAt FROM next_steps WHERE engagement_key = ? ORDER BY position")
      .all(key) as unknown as NextStep[];
  }
}
