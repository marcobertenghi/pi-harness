import type { DatabaseSync } from "node:sqlite";
import { bounded } from "./audit.ts";

export const findingStatuses = ["suspected", "validated", "reported", "dismissed"] as const;
export type FindingStatus = typeof findingStatuses[number];
export const osstmmCategories = ["Vulnerability", "Weakness", "Concern", "Exposure", "Anomaly"] as const;
export type OsstmmCategory = typeof osstmmCategories[number];

/** One finding in the house format of the security-findings skill, plus its tracking status. */
export interface Finding {
  id: number;
  status: FindingStatus;
  title: string;
  affectedSystems: string[];
  description: string;
  evidence: string[];
  risk: string;
  mitigation: string;
  osstmmCategory: OsstmmCategory | null;
  exploitability: number | null;
  technicalImpact: number | null;
  mitigationEffort: number | null;
  note: string;
  createdBy: "operator" | "agent";
  createdAt: string;
  updatedAt: string;
}

export type FindingFields = Partial<Pick<Finding, "title" | "affectedSystems" | "description" | "evidence" | "risk" | "mitigation"
  | "osstmmCategory" | "exploitability" | "technicalImpact" | "mitigationEffort" | "note">>;

const line = (value: string, max: number) => bounded(value.replace(/[\p{C}\p{Z}]+/gu, " ").trim(), max);
const text = (value: string, max: number) => bounded(value.replace(/[^\P{C}\n]+/gu, " ").trim(), max);
const list = (values: string[], max: number) => [...new Set(values.map((value) => line(value, 300)).filter(Boolean))].slice(0, max);
const rating = (value: number | null | undefined, name: string) => {
  if (value === null || value === undefined) return null;
  if (!Number.isInteger(value) || value < 1 || value > 3) throw new Error(`${name} must be 1, 2, or 3.`);
  return value;
};

/** What a finding still lacks before it may be called validated. */
export function validationGaps(finding: Pick<Finding, "affectedSystems" | "evidence" | "description">): string[] {
  return [
    ...(finding.affectedSystems.length ? [] : ["affected systems"]),
    ...(finding.evidence.length ? [] : ["evidence"]),
    ...(finding.description ? [] : ["description"]),
  ];
}

/** What a finding still lacks before it can go into a client report. */
export function reportGaps(finding: Finding): string[] {
  return [
    ...validationGaps(finding),
    ...(finding.risk ? [] : ["risk"]),
    ...(finding.mitigation ? [] : ["mitigation"]),
    ...(finding.osstmmCategory ? [] : ["OSSTMM category"]),
    ...(finding.exploitability && finding.technicalImpact && finding.mitigationEffort ? [] : ["ratings"]),
  ];
}

/**
 * Engagement findings register. Findings are evidence-backed notes for the
 * report: recording one never contacts a target, changes scope, or grants authorization.
 */
export class FindingStore {
  constructor(private readonly db: DatabaseSync) {
    db.exec(`CREATE TABLE IF NOT EXISTS findings (
      id INTEGER PRIMARY KEY,
      engagement_key TEXT NOT NULL,
      status TEXT NOT NULL,
      title TEXT NOT NULL,
      affected_json TEXT NOT NULL,
      description TEXT NOT NULL,
      evidence_json TEXT NOT NULL,
      risk TEXT NOT NULL,
      mitigation TEXT NOT NULL,
      osstmm_category TEXT,
      exploitability INTEGER,
      technical_impact INTEGER,
      mitigation_effort INTEGER,
      note TEXT NOT NULL,
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )`);
  }

  private clean(fields: FindingFields): FindingFields {
    const result: FindingFields = {};
    if (fields.title !== undefined) {
      result.title = line(fields.title, 160);
      if (!result.title) throw new Error("A finding needs a title.");
    }
    if (fields.affectedSystems !== undefined) result.affectedSystems = list(fields.affectedSystems, 60);
    if (fields.evidence !== undefined) result.evidence = list(fields.evidence, 20);
    if (fields.description !== undefined) result.description = text(fields.description, 2000);
    if (fields.risk !== undefined) result.risk = text(fields.risk, 2000);
    if (fields.mitigation !== undefined) result.mitigation = text(fields.mitigation, 1500);
    if (fields.note !== undefined) result.note = line(fields.note, 500);
    if (fields.osstmmCategory !== undefined) {
      if (fields.osstmmCategory !== null && !osstmmCategories.includes(fields.osstmmCategory)) throw new Error(`OSSTMM category must be one of ${osstmmCategories.join(", ")}.`);
      result.osstmmCategory = fields.osstmmCategory;
    }
    if (fields.exploitability !== undefined) result.exploitability = rating(fields.exploitability, "exploitability");
    if (fields.technicalImpact !== undefined) result.technicalImpact = rating(fields.technicalImpact, "technicalImpact");
    if (fields.mitigationEffort !== undefined) result.mitigationEffort = rating(fields.mitigationEffort, "mitigationEffort");
    return result;
  }

  add(key: string, fields: FindingFields & { title: string }, createdBy: Finding["createdBy"], status: FindingStatus = "suspected"): Finding {
    const clean = this.clean(fields);
    const draft = { affectedSystems: clean.affectedSystems ?? [], evidence: clean.evidence ?? [], description: clean.description ?? "" };
    if (status === "validated" && validationGaps(draft).length) throw new Error(`A validated finding needs ${validationGaps(draft).join(", ")}. Record it as suspected until then.`);
    const now = new Date().toISOString();
    const result = this.db.prepare(`INSERT INTO findings (engagement_key, status, title, affected_json, description, evidence_json, risk, mitigation,
      osstmm_category, exploitability, technical_impact, mitigation_effort, note, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(key, status, clean.title!, JSON.stringify(draft.affectedSystems), draft.description, JSON.stringify(draft.evidence), clean.risk ?? "", clean.mitigation ?? "",
        clean.osstmmCategory ?? null, clean.exploitability ?? null, clean.technicalImpact ?? null, clean.mitigationEffort ?? null, clean.note ?? "", createdBy, now, now);
    return this.get(key, Number(result.lastInsertRowid))!;
  }

  update(key: string, id: number, fields: FindingFields, status?: FindingStatus): Finding {
    const current = this.get(key, id);
    if (!current) throw new Error(`No finding #${id} in this engagement.`);
    const next = { ...current, ...this.clean(fields), status: status ?? current.status };
    if ((next.status === "validated" || next.status === "reported") && validationGaps(next).length) {
      throw new Error(`Finding #${id} cannot be ${next.status} without ${validationGaps(next).join(", ")}.`);
    }
    this.db.prepare(`UPDATE findings SET status = ?, title = ?, affected_json = ?, description = ?, evidence_json = ?, risk = ?, mitigation = ?, osstmm_category = ?,
      exploitability = ?, technical_impact = ?, mitigation_effort = ?, note = ?, updated_at = ? WHERE engagement_key = ? AND id = ?`)
      .run(next.status, next.title, JSON.stringify(next.affectedSystems), next.description, JSON.stringify(next.evidence), next.risk, next.mitigation, next.osstmmCategory,
        next.exploitability, next.technicalImpact, next.mitigationEffort, next.note, new Date().toISOString(), key, id);
    return this.get(key, id)!;
  }

  get(key: string, id: number): Finding | undefined {
    return this.rows(key, "AND id = ?", id)[0];
  }

  /** Most severe first: validated before suspected, then by impact and ease of exploitation. */
  list(key: string, includeDismissed = false): Finding[] {
    const order: Record<FindingStatus, number> = { validated: 0, reported: 1, suspected: 2, dismissed: 3 };
    return this.rows(key, includeDismissed ? "" : "AND status != 'dismissed'").sort((a, b) =>
      order[a.status] - order[b.status] || (b.technicalImpact ?? 0) - (a.technicalImpact ?? 0) || (a.exploitability ?? 4) - (b.exploitability ?? 4) || a.id - b.id);
  }

  counts(key: string): Record<FindingStatus, number> {
    const counts = Object.fromEntries(findingStatuses.map((status) => [status, 0])) as Record<FindingStatus, number>;
    for (const row of this.db.prepare("SELECT status, count(*) AS n FROM findings WHERE engagement_key = ? GROUP BY status").all(key) as { status: FindingStatus; n: number }[]) {
      counts[row.status] = Number(row.n);
    }
    return counts;
  }

  private rows(key: string, where: string, ...values: number[]): Finding[] {
    const rows = this.db.prepare(`SELECT * FROM findings WHERE engagement_key = ? ${where} ORDER BY id`).all(key, ...values) as Record<string, unknown>[];
    return rows.map((row) => ({
      id: Number(row.id), status: row.status as FindingStatus, title: String(row.title),
      affectedSystems: JSON.parse(String(row.affected_json)) as string[], description: String(row.description),
      evidence: JSON.parse(String(row.evidence_json)) as string[], risk: String(row.risk), mitigation: String(row.mitigation),
      osstmmCategory: (row.osstmm_category as OsstmmCategory | null) ?? null,
      exploitability: row.exploitability === null ? null : Number(row.exploitability),
      technicalImpact: row.technical_impact === null ? null : Number(row.technical_impact),
      mitigationEffort: row.mitigation_effort === null ? null : Number(row.mitigation_effort),
      note: String(row.note), createdBy: row.created_by as Finding["createdBy"], createdAt: String(row.created_at), updatedAt: String(row.updated_at),
    }));
  }
}
