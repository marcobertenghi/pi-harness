import type { DatabaseSync } from "node:sqlite";
import { bounded } from "./audit.ts";

export const credentialKinds = ["password", "hash", "token", "key", "cookie", "other"] as const;
export type CredentialKind = typeof credentialKinds[number];
export const credentialResults = ["valid", "invalid", "locked_out", "error"] as const;
export type CredentialResult = typeof credentialResults[number];

export interface CredentialTest { target: string; result: CredentialResult; note: string; testedAt: string }
export interface Credential {
  id: number;
  kind: CredentialKind;
  /** Username, service account, key name: who the secret belongs to. Never the secret. */
  account: string;
  /** Where it was found: host, service, or file. */
  foundAt: string;
  /** Evidence file that holds the value. The ledger itself never stores it. */
  secretLocation: string;
  note: string;
  createdBy: "operator" | "agent";
  createdAt: string;
  tests: CredentialTest[];
}

const line = (value: string, max: number) => bounded(value.replace(/[\p{C}\p{Zl}\p{Zp}]+/gu, " ").trim(), max);

/**
 * Ledger of captured credentials: what was found, where the value is kept, and
 * where it was tried. It holds no secret values, so listing it is safe, and it
 * grants nothing: trying a credential still needs the operator's approval.
 */
export class CredentialStore {
  constructor(private readonly db: DatabaseSync) {
    db.exec(`CREATE TABLE IF NOT EXISTS credentials (
      id INTEGER PRIMARY KEY,
      engagement_key TEXT NOT NULL,
      kind TEXT NOT NULL,
      account TEXT NOT NULL,
      found_at TEXT NOT NULL,
      secret_location TEXT NOT NULL,
      note TEXT NOT NULL,
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL,
      UNIQUE (engagement_key, kind, account, secret_location)
    );
    CREATE TABLE IF NOT EXISTS credential_tests (
      id INTEGER PRIMARY KEY,
      credential_id INTEGER NOT NULL,
      target TEXT NOT NULL,
      result TEXT NOT NULL,
      note TEXT NOT NULL,
      tested_at TEXT NOT NULL
    )`);
  }

  /** Records a credential once; recording the same one again returns the existing entry. */
  add(key: string, input: { kind: CredentialKind; account: string; foundAt: string; secretLocation: string; note?: string }, createdBy: Credential["createdBy"]): { credential: Credential; recorded: boolean } {
    if (!credentialKinds.includes(input.kind)) throw new Error(`kind must be one of ${credentialKinds.join(", ")}.`);
    const account = line(input.account, 200);
    const foundAt = line(input.foundAt, 300);
    const secretLocation = line(input.secretLocation, 300);
    if (!account || !foundAt || !secretLocation) throw new Error("A credential entry needs the account, where it was found, and the evidence file that holds the value.");
    const existing = this.db.prepare("SELECT id FROM credentials WHERE engagement_key = ? AND kind = ? AND account = ? AND secret_location = ?")
      .get(key, input.kind, account, secretLocation) as { id: number } | undefined;
    if (existing) return { credential: this.get(key, Number(existing.id))!, recorded: false };
    const result = this.db.prepare("INSERT INTO credentials (engagement_key, kind, account, found_at, secret_location, note, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .run(key, input.kind, account, foundAt, secretLocation, line(input.note ?? "", 300), createdBy, new Date().toISOString());
    return { credential: this.get(key, Number(result.lastInsertRowid))!, recorded: true };
  }

  /** Records the outcome of trying a credential against one target. The latest result per target is kept. */
  recordTest(key: string, id: number, target: string, result: CredentialResult, note = ""): Credential {
    if (!this.get(key, id)) throw new Error(`No credential #${id} in this engagement.`);
    if (!credentialResults.includes(result)) throw new Error(`result must be one of ${credentialResults.join(", ")}.`);
    const cleanTarget = line(target, 300);
    if (!cleanTarget) throw new Error("Name the service the credential was tried against.");
    this.db.prepare("DELETE FROM credential_tests WHERE credential_id = ? AND target = ?").run(id, cleanTarget);
    this.db.prepare("INSERT INTO credential_tests (credential_id, target, result, note, tested_at) VALUES (?, ?, ?, ?, ?)")
      .run(id, cleanTarget, result, line(note, 300), new Date().toISOString());
    return this.get(key, id)!;
  }

  get(key: string, id: number): Credential | undefined {
    return this.list(key).find((credential) => credential.id === id);
  }

  list(key: string): Credential[] {
    const rows = this.db.prepare(`SELECT id, kind, account, found_at AS foundAt, secret_location AS secretLocation, note, created_by AS createdBy, created_at AS createdAt
      FROM credentials WHERE engagement_key = ? ORDER BY id`).all(key) as unknown as Omit<Credential, "tests">[];
    const tests = this.db.prepare("SELECT target, result, note, tested_at AS testedAt FROM credential_tests WHERE credential_id = ? ORDER BY tested_at");
    return rows.map((row) => ({ ...row, id: Number(row.id), tests: tests.all(row.id) as unknown as CredentialTest[] }));
  }

  count(key: string): number {
    return Number((this.db.prepare("SELECT count(*) AS n FROM credentials WHERE engagement_key = ?").get(key) as { n: number }).n);
  }
}
