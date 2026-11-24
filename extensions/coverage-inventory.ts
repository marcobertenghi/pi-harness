import { execFile } from "node:child_process";
import { stat } from "node:fs/promises";
import { resolve } from "node:path";
import { serviceSubject, type CoverageScope, type ServiceSubject } from "./coverage.ts";
import { scopeDecision } from "./scope.ts";

const maxRows = 20_000;
const inventorySql = `SELECT DISTINCT ip, hostname, port, lower(protocol) AS protocol FROM v_services
  WHERE state = 'open' AND port BETWEEN 1 AND 65535 AND lower(protocol) IN ('tcp', 'udp')
  ORDER BY ip, hostname, port, protocol LIMIT ${maxRows + 1}`;

export function scanInventory(raw: string, scope: CoverageScope) {
  const rows: unknown = JSON.parse(raw);
  if (!Array.isArray(rows)) throw new Error("Unexpected Scanlens service inventory format.");
  const services = new Map<string, ServiceSubject>();
  let invalidRows = 0;
  for (const row of rows.slice(0, maxRows)) {
    if (!row || typeof row !== "object" || !("port" in row) || !("protocol" in row)) {
      invalidRows++;
      continue;
    }
    const candidates = [row.ip, row.hostname].flatMap(host => {
      if (typeof host !== "string" || !host) return [];
      try { return [serviceSubject({ host, port: row.port, transport: row.protocol })]; } catch { return []; }
    });
    if (!candidates.length) { invalidRows++; continue; }
    const decisions = candidates.map(candidate => scopeDecision(candidate.host, scope.targets, scope.exclusions));
    if (decisions.includes("excluded")) continue;
    const selected = candidates[decisions.indexOf("included")];
    if (selected) services.set(JSON.stringify(selected), selected);
  }
  return { services: [...services.values()], truncated: rows.length > maxRows, invalidRows };
}

export async function loadScanInventory(cwd: string, configuredDb: string, scope: CoverageScope, signal?: AbortSignal) {
  const db = resolve(cwd, configuredDb);
  if (!(await stat(db).catch(() => undefined))?.isFile()) throw new Error("Scanlens database is missing; cannot reconcile coverage.");
  const output = await new Promise<string>((resolveOutput, reject) => {
    execFile("scanlens", ["sql", inventorySql, "--db", db, "--format", "json", "--limit", "0"], {
      cwd, signal, timeout: 15_000, maxBuffer: 8 * 1024 * 1024,
    }, (error, stdout) => error ? reject(new Error("Local Scanlens inventory query failed; check the database and Scanlens version.")) : resolveOutput(stdout));
  });
  return scanInventory(output, scope);
}
