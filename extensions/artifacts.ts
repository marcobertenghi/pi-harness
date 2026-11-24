import { lstatSync, readdirSync } from "node:fs";
import { join } from "node:path";

const SKIPPED_DIRECTORIES = new Set(["node_modules", ".git"]);

export function artifactSignature(path: string): string | undefined {
  try {
    const stat = lstatSync(path);
    return stat.isFile() ? `${stat.size}:${stat.mtimeMs}` : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Size and modification time of every regular file under the given roots.
 * Symbolic links, dependency trees, and the skipped paths are not followed.
 * The walk stops at `limit` files so a large tools tree cannot stall a hook.
 */
export function snapshotArtifacts(roots: string[], skip: string[] = [], limit = 10_000): Map<string, string> {
  const files = new Map<string, string>();
  const pending = [...roots];
  while (pending.length && files.size < limit) {
    const directory = pending.pop()!;
    if (skip.includes(directory)) continue;
    let entries;
    try { entries = readdirSync(directory, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!SKIPPED_DIRECTORIES.has(entry.name)) pending.push(path);
      } else if (entry.isFile() && files.size < limit) {
        const signature = artifactSignature(path);
        if (signature) files.set(path, signature);
      }
    }
  }
  return files;
}

export function artifactChanges(before: Map<string, string>, after: Map<string, string>): { modified: string[]; removed: string[] } {
  return {
    modified: [...after].filter(([path, signature]) => before.get(path) !== signature).map(([path]) => path).sort(),
    removed: [...before.keys()].filter((path) => !after.has(path)).sort(),
  };
}
