import assert from "node:assert/strict";
import test from "node:test";
import { progressOverview, targetOverview } from "../extensions/administration.ts";

test("target overview highlights only proposal-onboarded exact targets", () => {
  const overview = targetOverview({
    targets: ["baseline.example.test", "added.example.test", "*.wild.example.test"],
    exclusions: ["blocked.example.test"],
    endpoints: ["https://baseline.example.test/", "https://added.example.test/app", "https://child.wild.example.test/"],
  }, [
    { host: "added.example.test", disposition: "onboarded", reason: "related" },
    { host: "pending.example.test", disposition: "pending", reason: "unreviewed" },
  ]);
  assert.equal(overview.onboarded, 1);
  assert.equal(overview.baseline, 2);
  assert.equal(overview.rows[0].target, "added.example.test");
  assert.equal(overview.rows[0].status, "onboarded");
  assert.equal(overview.rows.find(row => row.target === "*.wild.example.test")?.endpointCount, 1);
  assert.deepEqual(overview.exclusions, ["blocked.example.test"]);
});

test("progress overview separates completed evidence from open administrative work", () => {
  const progress = progressOverview({
    counts: { pending: 3, reviewed: 5, waiting_on_operator: 2, grouped: 1, blocked: 1 },
    gatewayOnly: 2,
    total: 12,
    matched: 12,
    nextOffset: null,
    entries: [],
  }, [{ host: "candidate.example.test", disposition: "pending", reason: "related" }]);
  assert.equal(progress.completed, 6);
  assert.equal(progress.open, 6);
  assert.equal(progress.percent, 50);
  assert.equal(progress.actions.length, 4);
  assert.match(progress.actions.join("\n"), /waiting on the operator/);
  assert.match(progress.actions.join("\n"), /pending scope proposal/);
});
