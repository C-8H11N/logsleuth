import test from "node:test";
import assert from "node:assert/strict";
import { retrieveEvidence, validateCitations } from "../app/evidence-retrieval.ts";

const findings = [
  { id: 1, severity: "high", category: "SQL Injection", source: "10.0.0.8", detail: "union select", timestamp: "2026-08-04T10:00:00Z", evidence: "/?id=1 union select" },
  { id: 2, severity: "medium", category: "Path Traversal", source: "10.0.0.9", detail: "dot dot slash", timestamp: "2026-08-04T10:01:00Z", evidence: "/../../etc/passwd" },
];

const sessions = [
  { id: 1, source: "10.0.0.8", severity: "high", confidence: 88, stages: ["exploitation"], evidenceIds: [1], startedAt: "2026-08-04T10:00:00Z", endedAt: "2026-08-04T10:00:00Z", eventCount: 1, summary: "SQL injection attempt" },
];

test("retrieves explicit evidence and IP matches with a read-only tool trace", () => {
  const result = retrieveEvidence("调查 10.0.0.8 的 E#1", findings, sessions);
  assert.deepEqual(result.findings.map((finding) => finding.id), [1]);
  assert.equal(result.sessions[0].id, 1);
  assert.ok(result.info.tools.some((tool) => tool.name === "get_evidence"));
  assert.ok(result.info.tools.some((tool) => tool.name === "search_findings"));
});

test("rejects model citations that do not exist", () => {
  const result = validateCitations("已确认 [E#1]，但 [E#404] 和 [S#9] 无法验证。", findings, sessions);
  assert.equal(result.citationsValid, false);
  assert.deepEqual(result.invalidCitations, ["[E#404]", "[S#9]"]);
});
