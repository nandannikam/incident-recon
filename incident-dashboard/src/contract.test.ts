/**
 * Guards the /analyze response shape the frontend depends on against the
 * shared fixture contracts/analyze_response.json (repo root) — the same file
 * the backend test src/tests/test_api_contract.py validates. Read via fs so it
 * works regardless of Vite's fs-root settings.
 *
 * Extra backend fields (confidence, severity, hosts, ...) are allowed; only
 * the fields modelled in src/types.ts are required here.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const body = JSON.parse(
  readFileSync(
    fileURLToPath(
      new URL("../../contracts/analyze_response.json", import.meta.url),
    ),
    "utf-8",
  ),
);

describe("shared /analyze contract fixture", () => {
  it("has exactly the incident and diagnostics top-level keys", () => {
    expect(body).toBeTypeOf("object");
    expect(body).not.toBeNull();
    expect(Object.keys(body).sort()).toEqual(["diagnostics", "incident"]);
    expect(body.incident).toBeTypeOf("object");
    expect(body.diagnostics).toBeTypeOf("object");
  });

  it("has the incident fields the frontend reads", () => {
    expect(body.incident.id).toBeTypeOf("string");
    expect(body.incident.summary).toBeTypeOf("string");
    expect(Array.isArray(body.incident.conclusions)).toBe(true);
  });

  it("has every conclusion field required by types.ts", () => {
    for (const conclusion of body.incident.conclusions) {
      expect(conclusion).toBeTypeOf("object");
      expect(conclusion.conclusion_id).toBeTypeOf("string");
      expect(conclusion.rule_id).toBeTypeOf("string");
      expect(conclusion.technique_id).toBeTypeOf("string");
      expect(conclusion.tactic).toBeTypeOf("string");
      expect(conclusion.description).toBeTypeOf("string");
      expect(Array.isArray(conclusion.evidence)).toBe(true);
    }
  });

  it("has every evidence field required by types.ts", () => {
    for (const conclusion of body.incident.conclusions) {
      for (const evidence of conclusion.evidence) {
        expect(evidence).toBeTypeOf("object");
        expect(Array.isArray(evidence.event_ids)).toBe(true);
        for (const eventId of evidence.event_ids) {
          expect(eventId).toBeTypeOf("string");
        }
        expect(evidence.explanation).toBeTypeOf("string");
        expect(
          evidence.parent_conclusion_id === null ||
            typeof evidence.parent_conclusion_id === "string",
        ).toBe(true);
      }
    }
  });

  it("has the diagnostics fields the frontend reads", () => {
    expect(body.diagnostics.total_rows).toBeTypeOf("number");
    expect(body.diagnostics.skipped).toBeTypeOf("number");
    expect(Array.isArray(body.diagnostics.errors)).toBe(true);
  });
});
