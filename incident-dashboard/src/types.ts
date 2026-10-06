/**
 * Mirror of the backend Pydantic models (src/app/models.py).
 * Field names match the API JSON exactly.
 */

export interface Evidence {
  event_ids: string[];
  explanation: string;
  /** Set when this evidence backs a chained/derived conclusion. */
  parent_conclusion_id: string | null;
}

export interface Conclusion {
  /** Required unique id (backend step 5). Kept non-optional per current API. */
  conclusion_id: string;
  rule_id: string;
  /** MITRE ATT&CK technique, e.g. "T1547.001". */
  technique_id: string;
  /** e.g. "Persistence", "Execution", "Defense Evasion", "Command and Control". */
  tactic: string;
  description: string;
  evidence: Evidence[];
  /** Rule confidence, 0..1. */
  confidence?: number | null;
  severity?: Severity | null;
  /** Hosts the finding was observed on. */
  hosts?: string[];
}

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Incident {
  id: string;
  summary: string;
  /** Most serious conclusion's severity. */
  severity?: Severity | null;
  conclusions: Conclusion[];
}
