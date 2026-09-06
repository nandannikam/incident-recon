/**
 * Tactic color-coding shared by the conclusion cards, legend, and attack
 * graph. Stays inside the design-system palette: pink / violet family /
 * neutral — one accent voice across both result views.
 *
 * Text never takes the accent color directly; chips use a neutral surface
 * with a colored dot so contrast stays AA everywhere.
 */

const TACTIC_COLORS: Record<string, string> = {
  persistence: "#fa7faa", // accent-pink
  execution: "#9d8fe0", // bright tint of accent-violet
  "defense evasion": "#6a5fc1", // accent-violet
  "command and control": "#bdb8c0", // neutral — external comms
};

const TACTIC_COLOR_DEFAULT = "#79628c"; // accent-violet-mid

export function tacticColor(tactic: string): string {
  return TACTIC_COLORS[tactic.trim().toLowerCase()] ?? TACTIC_COLOR_DEFAULT;
}

const TACTIC_CLASSES: Record<string, string> = {
  persistence: "tactic-persistence",
  execution: "tactic-execution",
  "defense evasion": "tactic-defense-evasion",
  "command and control": "tactic-command-and-control",
};

/** CSS class that sets the `--tactic` custom property for an element. */
export function tacticClass(tactic: string): string {
  return TACTIC_CLASSES[tactic.trim().toLowerCase()] ?? "tactic-default";
}
