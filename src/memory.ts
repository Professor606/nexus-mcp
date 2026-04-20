import type { SessionNote, Finding } from "./types.js";

// ── Store ─────────────────────────────────────────────────────────────────────

const notes = new Map<string, SessionNote>();

// ── Helpers ───────────────────────────────────────────────────────────────────

function blank(target: string): SessionNote {
  return {
    target,
    phase: "recon",
    findings: [],
    tools_run: [],
    next_steps: [],
    updated_at: new Date().toISOString(),
  };
}

function touch(note: SessionNote): SessionNote {
  note.updated_at = new Date().toISOString();
  return note;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Upsert a note for target. Merges partial data over the existing note.
 * Creates a blank note if none exists.
 */
export function saveNote(
  target: string,
  data: Partial<SessionNote>
): SessionNote {
  const existing = notes.get(target) ?? blank(target);
  const updated = touch({ ...existing, ...data, target });
  notes.set(target, updated);
  return updated;
}

/** Return the note for target, or null if none exists. */
export function loadNote(target: string): SessionNote | null {
  return notes.get(target) ?? null;
}

/** Append a single finding to the target note. */
export function appendFinding(target: string, finding: Finding): SessionNote {
  const note = notes.get(target) ?? blank(target);
  note.findings.push(finding);
  touch(note);
  notes.set(target, note);
  return note;
}

/** Record that a tool was run for target (deduplicates). */
export function appendToolRun(target: string, toolName: string): void {
  const note = notes.get(target) ?? blank(target);
  if (!note.tools_run.includes(toolName)) {
    note.tools_run.push(toolName);
    touch(note);
    notes.set(target, note);
  }
}

/** Append multiple findings at once (used by chain_tools). */
export function appendFindings(
  target: string,
  findings: Finding[]
): SessionNote {
  const note = notes.get(target) ?? blank(target);
  note.findings.push(...findings);
  touch(note);
  notes.set(target, note);
  return note;
}

/** Set the current pentest phase for a target. */
export function setPhase(target: string, phase: string): void {
  const note = notes.get(target) ?? blank(target);
  note.phase = phase;
  touch(note);
  notes.set(target, note);
}

/** Delete note for target. */
export function clearNote(target: string): void {
  notes.delete(target);
}

/** List all targets with active notes. */
export function allTargets(): string[] {
  return [...notes.keys()];
}
