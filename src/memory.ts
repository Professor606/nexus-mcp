import type { SessionNote, Finding } from "./types.js";

// ── Configuration ─────────────────────────────────────────────────────────────

const MAX_NOTES = Number(process.env.NEXUS_MAX_NOTES) || 100;
const MAX_NOTE_AGE_MS = Number(process.env.NEXUS_MAX_NOTE_AGE_HOURS || 24) * 60 * 60 * 1000;

// ── Store ─────────────────────────────────────────────────────────────────────

const notes = new Map<string, SessionNote>();

// Thread-safety note: Node.js is single-threaded, so synchronous Map operations are safe.
function cleanupOldNotes(): void {
  const now = Date.now();
  let deleted = 0;
  for (const [target, note] of notes) {
    if (now - new Date(note.updated_at).getTime() > MAX_NOTE_AGE_MS) {
      notes.delete(target);
      deleted++;
    }
  }
  if (deleted > 0 && process.env.DEBUG === "true") {
    console.error(`[nexus-mcp] Cleaned up ${deleted} expired notes`);
  }
}

function enforceMaxSize(): void {
  while (notes.size > MAX_NOTES) {
    // Delete oldest (lowest updated_at)
    let oldest: [string, SessionNote] | null = null;
    for (const entry of notes) {
      if (!oldest || new Date(entry[1].updated_at) < new Date(oldest[1].updated_at)) {
        oldest = entry;
      }
    }
    if (oldest) notes.delete(oldest[0]);
  }
}

// Periodic cleanup every 15 minutes
setInterval(() => {
  cleanupOldNotes();
  enforceMaxSize();
}, 15 * 60 * 1000).unref();

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
  if (notes.size > MAX_NOTES * 0.9) {
    cleanupOldNotes();
    enforceMaxSize();
  }

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
  cleanupOldNotes();
  enforceMaxSize();
  return [...notes.keys()];
}

/** Get memory usage statistics for monitoring. */
export function memoryStats(): { size: number; max: number; oldest_age_ms: number } {
  let oldestMs = 0;
  const now = Date.now();
  for (const note of notes.values()) {
    const age = now - new Date(note.updated_at).getTime();
    if (age > oldestMs) oldestMs = age;
  }
  return {
    size: notes.size,
    max: MAX_NOTES,
    oldest_age_ms: oldestMs
  };
}
