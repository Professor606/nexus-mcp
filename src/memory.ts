import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import type { SessionNote, Finding } from "./types.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ── Configuration ─────────────────────────────────────────────────────────────

const MAX_NOTES = Number(process.env.NEXUS_MAX_NOTES) || 100;
const MAX_NOTE_AGE_MS = Number(process.env.NEXUS_MAX_NOTE_AGE_HOURS || 24) * 60 * 60 * 1000;

const LOG_DIR = path.resolve(__dirname, '..', '.logs');

// ── Store ─────────────────────────────────────────────────────────────────────

const notes = new Map<string, SessionNote>();

function getFilePath(target: string): string {
  // Remove protocol (http:// or https://)
  let safeName = target.replace(/^https?:\/\//, '');
  // Sanitize the rest of the URL/target to be a safe filename
  safeName = safeName.replace(/[^a-zA-Z0-9-]/g, '_');
  return path.join(LOG_DIR, `${safeName}.json`);
}

// Initialize persistence
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
} else {
  // Load existing individual files
  const files = fs.readdirSync(LOG_DIR);
  for (const file of files) {
    if (!file.endsWith('.json') || file === 'pentest_notes.json') continue;
    try {
      const data = fs.readFileSync(path.join(LOG_DIR, file), 'utf-8');
      const parsed = JSON.parse(data);
      if (parsed.target) {
        notes.set(parsed.target, parsed as SessionNote);
      }
    } catch (e) {
      console.error(`[nexus-mcp] Failed to load pentest note from ${file}:`, e);
    }
  }
}

function persistTarget(target: string): void {
  try {
    const note = notes.get(target);
    if (!note) return;
    fs.writeFileSync(getFilePath(target), JSON.stringify(note, null, 2), 'utf-8');
  } catch (e) {
    console.error(`[nexus-mcp] Failed to save pentest note for ${target}:`, e);
  }
}

function deleteTargetFile(target: string): void {
  try {
    const filePath = getFilePath(target);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  } catch (e) {
    console.error(`[nexus-mcp] Failed to delete pentest note file for ${target}:`, e);
  }
}

// Thread-safety note: Node.js is single-threaded, so synchronous Map operations are safe.
function cleanupOldNotes(): void {
  const now = Date.now();
  let deleted = 0;
  for (const [target, note] of notes) {
    if (now - new Date(note.updated_at).getTime() > MAX_NOTE_AGE_MS) {
      notes.delete(target);
      deleteTargetFile(target);
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
    if (oldest) {
      notes.delete(oldest[0]);
      deleteTargetFile(oldest[0]);
    }
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
  if (notes.size >= MAX_NOTES && !notes.has(target)) {
    cleanupOldNotes();
    enforceMaxSize();
  }

  const existing = notes.get(target) ?? blank(target);
  const updated = touch({ ...existing, ...data, target });
  notes.set(target, updated);
  persistTarget(target);
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
  persistTarget(target);
  return note;
}

/** Record that a tool was run for target (deduplicates). */
export function appendToolRun(target: string, toolName: string): void {
  const note = notes.get(target) ?? blank(target);
  if (!note.tools_run.includes(toolName)) {
    note.tools_run.push(toolName);
    touch(note);
    notes.set(target, note);
    persistTarget(target);
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
  persistTarget(target);
  return note;
}

/** Set the current pentest phase for a target. */
export function setPhase(target: string, phase: string): void {
  const note = notes.get(target) ?? blank(target);
  note.phase = phase;
  touch(note);
  notes.set(target, note);
  persistTarget(target);
}

/** Delete note for target. */
export function clearNote(target: string): void {
  notes.delete(target);
  deleteTargetFile(target);
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
