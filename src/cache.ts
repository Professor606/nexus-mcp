import crypto from "node:crypto";
import type { ToolResult } from "./types.js";

// ── Configuration ─────────────────────────────────────────────────────────────

const CACHE_TTL_MS =
  (Number(process.env.CACHE_TTL_SECONDS) || 3600) * 1000;

// ── Store ─────────────────────────────────────────────────────────────────────

interface CacheEntry {
  result: ToolResult;
  ts: number;
}

const store = new Map<string, CacheEntry>();

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Build a deterministic cache key from tool name + argument list.
 * Uses MD5 — fast, not security-critical (internal key only).
 */
export function buildKey(tool: string, args: string[]): string {
  const payload = JSON.stringify({ tool, args });
  return crypto.createHash("md5").update(payload).digest("hex");
}

/** Return cached result if present and not expired; otherwise null. */
export function cacheGet(key: string): ToolResult | null {
  const entry = store.get(key);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL_MS) {
    store.delete(key);
    return null;
  }
  return entry.result;
}

/** Store a result. Only call this on successful (no error) executions. */
export function cacheSet(key: string, result: ToolResult): void {
  store.set(key, { result, ts: Date.now() });
}

/** Evict a specific key (useful after target data changes). */
export function cacheDelete(key: string): void {
  store.delete(key);
}

/** Wipe the entire cache. */
export function cacheClear(): void {
  store.clear();
}

/** Debug stats — logged on startup in debug mode. */
export function cacheStats(): { entries: number; ttl_seconds: number } {
  return { entries: store.size, ttl_seconds: CACHE_TTL_MS / 1000 };
}
