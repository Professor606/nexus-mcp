import { createHash } from "node:crypto";
import type { ToolResult } from "./types.js";

// ── Configuration ─────────────────────────────────────────────────────────────

const CACHE_TTL_MS =
  (Number(process.env.CACHE_TTL_SECONDS) || 3600) * 1000;
const CACHE_VERSION = "v1";
const MAX_CACHE_ENTRIES = Number(process.env.NEXUS_MAX_CACHE) || 1000;

// ── Store ─────────────────────────────────────────────────────────────────────

interface CacheEntry {
  result: ToolResult;
  ts: number;
  checksum: string;
}

const store = new Map<string, CacheEntry>();
let cacheHits = 0;
let cacheMisses = 0;

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Build a deterministic cache key from tool name + argument list.
 * Includes environment variables that affect execution.
 */
export function buildKey(tool: string, args: string[], env?: Record<string, string>): string {
  const payload = JSON.stringify({ 
    tool, 
    args, 
    env_keys: env ? Object.keys(env).sort() : [],
    env_hash: env ? createHash("sha256").update(JSON.stringify(env)).digest("hex").slice(0, 16) : ""
  });
  const hash = createHash("sha256").update(payload).digest("hex");
  return `${CACHE_VERSION}:${hash}`;
}

/** Return cached result if present, not expired, and passes integrity check; otherwise null. */
export function cacheGet(key: string): ToolResult | null {
  const entry = store.get(key);
  if (!entry) {
    cacheMisses++;
    return null;
  }
  
  if (Date.now() - entry.ts > CACHE_TTL_MS) {
    store.delete(key);
    cacheMisses++;
    return null;
  }

  // Integrity check
  const checksum = createHash("sha256").update(JSON.stringify(entry.result)).digest("hex");
  if (checksum !== entry.checksum) {
    console.error(`[nexus-mcp] Cache integrity failure for key ${key}`);
    store.delete(key);
    cacheMisses++;
    return null;
  }

  cacheHits++;
  return entry.result;
}

/** Store a result. Only call this on successful (no error) executions. */
export function cacheSet(key: string, result: ToolResult): void {
  // LRU Eviction
  if (store.size >= MAX_CACHE_ENTRIES && !store.has(key)) {
    let oldestKey: string | null = null;
    let oldestTs = Infinity;
    for (const [k, v] of store.entries()) {
      if (v.ts < oldestTs) {
        oldestTs = v.ts;
        oldestKey = k;
      }
    }
    if (oldestKey) {
      store.delete(oldestKey);
    }
  }

  const checksum = createHash("sha256").update(JSON.stringify(result)).digest("hex");
  store.set(key, { result, ts: Date.now(), checksum });
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
export function cacheStats(): { entries: number; max: number; hit_rate: number } {
  const total = cacheHits + cacheMisses;
  const hit_rate = total > 0 ? (cacheHits / total) : 0;
  return { entries: store.size, max: MAX_CACHE_ENTRIES, hit_rate };
}
