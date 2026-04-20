import { execa } from "execa";
import pLimit from "p-limit";
import { cleanOutput } from "./utils/clean.js";
import { cacheGet, cacheSet, buildKey } from "./cache.js";
import { TargetSchema, UrlTargetSchema, sanitizeTarget, ToolResultSchema, CVSS_MAP } from "./types.js";
import type { ToolResult, Finding, ParserFn } from "./types.js";

// ── Concurrency guard ─────────────────────────────────────────────────────────

const MAX_CONCURRENCY = Number(process.env.MAX_CONCURRENCY) || 4;
const limit = pLimit(MAX_CONCURRENCY);

const QUEUE_TIMEOUT_MS = Number(process.env.NEXUS_QUEUE_TIMEOUT_MS) || 30_000;
const CIRCUIT_BREAKER_THRESHOLD = 3; // errors before opening
const CIRCUIT_BREAKER_RESET_MS = 60_000;

const circuitState = new Map<string, { failures: number; lastFailure: number; open: boolean }>();

export function getQueueStats(): { pending: number; active: number; circuitBreakers: string[] } {
  return {
    pending: limit.pendingCount,
    active: limit.activeCount,
    circuitBreakers: Array.from(circuitState.entries())
      .filter(([_, state]) => state.open)
      .map(([tool]) => tool)
  };
}

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ExecOptions {
  /** Binary name, e.g. "nmap" */
  tool: string;
  /** Human-readable target label stored in ToolResult */
  target: string;
  /** Argument array passed to the binary */
  args: string[];
  /** Seconds before SIGKILL (default 300) */
  timeout?: number;
  /** Extra env vars merged over process.env */
  env?: Record<string, string>;
  /** Optional structured parser — if omitted, findings[] is empty */
  parse?: ParserFn;
  /** Skip the cache even if a hit exists */
  noCache?: boolean;
}

// ── Version Detection ─────────────────────────────────────────────────────────

function normalizeFindings(findings: Finding[]): Finding[] {
  findings.sort((a, b) => {
    const scoreA = a.severity ? CVSS_MAP[a.severity] : 0;
    const scoreB = b.severity ? CVSS_MAP[b.severity] : 0;
    return scoreB - scoreA;
  });
  
  for (const f of findings) {
    if (f.detail && f.detail.length > 2048) {
      f.detail = f.detail.slice(0, 2045) + "...";
    }
  }
  
  return findings.slice(0, 1000);
}

export function parseVersion(tool: string, raw: string): string | undefined {
  if (tool === "nmap" || tool === "nmap_scan") {
    const match = raw.match(/Nmap version ([\d.]+)/i);
    if (match) return match[1];
  } else if (tool === "ffuf") {
    const match = raw.match(/ffuf(?:\s+version)?\s+([\d.-]+(dev)?)/i) || raw.match(/"ffuf-version":\s*"([^"]+)"/);
    if (match) return match[1];
  } else if (tool === "sqlmap") {
    const match = raw.match(/sqlmap(?:\/)?([\d.-]+)/i);
    if (match) return match[1];
  }
  return undefined;
}

// ── Core runner ───────────────────────────────────────────────────────────────

/**
 * Single entry point for every tool subprocess.
 * - Cache-first (skip if noCache)
 * - Concurrency-limited via p-limit
 * - Never throws — errors returned in ToolResult.error
 */
export async function exec(opts: ExecOptions): Promise<ToolResult> {
  const start = Date.now();

  // ── Pre-flight target validation ─────────────────────────────────────────
  try {
    const sanitized = sanitizeTarget(opts.target);
    const targetOk = TargetSchema.safeParse(sanitized).success;
    const urlOk    = UrlTargetSchema.safeParse(sanitized).success;
    if (!targetOk && !urlOk) {
      throw new Error("Target failed validation");
    }
  } catch (validationErr) {
    const msg =
      validationErr instanceof Error
        ? validationErr.message
        : String(validationErr);
    return {
      tool: opts.tool,
      target: opts.target,
      summary: `Target validation failed: ${msg}`,
      findings: [],
      cached: false,
      duration_ms: 0,
      raw_truncated: "",
      error: `Target validation failed: ${msg}`,
    };
  }

  const cacheKey = buildKey(opts.tool, opts.args, opts.env);

  // Cache check
  if (!opts.noCache) {
    const cached = cacheGet(cacheKey);
    if (cached) {
      if (process.env.DEBUG === "true") {
        console.error(`[nexus-mcp] cache hit: ${opts.tool}`);
      }
      return { ...cached, cached: true, duration_ms: 0 };
    }
  }

  // Circuit breaker check & reset
  const toolState = circuitState.get(opts.tool) || { failures: 0, lastFailure: 0, open: false };
  if (toolState.open) {
    if (Date.now() - toolState.lastFailure > CIRCUIT_BREAKER_RESET_MS) {
      toolState.open = false;
      toolState.failures = 0;
      circuitState.set(opts.tool, toolState);
    } else {
      return {
        tool: opts.tool,
        target: opts.target,
        summary: `Circuit breaker open for ${opts.tool} due to repeated failures`,
        findings: [],
        cached: false,
        duration_ms: 0,
        raw_truncated: "",
        error: `Circuit breaker open for ${opts.tool} due to repeated failures`
      };
    }
  }

  // Subprocess execution (concurrency limited)
  const queueStart = Date.now();
  return limit(async () => {
    const queueWait = Date.now() - queueStart;
    if (queueWait > QUEUE_TIMEOUT_MS) {
      return {
        tool: opts.tool,
        target: opts.target,
        summary: "Request timed out waiting in execution queue",
        findings: [],
        cached: false,
        duration_ms: queueWait,
        raw_truncated: "",
        error: `Queue timeout: waited ${queueWait}ms, max ${QUEUE_TIMEOUT_MS}ms`
      };
    }
    let rawOutput = "";
    let error: string | undefined;

    try {
      const result = await execa(opts.tool, opts.args, {
        timeout: (opts.timeout ?? 300) * 1000,
        reject: false,           // non-zero exit codes don't throw
        env: { ...process.env, ...opts.env } as Record<string, string>,
        all: true,               // merge stdout + stderr into result.all
      });
      rawOutput = result.all ?? result.stdout ?? "";

      if (process.env.DEBUG === "true") {
        console.error(
          `[nexus-mcp] ${opts.tool} exit=${result.exitCode} ` +
          `duration=${Date.now() - start}ms`
        );
      }

      if (result.failed && result.exitCode === undefined) {
        throw new Error(result.shortMessage || "Command failed to start or timed out");
      }
    } catch (e) {
      const err = e as Error & {
        all?: string;
        stdout?: string;
        shortMessage?: string;
      };
      rawOutput = err.all ?? err.stdout ?? "";
      error = err.shortMessage ?? err.message ?? "Unknown error";
      console.error(`[nexus-mcp] exec error [${opts.tool}]: ${error}`);

      const state = circuitState.get(opts.tool) || { failures: 0, lastFailure: 0, open: false };
      state.failures++;
      state.lastFailure = Date.now();
      if (state.failures >= CIRCUIT_BREAKER_THRESHOLD) {
        state.open = true;
      }
      circuitState.set(opts.tool, state);
    }

    if (!error) {
      circuitState.set(opts.tool, { failures: 0, lastFailure: 0, open: false });
    }

    const cleaned = cleanOutput(rawOutput);
    const version = parseVersion(opts.tool, cleaned);

    let parsed: { summary: string; findings: Finding[]; parse_error?: boolean; raw_truncated?: string };
    try {
      parsed = opts.parse
        ? opts.parse(cleaned, version)
        : {
            summary: `${opts.tool} completed on ${opts.target}`,
            findings: [],
          };
      parsed.findings = normalizeFindings(parsed.findings || []);
    } catch (parseErr) {
      if (process.env.DEBUG === "true") {
        console.error(
          `[nexus-mcp] ${opts.tool} parser failed: ${String(parseErr)}`
        );
      }
      parsed = {
        summary: `${opts.tool} completed but output could not be parsed (format may have changed)`,
        findings: [],
        parse_error: true,
        raw_truncated: cleaned.slice(0, 3000)
      };
    }

    const toolResult: ToolResult = {
      tool: opts.tool,
      target: opts.target,
      summary: parsed.summary,
      findings: parsed.findings,
      cached: false,
      duration_ms: Date.now() - start,
      raw_truncated: parsed.raw_truncated || cleaned.slice(0, 6000),
      ...(parsed.parse_error && { parse_error: parsed.parse_error }),
      ...(error && { error }),
    };

    const validated = ToolResultSchema.safeParse(toolResult);
    if (!validated.success) {
      console.error(`[nexus-mcp] Output validation failed for ${opts.tool}: ${validated.error}`);
      return {
        tool: opts.tool,
        target: opts.target,
        summary: "Tool completed but output validation failed",
        findings: [],
        cached: false,
        duration_ms: Date.now() - start,
        raw_truncated: cleaned.slice(0, 6000),
        error: `Validation error: ${validated.error.issues.map(i => i.message).join(", ")}`
      };
    }

    const finalResult = validated.data as ToolResult;

    // Only cache successful results
    if (!finalResult.error) cacheSet(cacheKey, finalResult);

    return finalResult;
  });
}

/**
 * Read a JSON file written by a tool (e.g. ffuf -of json).
 * Returns the raw string ready for parsing. Returns "" on error.
 */
export async function readOutputFile(path: string): Promise<string> {
  try {
    const { readFile } = await import("node:fs/promises");
    return await readFile(path, "utf8");
  } catch {
    return "";
  }
}
