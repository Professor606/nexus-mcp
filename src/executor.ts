import { execa } from "execa";
import pLimit from "p-limit";
import { cleanOutput } from "./utils/clean.js";
import { cacheGet, cacheSet, buildKey } from "./cache.js";
import { TargetSchema, UrlTargetSchema, sanitizeTarget } from "./types.js";
import type { ToolResult, Finding, ParserFn } from "./types.js";

// ── Concurrency guard ─────────────────────────────────────────────────────────

const MAX_CONCURRENCY = Number(process.env.MAX_CONCURRENCY) || 4;
const limit = pLimit(MAX_CONCURRENCY);

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

  const cacheKey = buildKey(opts.tool, opts.args);

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

  // Subprocess execution (concurrency limited)
  return limit(async () => {
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
    } catch (e) {
      const err = e as Error & {
        all?: string;
        stdout?: string;
        shortMessage?: string;
      };
      rawOutput = err.all ?? err.stdout ?? "";
      error = err.shortMessage ?? err.message ?? "Unknown error";
      console.error(`[nexus-mcp] exec error [${opts.tool}]: ${error}`);
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

    // Only cache successful results
    if (!error) cacheSet(cacheKey, toolResult);

    return toolResult;
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
