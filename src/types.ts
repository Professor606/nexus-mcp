import { z } from "zod";

// ── Severity ──────────────────────────────────────────────────────────────────

export type Severity = "info" | "low" | "medium" | "high" | "critical";

/**
 * Normalise any tool-specific severity string to our five-value union.
 * Handles: informational, warning, CRITICAL, High, etc.
 */
export function mapSeverity(raw: string): Severity {
  const s = raw.toLowerCase().trim();
  if (s === "critical")                          return "critical";
  if (s === "high")                              return "high";
  if (s === "medium" || s === "moderate")        return "medium";
  if (s === "low" || s === "warning")            return "low";
  return "info"; // informational, note, unknown → info
}

/** CVSS base scores for report generation */
export const CVSS_MAP: Record<Severity, number> = {
  critical: 9.0,
  high:     7.5,
  medium:   5.0,
  low:      2.0,
  info:     0.0,
};

// ── Core Interfaces ───────────────────────────────────────────────────────────

export interface Finding {
  /** Open category: "open_port" | "subdomain" | "vuln" | "path" | "sqli" | etc. */
  type: string;
  /** Primary value: "80/tcp", "sub.example.com", "/admin", etc. */
  value: string;
  detail?: string;
  severity?: Severity;
  metadata?: Record<string, unknown>;
}

/** Structured result every tool returns — this is what the LLM sees. */
export interface ToolResult {
  tool: string;
  target: string;
  /** One-sentence summary for the LLM */
  summary: string;
  findings: Finding[];
  severity?: Severity;
  cached: boolean;
  duration_ms: number;
  /** Raw output hard-capped at 6000 chars */
  raw_truncated: string;
  error?: string;
}

/** Per-target session state stored in memory.ts */
export interface SessionNote {
  target: string;
  phase: string;
  findings: Finding[];
  tools_run: string[];
  next_steps: string[];
  updated_at: string;
}

// ── Profile ───────────────────────────────────────────────────────────────────

export type Profile =
  | "recon"
  | "web"
  | "network"
  | "bugbounty"
  | "ctf"
  | "cloud"
  | "osint"
  | "full";

// ── Zod Base Schemas ──────────────────────────────────────────────────────────

export const TargetSchema = z
  .string()
  .min(1)
  .describe("IP address, domain, URL, or file path");

export const FlagsSchema = z
  .string()
  .optional()
  .default("")
  .describe("Additional raw flags to pass to the tool");

export const TimeoutSchema = z
  .number()
  .int()
  .min(10)
  .max(3600)
  .default(300)
  .describe("Execution timeout in seconds (10–3600)");
