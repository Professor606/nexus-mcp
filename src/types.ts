import { z } from "zod";
import { resolve } from "node:path";

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

// ── Path Sandboxing ─────────────────────────────────────────────────────────

/**
 * Validate that a resolved absolute path stays within one of the allowed roots.
 * Returns the resolved path if allowed, or null if it escapes the sandbox.
 */
export function validatePath(input: string, allowedRoots: string[]): string | null {
  const resolved = resolve(input);
  const isAllowed = allowedRoots.some(root => resolved.startsWith(resolve(root)));
  return isAllowed ? resolved : null;
}

// ── Zod Base Schemas ──────────────────────────────────────────────────────────

export const TargetSchema = z
  .string()
  .min(1)
  .describe("IP address, domain, URL, or file path");

/** Rejects shell metacharacters to prevent command injection */
const SHELL_METACHAR_REGEX = /[;&|`$(){}[\]\\]/;

/**
 * Safe structured flags schema.
 * Accepts only an array of strings that do NOT contain shell metacharacters.
 */
export const SafeFlagsSchema = z
  .array(
    z
      .string()
      .min(1)
      .regex(
        /^[^;&|`$(){}[\]\\]+$/,
        "Flag contains shell metacharacters and is not allowed"
      )
  )
  .optional()
  .default([])
  .describe("Additional flags to pass to the tool as a safe array");

/** Preset strategy names mapped to approved flag arrays */
export const FLAG_MAP: Record<string, string[]> = {
  fast: ["-T4", "-F"],
  comprehensive: ["-sS", "-sV", "-sC", "-O", "--top-ports", "1000"],
  stealth: ["-T2", "-sS"],
  aggressive: ["-A", "-T4"],
  default: [],
};

/**
 * Runtime validator for flag arrays.
 * Throws if any flag contains shell metacharacters.
 */
export function sanitizeFlags(flags: string[]): string[] {
  return flags.filter((f) => {
    if (SHELL_METACHAR_REGEX.test(f)) {
      throw new Error(`Invalid flag contains shell metacharacters: ${f}`);
    }
    return f.length > 0;
  });
}

export const TimeoutSchema = z
  .number()
  .int()
  .min(10)
  .max(3600)
  .default(300)
  .describe("Execution timeout in seconds (10–3600)");
