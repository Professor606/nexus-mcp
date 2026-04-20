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

// ── Python Script Validation ─────────────────────────────────────────────────

/** Dangerous imports and function calls that are blocked in user scripts */
const BLOCKED_PATTERNS = [
  // Dangerous imports
  /\bimport\s+(os|subprocess|socket|pty|platform|shutil|pathlib|urllib|requests|http|ftplib|telnetlib|smtplib|poplib|imaplib|nntplib|ssl|ctypes|cffi|mmap|resource|signal|multiprocessing|concurrent|threading|asyncio|select|selectors|mimetypes|mailbox|mailcap|msilib|msvcrt|winreg|winsound|spwd|crypt|grp|pwd|termios|tty|fcntl|posix|pwd|spwd|grp|crypt|nis|nis|syslog|gc|inspect|imp|importlib\b)/i,
  /\bfrom\s+(os|subprocess|socket|pty|platform|shutil|pathlib|urllib|requests|http|ftplib|telnetlib|smtplib|poplib|imaplib|nntplib|ssl|ctypes|cffi|mmap|resource|signal|multiprocessing|concurrent|threading|asyncio|select|selectors|mimetypes|mailbox|mailcap|msilib|msvcrt|winreg|winsound|spwd|crypt|grp|pwd|termios|tty|fcntl|posix|pwd|spwd|grp|crypt|nis|nis|syslog|gc|inspect|imp|importlib)\s+import\b/i,
  // Dangerous functions and builtins
  /\b(os\.system|os\.popen|os\.exec|os\.spawn|os\.fork|os\.kill|os\.remove|os\.unlink|os\.rmdir|os\.mkdir|os\.makedirs|os\.rename|os\.chmod|os\.chown|subprocess\.run|subprocess\.call|subprocess\.Popen|subprocess\.check_output|eval|exec|compile|__import__|getattr|setattr|delattr|globals|locals|vars|file|input|raw_input|breakpoint|help|quit|exit|reload)\b/i,
  // Network operations
  /\b(socket\.|urllib\.|requests\.|http\.|ftplib\.|telnetlib\.|smtplib\.|poplib\.|imaplib\.|nntplib\.|ssl\.)/i,
  // Code execution / dynamic evaluation
  /\b(eval|exec|compile|__builtins__|__import__|types\.CodeType|types\.FunctionType|marshal\.loads|pickle\.loads|yaml\.load|jsonpickle|dill)/i,
  // Shell execution via string formatting
  /\$\{|%\(|`.*`/,
  // Obfuscation attempts — these match the literal two-character sequences
  // "\x", "\u", "\U", "\N" as they would appear in Python source code.
  // The double-backslash in the regex literal /\\x/ is required: it tells JS
  // to match one backslash followed by 'x', NOT to interpret \x as a hex escape.
  /\\x[0-9a-fA-F]{2}/,
  /\\u[0-9a-fA-F]{4}/,
  /\\U[0-9a-fA-F]{8}/,
  /\\N\{/,
  // Bytecode / code objects
  /\bbuiltins\b/,
  /\b__class__\b/,
  /\b__base__\b/,
  /\b__subclasses__\b/,
  /\b__globals__\b/,
  /\b__closure__\b/,
  /\b__code__\b/,
  /\bfunc_globals\b/,
];

/** Allowed file system paths for Python scripts */
const ALLOWED_FS_PATHS = ["/tmp/nexus-mcp", "/tmp"];

/**
 * Validate a Python script for dangerous patterns.
 * Returns { valid: true } if safe, or { valid: false, reason: string } if dangerous.
 *
 * Phases:
 *   Phase A — checks that run on the RAW script before string stripping.
 *             String stripping destroys path/URL content, so these must go first.
 *   Phase B — checks that run on the STRIPPED source (comments + string
 *             literals removed) to avoid false positives inside string values.
 */
export function validatePythonScript(script: string): { valid: boolean; reason?: string } {

  // ── Phase A: raw-script checks ────────────────────────────────────────────

  // A1. Obfuscation — detect literal backslash-escape sequences.
  //     /\\x[0-9a-fA-F]{2}/ matches the string "\x6f" (backslash + x + hex).
  //     Using a single \x inside a regex literal would be a JS hex escape (0x00),
  //     which is NOT what we want to detect here.
  if (/\\x[0-9a-fA-F]{2}/.test(script)) {
    return { valid: false, reason: "Blocked obfuscation: hex escape sequence detected." };
  }
  if (/\\u[0-9a-fA-F]{4}/.test(script)) {
    return { valid: false, reason: "Blocked obfuscation: unicode escape sequence detected." };
  }
  if (/\\U[0-9a-fA-F]{8}/.test(script)) {
    return { valid: false, reason: "Blocked obfuscation: unicode escape sequence detected." };
  }
  if (/\\N\{/.test(script)) {
    return { valid: false, reason: "Blocked obfuscation: named unicode escape detected." };
  }

  // A2. Shell injection via string interpolation syntax.
  if (/\$\{|%\(|`.*`/.test(script)) {
    return { valid: false, reason: "Blocked shell injection: dangerous string interpolation detected." };
  }

  // A3. File-system access — validate literal paths passed to open().
  //     MUST run before string stripping: stripping replaces '/etc/passwd' with ''
  //     making path extraction impossible.
  //     Regex: open( 'path'  or  open( "path"  — requires at least one char in path.
  const openCallRegex = /\bopen\s*\(\s*["']([^"']+)["']/g;
  let openMatch: RegExpExecArray | null;
  while ((openMatch = openCallRegex.exec(script)) !== null) {
    const filePath = openMatch[1];
    const isAllowed = ALLOWED_FS_PATHS.some(
      (allowed) => resolve(filePath).startsWith(resolve(allowed))
    );
    if (!isAllowed) {
      return {
        valid: false,
        reason: `Blocked file operation: path "${filePath}" is outside allowed directories (${ALLOWED_FS_PATHS.join(", ")}).`,
      };
    }
  }

  // A4. Network URLs embedded in string literals.
  const urlRegex = /["'](https?|ftp|telnet|ssh|smtp|pop3|imap):\/\/[^"']+["']/g;
  let urlMatch: RegExpExecArray | null;
  while ((urlMatch = urlRegex.exec(script)) !== null) {
    return {
      valid: false,
      reason: `Blocked network URL: ${urlMatch[0]}.`,
    };
  }

  // ── Phase B: strip strings, then check code structure ────────────────────

  // B1. Strip comments and string literal contents to avoid false positives.
  //
  //     Character class explanation for the single/double-quoted string regex:
  //       [^"\\]   — any char that is NOT a double-quote AND NOT a backslash
  //       |\\.     — OR a backslash followed by any char (handles \" inside strings)
  //     Together they correctly consume string content including escaped quotes.
  const codeOnly = script
    .replace(/#.*$/gm, "")
    .replace(/"""[\s\S]*?"""/g, '""')
    .replace(/'''[\s\S]*?'''/g, "''")
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
    .replace(/'(?:[^'\\]|\\.)*'/g, "''");

  // B2. Check all dangerous-pattern rules against the stripped source.
  for (const pattern of BLOCKED_PATTERNS) {
    const match = codeOnly.match(pattern);
    if (match) {
      return {
        valid: false,
        reason: `Blocked pattern detected: "${match[0]}". Dangerous imports, function calls, and obfuscation are not allowed.`,
      };
    }
  }

  return { valid: true };
}

export const PythonScriptSchema = z
  .string()
  .min(1)
  .max(50000)
  .refine(
    (val) => {
      const result = validatePythonScript(val);
      return result.valid;
    },
    (val) => {
      const result = validatePythonScript(val);
      return { message: result.reason || "Python script validation failed" };
    }
  )
  .describe("Python code validated for dangerous patterns before execution");

// ── Zod Base Schemas ──────────────────────────────────────────────────────────

/** Rejects shell metacharacters to prevent command injection */
const SHELL_METACHAR_REGEX = /[;&|`$(){}[\]\\]/;

/**
 * Hardened target schema.
 * Blocks shell metacharacters and enforces a strict character whitelist.
 */
export const TargetSchema = z
  .string()
  .min(1)
  .max(2048)
  .refine(
    (val) => !SHELL_METACHAR_REGEX.test(val),
    { message: "Target contains dangerous characters" }
  )
  .refine(
    (val) => {
      // URL / IP / file-path character set (shell metas already filtered above)
      // OR a simple domain/hostname-like string
      return (
        /^[a-zA-Z0-9._~:/?#@[\]!*+,\-=%]+$/.test(val) ||
        /^[a-zA-Z0-9._-]+$/.test(val)
      );
    },
    { message: "Invalid target format" }
  );

/**
 * URL target schema for tools that legitimately need query parameters.
 * Requires percent-encoding of dangerous characters.
 */
export const UrlTargetSchema = z
  .string()
  .min(1)
  .max(2048)
  .refine(
    (val) => {
      const withoutEncoded = val.replace(/%[0-9A-Fa-f]{2}/g, "");
      return !SHELL_METACHAR_REGEX.test(withoutEncoded);
    },
    { message: "URL contains unencoded dangerous characters" }
  )
  .refine(
    (val) => {
      return (
        /^[a-zA-Z0-9._~:/?#@[\]!$&'()*+,;=%-]+$/.test(val) ||
        /^[a-zA-Z0-9._-]+$/.test(val)
      );
    },
    { message: "Invalid URL format" }
  );

/**
 * Sanitize a target string.
 * - Strips null bytes
 * - Collapses multiple path separators
 * - Rejects flag injection (strings starting with "-")
 */
export function sanitizeTarget(input: string): string {
  let sanitized = input.replace(/\0/g, "");
  sanitized = sanitized.replace(/\/+/g, "/");
  if (sanitized.startsWith("-")) {
    throw new Error("Target cannot start with '-' (flag injection attempt)");
  }
  return sanitized;
}

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
