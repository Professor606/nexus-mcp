import fs from "node:fs";
import { resolve } from "node:path";
import { validatePath } from "../types.js";

// ── SecLists roots ────────────────────────────────────────────────────────────

const SECLISTS_ROOTS = [
  "/usr/share/seclists",
  "/usr/share/SecLists",
  "/opt/SecLists",
  `${process.env.HOME}/SecLists`,
  `${process.env.HOME}/tools/SecLists`,
  `${process.env.HOME}/SecLists`,
];

const WORDLISTS_ROOTS = [
  "/usr/share/dirb/wordlists",
  "/usr/share/wordlists",
  `${process.env.HOME}/wordlists`,
];

// ── Allowed roots for user-provided paths ────────────────────────────────────

export const ALLOWED_WORDLIST_ROOTS = [
  "/usr/share/seclists",
  "/usr/share/wordlists",
  "/opt/SecLists",
  `${process.env.HOME}/SecLists`,
  process.env.NEXUS_OUTPUT_DIR || "/tmp/nexus-mcp",
];

// ── Resolved paths ────────────────────────────────────────────────────────────

function findRoot(roots: string[]): string | null {
  return roots.find((r) => r && fs.existsSync(r)) ?? null;
}

export const SECLISTS: string | null = findRoot(SECLISTS_ROOTS);
export const WORDLISTS: string | null = findRoot(WORDLISTS_ROOTS);

if (process.env.DEBUG === "true") {
  console.error(
    `[nexus-mcp] SecLists: ${SECLISTS ?? "not found"} | Wordlists: ${WORDLISTS ?? "not found"}`
  );
}

// ── Wordlist resolver ─────────────────────────────────────────────────────────

type WordlistName = "common" | "big" | "subdomains" | "params" | "passwords";

const FALLBACKS: Record<WordlistName, string[]> = {
  common: [
    SECLISTS ? `${SECLISTS}/Discovery/Web-Content/common.txt` : "",
    WORDLISTS ? `${WORDLISTS}/common.txt` : "",
    "/usr/share/wordlists/dirb/common.txt",
  ],
  big: [
    SECLISTS ? `${SECLISTS}/Discovery/Web-Content/big.txt` : "",
    WORDLISTS ? `${WORDLISTS}/big.txt` : "",
    "/usr/share/wordlists/dirb/big.txt",
  ],
  subdomains: [
    SECLISTS
      ? `${SECLISTS}/Discovery/DNS/subdomains-top1million-5000.txt`
      : "",
    SECLISTS
      ? `${SECLISTS}/Discovery/DNS/subdomains-top1million-20000.txt`
      : "",
  ],
  params: [
    SECLISTS
      ? `${SECLISTS}/Discovery/Web-Content/burp-parameter-names.txt`
      : "",
  ],
  passwords: [
    SECLISTS
      ? `${SECLISTS}/Passwords/Leaked-Databases/rockyou.txt`
      : "",
    "/usr/share/wordlists/rockyou.txt",
    WORDLISTS ? `${WORDLISTS}/rockyou.txt` : "",
  ],
};

/**
 * Resolve a wordlist name to an absolute path that actually exists.
 * If the input is a known preset name, returns the built-in path.
 * If the input is a user-provided path, validates it against ALLOWED_WORDLIST_ROOTS.
 * Returns empty string if none found or if the path is rejected — callers should handle gracefully.
 */
export function resolveWordlist(name: WordlistName | string): string {
  // Handle preset names
  if (name in FALLBACKS) {
    return FALLBACKS[name as WordlistName].find((p) => p && fs.existsSync(p)) ?? "";
  }

  // User-provided path — validate against sandbox
  const validated = validatePath(name, ALLOWED_WORDLIST_ROOTS);
  if (!validated) {
    console.error(`[nexus-mcp] Rejected wordlist path outside allowed roots: ${name}`);
    return "";
  }

  if (!fs.existsSync(validated)) {
    console.error(`[nexus-mcp] Wordlist not found: ${validated}`);
    return "";
  }

  return validated;
}
