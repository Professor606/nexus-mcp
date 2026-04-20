import fs from "node:fs";

// ── SecLists roots ────────────────────────────────────────────────────────────

const SECLISTS_ROOTS = [
  "/usr/share/seclists",
  "/usr/share/SecLists",
  "/opt/SecLists",
  `${process.env.HOME}/SecLists`,
  `${process.env.HOME}/tools/SecLists`,
];

const WORDLISTS_ROOTS = [
  "/usr/share/dirb/wordlists",
  "/usr/share/wordlists",
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
 * Returns empty string if none found — callers should handle gracefully.
 */
export function resolveWordlist(name: WordlistName): string {
  return FALLBACKS[name].find((p) => p && fs.existsSync(p)) ?? "";
}
