import type { Finding } from "../types.js";

/**
 * Subfinder outputs one subdomain per line (plain text or JSON with -oJ).
 * We handle both formats.
 */
export function parseSubfinder(raw: string): {
  summary: string;
  findings: Finding[];
} {
  const findings: Finding[] = [];

  if (!raw.trim()) {
    return { summary: "Subfinder found no subdomains", findings };
  }

  // Try JSON array format first (subfinder -oJ -)
  if (raw.trim().startsWith("[") || raw.trim().startsWith("{")) {
    try {
      const parsed = JSON.parse(
        raw.trim().startsWith("[") ? raw : `[${raw.split("\n").filter((l) => l.trim().startsWith("{")).join(",")}]`
      ) as Array<{ host?: string; ip?: string; source?: string[] } | string>;

      for (const entry of parsed) {
        if (typeof entry === "string") {
          if (isValidSubdomain(entry)) {
            findings.push({
              type: "subdomain",
              value: entry.trim(),
              severity: "info",
            });
          }
        } else if (entry.host) {
          findings.push({
            type: "subdomain",
            value: entry.host.trim(),
            severity: "info",
            metadata: { ip: entry.ip, sources: entry.source },
          });
        }
      }

      return {
        summary: `Subfinder found ${findings.length} subdomain${findings.length !== 1 ? "s" : ""}`,
        findings,
      };
    } catch {
      // Fall through to line-by-line parsing
    }
  }

  // Plain text: one subdomain per line
  const lines = raw
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && isValidSubdomain(l));

  for (const sub of lines) {
    findings.push({
      type: "subdomain",
      value: sub,
      severity: "info",
    });
  }

  return {
    summary: `Subfinder found ${findings.length} subdomain${findings.length !== 1 ? "s" : ""}`,
    findings,
  };
}

function isValidSubdomain(s: string): boolean {
  // Basic sanity check — not a log line or error message
  return /^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$/.test(s) && !s.includes(" ");
}
