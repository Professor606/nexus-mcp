import type { Finding } from "../types.js";

/**
 * Nikto outputs lines prefixed with "+ " for findings.
 * Examples:
 *   + OSVDB-3092: /admin/: This might be interesting
 *   + /login.php: Cookie set without HttpOnly flag
 *   + Server: Apache/2.4.51 (Ubuntu)
 */
export function parseNikto(raw: string): {
  summary: string;
  findings: Finding[];
} {
  const findings: Finding[] = [];
  const lines = raw.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("+")) continue;

    // Strip leading "+ " or "+"
    const content = trimmed.replace(/^\+\s*/, "");

    // OSVDB reference: "OSVDB-3092: /path: description"
    const osvdbMatch = content.match(/^(OSVDB-\d+):\s*(\S+):\s*(.+)$/);
    if (osvdbMatch) {
      const [, ref, path, desc] = osvdbMatch;
      findings.push({
        type: "web_vuln",
        value: path,
        detail: `[${ref}] ${desc.trim()}`,
        severity: "medium",
        metadata: { osvdb: ref },
      });
      continue;
    }

    // Server header: "Server: Apache/2.4.51"
    const serverMatch = content.match(/^Server:\s*(.+)$/i);
    if (serverMatch) {
      findings.push({
        type: "server_banner",
        value: serverMatch[1].trim(),
        severity: "info",
      });
      continue;
    }

    // Path-based finding: "/path: description"
    const pathMatch = content.match(/^(\/\S*):\s*(.+)$/);
    if (pathMatch) {
      const [, path, desc] = pathMatch;
      // Classify severity from description keywords
      const d = desc.toLowerCase();
      let severity: Finding["severity"] = "low";
      if (d.includes("vulnerable") || d.includes("xss") || d.includes("inject")) {
        severity = "high";
      } else if (d.includes("exposed") || d.includes("disclosure")) {
        severity = "medium";
      }
      findings.push({
        type: "web_vuln",
        value: path,
        detail: desc.trim(),
        severity,
      });
      continue;
    }

    // Generic finding
    if (content.length > 5) {
      findings.push({
        type: "nikto_finding",
        value: content.slice(0, 120),
        severity: "info",
      });
    }
  }

  const highCount = findings.filter(
    (f) => f.severity === "high" || f.severity === "medium"
  ).length;

  return {
    summary:
      findings.length === 0
        ? "Nikto found no issues"
        : `Nikto found ${findings.length} issue${findings.length !== 1 ? "s" : ""}` +
          (highCount > 0 ? ` (${highCount} medium+)` : ""),
    findings,
  };
}
