import type { Finding } from "../types.js";
import { mapSeverity } from "../types.js";

/**
 * Nuclei outputs one JSON object per line when run with -j flag.
 * Format: { "template-id", "info": { "severity", "name" }, "type", "matched-at", ... }
 */
export function parseNuclei(raw: string, version?: string): {
  summary: string;
  findings: Finding[];
  parse_error?: boolean;
  raw_truncated?: string;
} {
  const findings: Finding[] = [];
  const lines = raw.split("\n").filter((l) => l.trim().startsWith("{"));

  for (const line of lines) {
    try {
      const obj = JSON.parse(line) as {
        "template-id"?: string;
        info?: { severity?: string; name?: string; description?: string };
        type?: string;
        "matched-at"?: string;
        host?: string;
      };

      const templateId = obj["template-id"] ?? "unknown";
      const severity = mapSeverity(obj.info?.severity ?? "info");
      const name = obj.info?.name ?? templateId;
      const matched = obj["matched-at"] ?? obj.host ?? "";

      findings.push({
        type: "vulnerability",
        value: templateId,
        detail: `${name}${matched ? " @ " + matched : ""}`,
        severity,
        metadata: {
          template: templateId,
          type: obj.type,
          matched,
          description: obj.info?.description,
        },
      });
    } catch {
      // Non-JSON line — try line-based fallback format
      // [critical] [template-id] [type] url [matched]
      const lineMatch = line.match(
        /\[(critical|high|medium|low|info)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)(?:\s+\[(.+)\])?/i
      );
      if (lineMatch) {
        const [, sev, tmpl, , url, matched] = lineMatch;
        findings.push({
          type: "vulnerability",
          value: tmpl,
          detail: `${url}${matched ? " — " + matched : ""}`,
          severity: mapSeverity(sev),
        });
      }
    }
  }

  const critHigh = findings.filter(
    (f) => f.severity === "critical" || f.severity === "high"
  ).length;

  const summary =
    findings.length === 0
      ? "Nuclei found no vulnerabilities"
      : `Nuclei found ${findings.length} issue${findings.length !== 1 ? "s" : ""}` +
        (critHigh > 0 ? ` (${critHigh} critical/high)` : "");

  return { summary, findings };
}
