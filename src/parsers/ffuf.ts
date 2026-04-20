import type { Finding } from "../types.js";

/**
 * ffuf is invoked with -of json -o /tmp/nexus-mcp/ffuf_out.json
 * This parser reads the JSON file content (passed as raw string).
 *
 * ffuf JSON schema:
 * { "results": [{ "url", "status", "length", "words", "lines", "content-type", ... }] }
 */
export function parseFfuf(raw: string): { summary: string; findings: Finding[] } {
  const findings: Finding[] = [];

  if (!raw.trim()) {
    return { summary: "ffuf produced no output", findings };
  }

  try {
    const data = JSON.parse(raw) as {
      results?: Array<{
        url?: string;
        input?: Record<string, string>;
        status?: number;
        length?: number;
        words?: number;
        lines?: number;
        "content-type"?: string;
      }>;
    };

    const results = data.results ?? [];

    for (const r of results) {
      const url = r.url ?? Object.values(r.input ?? {}).join("/");
      const status = r.status ?? 0;
      const size = r.length ?? 0;

      // Severity hint based on status code
      let severity: Finding["severity"] = "info";
      if (status === 200 || status === 301 || status === 302) severity = "info";
      if (status === 403)  severity = "low";    // forbidden but exists
      if (status === 401)  severity = "medium"; // requires auth

      findings.push({
        type: "path",
        value: url,
        detail: `status:${status} size:${size} words:${r.words ?? 0}`,
        severity,
        metadata: {
          status,
          length: size,
          words: r.words,
          lines: r.lines,
          content_type: r["content-type"],
        },
      });
    }

    return {
      summary:
        results.length === 0
          ? "ffuf found no paths"
          : `ffuf found ${results.length} path${results.length !== 1 ? "s" : ""}`,
      findings,
    };
  } catch {
    // Fallback: parse line-by-line text output
    const lines = raw.split("\n");
    for (const line of lines) {
      const m = line.match(/^\s*(\S+)\s+\[Status:\s*(\d+),/);
      if (m) {
        findings.push({
          type: "path",
          value: m[1],
          detail: `status:${m[2]}`,
          severity: "info",
        });
      }
    }
    return {
      summary: `ffuf found ${findings.length} path${findings.length !== 1 ? "s" : ""} (text parse)`,
      findings,
    };
  }
}
