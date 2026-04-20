import type { Finding } from "../types.js";
import { mapSeverity } from "../types.js";

export function parseNmap(raw: string, version?: string): { summary: string; findings: Finding[]; parse_error?: boolean; raw_truncated?: string } {
  const findings: Finding[] = [];
  const lines = raw.split("\n");

  let target = "";
  let openCount = 0;

  for (const line of lines) {
    // Extract target from "Nmap scan report for X"
    const reportMatch = line.match(/Nmap scan report for (.+)/);
    if (reportMatch) {
      target = reportMatch[1].trim();
      continue;
    }

    // Open port line: "80/tcp   open  http    Apache httpd 2.4.51"
    const portMatch = line.match(
      /^(\d+\/(?:tcp|udp))\s+(open|filtered)\s+(\S+)\s*(.*)?$/
    );
    if (portMatch) {
      const [, port, state, service, version] = portMatch;
      if (state === "open") {
        openCount++;
        findings.push({
          type: "open_port",
          value: port,
          detail: [service, version?.trim()].filter(Boolean).join(" — "),
          severity: "info",
          metadata: { state, service, version: version?.trim() },
        });
      }
      continue;
    }

    // OS guess: "OS details: Linux 4.15 - 5.8"
    const osMatch = line.match(/OS details:\s*(.+)/);
    if (osMatch) {
      findings.push({
        type: "os_guess",
        value: osMatch[1].trim(),
        severity: "info",
      });
      continue;
    }

    // OS CPE: "OS CPE: cpe:/o:linux:linux_kernel:4"
    const cpeMatch = line.match(/OS CPE:\s*(.+)/);
    if (cpeMatch) {
      findings.push({
        type: "os_cpe",
        value: cpeMatch[1].trim(),
        severity: "info",
      });
      continue;
    }

    // Script output: "|_http-title: My Site" or "| ssl-cert: ..."
    const scriptMatch = line.match(/^\|\s+(\S[\s\S]+?):\s(.+)$/);
    if (scriptMatch) {
      findings.push({
        type: "nse_result",
        value: scriptMatch[1].trim(),
        detail: scriptMatch[2].trim(),
        severity: "info",
      });
    }
  }

  // Ignored ports summary
  const ignoredMatch = raw.match(/Not shown:\s*(\d+)\s+filtered/);
  if (ignoredMatch) {
    findings.push({
      type: "filtered_ports",
      value: `${ignoredMatch[1]} filtered`,
      severity: "info",
    });
  }

  const tgt = target || "target";
  const summary =
    openCount > 0
      ? `Found ${openCount} open port${openCount !== 1 ? "s" : ""} on ${tgt}`
      : `No open ports found on ${tgt}`;

  return { summary, findings };
}

// Re-export mapSeverity for convenience
export { mapSeverity };
