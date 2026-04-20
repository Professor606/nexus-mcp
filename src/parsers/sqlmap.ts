import type { Finding } from "../types.js";

/**
 * sqlmap output parser.
 * Looks for:
 *   - Injectable parameter confirmations: "Parameter: X (GET)"
 *   - Injection types: "Type: boolean-based blind"
 *   - DBMS identification: "back-end DBMS: MySQL"
 *   - OS identification: "web server operating system: Linux"
 */
export function parseSqlmap(raw: string): {
  summary: string;
  findings: Finding[];
} {
  const findings: Finding[] = [];
  const lines = raw.split("\n");

  let currentParam = "";
  let currentTypes: string[] = [];
  let dbms = "";
  let os = "";

  for (const line of lines) {
    const trimmed = line.trim();

    // Parameter line: "Parameter: id (GET)"
    const paramMatch = trimmed.match(/^Parameter:\s*(\S+)\s*\(([^)]+)\)/i);
    if (paramMatch) {
      // Save previous parameter if exists
      if (currentParam) {
        findings.push(buildSqliFound(currentParam, currentTypes, dbms));
      }
      currentParam = `${paramMatch[1]} (${paramMatch[2]})`;
      currentTypes = [];
      continue;
    }

    // Injection type: "    Type: boolean-based blind"
    const typeMatch = trimmed.match(/^Type:\s*(.+)$/i);
    if (typeMatch && currentParam) {
      currentTypes.push(typeMatch[1].trim());
      continue;
    }

    // DBMS: "back-end DBMS: MySQL >= 5.0"
    const dbmsMatch = trimmed.match(/back-end DBMS:\s*(.+)/i);
    if (dbmsMatch) {
      dbms = dbmsMatch[1].trim();
      continue;
    }

    // OS: "web server operating system: Linux"
    const osMatch = trimmed.match(/web server operating system:\s*(.+)/i);
    if (osMatch) {
      os = osMatch[1].trim();
      continue;
    }

    // Database user: "current user: 'root@localhost'"
    const userMatch = trimmed.match(/current user(?:'s)?(?:\s+is)?:\s*'?([^']+)'?/i);
    if (userMatch) {
      findings.push({
        type: "db_user",
        value: userMatch[1].trim(),
        severity: "high",
        detail: "Current database user",
      });
    }
  }

  // Save last parameter
  if (currentParam) {
    findings.push(buildSqliFound(currentParam, currentTypes, dbms));
  }

  // Add OS/DBMS metadata findings
  if (dbms) {
    findings.push({ type: "dbms", value: dbms, severity: "info" });
  }
  if (os) {
    findings.push({ type: "target_os", value: os, severity: "info" });
  }

  const sqliCount = findings.filter((f) => f.type === "sqli").length;

  return {
    summary:
      sqliCount === 0
        ? "sqlmap found no injectable parameters"
        : `sqlmap found ${sqliCount} injectable parameter${sqliCount !== 1 ? "s" : ""}` +
          (dbms ? ` (${dbms})` : ""),
    findings,
  };
}

function buildSqliFound(
  param: string,
  types: string[],
  dbms: string
): Finding {
  return {
    type: "sqli",
    value: param,
    detail: [
      types.length ? `types: ${types.join(", ")}` : "",
      dbms ? `DBMS: ${dbms}` : "",
    ]
      .filter(Boolean)
      .join(" | "),
    severity: "critical",
    metadata: { injection_types: types, dbms },
  };
}

// Alias for consistency
const buildSqliFind = buildSqliFound;
export { buildSqliFind as buildSqliF };
