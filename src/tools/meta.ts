import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec } from "../executor.js";
import { saveNote, loadNote, appendFindings, clearNote, allTargets, setPhase } from "../memory.js";
import { setActiveProfile, getActiveProfile } from "../registry.js";
import type { Finding, Profile } from "../types.js";
import { CVSS_MAP, sanitizeFlags } from "../types.js";

function getSeverityNumber(sev: string): number {
    return CVSS_MAP[sev as keyof typeof CVSS_MAP] || 0.0;
}

export async function register(server: McpServer): Promise<void> {

  server.tool(
    "switch_phase",
    "Switch tool profile: recon|web|network|bugbounty|ctf|cloud|osint|full",
    {
      profile: z.enum(["recon","web","network","bugbounty","ctf","cloud","osint","full"])
    },
    async ({ profile }) => {
      setActiveProfile(profile as Profile);
      return { content: [{ type: "text", text: `Profile switched to ${profile}. LLM should now rely on tools for this phase.` }] };
    }
  );

  server.tool(
    "pentest_notes",
    "Save/load/append structured pentest findings per target.",
    {
      action: z.enum(["save","load","append","clear","list_targets"]),
      target: z.string().optional(),
      data: z.record(z.unknown()).optional(),
    },
    async ({ action, target, data }) => {
      if (action === "list_targets") {
          return { content: [{ type: "text", text: JSON.stringify(allTargets(), null, 2) }] };
      }
      if (!target) return { content: [{ type: "text", text: "Error: target required" }] };

      if (action === "clear") {
          clearNote(target);
          return { content: [{ type: "text", text: `Cleared notes for ${target}` }] };
      }
      if (action === "load") {
          const note = loadNote(target);
          return { content: [{ type: "text", text: note ? JSON.stringify(note, null, 2) : "No notes found" }] };
      }
      if (action === "save") {
          const note = saveNote(target, data as any);
          return { content: [{ type: "text", text: JSON.stringify(note, null, 2) }] };
      }
      if (action === "append") {
          if (data && data.phase) setPhase(target, data.phase as string);
          return { content: [{ type: "text", text: `Appended data for ${target}` }] };
      }

      return { content: [{ type: "text", text: "Unknown action" }] };
    }
  );

  server.tool(
    "chain_tools",
    "Run tools in sequence. Each tool's findings feed into the next.",
    {
      target: z.string(),
      chain: z.array(z.object({
        tool: z.string(),
        args: z.record(z.unknown()).optional(),
      }))
    },
    async ({ target, chain }) => {
      const results = [];
      const allFindings: Finding[] = [];

      for (const step of chain) {
          const stepFlags = Array.isArray(step.args?.flags) ? step.args.flags : [];
          sanitizeFlags(stepFlags);
          const binaryOpts = {
              tool: step.tool.replace(/_(scan|probe|crawl|enum|detect|test|discover|crack|analyze|carve|extract|read|find)$/, ""), 
              target,
              args: stepFlags.length > 0 ? stepFlags : [target]
          };
          const res = await exec(binaryOpts);
          results.push(res);
          allFindings.push(...res.findings);
      }
      appendFindings(target, allFindings);

      return { content: [{ type: "text", text: JSON.stringify({ results, merged_findings: allFindings }, null, 2) }] };
    }
  );

  server.tool(
    "attack_chain_suggest",
    "Suggest next attack steps based on current findings for a target.",
    {
      target: z.string()
    },
    async ({ target }) => {
      const note = loadNote(target);
      if (!note) return { content: [{ type: "text", text: "No findings available for target." }] };

      const findings = note.findings;
      const suggestions = [];

      const hasPort = (port: string) => findings.some(f => f.type === "open_port" && f.value.includes(port));
      const hasFinding = (type: string) => findings.some(f => f.type === type);
      const getDetail = (type: string) => findings.find(f => f.type === type)?.detail || "";

      if (hasPort("80") || hasPort("443") || hasPort("8080") || hasPort("8443")) {
          suggestions.push("Web server detected: Run httpx_probe, then nuclei_scan or ffuf_scan.");
      }
      if (hasPort("445") || hasPort("139")) {
          suggestions.push("SMB detected: Run enum4linux_ng_scan, netexec_run smb, and smbmap_scan.");
      }
      if (hasPort("22")) {
          suggestions.push("SSH detected: Run hydra_crack if credentials are known, or netexec_run ssh.");
      }
      if (getDetail("open_port").toLowerCase().includes("wordpress") || hasFinding("tech") && getDetail("tech").toLowerCase().includes("wordpress")) {
          suggestions.push("WordPress detected: Run wpscan_scan.");
      }
      if (hasFinding("subdomain")) {
          suggestions.push("Subdomains found: Run subjack_check for takeovers, httpx_probe for active probing.");
      }
      if (hasFinding("sqli")) {
          suggestions.push("SQLi detected: Run sqlmap_scan to exploit or dalfox_scan to check for chained XSS.");
      }
      if (hasFinding("secret") || hasFinding("hash_type")) {
          suggestions.push("Hashes/Secrets found: Run hashcat_crack or john_crack.");
      }

      if (suggestions.length === 0) {
          suggestions.push("No specific automated chain matched. Continue manual recon.");
      }

      note.next_steps = suggestions;
      return { content: [{ type: "text", text: JSON.stringify(suggestions, null, 2) }] };
    }
  );

  server.tool(
    "generate_report",
    "Generate markdown pentest report from session findings.",
    {
      target: z.string(),
      format: z.enum(["markdown","json"]).default("markdown")
    },
    async ({ target, format }) => {
      const note = loadNote(target);
      if (!note) return { content: [{ type: "text", text: "No notes found for target." }] };

      if (format === "json") {
          return { content: [{ type: "text", text: JSON.stringify(note, null, 2) }] };
      }

      const sortedFindings = [...note.findings].sort((a, b) => getSeverityNumber(b.severity || "info") - getSeverityNumber(a.severity || "info"));

      let md = `# Penetration Test Report: ${target}\n\n`;
      md += `**Date:** ${new Date().toISOString().split('T')[0]}\n`;
      md += `**Total Findings:** ${sortedFindings.length}\n\n`;

      md += `## Executive Summary\n\n`;
      const criticalCount = sortedFindings.filter(f => f.severity === "critical").length;
      const highCount = sortedFindings.filter(f => f.severity === "high").length;
      const mediumCount = sortedFindings.filter(f => f.severity === "medium").length;
      md += `- **Critical:** ${criticalCount}\n- **High:** ${highCount}\n- **Medium:** ${mediumCount}\n\n`;

      md += `## Findings\n\n`;
      if (sortedFindings.length === 0) {
          md += `No findings recorded.\n`;
      } else {
          md += `| Severity | Type | Value | Detail |\n`;
          md += `|---|---|---|---|\n`;
          for (const f of sortedFindings) {
              md += `| **${(f.severity || "info").toUpperCase()}** | ${f.type} | \`${f.value}\` | ${f.detail || ""} |\n`;
          }
      }

      md += `\n## Tools Executed\n\n`;
      md += note.tools_run.length > 0 ? note.tools_run.map(t => `- ${t}`).join("\n") : "No tools recorded.";
      md += `\n\n## Recommendations / Next Steps\n\n`;
      md += note.next_steps.length > 0 ? note.next_steps.map(s => `- ${s}`).join("\n") : "None.";

      return { content: [{ type: "text", text: md }] };
    }
  );
}