import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec, readOutputFile } from "../executor.js";
import { isInstalled } from "../utils/detect.js";
import { appendToolRun } from "../memory.js";
import { TargetSchema, SafeFlagsSchema, TimeoutSchema } from "../types.js";
import { forceSafeJson } from "../utils/clean.js";

export async function register(server: McpServer): Promise<void> {
  if (await isInstalled("prowler")) {
    server.tool(
      "prowler_assess",
      "Cloud security assessments, audits, incident response.",
      {
        target: TargetSchema.describe("Target account/env name for logging"),
        provider: z.enum(["aws", "azure", "gcp"]).describe("Cloud provider"),
        flags: SafeFlagsSchema,
        timeout: TimeoutSchema.default(3600),
      },
      async ({ target, provider, flags, timeout }) => {
        appendToolRun(target, "prowler_assess");
        const outDir = `/tmp/nexus-mcp/prowler_${Date.now()}`;
        const result = await exec({
          tool: "prowler",
          target,
          args: [provider, "-M", "json", "-F", outDir, ...flags],
          timeout,
        });
        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("trivy")) {
    server.tool(
      "trivy_scan",
      "Comprehensive vulnerability scanner.",
      {
        target: TargetSchema,
        target_type: z.enum(["image", "fs", "repo", "k8s"]).default("fs"),
        flags: SafeFlagsSchema,
        timeout: TimeoutSchema,
      },
      async ({ target, target_type, flags, timeout }) => {
        appendToolRun(target, "trivy_scan");
        const outPath = `/tmp/nexus-mcp/trivy_${Date.now()}.json`;
        const result = await exec({
          tool: "trivy",
          target,
          args: [target_type, "--format", "json", "-o", outPath, ...flags, target],
          timeout,
        });

        const jsonRaw = await readOutputFile(outPath);
        if (jsonRaw) {
             try {
                 const obj = JSON.parse(jsonRaw);
                 result.findings = [];
                 let totalVulns = 0;
                 if (obj.Results) {
                     for (const r of obj.Results) {
                         if (r.Vulnerabilities) {
                             totalVulns += r.Vulnerabilities.length;
                             r.Vulnerabilities.forEach((v: any) => {
                                 result.findings.push({
                                     type: "vuln",
                                     value: v.VulnerabilityID,
                                     detail: v.PkgName,
                                     severity: v.Severity === "CRITICAL" ? "critical" : v.Severity === "HIGH" ? "high" : v.Severity === "MEDIUM" ? "medium" : "low"
                                 });
                             });
                         }
                     }
                 }
                 result.summary = `Trivy found ${totalVulns} vulnerabilities`;
             } catch { /* ignore */ }
        }
        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("kube-hunter")) {
    server.tool(
      "kube_hunter_scan",
      "Hunt for security weaknesses in Kubernetes clusters.",
      {
        target: TargetSchema,
        active: z.boolean().default(false).describe("Enable active hunting"),
        flags: SafeFlagsSchema,
        timeout: TimeoutSchema,
      },
      async ({ target, active, flags, timeout }) => {
        appendToolRun(target, "kube_hunter_scan");
        const args = ["--remote", target, "--report", "json"];
        if (active) args.push("--active");
        args.push(...flags);

        const result = await exec({
          tool: "kube-hunter",
          target,
          args,
          timeout,
        });

        try {
             const cleanJson = result.raw_truncated.substring(result.raw_truncated.indexOf('{'));
             const obj = JSON.parse(cleanJson);
             if (obj.vulnerabilities) {
                 result.findings = obj.vulnerabilities.map((v: any) => ({
                     type: "k8s_vuln",
                     value: v.vulnerability,
                     detail: v.description,
                     severity: v.severity === "high" ? "high" : v.severity === "medium" ? "medium" : "low"
                 }));
                 result.summary = `kube-hunter found ${result.findings.length} issues`;
             }
        } catch { /* ignore */ }
        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("pacu")) {
    server.tool(
      "pacu_run",
      "AWS exploitation framework.",
      {
        target: TargetSchema.describe("Session or target name"),
        module: z.string().describe("Pacu module to run"),
        flags: SafeFlagsSchema,
        timeout: TimeoutSchema,
      },
      async ({ target, module, flags, timeout }) => {
        appendToolRun(target, "pacu_run");
        const result = await exec({
          tool: "pacu",
          target,
          args: ["--session", target, "--module-name", module, "--exec", ...flags],
          timeout,
        });
        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
      }
    );
  }
}