import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec, readOutputFile } from "../executor.js";
import { isInstalled } from "../utils/detect.js";
import { appendToolRun } from "../memory.js";
import { TargetSchema, SafeFlagsSchema, TimeoutSchema } from "../types.js";
import { forceSafeJson } from "../utils/clean.js";

export async function register(server: McpServer): Promise<void> {
  if (await isInstalled("sherlock")) {
    server.tool(
      "sherlock_search",
      "Hunt down social media accounts by username.",
      {
        target: TargetSchema.describe("Username"),
        flags: SafeFlagsSchema,
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "sherlock_search");
        const result = await exec({
          tool: "sherlock",
          target,
          args: ["--json", "--print-found", ...flags, target],
          timeout,
        });
        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("trufflehog")) {
    server.tool(
      "trufflehog_scan",
      "Find credentials in code and history.",
      {
        target: TargetSchema.describe("Git URL or filesystem path"),
        target_type: z.enum(["git", "filesystem", "github"]).default("git"),
        flags: SafeFlagsSchema,
        timeout: TimeoutSchema,
      },
      async ({ target, target_type, flags, timeout }) => {
        appendToolRun(target, "trufflehog_scan");
        const result = await exec({
          tool: "trufflehog",
          target,
          args: [target_type, target, "--json", ...flags],
          timeout,
        });

        try {
            const lines = result.raw_truncated.split('\n').filter(Boolean);
            result.findings = lines.map(l => {
                const obj = JSON.parse(l);
                return {
                    type: "secret",
                    value: obj.DetectorName,
                    detail: obj.Raw || obj.Redacted,
                    severity: "high",
                    metadata: obj
                };
            });
            result.summary = `Trufflehog found ${result.findings.length} secrets`;
        } catch { /* ignore */ }

        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("spiderfoot")) {
    server.tool(
      "spiderfoot_scan",
      "OSINT automation tool.",
      {
        target: TargetSchema,
        flags: SafeFlagsSchema.default(["-s"]),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "spiderfoot_scan");
        if (!process.env.SPIDERFOOT_API_KEY) {
           return { content: [{ type: "text", text: forceSafeJson({ error: "SPIDERFOOT_API_KEY env var not set" }) }] };
        }
        const result = await exec({
          tool: "spiderfoot",
          target,
          args: ["-t", target, "-q", ...flags],
          timeout,
        });
        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("shodan")) {
    server.tool(
      "shodan_search",
      "Search Shodan via CLI.",
      {
        target: TargetSchema.describe("Search query (e.g. org:target or ip)"),
        flags: SafeFlagsSchema.default(["--fields", "ip_str,port,org,hostnames"]),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "shodan_search");
        if (!process.env.SHODAN_API_KEY) {
            return { content: [{ type: "text", text: forceSafeJson({ error: "SHODAN_API_KEY env var not set" }) }] };
        }
        await exec({tool: "shodan", target, args: ["init", process.env.SHODAN_API_KEY]});

        const result = await exec({
          tool: "shodan",
          target,
          args: ["search", ...flags, target],
          timeout,
        });

        const lines = result.raw_truncated.split('\n').filter(Boolean);
        result.findings = lines.map(l => ({
            type: "shodan_host",
            value: l.split('\t')[0] || l,
            detail: l,
            severity: "info"
        }));
        result.summary = `Shodan found ${result.findings.length} results`;

        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
      }
    );
  }
}