import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec } from "../executor.js";
import { isInstalled } from "../utils/detect.js";
import { appendToolRun } from "../memory.js";
import { getParser } from "../parsers/index.js";
import { TargetSchema, SafeFlagsSchema, TimeoutSchema } from "../types.js";
import { forceSafeJson } from "../utils/clean.js";

export async function register(server: McpServer): Promise<void> {
  if (await isInstalled("nmap")) {
    server.tool(
      "nmap_scan",
      "Port scan, service detection, OS fingerprint, NSE scripts.",
      {
        target: TargetSchema,
        ports: z.string().default("top1000").describe("Port range: top1000, 1-65535, 80,443"),
        flags: SafeFlagsSchema.default(["-sV", "-sC"]),
        timeout: TimeoutSchema,
      },
      async ({ target, ports, flags, timeout }) => {
        appendToolRun(target, "nmap_scan");
        const portArg = ports === "top1000" ? ["--top-ports", "1000"] : ["-p", ports];
        const result = await exec({
          tool: "nmap",
          target,
          args: [target, ...portArg, ...flags, "-oN", "-"],
          timeout,
          parse: getParser("nmap"),
        });
        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("rustscan")) {
    server.tool(
      "rustscan_scan",
      "Fast port scanner, pipes to nmap for service detection.",
      {
        target: TargetSchema,
        flags: SafeFlagsSchema,
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "rustscan_scan");
        const result = await exec({
          tool: "rustscan",
          target,
          args: ["-a", target, "--ulimit", "5000", ...flags, "--", "-sV", "-sC", "-oN", "-"],
          timeout,
          parse: getParser("nmap"),
        });
        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("subfinder")) {
    server.tool(
      "subfinder_scan",
      "Fast passive subdomain enumeration.",
      {
        target: TargetSchema,
        flags: SafeFlagsSchema,
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "subfinder_scan");
        const result = await exec({
          tool: "subfinder",
          target,
          args: ["-d", target, "-oJ", "-", "-silent", ...flags],
          timeout,
          parse: getParser("subfinder"),
        });
        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("amass")) {
    server.tool(
      "amass_enum",
      "In-depth attack surface mapping and asset discovery.",
      {
        target: TargetSchema,
        active: z.boolean().default(false).describe("Enable active mode"),
        timeout: TimeoutSchema,
      },
      async ({ target, active, timeout }) => {
        appendToolRun(target, "amass_enum");
        const args = ["enum", "-d", target];
        if (!active) args.push("-passive");
        const result = await exec({
          tool: "amass",
          target,
          args,
          timeout,
        });
        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("theHarvester") || await isInstalled("theharvester")) {
    const bin = (await isInstalled("theHarvester")) ? "theHarvester" : "theharvester";
    server.tool(
      "theharvester_scan",
      "E-mails, subdomains and names OSINT.",
      {
        target: TargetSchema,
        source: z.string().default("all").describe("Data source"),
        timeout: TimeoutSchema,
      },
      async ({ target, source, timeout }) => {
        appendToolRun(target, "theharvester_scan");
        const result = await exec({
          tool: bin,
          target,
          args: ["-d", target, "-b", source, "-f", `/tmp/nexus-mcp/harvester_out.json`],
          timeout,
        });
        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
      }
    );
  }
}