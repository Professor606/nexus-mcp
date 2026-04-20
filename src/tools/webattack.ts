import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec, readOutputFile } from "../executor.js";
import { isInstalled } from "../utils/detect.js";
import { appendToolRun } from "../memory.js";
import { getParser } from "../parsers/index.js";
import { TargetSchema, FlagsSchema, TimeoutSchema } from "../types.js";
import { resolveWordlist } from "../utils/wordlists.js";

export async function register(server: McpServer): Promise<void> {
  if (await isInstalled("sqlmap")) {
    server.tool(
      "sqlmap_scan",
      "Automatic SQL injection and database takeover.",
      {
        target: TargetSchema,
        flags: FlagsSchema.default("--batch"),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "sqlmap_scan");
        const extraFlags = flags.split(" ").filter(Boolean).filter(f => !f.includes("--dump")); // Prevent dumping
        const result = await exec({
          tool: "sqlmap",
          target,
          args: ["-u", target, "--batch", "--output-dir=/tmp/nexus-mcp/sqlmap", ...extraFlags],
          timeout,
          parse: getParser("sqlmap"),
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("dalfox")) {
    server.tool(
      "dalfox_scan",
      "Fast, powerful XSS scanner and utility tool.",
      {
        target: TargetSchema,
        flags: FlagsSchema.default(""),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "dalfox_scan");
        const extraFlags = flags.split(" ").filter(Boolean);
        const outPath = `/tmp/nexus-mcp/dalfox_${Date.now()}.json`;
        const result = await exec({
          tool: "dalfox",
          target,
          args: ["url", target, "--format", "json", "-o", outPath, ...extraFlags],
          timeout,
        });

        const jsonRaw = await readOutputFile(outPath);
        if (jsonRaw) {
             try {
                 const arr = JSON.parse(jsonRaw);
                 result.findings = arr.map((x: any) => ({
                     type: "xss",
                     value: x.inject_param || x.url,
                     detail: x.type,
                     severity: x.severity === "High" ? "high" : "medium"
                 }));
                 result.summary = `Dalfox found ${result.findings.length} XSS issues`;
             } catch { /* ignore */ }
        }

        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("arjun")) {
    server.tool(
      "arjun_discover",
      "HTTP parameter discovery suite.",
      {
        target: TargetSchema,
        flags: FlagsSchema.default(""),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "arjun_discover");
        const extraFlags = flags.split(" ").filter(Boolean);
        const outPath = `/tmp/nexus-mcp/arjun_${Date.now()}.json`;
        const result = await exec({
          tool: "arjun",
          target,
          args: ["-u", target, "-oJ", outPath, ...extraFlags],
          timeout,
        });

        const jsonRaw = await readOutputFile(outPath);
        if (jsonRaw) {
             try {
                 const obj = JSON.parse(jsonRaw);
                 result.findings = Object.keys(obj).flatMap(url => 
                     obj[url].params.map((p: string) => ({
                         type: "parameter",
                         value: p,
                         detail: `Method: ${obj[url].method}`,
                         severity: "info"
                     }))
                 );
                 result.summary = `Arjun discovered parameters on ${Object.keys(obj).length} URLs`;
             } catch { /* ignore */ }
        }
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("x8")) {
    server.tool(
      "x8_discover",
      "Hidden parameter discovery suite.",
      {
        target: TargetSchema,
        flags: FlagsSchema.default(""),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "x8_discover");
        const extraFlags = flags.split(" ").filter(Boolean);
        const result = await exec({
          tool: "x8",
          target,
          args: ["-u", target, ...extraFlags], // x8 text output to stdout
          timeout,
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("wpscan")) {
    server.tool(
      "wpscan_scan",
      "Black box WordPress vulnerability scanner.",
      {
        target: TargetSchema,
        flags: FlagsSchema.default(""),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "wpscan_scan");
        const extraFlags = flags.split(" ").filter(Boolean);
        const outPath = `/tmp/nexus-mcp/wpscan_${Date.now()}.json`;
        const args = ["--url", target, "--format", "json", "-o", outPath, ...extraFlags];
        if (process.env.WPSCAN_API_TOKEN) {
            args.push("--api-token", process.env.WPSCAN_API_TOKEN);
        }

        const result = await exec({
          tool: "wpscan",
          target,
          args,
          timeout,
        });

        const jsonRaw = await readOutputFile(outPath);
        if (jsonRaw) {
             try {
                 const obj = JSON.parse(jsonRaw);
                 // Very basic parsing for summary
                 result.summary = `WPScan completed on ${target}`;
             } catch { /* ignore */ }
        }

        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("nosqlmap")) {
    server.tool(
      "nosqlmap_scan",
      "Automated NoSQL database exploitation.",
      {
        target: TargetSchema,
        flags: FlagsSchema.default(""),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "nosqlmap_scan");
        const extraFlags = flags.split(" ").filter(Boolean);
        const result = await exec({
          tool: "nosqlmap",
          target,
          args: ["--batch", ...extraFlags],
          timeout,
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("tplmap")) {
    server.tool(
      "tplmap_scan",
      "Server-side template injection and Web server exploitation.",
      {
        target: TargetSchema,
        flags: FlagsSchema.default("--level 3"),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "tplmap_scan");
        const extraFlags = flags.split(" ").filter(Boolean);
        const result = await exec({
          tool: "tplmap",
          target,
          args: ["-u", target, ...extraFlags],
          timeout,
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("commix")) {
    server.tool(
      "commix_scan",
      "Automated OS command injection exploitation tool.",
      {
        target: TargetSchema,
        flags: FlagsSchema.default(""),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "commix_scan");
        const extraFlags = flags.split(" ").filter(Boolean).filter(f => !f.includes("--os-cmd"));
        const result = await exec({
          tool: "commix",
          target,
          args: ["--url", target, "--batch", ...extraFlags],
          timeout,
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("jwt_tool") || await isInstalled("jwt-tool") || await isInstalled("jwt_tool.py")) {
    const bin = await isInstalled("jwt_tool") ? "jwt_tool" : await isInstalled("jwt-tool") ? "jwt-tool" : "jwt_tool.py";
    server.tool(
      "jwt_tool_test",
      "Toolkit for validating, forging and cracking JWTs.",
      {
        target: TargetSchema.describe("JWT Token or Target URL"),
        flags: FlagsSchema.default("--mode at"),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "jwt_tool_test");
        const extraFlags = flags.split(" ").filter(Boolean);
        const result = await exec({
          tool: bin,
          target,
          args: [target, ...extraFlags],
          timeout,
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("subjack")) {
    server.tool(
      "subjack_check",
      "Hostile subdomain takeover vulnerability routing.",
      {
        target: TargetSchema.describe("File containing subdomains or single domain"),
        flags: FlagsSchema.default("-ssl"),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "subjack_check");
        const extraFlags = flags.split(" ").filter(Boolean);
        const args = extraFlags;
        if (!args.includes("-w") && !args.includes("-d")) {
             // Assume target is a list of subdomains
             args.push("-w", target);
        }
        const result = await exec({
          tool: "subjack",
          target,
          args,
          timeout,
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }
}
