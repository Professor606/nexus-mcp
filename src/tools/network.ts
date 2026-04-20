import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec, readOutputFile } from "../executor.js";
import { isInstalled } from "../utils/detect.js";
import { appendToolRun } from "../memory.js";
import { TargetSchema, SafeFlagsSchema, TimeoutSchema } from "../types.js";
import { forceSafeJson } from "../utils/clean.js";

export async function register(server: McpServer): Promise<void> {
  if (await isInstalled("enum4linux-ng")) {
    server.tool(
      "enum4linux_ng_scan",
      "Next generation version of enum4linux.",
      {
        target: TargetSchema,
        flags: SafeFlagsSchema.default(["-A"]),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "enum4linux_ng_scan");
        const outPath = `/tmp/nexus-mcp/enum4linux_${Date.now()}`;
        const result = await exec({
          tool: "enum4linux-ng",
          target,
          args: [...flags, "-oJ", outPath, target],
          timeout,
        });

        const jsonRaw = await readOutputFile(outPath + ".json");
        if (jsonRaw) {
             try {
                 const obj = JSON.parse(jsonRaw);
                 if (obj.shares && obj.shares.shares) {
                     result.findings = Object.keys(obj.shares.shares).map(s => ({
                         type: "smb_share",
                         value: s,
                         detail: `Access: ${obj.shares.shares[s].access || "Unknown"}`,
                         severity: "info"
                     }));
                 }
                 result.summary = `enum4linux-ng completed on ${target}`;
             } catch { /* ignore */ }
        }

        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("netexec") || await isInstalled("nxc")) {
    const bin = await isInstalled("netexec") ? "netexec" : "nxc";
    server.tool(
      "netexec_run",
      "Network service exploitation tool.",
      {
        target: TargetSchema,
        protocol: z.enum(["smb","winrm","ssh","mssql","ldap"]).describe("Protocol to attack"),
        flags: SafeFlagsSchema,
        timeout: TimeoutSchema,
      },
      async ({ target, protocol, flags, timeout }) => {
        appendToolRun(target, "netexec_run");
        const result = await exec({
          tool: bin,
          target,
          args: [protocol, target, ...flags],
          timeout,
        });
        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("smbmap")) {
    server.tool(
      "smbmap_scan",
      "Handy SMB enumeration tool.",
      {
        target: TargetSchema,
        flags: SafeFlagsSchema,
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "smbmap_scan");
        const result = await exec({
          tool: "smbmap",
          target,
          args: ["-H", target, ...flags],
          timeout,
        });
        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("responder")) {
    server.tool(
      "responder_run",
      "LLMNR, NBT-NS and MDNS poisoner.",
      {
        target: TargetSchema.describe("Interface to listen on (e.g. eth0)"),
        flags: SafeFlagsSchema.default(["-A"]),
        timeout: TimeoutSchema.default(600),
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "responder_run");
        const result = await exec({
          tool: "responder",
          target,
          args: ["-I", target, ...flags],
          timeout,
        });
        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
      }
    );
  }
}