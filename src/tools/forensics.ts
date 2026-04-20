import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec } from "../executor.js";
import { isInstalled } from "../utils/detect.js";
import { appendToolRun } from "../memory.js";
import { TargetSchema, FlagsSchema, TimeoutSchema } from "../types.js";

export async function register(server: McpServer): Promise<void> {
  if (await isInstalled("vol") || await isInstalled("volatility3") || await isInstalled("vol.py")) {
    const bin = await isInstalled("vol") ? "vol" : await isInstalled("volatility3") ? "volatility3" : "vol.py";
    server.tool(
      "volatility3_analyze",
      "Memory forensics framework.",
      {
        target: TargetSchema.describe("Memory image file"),
        plugin: z.string().optional().describe("Plugin name to run. Leave empty for info/list."),
        flags: FlagsSchema.default(""),
        timeout: TimeoutSchema,
      },
      async ({ target, plugin, flags, timeout }) => {
        appendToolRun(target, "volatility3_analyze");
        const extraFlags = flags.split(" ").filter(Boolean);
        const args = ["-f", target];
        if (plugin) args.push(plugin);
        else args.push("windows.info"); // Default to windows info if no plugin
        args.push(...extraFlags);

        const result = await exec({
          tool: bin,
          target,
          args,
          timeout,
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("foremost")) {
    server.tool(
      "foremost_carve",
      "File carving from disk image.",
      {
        target: TargetSchema.describe("Disk image file"),
        flags: FlagsSchema.default(""),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "foremost_carve");
        const extraFlags = flags.split(" ").filter(Boolean);
        const outDir = `/tmp/nexus-mcp/foremost_${Date.now()}`;
        const result = await exec({
          tool: "foremost",
          target,
          args: ["-T", "-i", target, "-o", outDir, ...extraFlags],
          timeout,
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("steghide")) {
    server.tool(
      "steghide_extract",
      "Extract hidden data using steghide.",
      {
        target: TargetSchema,
        passphrase: z.string().optional().describe("Passphrase if known"),
        timeout: TimeoutSchema,
      },
      async ({ target, passphrase, timeout }) => {
        appendToolRun(target, "steghide_extract");
        const args = ["extract", "-sf", target, "-f"];
        if (passphrase) args.push("-p", passphrase);
        else args.push("-p", ""); // Try empty passphrase

        const result = await exec({
          tool: "steghide",
          target,
          args,
          timeout,
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("zsteg")) {
    server.tool(
      "zsteg_analyze",
      "PNG/BMP steganography LSB analysis.",
      {
        target: TargetSchema,
        flags: FlagsSchema.default("-a"),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "zsteg_analyze");
        const extraFlags = flags.split(" ").filter(Boolean);
        const result = await exec({
          tool: "zsteg",
          target,
          args: [...extraFlags, target],
          timeout,
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("exiftool")) {
    server.tool(
      "exiftool_read",
      "Read file metadata.",
      {
        target: TargetSchema,
        flags: FlagsSchema.default(""),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "exiftool_read");
        const extraFlags = flags.split(" ").filter(Boolean);
        const result = await exec({
          tool: "exiftool",
          target,
          args: ["-json", ...extraFlags, target],
          timeout,
        });
        try {
           const arr = JSON.parse(result.raw_truncated);
           if (Array.isArray(arr) && arr.length > 0) {
              const meta = arr[0];
              result.findings = Object.keys(meta).map(k => ({
                 type: "metadata",
                 value: k,
                 detail: String(meta[k]),
                 severity: "info"
              }));
           }
        } catch { /* ignore */ }
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("rsatool")) {
    server.tool(
      "rsatool_analyze",
      "RSA key analysis.",
      {
        target: TargetSchema.describe("Public key file"),
        flags: FlagsSchema.default(""),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "rsatool_analyze");
        const extraFlags = flags.split(" ").filter(Boolean);
        const result = await exec({
          tool: "rsatool",
          target,
          args: [...extraFlags, "-n", target],
          timeout,
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }
}
