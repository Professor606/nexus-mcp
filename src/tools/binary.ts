import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec } from "../executor.js";
import { isInstalled } from "../utils/detect.js";
import { appendToolRun } from "../memory.js";
import { TargetSchema, FlagsSchema, TimeoutSchema } from "../types.js";
import fs from "node:fs/promises";

export async function register(server: McpServer): Promise<void> {
  if (await isInstalled("gdb")) {
    server.tool(
      "gdb_debug",
      "GNU Debugger with script automation.",
      {
        target: TargetSchema,
        commands: z.string().describe("GDB commands to run (\\n separated)"),
        timeout: TimeoutSchema,
      },
      async ({ target, commands, timeout }) => {
        appendToolRun(target, "gdb_debug");
        const scriptPath = `/tmp/nexus-mcp/gdb_${Date.now()}.script`;
        await fs.writeFile(scriptPath, commands + "\nquit\n");
        const result = await exec({
          tool: "gdb",
          target,
          args: ["-q", "-batch", "-x", scriptPath, target],
          timeout,
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("r2")) {
    server.tool(
      "radare2_analyze",
      "Advanced commandline hex editor and disassembler.",
      {
        target: TargetSchema,
        commands: z.string().describe("r2 commands to run (e.g. 'aaa; pdf @ main')"),
        timeout: TimeoutSchema,
      },
      async ({ target, commands, timeout }) => {
        appendToolRun(target, "radare2_analyze");
        const result = await exec({
          tool: "r2",
          target,
          args: ["-A", "-q", "-c", commands, target],
          timeout,
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("analyzeHeadless")) {
    server.tool(
      "ghidra_analyze",
      "Ghidra headless analyzer.",
      {
        target: TargetSchema,
        script: z.string().optional().describe("Post-analysis script name"),
        timeout: TimeoutSchema.default(600), // Ghidra takes a while
      },
      async ({ target, script, timeout }) => {
        appendToolRun(target, "ghidra_analyze");
        const projDir = `/tmp/nexus-mcp/ghidra_${Date.now()}`;
        await fs.mkdir(projDir, { recursive: true });
        const args = [projDir, "Proj", "-import", target];
        if (script) args.push("-postScript", script);
        
        const result = await exec({
          tool: "analyzeHeadless",
          target,
          args,
          timeout,
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("binwalk")) {
    server.tool(
      "binwalk_extract",
      "Firmware analysis and extraction tool.",
      {
        target: TargetSchema,
        flags: FlagsSchema.default("-e"),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "binwalk_extract");
        const extraFlags = flags.split(" ").filter(Boolean);
        const outDir = `/tmp/nexus-mcp/binwalk_${Date.now()}`;
        const result = await exec({
          tool: "binwalk",
          target,
          args: [...extraFlags, target, "-C", outDir],
          timeout,
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("checksec")) {
    server.tool(
      "checksec_check",
      "Check binary for security properties.",
      {
        target: TargetSchema,
        timeout: TimeoutSchema,
      },
      async ({ target, timeout }) => {
        appendToolRun(target, "checksec_check");
        const result = await exec({
          tool: "checksec",
          target,
          args: [`--file=${target}`, "--format=json"],
          timeout,
        });
        try {
             // Handle some checksec versions outputting to stderr or having trailing newlines
             const cleanJson = result.raw_truncated.replace(/^[^{]*/, '').replace(/[^}]*$/, '');
             const obj = JSON.parse(cleanJson);
             result.findings = Object.keys(obj).flatMap(k => 
                Object.keys(obj[k]).map(prop => ({
                    type: "sec_prop",
                    value: prop,
                    detail: obj[k][prop],
                    severity: "info"
                }))
             );
             result.summary = `checksec analyzed ${target}`;
        } catch { /* ignore */ }
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  server.tool(
    "binary_info",
    "Meta-tool wrapping strings, objdump, and readelf.",
    {
      target: TargetSchema,
      mode: z.enum(["strings","headers","sections","symbols","all"]),
      timeout: TimeoutSchema,
    },
    async ({ target, mode, timeout }) => {
      appendToolRun(target, "binary_info");
      let out = "";
      if (mode === "strings" || mode === "all") {
         const { raw_truncated } = await exec({tool: "strings", target, args: [target], timeout});
         out += `\n--- STRINGS ---\n${raw_truncated}\n`;
      }
      if (mode === "headers" || mode === "all") {
         const { raw_truncated } = await exec({tool: "readelf", target, args: ["-h", target], timeout});
         out += `\n--- HEADERS ---\n${raw_truncated}\n`;
      }
      if (mode === "sections" || mode === "all") {
         const { raw_truncated } = await exec({tool: "readelf", target, args: ["-S", target], timeout});
         out += `\n--- SECTIONS ---\n${raw_truncated}\n`;
      }
      if (mode === "symbols" || mode === "all") {
         const { raw_truncated } = await exec({tool: "readelf", target, args: ["-s", target], timeout});
         out += `\n--- SYMBOLS ---\n${raw_truncated}\n`;
      }
      return { content: [{ type: "text", text: out.slice(0, 6000) }] }; // Simple truncate
    }
  );

  if (await isInstalled("ropper")) {
    server.tool(
      "ropper_find",
      "ROP gadget finder.",
      {
        target: TargetSchema,
        search: z.string().describe("Gadget to search (e.g. 'pop rdi')"),
        timeout: TimeoutSchema,
      },
      async ({ target, search, timeout }) => {
        appendToolRun(target, "ropper_find");
        const result = await exec({
          tool: "ropper",
          target,
          args: ["--file", target, "--search", search],
          timeout,
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("one_gadget")) {
    server.tool(
      "one_gadget_find",
      "Find one-shot RCE gadgets in libc.",
      {
        target: TargetSchema.describe("libc file path"),
        timeout: TimeoutSchema,
      },
      async ({ target, timeout }) => {
        appendToolRun(target, "one_gadget_find");
        const result = await exec({
          tool: "one_gadget",
          target,
          args: [target],
          timeout,
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }
}
