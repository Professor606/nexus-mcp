import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec, readOutputFile } from "../executor.js";
import { isInstalled } from "../utils/detect.js";
import { appendToolRun } from "../memory.js";
import { TargetSchema, FlagsSchema, TimeoutSchema } from "../types.js";
import { resolveWordlist } from "../utils/wordlists.js";

export async function register(server: McpServer): Promise<void> {
  if (await isInstalled("hydra")) {
    server.tool(
      "hydra_crack",
      "Fast network logon cracker.",
      {
        target: TargetSchema,
        service: z.string().describe("Service to attack (e.g. ssh, ftp, http-post-form)"),
        username: z.string().optional().describe("Single username or -L path"),
        wordlist: z.string().optional().describe("Wordlist path or 'passwords'"),
        flags: FlagsSchema.default(""),
        timeout: TimeoutSchema,
      },
      async ({ target, service, username, wordlist, flags, timeout }) => {
        appendToolRun(target, "hydra_crack");
        const extraFlags = flags.split(" ").filter(Boolean);
        const args = [];
        if (username) {
            args.push(username.startsWith("/") ? "-L" : "-l", username);
        }
        const wlPath = wordlist === "passwords" ? resolveWordlist("passwords") : (wordlist || resolveWordlist("passwords"));
        if (wlPath) {
            args.push("-P", wlPath);
        }
        args.push(...extraFlags, target, service);

        const result = await exec({
          tool: "hydra",
          target,
          args,
          timeout,
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("hashcat")) {
    server.tool(
      "hashcat_crack",
      "Advanced password recovery utility.",
      {
        target: TargetSchema.describe("Hash string or file containing hashes"),
        mode: z.string().describe("Hash type mode (e.g. 0 for MD5, 1000 for NTLM)"),
        wordlist: z.string().optional().describe("Wordlist path or 'passwords'"),
        flags: FlagsSchema.default(""),
        timeout: TimeoutSchema,
      },
      async ({ target, mode, wordlist, flags, timeout }) => {
        appendToolRun(target, "hashcat_crack");
        const extraFlags = flags.split(" ").filter(Boolean);
        const wlPath = wordlist === "passwords" ? resolveWordlist("passwords") : (wordlist || resolveWordlist("passwords"));
        
        // Auto-detect OpenCL device type (1=CPU, 2=GPU). Best effort via flags:
        if (!extraFlags.some(f => f.includes("opencl"))) {
           extraFlags.push("--opencl-device-types", "1,2");
        }

        const args = ["-m", mode, ...extraFlags, target];
        if (wlPath) {
            args.push(wlPath);
        }

        const result = await exec({
          tool: "hashcat",
          target,
          args,
          timeout,
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("john")) {
    server.tool(
      "john_crack",
      "John the Ripper password cracker.",
      {
        target: TargetSchema.describe("File containing hashes"),
        wordlist: z.string().optional().describe("Wordlist path or 'passwords'"),
        flags: FlagsSchema.default(""),
        timeout: TimeoutSchema,
      },
      async ({ target, wordlist, flags, timeout }) => {
        appendToolRun(target, "john_crack");
        const extraFlags = flags.split(" ").filter(Boolean);
        const wlPath = wordlist === "passwords" ? resolveWordlist("passwords") : (wordlist || resolveWordlist("passwords"));
        
        const args = [...extraFlags];
        if (wlPath) {
            args.push(`--wordlist=${wlPath}`);
        }
        args.push(target);

        const result = await exec({
          tool: "john",
          target,
          args,
          timeout,
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("hashid")) {
    server.tool(
      "hashid_identify",
      "Identify the different types of hashes.",
      {
        target: TargetSchema.describe("Hash string"),
        flags: FlagsSchema.default("-j"),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "hashid_identify");
        const extraFlags = flags.split(" ").filter(Boolean);
        const result = await exec({
          tool: "hashid",
          target,
          args: [...extraFlags, target],
          timeout,
        });
        
        try {
           const arr = JSON.parse(result.raw_truncated);
           if (Array.isArray(arr) && arr.length > 0) {
              result.findings = arr[0].types.map((t: any) => ({
                 type: "hash_type",
                 value: t.name,
                 detail: target.slice(0, 10) + "...",
                 severity: "info"
              }));
              result.summary = `Identified ${arr[0].types.length} possible hash types`;
           }
        } catch { /* ignore */ }

        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("evil-winrm")) {
    server.tool(
      "evil_winrm_shell",
      "WinRM shell for pentesting.",
      {
        target: TargetSchema,
        user: z.string().describe("Username"),
        password: z.string().optional().describe("Password"),
        hash: z.string().optional().describe("NTLM hash"),
        flags: FlagsSchema.default(""),
        timeout: TimeoutSchema,
      },
      async ({ target, user, password, hash, flags, timeout }) => {
        appendToolRun(target, "evil_winrm_shell");
        const extraFlags = flags.split(" ").filter(Boolean);
        const args = ["-i", target, "-u", user, ...extraFlags];
        if (password) args.push("-p", password);
        if (hash) args.push("-H", hash);

        const result = await exec({
          tool: "evil-winrm",
          target,
          args,
          timeout,
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }
}
