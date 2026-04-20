import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec, readOutputFile } from "../executor.js";
import { isInstalled } from "../utils/detect.js";
import { appendToolRun } from "../memory.js";
import { TargetSchema, SafeFlagsSchema, TimeoutSchema, validatePath } from "../types.js";
import { resolveWordlist, ALLOWED_WORDLIST_ROOTS } from "../utils/wordlists.js";
import { forceSafeJson } from "../utils/clean.js";

/** Helper to build a path-rejection ToolResult */
function pathRejection(tool: string, target: string, path: string): any {
  return {
    tool,
    target,
    summary: `Rejected unsafe path: ${path}`,
    findings: [],
    severity: "info" as const,
    cached: false,
    duration_ms: 0,
    raw_truncated: "",
    error: `Path sandboxing rejected: ${path} is outside allowed directories.`,
  };
}

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
        flags: SafeFlagsSchema,
        timeout: TimeoutSchema,
      },
      async ({ target, service, username, wordlist, flags, timeout }) => {
        appendToolRun(target, "hydra_crack");
        const args = [];
        if (username) {
            args.push(username.startsWith("/") ? "-L" : "-l", username);
        }
        const wlPath = wordlist === "passwords" ? resolveWordlist("passwords") : (wordlist ? resolveWordlist(wordlist) : resolveWordlist("passwords"));
        if (wordlist && !wlPath) {
          return { content: [{ type: "text", text: forceSafeJson(pathRejection("hydra", target, wordlist), null, 2) }] };
        }
        if (wlPath) {
            args.push("-P", wlPath);
        }
        args.push(...flags, target, service);

        const result = await exec({
          tool: "hydra",
          target,
          args,
          timeout,
        });
        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
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
        flags: SafeFlagsSchema,
        timeout: TimeoutSchema,
      },
      async ({ target, mode, wordlist, flags, timeout }) => {
        appendToolRun(target, "hashcat_crack");
        const extraFlags = [...flags];

        if (!extraFlags.some(f => f.includes("opencl"))) {
           extraFlags.push("--opencl-device-types", "1,2");
        }

        const wlPath = wordlist === "passwords" ? resolveWordlist("passwords") : (wordlist ? resolveWordlist(wordlist) : resolveWordlist("passwords"));
        if (wordlist && !wlPath) {
          return { content: [{ type: "text", text: forceSafeJson(pathRejection("hashcat", target, wordlist), null, 2) }] };
        }

        // Validate target if it looks like a file path (not a hash string)
        let safeTarget = target;
        if (target.startsWith("/") || target.includes("..")) {
          const validated = validatePath(target, ALLOWED_WORDLIST_ROOTS);
          if (!validated) {
            return { content: [{ type: "text", text: forceSafeJson(pathRejection("hashcat", target, target), null, 2) }] };
          }
          safeTarget = validated;
        }

        const args = ["-m", mode, ...extraFlags, safeTarget];
        if (wlPath) {
            args.push(wlPath);
        }

        const result = await exec({
          tool: "hashcat",
          target,
          args,
          timeout,
        });
        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
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
        flags: SafeFlagsSchema,
        timeout: TimeoutSchema,
      },
      async ({ target, wordlist, flags, timeout }) => {
        appendToolRun(target, "john_crack");
        const wlPath = wordlist === "passwords" ? resolveWordlist("passwords") : (wordlist ? resolveWordlist(wordlist) : resolveWordlist("passwords"));
        if (wordlist && !wlPath) {
          return { content: [{ type: "text", text: forceSafeJson(pathRejection("john", target, wordlist), null, 2) }] };
        }

        // Validate target file path
        const validatedTarget = validatePath(target, ALLOWED_WORDLIST_ROOTS);
        if (!validatedTarget) {
          return { content: [{ type: "text", text: forceSafeJson(pathRejection("john", target, target), null, 2) }] };
        }

        const args = [...flags];
        if (wlPath) {
            args.push(`--wordlist=${wlPath}`);
        }
        args.push(validatedTarget);

        const result = await exec({
          tool: "john",
          target,
          args,
          timeout,
        });
        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("hashid")) {
    server.tool(
      "hashid_identify",
      "Identify the different types of hashes.",
      {
        target: TargetSchema.describe("Hash string"),
        flags: SafeFlagsSchema.default(["-j"]),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "hashid_identify");
        const result = await exec({
          tool: "hashid",
          target,
          args: [...flags, target],
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

        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
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
        flags: SafeFlagsSchema,
        timeout: TimeoutSchema,
      },
      async ({ target, user, password, hash, flags, timeout }) => {
        appendToolRun(target, "evil_winrm_shell");
        const args = ["-i", target, "-u", user, ...flags];
        if (password) args.push("-p", password);
        if (hash) args.push("-H", hash);

        const result = await exec({
          tool: "evil-winrm",
          target,
          args,
          timeout,
        });
        return { content: [{ type: "text", text: forceSafeJson(result, null, 2) }] };
      }
    );
  }
}
