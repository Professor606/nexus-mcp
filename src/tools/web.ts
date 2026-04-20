import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec, readOutputFile } from "../executor.js";
import { isInstalled } from "../utils/detect.js";
import { appendToolRun } from "../memory.js";
import { getParser } from "../parsers/index.js";
import { TargetSchema, SafeFlagsSchema, TimeoutSchema } from "../types.js";
import { resolveWordlist } from "../utils/wordlists.js";

export async function register(server: McpServer): Promise<void> {
  if (await isInstalled("ffuf")) {
    server.tool(
      "ffuf_scan",
      "Fast web fuzzer for directory and file discovery.",
      {
        target: TargetSchema.describe("Target URL with FUZZ keyword, e.g. http://x/FUZZ"),
        wordlist: z.string().optional().describe("Wordlist path or 'common'/'big'"),
        flags: SafeFlagsSchema,
        timeout: TimeoutSchema,
      },
      async ({ target, wordlist, flags, timeout }) => {
        appendToolRun(target, "ffuf_scan");
        const wlPath = wordlist === "common" || wordlist === "big" 
          ? resolveWordlist(wordlist) 
          : (wordlist || resolveWordlist("common"));

        const outPath = `/tmp/nexus-mcp/ffuf_${Date.now()}.json`;

        const result = await exec({
          tool: "ffuf",
          target,
          args: ["-w", wlPath, "-u", target, "-of", "json", "-o", outPath, ...flags],
          timeout,
        });

        const jsonRaw = await readOutputFile(outPath);
        const parseFn = getParser("ffuf");
        if (parseFn && jsonRaw) {
          const parsed = parseFn(jsonRaw);
          result.findings = parsed.findings;
          result.summary = parsed.summary;
        }

        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("feroxbuster")) {
    server.tool(
      "feroxbuster_scan",
      "Fast, simple, recursive content discovery.",
      {
        target: TargetSchema,
        flags: SafeFlagsSchema,
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "feroxbuster_scan");
        const outPath = `/tmp/nexus-mcp/ferox_${Date.now()}.json`;
        const result = await exec({
          tool: "feroxbuster",
          target,
          args: ["--url", target, "--json", "-o", outPath, ...flags],
          timeout,
        });

        // Simple JSON parsing since no dedicated parser was requested in blueprint
        const jsonRaw = await readOutputFile(outPath);
        if (jsonRaw) {
            const lines = jsonRaw.split('\n').filter(Boolean);
            result.findings = lines.map((l: string) => {
               try {
                 const obj = JSON.parse(l);
                 return { type: "path", value: obj.url, severity: "info", metadata: obj };
               } catch { return null; }
            }).filter((x: any): x is any => x !== null);
            result.summary = `Feroxbuster found ${result.findings.length} items`;
        }

        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("httpx")) {
    server.tool(
      "httpx_probe",
      "Fast HTTP prober and tech detection.",
      {
        target: TargetSchema,
        flags: SafeFlagsSchema.default(["-tech-detect", "-status-code", "-title"]),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "httpx_probe");
        const outPath = `/tmp/nexus-mcp/httpx_${Date.now()}.json`;
        const result = await exec({
          tool: "httpx",
          target,
          // Support multiple targets if passed in a file or string? Let's just use -u for single
          args: ["-u", target, "-json", "-o", outPath, ...flags],
          timeout,
        });

        const jsonRaw = await readOutputFile(outPath);
        if (jsonRaw) {
             const lines = jsonRaw.split('\n').filter(Boolean);
             result.findings = lines.map((l: string) => {
               try {
                 const obj = JSON.parse(l);
                 return { type: "http_probe", value: obj.url, detail: `status:${obj["status_code"]} title:${obj.title}`, severity: "info", metadata: obj };
               } catch { return null; }
             }).filter((x: any): x is any => x !== null);
             result.summary = `httpx probed ${result.findings.length} endpoints`;
        }
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("katana")) {
    server.tool(
      "katana_crawl",
      "Next-generation crawling and spidering framework.",
      {
        target: TargetSchema,
        depth: z.number().int().default(3).describe("Crawl depth"),
        flags: SafeFlagsSchema,
        timeout: TimeoutSchema,
      },
      async ({ target, depth, flags, timeout }) => {
        appendToolRun(target, "katana_crawl");
        const outPath = `/tmp/nexus-mcp/katana_${Date.now()}.json`;
        const result = await exec({
          tool: "katana",
          target,
          args: ["-u", target, "-d", depth.toString(), "-json", "-o", outPath, ...flags],
          timeout,
        });

        const jsonRaw = await readOutputFile(outPath);
        if (jsonRaw) {
             const lines = jsonRaw.split('\n').filter(Boolean);
             result.findings = lines.map((l: string) => {
               try {
                 const obj = JSON.parse(l);
                 return { type: "url", value: obj.request?.endpoint || obj.endpoint, severity: "info", metadata: obj };
               } catch { return null; }
             }).filter((x: any): x is any => x !== null);
             result.summary = `Katana crawled ${result.findings.length} URLs`;
        }

        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("gau")) {
    server.tool(
      "gau_urls",
      "Fetch known URLs from AlienVault, wayback, etc.",
      {
        target: TargetSchema,
        flags: SafeFlagsSchema,
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "gau_urls");
        const outPath = `/tmp/nexus-mcp/gau_${Date.now()}.txt`;
        const result = await exec({
          tool: "gau",
          target,
          args: [target, "--o", outPath, ...flags],
          timeout,
        });

        const textRaw = await readOutputFile(outPath);
        if (textRaw) {
            const urls = textRaw.split('\n').filter(Boolean);
            result.findings = urls.map((u: string) => ({ type: "url", value: u, severity: "info" }));
            result.summary = `gau found ${urls.length} URLs`;
        }

        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("nuclei")) {
    server.tool(
      "nuclei_scan",
      "Fast and customizable vulnerability scanner.",
      {
        target: TargetSchema,
        flags: SafeFlagsSchema.default(["-as"]),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "nuclei_scan");
        const outPath = `/tmp/nexus-mcp/nuclei_${Date.now()}.json`;
        const result = await exec({
          tool: "nuclei",
          target,
          args: ["-u", target, "-j", "-o", outPath, ...flags],
          timeout,
        });

        const jsonRaw = await readOutputFile(outPath);
        const parseFn = getParser("nuclei");
        if (parseFn && jsonRaw) {
            const parsed = parseFn(jsonRaw);
            result.findings = parsed.findings;
            result.summary = parsed.summary;
        }

        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("nikto")) {
    server.tool(
      "nikto_scan",
      "Web server scanner for vulnerabilities.",
      {
        target: TargetSchema,
        flags: SafeFlagsSchema,
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "nikto_scan");
        // Note: Nikto's plain text output is parsed by parseNikto, no need for file output if we capture stdout,
        // but blueprint says "-h target -o /tmp/nexus-mcp/nikto_out.txt". Let's capture stdout instead so we don't need readOutputFile, unless it bypasses stdout.
        // Usually Nikto writes to stdout. We'll use stdout.
        const result = await exec({
          tool: "nikto",
          target,
          args: ["-h", target, ...flags],
          timeout,
          parse: getParser("nikto"),
        });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("whatweb")) {
    server.tool(
      "whatweb_detect",
      "Next generation web scanner (tech detection).",
      {
        target: TargetSchema,
        flags: SafeFlagsSchema,
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "whatweb_detect");
        const result = await exec({
          tool: "whatweb",
          target,
          // WhatWeb can output JSON to stdout with --log-json=- 
          args: ["--log-json=-", ...flags, target],
          timeout,
        });

        try {
            const arr = JSON.parse(result.raw_truncated);
            if (Array.isArray(arr) && arr.length > 0) {
               const plugins = arr[0].plugins;
               result.findings = Object.keys(plugins).map(k => ({
                   type: "tech",
                   value: k,
                   detail: plugins[k].string?.join(", ") || plugins[k].version?.join(", ") || "",
                   severity: "info"
               }));
               result.summary = `WhatWeb found ${result.findings.length} technologies`;
            }
        } catch { /* ignore */ }

        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("wafw00f")) {
    server.tool(
      "wafw00f_detect",
      "Identify and fingerprint Web Application Firewalls.",
      {
        target: TargetSchema,
        flags: SafeFlagsSchema.default(["-a"]),
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "wafw00f_detect");
        const outPath = `/tmp/nexus-mcp/wafw00f_${Date.now()}.json`;
        const result = await exec({
          tool: "wafw00f",
          target,
          args: [...flags, "-o", outPath, target],
          timeout,
        });

        const jsonRaw = await readOutputFile(outPath);
        if (jsonRaw) {
             try {
                 const arr = JSON.parse(jsonRaw);
                 if (Array.isArray(arr) && arr.length > 0) {
                     result.findings = arr.map((x: any) => ({
                         type: "waf",
                         value: x.firewall,
                         detail: x.manufacturer,
                         severity: "info"
                     }));
                     result.summary = `wafw00f detected WAF: ${arr[0].firewall}`;
                 }
             } catch { /* ignore */ }
        }

        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }

  if (await isInstalled("testssl")) {
    server.tool(
      "testssl_scan",
      "Check TLS/SSL cipher, protocols and vulnerabilities.",
      {
        target: TargetSchema,
        flags: SafeFlagsSchema,
        timeout: TimeoutSchema,
      },
      async ({ target, flags, timeout }) => {
        appendToolRun(target, "testssl_scan");
        const outPath = `/tmp/nexus-mcp/testssl_${Date.now()}.json`;
        const result = await exec({
          tool: "testssl",
          target,
          args: ["--jsonfile", outPath, ...flags, target],
          timeout,
        });

        const jsonRaw = await readOutputFile(outPath);
        if (jsonRaw) {
             try {
                 const arr = JSON.parse(jsonRaw);
                 result.findings = arr.filter((x:any) => x.severity === "HIGH" || x.severity === "CRITICAL").map((x: any) => ({
                     type: "ssl_vuln",
                     value: x.id,
                     detail: x.finding,
                     severity: x.severity === "CRITICAL" ? "critical" : "high"
                 }));
                 result.summary = `testssl found ${result.findings.length} high/critical issues`;
             } catch { /* ignore */ }
        }

        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
    );
  }
}