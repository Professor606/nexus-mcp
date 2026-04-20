import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer } from "./server.js";
import { parseArgs } from "node:util";
import { config } from "dotenv";
import type { Profile } from "./types.js";
import fs from "node:fs";

// Load .env variables
config();

// Parse CLI arguments
const { values } = parseArgs({
  options: {
    profile: { type: "string", short: "p", default: "recon" },
    "cache-ttl": { type: "string", default: "3600" },
    debug: { type: "boolean", default: false },
    "enable-exploit": { type: "boolean", default: false },
  },
  strict: false,
});

const profile = (values.profile ?? "recon") as Profile;

if (values.debug) {
  process.env.DEBUG = "true";
  console.error(`[nexus-mcp] Debug mode ON`);
}

if (values["enable-exploit"]) {
  process.env.NEXUS_ENABLE_EXPLOIT = "true";
  console.error(`[nexus-mcp] Exploit tools ENABLED (pwntools_run, angr_analyze, libc_database_lookup)`);
}

process.env.CACHE_TTL_SECONDS = values["cache-ttl"] as string;

// Bootstrap output directory
const outDir = process.env.NEXUS_OUTPUT_DIR || "/tmp/nexus-mcp";
try {
  fs.mkdirSync(outDir, { recursive: true });
} catch (e) {
  console.error(`[nexus-mcp] Warning: Could not create output dir ${outDir}:`, e);
}

// Create and connect server
const server = await createServer(profile);
const transport = new StdioServerTransport();

await server.connect(transport);

console.error(`[nexus-mcp] Connected via stdio. Context Profile: ${profile}`);
console.error(`[nexus-mcp] Output dir: ${outDir}`);
