import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { PROFILES } from "./profiles.js";
import type { Profile } from "./types.js";

import * as recon from "./tools/recon.js";
import * as web from "./tools/web.js";
import * as webattack from "./tools/webattack.js";
import * as auth from "./tools/auth.js";
import * as network from "./tools/network.js";
import * as binary from "./tools/binary.js";
import * as exploit from "./tools/exploit.js";
import * as forensics from "./tools/forensics.js";
import * as osint from "./tools/osint.js";
import * as cloud from "./tools/cloud.js";
import * as meta from "./tools/meta.js";

const MODULES = [recon, web, webattack, auth, network, binary, exploit, forensics, osint, cloud, meta];

let activeProfile: Profile = "recon";

export function getActiveProfile(): Profile {
  return activeProfile;
}

export function setActiveProfile(p: Profile): void {
  activeProfile = p;
}

/**
 * Registers ALL tools from all modules at startup.
 * The MCP SDK doesn't support unregistering tools or hot-swapping schemas after connect.
 * We register everything, and the LLM can use `switch_phase` to logically shift context,
 * though we don't strictly hide them from the protocol because of SDK limitations.
 * Wait, we CAN filter the tools if we intercept the server request handler, but McpServer abstraction
 * handles `tools/list` internally. The blueprint noted this in the Implementation Plan: 
 * "We register all tools, switch_phase updates context". Let's stick to that simple approach for stability.
 */
export async function registerAll(server: McpServer, initialProfile: Profile): Promise<void> {
  activeProfile = initialProfile;

  // Register all modules. Each module checks isInstalled() internally and skips missing tools.
  await Promise.all(MODULES.map(m => m.register(server)));

  if (process.env.DEBUG === "true") {
      console.error(`[nexus-mcp] Registered all available tools. Initial profile context: ${initialProfile}`);
  }
}
