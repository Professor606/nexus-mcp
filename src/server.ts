import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerAll } from "./registry.js";
import type { Profile } from "./types.js";

export async function createServer(profile: Profile): Promise<McpServer> {
  const server = new McpServer({
    name: "nexus-mcp",
    version: "1.0.0",
  });

  await registerAll(server, profile);

  return server;
}
