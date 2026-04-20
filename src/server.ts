import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { registerAll, getActiveProfile, isToolAllowed } from "./registry.js";
import type { Profile } from "./types.js";

export async function createServer(profile: Profile): Promise<McpServer> {
  const server = new McpServer({
    name: "nexus-mcp",
    version: "1.0.0",
  });

  await registerAll(server, profile);

  // Intercept tools/list to filter by active profile
  const originalListHandler = (server.server as any)._requestHandlers["tools/list"];
  if (originalListHandler) {
    server.server.setRequestHandler(ListToolsRequestSchema, async (request, extra) => {
      const response = await originalListHandler(request, extra);
      const activeProfile = getActiveProfile();
      if (activeProfile !== "full" && response.tools) {
        response.tools = response.tools.filter((t: any) => isToolAllowed(t.name, activeProfile));
      }
      return response;
    });
  }

  // Intercept tools/call to enforce profile filtering at execution time
  const originalCallHandler = (server.server as any)._requestHandlers["tools/call"];
  if (originalCallHandler) {
    server.server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
      const activeProfile = getActiveProfile();
      const toolName = request.params.name;
      
      if (!isToolAllowed(toolName, activeProfile)) {
        throw new Error(`Tool ${toolName} not available in ${activeProfile} profile. Switch to full profile or appropriate profile using switch_phase.`);
      }
      
      return await originalCallHandler(request, extra);
    });
  }

  return server;
}
