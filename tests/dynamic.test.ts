import { jest, describe, it, expect, beforeAll } from "@jest/globals";

// Mock the detection utility so all tools are considered "installed" for registration testing
jest.unstable_mockModule("../src/utils/detect.js", () => ({
  isInstalled: jest.fn().mockResolvedValue(true),
  detectAll: jest.fn(),
  filterInstalled: jest.fn(),
}));

// Mock the memory utility to avoid side effects
jest.unstable_mockModule("../src/memory.js", () => ({
  appendToolRun: jest.fn(),
  loadNote: jest.fn(),
  saveNote: jest.fn(),
  appendFinding: jest.fn(),
  appendFindings: jest.fn(),
  setPhase: jest.fn(),
  clearNote: jest.fn(),
  allTargets: jest.fn(),
  memoryStats: jest.fn(),
}));

// Dynamically import everything AFTER mocks are established
const { McpServer } = await import("@modelcontextprotocol/sdk/server/mcp.js");
const { PROFILES } = await import("../src/profiles.js");

const MODULES = [
  await import("../src/tools/recon.js"),
  await import("../src/tools/web.js"),
  await import("../src/tools/webattack.js"),
  await import("../src/tools/auth.js"),
  await import("../src/tools/network.js"),
  await import("../src/tools/binary.js"),
  await import("../src/tools/exploit.js"),
  await import("../src/tools/forensics.js"),
  await import("../src/tools/osint.js"),
  await import("../src/tools/cloud.js"),
  await import("../src/tools/meta.js"),
];

describe("Dynamic Tool Registry Validation", () => {
  const registeredTools = new Map<string, { description: string; schema: any }>();
  
  const mockServer = {
    tool: jest.fn((name: string, description: string, schema: any, handler: any) => {
      if (registeredTools.has(name)) {
        throw new Error(`Duplicate tool name detected: ${name}`);
      }
      registeredTools.set(name, { description, schema });
    }),
  } as unknown as typeof McpServer;

  beforeAll(async () => {
    // Register all tools from all modules
    for (const mod of MODULES) {
      if (typeof mod.register === "function") {
        await mod.register(mockServer);
      }
    }
  });

  it("should have registered at least one tool", () => {
    expect(registeredTools.size).toBeGreaterThan(0);
  });

  it("should have no duplicate tool names across all modules", () => {
    // The mockServer.tool implementation already throws on duplicates
    expect(true).toBe(true);
  });

  it("should ensure every tool listed in PROFILES is actually registered", () => {
    const profileTools = new Set<string>();
    Object.entries(PROFILES).forEach(([profile, tools]) => {
      // "full" profile is usually empty in the map as it's a special case in registry.ts
      if (Array.isArray(tools)) {
        tools.forEach((t: string) => profileTools.add(t));
      }
    });

    const missing = [...profileTools].filter(t => !registeredTools.has(t));
    expect(missing).toEqual([]);
  });

  it("should verify each registered tool has a valid description and schema", () => {
    for (const [name, { description, schema }] of registeredTools) {
      expect(description.length).toBeGreaterThan(10);
      expect(schema).toBeDefined();
      expect(typeof schema).toBe("object");
    }
  });

  it("should verify that 'switch_phase' is registered (core meta tool)", () => {
    expect(registeredTools.has("switch_phase")).toBe(true);
  });

  it("should verify that 'nmap_scan' is registered (core recon tool)", () => {
    expect(registeredTools.has("nmap_scan")).toBe(true);
  });
});
