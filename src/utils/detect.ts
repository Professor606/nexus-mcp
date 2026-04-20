import { execa } from "execa";

// ── In-memory cache ───────────────────────────────────────────────────────────

const cache = new Map<string, boolean>();

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Check if a binary is available on $PATH.
 * Results are cached for the lifetime of the process.
 */
export async function isInstalled(tool: string): Promise<boolean> {
  if (cache.has(tool)) return cache.get(tool)!;
  try {
    await execa("which", [tool], { reject: true });
    cache.set(tool, true);
    return true;
  } catch {
    cache.set(tool, false);
    return false;
  }
}

/**
 * Check multiple tools in parallel.
 * Returns a map of { toolName → installed }.
 */
export async function detectAll(
  tools: string[]
): Promise<Record<string, boolean>> {
  const entries = await Promise.all(
    tools.map(async (t) => [t, await isInstalled(t)] as const)
  );
  return Object.fromEntries(entries);
}

/**
 * Return only the tools from the list that are installed.
 */
export async function filterInstalled(tools: string[]): Promise<string[]> {
  const results = await detectAll(tools);
  return tools.filter((t) => results[t]);
}
