import type { Finding } from "../types.js";
import { parseNmap } from "./nmap.js";
import { parseNuclei } from "./nuclei.js";
import { parseFfuf } from "./ffuf.js";
import { parseNikto } from "./nikto.js";
import { parseSubfinder } from "./subfinder.js";
import { parseSqlmap } from "./sqlmap.js";

export type ParserFn = (raw: string) => { summary: string; findings: Finding[] };

/**
 * Map of tool binary name → parser function.
 * Used by executor.ts to auto-select the correct parser.
 */
export const parsers: Record<string, ParserFn> = {
  nmap:       parseNmap,
  nuclei:     parseNuclei,
  ffuf:       parseFfuf,
  nikto:      parseNikto,
  subfinder:  parseSubfinder,
  sqlmap:     parseSqlmap,
};

export {
  parseNmap,
  parseNuclei,
  parseFfuf,
  parseNikto,
  parseSubfinder,
  parseSqlmap,
};

/** Look up a parser by tool name, returns undefined if none registered. */
export function getParser(toolName: string): ParserFn | undefined {
  return parsers[toolName];
}
