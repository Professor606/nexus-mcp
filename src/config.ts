import { config as dotenvConfig } from 'dotenv';
import { resolve } from 'path';
import { existsSync } from 'fs';
import { homedir } from 'os';

export function loadConfig(): void {
  const paths = [
    process.env.NEXUS_CONFIG_DIR ? resolve(process.env.NEXUS_CONFIG_DIR, '.env') : null,
    resolve(homedir(), '.config', 'nexus-mcp', '.env'),
    resolve(process.cwd(), '.env'),
  ].filter(Boolean) as string[];

  for (const path of paths) {
    if (existsSync(path)) {
      dotenvConfig({ path, override: false });
      if (process.env.DEBUG === 'true') {
        console.error(`[nexus-mcp] Loaded env from ${path}`);
      }
      break;
    }
  }
}
