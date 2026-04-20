# Nexus MCP

Nexus MCP is a high-performance stdio Model Context Protocol (MCP) server specifically designed for penetration testing, bug bounty hunting, and security assessments. It exposes a vast array of security tools and capabilities directly to AI assistants like Claude Desktop, enabling seamless, AI-assisted security workflows.

> **⚠️ Security Notice: Exploit tools are disabled by default.**
>
> Tools such as `pwntools_run`, `angr_analyze`, and `libc_database_lookup` execute
> user-controlled Python code and carry significant RCE risk. They require explicit
> opt-in via the `--enable-exploit` CLI flag or the `NEXUS_ENABLE_EXPLOIT=true`
> environment variable. When enabled, all user-provided Python scripts are scanned
> for dangerous imports (e.g. `os`, `subprocess`, `socket`), function calls
> (e.g. `eval`, `exec`, `os.system`), network operations, and file-system access
> outside `/tmp/nexus-mcp` before execution.

## 🚀 Features

Nexus MCP categorizes its capabilities into different toolsets and allows loading specific **Profiles** to tailor the AI's context window and available tools based on the task at hand.

### Supported Profiles
When starting the server, you can load specific profiles to narrow down or expand the available tools:
- `recon`: Reconnaissance and discovery tools.
- `web`: Web application assessment tools.
- `ctf`: Tools tailored for Capture The Flag competitions.
- `bugbounty`: A curated set of tools for bug bounty hunting.
- `cloud`: Cloud security assessment tools.
- `osint`: Open Source Intelligence gathering.
- `network`: Network-level assessment tools.
- `full`: Loads all available capabilities.

### Tool Categories
- **Reconnaissance** (`recon`): Asset discovery, port scanning, and topology mapping.
- **Web Application & Web Attack** (`web`, `webattack`): Directory fuzzing, vulnerability scanning, SQLi, XSS, and more.
- **Network** (`network`): Packet analysis, network sniffing, and protocol testing.
- **Exploitation** (`exploit`): Exploit search, payload generation, and execution assistance.
- **Cloud** (`cloud`): Cloud enumeration, IAM checking, and misconfiguration scanning.
- **OSINT** (`osint`): Threat intelligence, public records, and metadata extraction.
- **Binary Analysis** (`binary`): Disassembly, static analysis, and reverse engineering.
- **Forensics** (`forensics`): Artifact analysis, memory parsing, and disk investigation.
- **Authentication** (`auth`): Brute-forcing, hash cracking, and credential testing.
- **Meta** (`meta`): General utility functions and meta commands.

## 🛠️ Setup Instructions

### Prerequisites
- [Node.js](https://nodejs.org/) (v18 or higher recommended)
- `npm` (Node Package Manager)

### Installation
1. Clone the repository and navigate to the project directory:
   ```bash
   git clone https://github.com/professor404/nexus-mcp.git
   cd nexus-mcp
   ```

2. Install the dependencies:
  ```bash
  npm install
  ```

3. Setup environment variables:
```bash
cp .env.example .env
```

3. Edit .env to configure any API keys or specific configuration needed for the tools. Key environment variables include:

```
API Keys: SHODAN_API_KEY, SPIDERFOOT_API_KEY, WPSCAN_API_TOKEN
Cache: CACHE_TTL_SECONDS (Cache identical tool results, default: 3600)
Concurrency: MAX_CONCURRENCY (Max parallel subprocesses, default: 4)
Debug: DEBUG (Set to true to enable verbose stderr logging)
Output: NEXUS_OUTPUT_DIR (Custom directory for tool outputs)
Exploit Tools: NEXUS_ENABLE_EXPLOIT (Set to true to enable pwntools_run, angr_analyze, and libc_database_lookup)
```

Build the project:
```bash
npm run build
```

💻 Usage
Running Locally (Development)
You can start specific profiles directly using npm scripts defined in package.json:
```bash
npm run start:recon
npm run start:web
npm run start:full
```

To enable exploit tools (e.g. for CTF or binary-analysis workflows), add the --enable-exploit flag:
```bash
node dist/index.js --profile ctf --enable-exploit
```

Environment Variables
```
NEXUS_OUTPUT_DIR: The directory where the server will drop output files (defaults to /tmp/nexus-mcp).
CACHE_TTL_SECONDS: Caching time-to-live for tool results (defaults to 3600).
DEBUG: Set to true to enable verbose logging.
NEXUS_ENABLE_EXPLOIT: Set to true to enable exploit tools (pwntools_run, angr_analyze, libc_database_lookup). Use with caution — these tools execute
```
Python code and are gated behind AST-based validation.
Integrating with Claude Desktop
To use Nexus MCP with Claude Desktop, you need to add it to your claude_desktop_config.json file.
Open your Claude Desktop configuration file (usually located at ~/.config/Claude/claude_desktop_config.json on Linux/macOS or %APPDATA%\Claude\claude_desktop_config.json on Windows).
Add the nexus server configuration, pointing it to your built dist/index.js file:
```JSON

{
  "mcpServers": {
    "nexus": {
      "command": "node",
      "args": [
        "/absolute/path/to/nexus-mcp/dist/index.js",
        "--profile",
        "full"
      ],
      "env": {
        "NEXUS_OUTPUT_DIR": "/tmp/nexus-mcp",
        "CACHE_TTL_SECONDS": "3600"
      }
    }
  }
}
```

(Make sure to replace /absolute/path/to/nexus-mcp/ with the actual absolute path to the directory where this project resides.)
To enable exploit tools in Claude Desktop, add "--enable-exploit" to the args array or set NEXUS_ENABLE_EXPLOIT: "true" in the env block.
Once configured, restart Claude Desktop. The tools will now be available in your chats when discussing security and penetration testing.
Integrating with Antigravity
Antigravity natively supports MCP servers using a standard JSON configuration.
Open your Antigravity MCP configuration file located at ~/.gemini/antigravity/mcp_config.json.
Add the server configuration to the file:
```JSON

{
  "mcpServers": {
    "nexus": {
      "command": "node",
      "args": [
        "/absolute/path/to/nexus-mcp/dist/index.js",
        "--profile",
        "full"
      ],
      "env": {
        "NEXUS_OUTPUT_DIR": "/tmp/nexus-mcp",
        "CACHE_TTL_SECONDS": "3600"
      }
    }
  }
}
```
Once the file is saved, Antigravity will automatically detect the new configuration and initialize the Nexus tools for your session.
