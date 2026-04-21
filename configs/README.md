# Nexus MCP Configuration Guide

This directory contains configuration snippets for various MCP-compatible clients. To use Nexus MCP, copy the relevant configuration to your client's settings.

## 🛠️ Configuration Files

### [Claude Desktop](claude_desktop.json)
- **Path (macOS):** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Path (Windows):** `%APPDATA%\Claude\claude_desktop_config.json`
- **Action:** Copy the `mcpServers` block into your config file.

### [Cursor IDE](cursor.json)
- **Settings:** `Cursor Settings` > `Features` > `MCP Servers`
- **Action:** Add a new server with the command and arguments provided in the JSON file.

### [VS Code Copilot](vscode_copilot.json)
- **Settings:** `settings.json`
- **Action:** Add the configuration to the `github.copilot.chat.mcpServers` array.

### [Roo Code](roo_code.json)
- **Path:** `~/.vscode/extensions/roovet.roo-code-xxx/settings/cline_mcp_settings.json` (or via the UI)
- **Action:** Use the provided JSON to register the server.

### [Antigravity IDE](antigravity.json)
- **Action:** Use this configuration to connect Antigravity to the Nexus MCP server.

### Auto-Discovery (Recommended)
Nexus MCP automatically looks for `.env` files in:
1. `$NEXUS_CONFIG_DIR/.env`
2. `~/.config/nexus-mcp/.env` (XDG compliant)
3. `./.env` (Project local)

Storing your keys in `~/.config/nexus-mcp/.env` allows you to keep your client configuration files (`claude_desktop_config.json`, etc.) minimal and clean.

### Client-Specific (JSON Env)
If you prefer, you can still define environment variables directly in your client's configuration file. Inline `env` variables will **override** values found in `.env` files.

Replace `"your_key_here"` with your actual API keys if using this method.

## 🚀 Profiles

The default configuration uses the `--profile full` argument. You can change this to one of the following:
- `recon`: Reconnaissance focused.
- `web`: Web application security focused.
- `network`: Network security focused.
- `ctf`: Capture The Flag focused.
- `cloud`: Cloud security focused.
- `osint`: Open Source Intelligence focused.
- `bugbounty`: Bug Bounty hunting focused.
