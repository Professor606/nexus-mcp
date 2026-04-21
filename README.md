# 🛡️ Nexus MCP

**Nexus MCP** is a high-performance, token-efficient Model Context Protocol (MCP) server engineered for the modern security professional. Optimized for speed and precision, it transforms AI assistants like Claude Desktop into powerful partners for penetration testing, bug bounty hunting, and comprehensive security assessments.

Nexus MCP bridges the gap between raw security tools and AI-driven logic, providing a seamless interface to a vast arsenal of industry-standard utilities.

---

> [!CAUTION]
> ### 🚨 Security Notice: Exploit Tools Disabled by Default
> Tools such as `pwntools_run`, `angr_analyze`, and `libc_database_lookup` carry significant RCE risk as they execute user-controlled code.
> 
> **Explicit Opt-in Required:**
> - CLI Flag: `--enable-exploit`
> - Environment: `NEXUS_ENABLE_EXPLOIT=true`
> 
> When enabled, scripts are scanned via AST-based validation for dangerous operations (e.g., `os.system`, `subprocess`, unauthorized network/FS access) before execution.

---

## 🚀 Key Features

- **Profile-Based Toolsets**: Dynamically switch between specialized toolsets to keep the AI's context window lean and focused.
- **Smart Chaining**: Execute complex multi-tool workflows where findings from one tool automatically inform the next.
- **AI-Driven Suggestions**: Get context-aware recommendations for next steps based on current findings.
- **Structured Note-taking**: Built-in persistence for findings, ensuring no evidence is lost during a session.
- **High Concurrency**: Optimized subprocess management for fast, parallel execution of network scans and fuzzing.

---

## 📂 Tool Profiles

Profiles allow you to tailor the available tools to your specific task, reducing noise and optimizing token usage. You can switch profiles mid-session using the `switch_phase` tool.

| Profile | Focus Area | Key Tools |
| :--- | :--- | :--- |
| `recon` | Discovery & Mapping | `nmap`, `subfinder`, `amass`, `rustscan` |
| `web` | Web App Security | `ffuf`, `nuclei`, `katana`, `sqlmap`, `dalfox` |
| `network` | Infrastructure | `netexec`, `enum4linux-ng`, `responder`, `hydra` |
| `osint` | Intelligence | `theHarvester`, `sherlock`, `spiderfoot`, `shodan` |
| `binary` | Reverse Engineering | `gdb`, `radare2`, `ghidra`, `checksec`, `ropper` |
| `cloud` | Cloud Security | `prowler`, `trivy`, `pacu`, `kube-hunter` |
| `ctf` | Capture The Flag | `pwntools`, `angr`, `zsteg`, `stegsolve`, `hashcat` |
| `full` | Complete Arsenal | All tools enabled (use with high context limits) |

---

## 🛠️ Setup & Installation

### Prerequisites
- **Node.js**: v18.0.0 or higher
- **Python 3.10+**: (Required for exploit and OSINT tools)
- **Go**: (Required for many ProjectDiscovery tools like `nuclei`, `subfinder`)

### Quick Start
1. **Clone & Install**
   ```bash
   git clone https://github.com/professor404/nexus-mcp.git
   cd nexus-mcp
   npm install
   ```

2. **Configure Environment**
   Nexus MCP automatically looks for `.env` files in these locations:
   1. `$NEXUS_CONFIG_DIR/.env`
   2. `~/.config/nexus-mcp/.env` (Recommended for global keys)
   3. `./.env` (Project local)

   ```bash
   mkdir -p ~/.config/nexus-mcp
   cp .env.example ~/.config/nexus-mcp/.env
   # Edit with your API keys (Shodan, Hunter.io, etc.)
   ```

3. **Build & Run**
   ```bash
   npm run build
   npm run start:full
   ```

---

## 💻 Integration

### Claude Desktop
Add Nexus to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "nexus": {
      "command": "node",
      "args": ["/path/to/nexus-mcp/dist/index.js", "--profile", "full"]
    }
  }
}
```
*Note: Environment variables in the `env` block are optional if you use a `.env` file.*

### Antigravity
Add to your `mcp_config.json`:

```json
{
  "mcpServers": {
    "nexus": {
      "command": "node",
      "args": ["/path/to/nexus-mcp/dist/index.js", "--profile", "full"]
    }
  }
}
```

---

## ⚙️ Configuration Priority

Nexus MCP resolves configuration settings using the following hierarchy (highest to lowest):

1. **CLI Flags**: `--profile`, `--debug`, `--enable-exploit`, `--output-dir`.
2. **JSON Env**: Variables defined in your MCP client's `env` block.
3. **.env File**: Discovered automatically in `$NEXUS_CONFIG_DIR`, `~/.config/nexus-mcp/.env`, or `./.env`.
4. **Built-in Defaults**.

---

## 🧠 Nexus Internal Tools

Beyond standard wrappers, Nexus provides custom tools to orchestrate your assessment:

- **`switch_phase`**: Dynamically refresh the tool list available to the AI.
- **`chain_tools`**: Define and run automated sequences (e.g., `nmap` -> `httpx` -> `nuclei`).
- **`attack_chain_suggest`**: Analyzes current `pentest_notes` to suggest the most logical next step.
- **`pentest_notes`**: Centralized, structured storage for all discovered vulnerabilities and assets.
- **`generate_report`**: Export all findings into a professional Markdown report.

---

## 📜 License
This project is licensed under the **MIT License**. Use responsibly and only on systems you have explicit permission to test.
