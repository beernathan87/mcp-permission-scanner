# MCP Permission Scanner

Security scanner for MCP servers and tool definitions. It enumerates what each server can do, flags dangerous capability combinations and poisoned tool descriptions, explains every point of its risk score, and **diffs snapshots between versions** so you notice when an update quietly adds a capability.

```bash
npx mcp-scan                      # finds Claude Desktop / Claude Code / Cursor / Windsurf / VS Code / Codex configs, connects, reports
npx mcp-scan --config ./.mcp.json --snapshot before.json
npx mcp-scan --tools tools.json   # static scan of a tool-definition document
npx mcp-scan diff before.json after.json
```

Example (a real scan of a JS-REPL server):

```
| Server    | Transport | Tools | Risk     | Score |
| node_repl | stdio     | 4     | CRITICAL | 98    |

### Why this score
- Capabilities present: Filesystem write, Shell / process execution, Code execution, Browser control, ... (+58)
- HIGH combination Filesystem write + Shell / process execution: Can write files and execute: persistence is one step. (+15)
- 1 destructive tool(s) without a confirm/dry-run parameter: js_reset (+5)
```

## What it checks

- **Capabilities** per tool, from name, description and input schema: filesystem read/write/delete, shell, code execution, network fetch/send, browser control, credentials, environment access, database read/write, messaging/email, payments, cloud/infra, clipboard/input, destructive operations, persistent memory. Each match shows its evidence.
- **Dangerous combinations** (with the attack class they enable): file read + network send (exfiltration), credentials + network, shell + network (download-and-run), write + shell (persistence), browser + credentials, env + network, and more.
- **Description injection / tool poisoning**: instruction overrides, "always call this tool first", "don't tell the user", cross-tool hijacking, references to `~/.ssh` and other secret paths, exfil-to-URL instructions, role markup, zero-width/bidi hidden text, base64 blobs, parameter smuggling, oversized or missing descriptions.
- **Launch/config findings**: `npx -y`/`uvx` ephemeral execution, unpinned packages, plaintext remote HTTP, secrets inline in config or headers, whole-drive/home filesystem roots, privilege-raising flags.
- **Destructive tools without a confirm/dry-run parameter.**
- **Diff**: new servers, new tools, new capabilities, new description findings, launch/version changes, score deltas. Exit code 2 when risk increased - usable in CI.

Scores are heuristic: they rank what a server *could* do if misused (by a prompt injection, a compromised update, or a malicious author), not whether it is malicious. CRITICAL/HIGH means "review before enabling".

## Usage

```
mcp-scan [--config <file>] [--tools <file>] [--server <name>] [--no-live] [--json] [--snapshot <file>] [--timeout <ms>] [--fail-on low|medium|high|critical]
mcp-scan diff <before.json> <after.json> [--json]
```

Live scans launch stdio servers (with the config's command and env) or connect to HTTP/SSE servers and call `initialize` + `tools/list`; nothing else is invoked. Use `--no-live` for config-only findings. Static tool documents accept `{ "tools": [...] }`, a bare array, or `{ "servers": { name: { tools } } }`.

Supported configs: `claude_desktop_config.json`, `~/.claude.json` (incl. per-project servers), `.mcp.json`, Cursor/Windsurf/VS Code `mcp.json`, Codex `config.toml`.

## Development

```bash
npm install
npm test        # includes a live stdio enumeration of a deliberately poisoned fixture server
```

## Not in v1 (on purpose)

Hosted registry scanning, continuous monitoring, team policies, sandboxed dynamic analysis of tool behaviour, LLM-assisted description review. Those are the hosted layer; the CLI stays free.

MIT.
