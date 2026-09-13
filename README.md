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
- **Destructive tools without an enforceable confirmation gate.** Parameters and annotations are untrusted and never reduce risk.
- **Diff**: new servers, new tools, new capabilities, new description findings, launch/version changes, score deltas. Exit code 2 when risk increased - usable in CI.

Scores are heuristic: they rank what a server *could* do if misused (by a prompt injection, a compromised update, or a malicious author), not whether it is malicious. CRITICAL/HIGH means "review before enabling".

## Usage

```
mcp-scan [--config <file>] [--tools <file>] [--server <name>] [--no-live] [--json] [--snapshot <file>] [--timeout <ms>] [--fail-on low|medium|high|critical]
mcp-scan diff <before.json> <after.json> [--json]
```

Live scans launch stdio servers (with the config's command and env) or connect to HTTP/SSE servers and call `initialize` + paginated `tools/list`; no tool is invoked. Use `--no-live` for config-only findings. Static tool documents accept `{ "tools": [...] }`, a bare array, or `{ "servers": { name: { tools } } }`.

Supported configs: `claude_desktop_config.json`, `~/.claude.json` (incl. per-project servers), `.mcp.json`, Cursor/Windsurf/VS Code `mcp.json`, Codex `config.toml`.

## Security boundaries and limits

**Do not live-scan untrusted local executables on your host.** Starting a stdio server executes arbitrary code with your user privileges, even when no tool is called. Use an isolated disposable VM for hostile servers, or obtain tool definitions and use `--tools`. This scanner is not a sandbox. See the [MCP security model](https://github.com/modelcontextprotocol/modelcontextprotocol/security).

Only the SDK platform allowlist of environment variables plus explicitly configured `env` is inherited. HTTP/SSE requests reject redirects and cross-origin targets; configured authentication stays on the original origin. Limits are 4 MiB received per server, 512 tools, 100 pagination cursors, 256 characters per name, 16,000 per description, and 64 KiB per tool definition. Limit violations fail enumeration rather than producing a partial clean report. Resources/prompts are not enumerated. Timeout cancels requests. Servers run in their own process group on POSIX (killed as a group) and are removed with `taskkill /T /F` on Windows, so a server's own children die with it; a server that deliberately double-forks into a new session, or the scanner being SIGKILLed mid-scan, can still leave processes behind. This is process cleanup, not containment.

Launch details and peer errors are withheld from reports. A deterministic launch fingerprint detects configuration changes without printing arguments, URLs, environment or header values. Configured env/header values echoed verbatim by a peer are redacted; encoded/transformed secrets or other private data supplied by the peer cannot reliably be recognized. Treat reports as sensitive. Fingerprints are not password hashes and should not be published when configs contain low-entropy secrets.

Detection examines names, titles, nested schemas and enum values, with NFKC/identifier normalization and hidden-character findings. Mixed Latin/Cyrillic words are suspicious; this is not complete Unicode-confusable or multilingual detection. Evidence indicates lexical capability signals, not verified behavior: examples, negation, and legitimate secret-management tools can produce false positives. Undeclared capabilities and paraphrased poisoning can evade detection. No low-false-negative claim is established without a labeled corpus. Annotation hints are untrusted ([MCP guidance](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/)).

Snapshots sort object keys and retain tool definitions so schema/annotation changes are visible. Diff `riskIncreased` means score increase, added capabilities/tools/config findings/injection findings, changed launch, or a new nonzero-risk server; it is a conservative review trigger, not proof of maliciousness. Version-only changes are visible but do not trigger it. Exit codes: 0 success, 1 invalid input or failed enumeration, 2 reached `--fail-on` threshold or diff review trigger. A failed enumeration is incomplete regardless of its config-only score.

## Development

```bash
npm install
npm test        # includes a live stdio enumeration of a deliberately poisoned fixture server
```

## Not in v1 (on purpose)

Hosted registry scanning, continuous monitoring, team policies, sandboxed dynamic analysis of tool behaviour, LLM-assisted description review. Those are the hosted layer; the CLI stays free.

## Install

```bash
npm install -g mcp-permission-scanner    # Node 22.13+
mcp-scan --help
```

## Production notes

- **Verified 2026-09-13** from the packed tarball on Windows 11 and Linux (node:22 container): static scans are deterministic (identical JSON across runs) and exit `0/1/2` as documented; live enumeration of a real published server (`@modelcontextprotocol/server-filesystem` via `npx`, 14 tools, HIGH) and a real Streamable HTTP server (`server-everything`, 13 tools); a hostile corpus (never-answering, crashing, 6 MiB-flooding, grandchild-spawning and poisoned servers) fails enumeration with exit 1 and leaves **no processes behind** after repeated runs on both platforms; Codex `config.toml` and JSON client configs parse.
- **Exit codes** are the contract for CI: `0` clean, `1` invalid input or any server that could not be enumerated (a partial report is never a clean report), `2` `--fail-on` threshold reached or diff review trigger.
- **Heuristics, honestly:** capability detection is lexical (names, descriptions, schemas). Expect false positives on tools that *mention* shells or credentials and false negatives on undeclared or paraphrased behaviour; there is no labelled corpus behind a recall number. Use the score to decide what to review, not what to trust.
- **Safe workflow for untrusted servers:** obtain the tool definitions (from the vendor, a registry, or a scan run inside a disposable VM) and use `--tools file.json` - it never executes anything. `--no-live` gives config-only findings without launching servers.
- **Update:** `npm install -g mcp-permission-scanner@latest`. The tool keeps no state; snapshots are files you own.

### Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Could not enumerate tools` for an `npx` server on Windows | fixed in 0.1.0 (cross-spawn); on older builds use the full path to `npx.cmd` |
| enumeration times out | raise `--timeout` (first `npx -y` run downloads the package) |
| exit 1 with a report | at least one server was not enumerated - the report is incomplete by design |
| a hostile server keeps running | it detached into a new session; kill it manually and scan its tool document with `--tools` instead |

## Credits

Created by Nathan Beer. Developed by Nathan Beer with AI-assisted engineering using Claude and ChatGPT. Third-party licenses: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Not affiliated with or endorsed by Anthropic, OpenAI, Cursor, Windsurf or the Model Context Protocol project.

MIT.
