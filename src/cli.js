#!/usr/bin/env node
import { parseArgs } from "node:util";
import { readFileSync, writeFileSync } from "node:fs";
import { knownConfigPaths, parseConfig } from "./config.js";
import { scanServers, scanStatic } from "./scan.js";
import { toMarkdown, toSnapshot } from "./report.js";
import { diffSnapshots } from "./diff.js";

const HELP = `mcp-scan - security scanner for MCP servers and tool definitions

  mcp-scan                          scan every MCP client config found on this machine (live enumeration)
  mcp-scan --config <file>          scan servers from one client config (claude_desktop_config.json, .mcp.json, config.toml, ...)
  mcp-scan --tools <file.json>      scan a static tool-definition document ({ tools: [...] } or [...])
  mcp-scan --server <name>          only this server (with --config or discovery)
  mcp-scan diff <before.json> <after.json>   compare two snapshots

Options:
  --no-live          do not launch/connect to servers; config-only findings
  --json             print JSON instead of markdown
  --snapshot <file>  also write a compact snapshot for later diffing
  --timeout <ms>     per-server enumeration timeout (default 20000)
  --fail-on <level>  exit 2 if any server reaches this level (low|medium|high|critical)
`;

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: { config: { type: "string" }, tools: { type: "string" }, server: { type: "string" }, "no-live": { type: "boolean", default: false }, json: { type: "boolean", default: false }, snapshot: { type: "string" }, timeout: { type: "string" }, "fail-on": { type: "string" }, help: { type: "boolean", short: "h", default: false } },
});
if (values.help) { console.log(HELP); process.exit(0); }

if (positionals[0] === "diff") {
  const [, a, b] = positionals;
  if (!a || !b) { console.error("usage: mcp-scan diff <before.json> <after.json>"); process.exit(1); }
  const d = diffSnapshots(JSON.parse(readFileSync(a, "utf8")), JSON.parse(readFileSync(b, "utf8")));
  console.log(values.json ? JSON.stringify(d, null, 2) : d.markdown);
  process.exit(d.riskIncreased ? 2 : 0);
}

let scan;
if (values.tools) {
  scan = scanStatic(JSON.parse(readFileSync(values.tools, "utf8")), values.tools);
} else {
  let servers = [];
  if (values.config) servers = parseConfig(values.config, "config");
  else for (const c of knownConfigPaths()) { try { servers.push(...parseConfig(c.path, c.client)); } catch (e) { console.error(`skip ${c.path}: ${e.message}`); } }
  if (values.server) servers = servers.filter((s) => s.name === values.server || s.name.startsWith(values.server + " ("));
  if (!servers.length) { console.error("No MCP servers found. Use --config <file> or --tools <file>."); process.exit(1); }
  if (!values.json) console.error(`Scanning ${servers.length} server(s)${values["no-live"] ? " (config only)" : ""}...`);
  scan = await scanServers(servers, { live: !values["no-live"], timeoutMs: Number(values.timeout) || 20_000 });
}

if (values.snapshot) writeFileSync(values.snapshot, JSON.stringify(toSnapshot(scan), null, 2));
console.log(values.json ? JSON.stringify(scan, null, 2) : toMarkdown(scan));
const order = ["low", "medium", "high", "critical"];
if (values["fail-on"] && scan.servers.some((s) => order.indexOf(s.risk.level) >= order.indexOf(values["fail-on"]))) process.exit(2);
