import { readFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, extname } from "node:path";
import { parse as parseToml } from "smol-toml";

/** Well-known MCP client config locations (Windows/macOS/Linux). */
export function knownConfigPaths() {
  const h = homedir(), app = process.env.APPDATA || join(h, "AppData", "Roaming");
  return [
    { client: "Claude Desktop", path: join(app, "Claude", "claude_desktop_config.json") },
    { client: "Claude Desktop", path: join(h, "Library", "Application Support", "Claude", "claude_desktop_config.json") },
    { client: "Claude Code (user)", path: join(h, ".claude.json") },
    { client: "Claude Code (project)", path: join(process.cwd(), ".mcp.json") },
    { client: "Cursor", path: join(h, ".cursor", "mcp.json") },
    { client: "Cursor (project)", path: join(process.cwd(), ".cursor", "mcp.json") },
    { client: "Windsurf", path: join(h, ".codeium", "windsurf", "mcp_config.json") },
    { client: "VS Code (project)", path: join(process.cwd(), ".vscode", "mcp.json") },
    { client: "Codex", path: join(h, ".codex", "config.toml") },
  ].filter((p) => existsSync(p.path));
}

/** Parse a client config into a normalised list of servers: { name, transport, command, args, env, url, headers, source }. */
export function parseConfig(path, client = "unknown") {
  try {
  const raw = readFileSync(path, "utf8");
  if (raw.length > 4 * 1024 * 1024) throw new Error();
  let servers = {};
  if (extname(path).toLowerCase() === ".toml") {
    const t = parseToml(raw);
    servers = t.mcp_servers || t.mcpServers || {};
  } else {
    const j = JSON.parse(raw);
    servers = j.mcpServers || j.servers || j.mcp?.servers || {};
    // Claude Code ~/.claude.json keeps per-project servers too.
    if (j.projects) for (const [proj, cfg] of Object.entries(j.projects)) for (const [n, s] of Object.entries(cfg?.mcpServers || {})) servers[`${n} (${proj})`] = s;
  }
  if (!servers || typeof servers !== "object" || Array.isArray(servers)) throw new Error();
  for (const s of Object.values(servers)) if (!s || typeof s !== "object" || (s.args && (!Array.isArray(s.args) || s.args.some(a => typeof a !== "string")))) throw new Error();
  return Object.entries(servers).map(([name, s]) => ({
    name, source: path, client,
    transport: s.url ? (s.type === "sse" ? "sse" : "http") : "stdio",
    command: s.command || null, args: s.args || [], env: s.env || {}, url: s.url || null, headers: s.headers || {},
    enabled: s.enabled !== false && s.disabled !== true,
  }));
  } catch { throw new Error("Unable to read or parse MCP config"); }
}

/** Static risk findings about how a server is launched/configured (no network needed). */
export function auditServerConfig(server) {
  const f = [];
  const argStr = [server.command, ...server.args].filter(Boolean).join(" ");
  if (/\bnpx\b.*\s-y\b|\bnpx\s+-y|\buvx?\b|\bpipx\b/.test(argStr)) f.push({ code: "ephemeral-package-exec", severity: "medium", points: 8, why: `Runs a package fetched from a registry at launch : the code executed can change between runs (supply-chain exposure). Pin a version or install locally.` });
  const unpinned = /npx|uvx|pipx/.test(server.command || "") ? server.args.find((a) => !a.startsWith("-") && /^(@[A-Za-z0-9_.-]+\/)?[A-Za-z0-9_.-]+$/.test(a) && !/@\d/.test(a)) : null;
  if (unpinned) f.push({ code: "unpinned-version", severity: "low", points: 3, why: `A launched package has no version pin.` });
  if (server.url && isRemoteHttp(server.url)) f.push({ code: "plaintext-remote", severity: "high", points: 15, why: `Remote server over plain HTTP : tool calls and any tokens travel unencrypted.` });
  const secretEnv = Object.entries(server.env).filter(([k, v]) => /key|token|secret|password|passwd|auth/i.test(k) && typeof v === "string" && v.length > 0 && !/^\$\{?[A-Z_]+\}?$/.test(v));
  if (secretEnv.length) f.push({ code: "secrets-in-config", severity: "medium", points: 6, why: `Secrets stored inline in the config (${secretEnv.map(([k]) => k).join(", ")}); anything that can read this file gets them.` });
  const secretHeaders = Object.keys(server.headers).filter((k) => /authorization|api-key|token/i.test(k));
  if (secretHeaders.length) f.push({ code: "secrets-in-headers", severity: "low", points: 3, why: `Auth headers stored in config (${secretHeaders.join(", ")}).` });
  if (server.args.some((a) => /^(\/|[A-Za-z]:\\|~)/.test(a) && /^(\/|[A-Za-z]:\\|~)$|^(\/home|\/Users|[A-Za-z]:\\Users\\[^\\]+)\\?$/.test(a))) f.push({ code: "broad-filesystem-root", severity: "high", points: 12, why: "Launched with a root, drive or whole home directory as its scope." });
  if (/(?<!\S)(sudo|runas|--privileged|--allow-all|--dangerously|--yolo|--no-sandbox)\b/i.test(argStr)) f.push({ code: "elevated-flags", severity: "high", points: 12, why: `Launch flags reduce sandboxing or raise privileges: ${argStr.match(/(?<!\S)(sudo|runas|--privileged|--allow-all|--dangerously[\w-]*|--yolo|--no-sandbox)\b/i)[0]}.` });
  return f;
}

function isRemoteHttp(value) { try { const u = new URL(value); return u.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]"].includes(u.hostname); } catch { return false; } }
