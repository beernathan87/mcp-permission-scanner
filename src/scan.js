import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { classifyTool, scoreServer } from "./classify.js";
import { auditServerConfig } from "./config.js";

/** Connect to a server description and list its tools/resources/prompts. Bounded by a timeout; never throws. */
export async function enumerate(server, { timeoutMs = 20_000 } = {}) {
  const client = new Client({ name: "mcp-permission-scanner", version: "0.1.0" });
  let transport;
  try {
    if (server.transport === "stdio") {
      transport = new StdioClientTransport({ command: server.command, args: server.args, env: { ...process.env, ...server.env }, stderr: "ignore" });
    } else if (server.transport === "sse") {
      transport = new SSEClientTransport(new URL(server.url), { requestInit: { headers: server.headers } });
    } else {
      transport = new StreamableHTTPClientTransport(new URL(server.url), { requestInit: { headers: server.headers } });
    }
    const timer = new Promise((_, rej) => setTimeout(() => rej(new Error(`timeout after ${timeoutMs} ms`)), timeoutMs).unref?.());
    await Promise.race([client.connect(transport), timer]);
    const info = client.getServerVersion?.() || {};
    const caps = client.getServerCapabilities?.() || {};
    const tools = caps.tools !== undefined || true ? (await Promise.race([client.listTools(), timer])).tools : [];
    let resources = [], prompts = [];
    if (caps.resources) resources = (await Promise.race([client.listResources(), timer]).catch(() => ({ resources: [] }))).resources;
    if (caps.prompts) prompts = (await Promise.race([client.listPrompts(), timer]).catch(() => ({ prompts: [] }))).prompts;
    return { ok: true, info: { name: info.name, version: info.version }, tools, resources: resources.map((r) => ({ uri: r.uri, name: r.name })), prompts: prompts.map((p) => p.name) };
  } catch (e) {
    return { ok: false, error: e.message, tools: [], resources: [], prompts: [] };
  } finally {
    try { await client.close(); } catch {}
  }
}

/** Build the scan record for one server from already-known tools (static) or by enumerating (live). */
export function analyseServer(server, tools, extra = {}) {
  const classified = tools.map(classifyTool);
  const configFindings = auditServerConfig(server);
  const risk = scoreServer(classified, configFindings);
  return {
    name: server.name, client: server.client, transport: server.transport, source: server.source,
    launch: server.transport === "stdio" ? [server.command, ...server.args].join(" ") : server.url,
    enumerated: extra.ok ?? null, error: extra.error ?? null, serverInfo: extra.info ?? null,
    toolCount: tools.length, tools: classified, resources: extra.resources ?? [], prompts: extra.prompts ?? [],
    configFindings, risk,
  };
}

export async function scanServers(servers, { live = true, timeoutMs } = {}) {
  const out = [];
  for (const s of servers) {
    if (!live) { out.push(analyseServer(s, [], { ok: null })); continue; }
    const e = await enumerate(s, { timeoutMs });
    out.push(analyseServer(s, e.tools, e));
  }
  return { scannedAt: new Date().toISOString(), servers: out };
}

/** Scan a static tool-definition document: { tools: [...] } | [...] | { servers: { name: { tools } } }. */
export function scanStatic(doc, name = "static") {
  const list = Array.isArray(doc) ? doc : Array.isArray(doc.tools) ? doc.tools : null;
  if (list) return { scannedAt: new Date().toISOString(), servers: [analyseServer({ name, transport: "static", command: null, args: [], env: {}, headers: {}, url: null }, list, { ok: true })] };
  const servers = Object.entries(doc.servers || doc).map(([n, s]) => analyseServer({ name: n, transport: "static", command: null, args: [], env: {}, headers: {}, url: null }, s.tools || [], { ok: true }));
  return { scannedAt: new Date().toISOString(), servers };
}
