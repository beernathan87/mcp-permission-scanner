import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { BoundedStdioTransport, boundedFetch } from "./transport.js";
import { canonical } from "./report.js";
import { createHash } from "node:crypto";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { classifyTool, scoreServer } from "./classify.js";
import { auditServerConfig } from "./config.js";

/** Connect to a server description and list its tools/resources/prompts. Bounded by a timeout; never throws. */
export async function enumerate(server, { timeoutMs = 20_000 } = {}) {
  const client = new Client({ name: "mcp-permission-scanner", version: "0.1.0" });
  let transport, timerId;
  const controller = new AbortController();
  try {
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300000) throw new Error("Invalid timeout");
    if (server.transport === "stdio") transport = new BoundedStdioTransport(server);
    else {
      const options = { requestInit: { headers: server.headers }, fetch: boundedFetch(server.url, controller) };
      transport = server.transport === "sse" ? new SSEClientTransport(new URL(server.url), options) : new StreamableHTTPClientTransport(new URL(server.url), options);
    }
    const failure = new Promise((_, reject) => {
      client.onerror = () => reject(new Error("Invalid server response"));
      timerId = setTimeout(() => { controller.abort(); reject(new Error("Enumeration timed out")); }, timeoutMs);
    });
    const work = async () => {
      await client.connect(transport);
      const info = client.getServerVersion() || {};
      const caps = client.getServerCapabilities() || {};
      const tools = [], seen = new Set();
      if (caps.tools) {
        let cursor;
        do {
          const page = await client.listTools(cursor ? { cursor } : undefined);
          tools.push(...page.tools);
          validateTools(tools);
          cursor = page.nextCursor;
          if (cursor && seen.has(cursor)) throw new Error("Repeated pagination cursor");
          if (cursor) seen.add(cursor);
          if (seen.size > 100) throw new Error("Too many pages");
        } while (cursor);
      }
      return { ok: true, info: { name: info.name, version: info.version }, tools, resources: [], prompts: [] };
    };
    return await Promise.race([work(), failure]);
  } catch {
    // Peer errors can echo credentials, headers, URLs or arbitrary terminal escapes.
    return { ok: false, error: "Enumeration failed (timeout, transport, invalid response or limit exceeded)", tools: [], resources: [], prompts: [] };
  } finally {
    clearTimeout(timerId);
    controller.abort();
    try { await transport?.close(); } catch {}
    try { await client.close(); } catch {}
  }
}

export function validateTools(tools) {
  if (!Array.isArray(tools) || tools.length > 512) throw new Error("Tool count exceeds 512");
  const names = new Set();
  for (const tool of tools) {
    if (!tool || typeof tool.name !== "string" || tool.name.length > 256 || typeof (tool.description ?? "") !== "string" || (tool.description || "").length > 16000 || JSON.stringify(tool).length > 65536 || names.has(tool.name)) throw new Error("Invalid, duplicate or oversized tool");
    names.add(tool.name);
  }
}

/** Build the scan record for one server from already-known tools (static) or by enumerating (live). */
export function analyseServer(server, tools, extra = {}) {
  validateTools(tools);
  const classified = tools.map(classifyTool);
  const configFindings = auditServerConfig(server);
  const risk = scoreServer(classified, configFindings);
  return {
    name: server.name, client: server.client, transport: server.transport, source: server.source,
    launch: server.transport === "static" ? null : `${server.transport} (details withheld)`,
    launchFingerprint: createHash("sha256").update(JSON.stringify(canonical([server.command, server.args, server.url, server.env, server.headers]))).digest("hex"),
    enumerated: extra.ok ?? null, error: extra.error ?? null, serverInfo: extra.info ?? null,
    toolCount: tools.length, tools: classified, resources: extra.resources ?? [], prompts: extra.prompts ?? [],
    configFindings, risk,
  };
}

export async function scanServers(servers, { live = true, timeoutMs } = {}) {
  const out = [];
  for (const s of servers) {
    if (s.enabled === false) continue;
    if (!live) { out.push(analyseServer(s, [], { ok: null })); continue; }
    const e = await enumerate(s, { timeoutMs });
    const record = analyseServer(s, e.tools, e);
    const secrets = [...Object.values(s.env || {}), ...Object.values(s.headers || {})].filter(v => typeof v === "string" && v.length);
    const redact = v => typeof v === "string" ? secrets.reduce((x, secret) => x.split(secret).join("[REDACTED]"), v) : Array.isArray(v) ? v.map(redact) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [redact(k), redact(x)])) : v;
    out.push(redact(record));
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
