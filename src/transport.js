import { execFile } from "node:child_process";
import crossSpawn from "cross-spawn";
import { getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { JSONRPCMessageSchema } from "@modelcontextprotocol/sdk/types.js";

export const MAX_BYTES = 4 * 1024 * 1024;
export class BoundedStdioTransport {
  constructor(server) { this.server = server; }
  async start() {
    // cross-spawn resolves `npx`/`uvx`/`.cmd` shims on Windows without a shell (Node refuses bare .cmd spawns).
    this.child = crossSpawn(this.server.command, this.server.args || [], { env: { ...getDefaultEnvironment(), ...this.server.env }, stdio: ["pipe", "pipe", "ignore"], windowsHide: true, detached: process.platform !== "win32" }); // own process group on POSIX so the whole tree can be killed
    this.pid = this.child.pid;
    let bytes = 0, pending = "";
    this.child.stdout.setEncoding("utf8");
    this.child.stdout.on("data", chunk => {
      bytes += Buffer.byteLength(chunk);
      if (bytes > MAX_BYTES) { this.onerror?.(new Error("Server output exceeds 4 MiB")); this.child.stdout.pause(); return; }
      pending += chunk;
      let end;
      while ((end = pending.indexOf("\n")) >= 0) {
        const line = pending.slice(0, end); pending = pending.slice(end + 1);
        try { this.onmessage?.(JSONRPCMessageSchema.parse(JSON.parse(line))); }
        catch { this.onerror?.(new Error("Invalid server message")); return; }
      }
    });
    this.child.stdin.on("error", e => this.onerror?.(e));
    this.child.on("error", e => this.onerror?.(e));
    this.child.on("close", () => this.onclose?.());
    await new Promise((resolve, reject) => { this.child.once("spawn", resolve); this.child.once("error", reject); });
  }
  async send(message) { await new Promise((resolve, reject) => this.child.stdin.write(JSON.stringify(message) + "\n", e => e ? reject(e) : resolve())); }
  async close() {
    if (!this.child || this.child.exitCode !== null) return;
    if (process.platform === "win32" && this.pid) await new Promise(resolve => execFile("taskkill", ["/PID", String(this.pid), "/T", "/F"], { windowsHide: true, timeout: 3000 }, () => resolve()));
    else if (this.pid) { try { process.kill(-this.pid, "SIGKILL"); } catch { /* group already gone */ } }
    this.child.kill("SIGKILL");
    this.child.stdin.destroy(); this.child.stdout.destroy();
  }
}

export function boundedFetch(url, controller) {
  const origin = new URL(url).origin;
  let bytes = 0;
  return async (input, init = {}) => {
    const target = new URL(input instanceof Request ? input.url : input);
    if (target.origin !== origin || !["http:", "https:"].includes(target.protocol)) throw new Error("Cross-origin request blocked");
    const signal = AbortSignal.any([controller.signal, ...(init.signal ? [init.signal] : [])]);
    const response = await fetch(input, { ...init, redirect: "error", signal });
    if (!response.body) return response;
    const reader = response.body.getReader();
    const body = new ReadableStream({
      async pull(c) {
        try {
          const { done, value } = await reader.read();
          if (done) { c.close(); return; }
          bytes += value.byteLength;
          if (bytes > MAX_BYTES) { controller.abort(); await reader.cancel(); c.error(new Error("Server output exceeds 4 MiB")); return; }
          c.enqueue(value);
        } catch (e) { c.error(e); }
      },
      cancel(reason) { return reader.cancel(reason); },
    });
    return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers });
  };
}
