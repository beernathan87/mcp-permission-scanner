import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { scanServers } from "../src/scan.js";

// Production corpus: a server that spawns a grandchild and hangs, a server that crashes, one that never answers,
// and (on Windows) a `.cmd` shim - the shape of every `npx`-launched server in real client configs.
const dir = mkdtempSync(join(tmpdir(), "mcp-scan-prod-"));
const fx = (name, code) => { const p = join(dir, name); writeFileSync(p, code); return p; };
const orphan = fx("orphan.cjs", `const { spawn } = require("node:child_process"); const fs = require("node:fs");
const c = spawn(process.execPath, ["-e", "setInterval(()=>{},1000)"], { stdio: "ignore" }); fs.writeFileSync(process.argv[2], String(c.pid)); process.stdin.resume(); setInterval(() => {}, 1000);`);
const hang = fx("hang.cjs", "process.stdin.resume(); setInterval(() => {}, 1000);");
const crash = fx("crash.cjs", "process.exit(3);");
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };

test("hostile servers: hang/crash/orphan-spawner fail enumeration, and the whole process tree is cleaned up", async () => {
  const pidFile = join(dir, "orphan.pid");
  const servers = [
    { name: "orphan", client: "test", transport: "stdio", command: process.execPath, args: [orphan, pidFile], env: {}, headers: {}, url: null },
    { name: "hang", client: "test", transport: "stdio", command: process.execPath, args: [hang], env: {}, headers: {}, url: null },
    { name: "crash", client: "test", transport: "stdio", command: process.execPath, args: [crash], env: {}, headers: {}, url: null },
  ];
  for (let round = 0; round < 2; round++) {
    const scan = await scanServers(servers, { live: true, timeoutMs: 3000 });
    assert.deepEqual(scan.servers.map((s) => s.enumerated), [false, false, false]);
    await new Promise((r) => setTimeout(r, 500));
    assert.ok(existsSync(pidFile), "orphan fixture started");
    const gp = Number(readFileSync(pidFile, "utf8"));
    assert.equal(alive(gp), false, `grandchild ${gp} must not survive the scan (round ${round + 1})`);
  }
  rmSync(dir, { recursive: true, force: true });
});

test("windows: servers launched through a .cmd shim (like npx) are enumerated", { skip: process.platform !== "win32" }, async () => {
  const d = mkdtempSync(join(tmpdir(), "mcp-scan-cmd-"));
  const server = join(import.meta.dirname, "fixtures", "min-server.cjs");
  const shim = join(d, "srv.cmd");
  writeFileSync(shim, `@echo off
"${process.execPath}" "${server}" %*
`);
  const scan = await scanServers([{ name: "shim", client: "test", transport: "stdio", command: shim, args: [], env: {}, headers: {}, url: null }], { live: true, timeoutMs: 10000 });
  assert.equal(scan.servers[0].enumerated, true, scan.servers[0].error ?? "");
  assert.equal(scan.servers[0].toolCount, 1);
  rmSync(d, { recursive: true, force: true });
});
