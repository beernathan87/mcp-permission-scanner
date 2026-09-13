import { CAPABILITIES } from "./classify.js";

const label = (id) => CAPABILITIES[id]?.label || id;
const setDiff = (a = [], b = []) => ({ added: b.filter((x) => !a.includes(x)), removed: a.filter((x) => !b.includes(x)) });

/** Compare two snapshots (toSnapshot output). Returns a structured diff and a markdown rendering. */
export function diffSnapshots(before, after) {
  const names = new Set([...Object.keys(before.servers), ...Object.keys(after.servers)]);
  const servers = [];
  for (const n of names) {
    const a = before.servers[n], b = after.servers[n];
    if (!a) { servers.push({ name: n, status: "added", score: b.score, level: b.level, capabilities: b.capabilities, tools: Object.keys(b.tools) }); continue; }
    if (!b) { servers.push({ name: n, status: "removed", score: a.score, level: a.level }); continue; }
    const caps = setDiff(a.capabilities, b.capabilities);
    const toolNames = setDiff(Object.keys(a.tools), Object.keys(b.tools));
    const changed = [];
    for (const t of Object.keys(b.tools)) {
      if (!a.tools[t]) continue;
      const ta = a.tools[t], tb = b.tools[t];
      const c = setDiff(ta.capabilities, tb.capabilities), inj = setDiff(ta.injection, tb.injection);
      const descChanged = ta.description !== tb.description;
      if (c.added.length || c.removed.length || inj.added.length || inj.removed.length || descChanged || ta.paramCount !== tb.paramCount)
        changed.push({ tool: t, capabilities: c, injection: inj, descriptionChanged: descChanged, paramCount: [ta.paramCount, tb.paramCount] });
    }
    const cfg = setDiff(a.configFindings, b.configFindings);
    const launchChanged = a.launch !== b.launch;
    const versionChanged = (a.serverInfo?.version || "") !== (b.serverInfo?.version || "");
    const noChange = !caps.added.length && !caps.removed.length && !toolNames.added.length && !toolNames.removed.length && !changed.length && !cfg.added.length && !cfg.removed.length && !launchChanged && a.score === b.score;
    servers.push({ name: n, status: noChange ? "unchanged" : "changed", scoreBefore: a.score, scoreAfter: b.score, levelBefore: a.level, levelAfter: b.level, capabilities: caps, tools: toolNames, changedTools: changed, configFindings: cfg, launchChanged, launch: [a.launch, b.launch], versionChanged, version: [a.serverInfo?.version, b.serverInfo?.version] });
  }
  const riskIncreased = servers.some((s) => s.status === "added" ? s.score >= 45 : s.status === "changed" && (s.scoreAfter > s.scoreBefore || s.capabilities.added.length || s.changedTools.some((t) => t.injection.added.length)));
  return { before: before.scannedAt, after: after.scannedAt, riskIncreased, servers, markdown: render({ before, after, servers, riskIncreased }) };
}

function render({ before, after, servers, riskIncreased }) {
  const L = [`# MCP permission diff`, "", `${before.scannedAt} -> ${after.scannedAt}`, "", riskIncreased ? "**Risk increased.** Review the additions below before trusting the new version." : "No risk increase detected.", ""];
  for (const s of servers) {
    if (s.status === "unchanged") { L.push(`- ${s.name}: unchanged (${s.scoreAfter})`); continue; }
    if (s.status === "added") { L.push(`- **${s.name}: NEW server** - ${s.level.toUpperCase()} ${s.score}; capabilities: ${s.capabilities.map(label).join(", ") || "none"}; tools: ${s.tools.join(", ")}`); continue; }
    if (s.status === "removed") { L.push(`- ${s.name}: removed (was ${s.score})`); continue; }
    L.push(`- **${s.name}**: ${s.scoreBefore} -> ${s.scoreAfter} (${s.levelBefore} -> ${s.levelAfter})${s.versionChanged ? ` version ${s.version[0] || "?"} -> ${s.version[1] || "?"}` : ""}`);
    if (s.launchChanged) L.push(`  - launch changed: \`${s.launch[0]}\` -> \`${s.launch[1]}\``);
    if (s.capabilities.added.length) L.push(`  - NEW capabilities: ${s.capabilities.added.map(label).join(", ")}`);
    if (s.capabilities.removed.length) L.push(`  - removed capabilities: ${s.capabilities.removed.map(label).join(", ")}`);
    if (s.tools.added.length) L.push(`  - NEW tools: ${s.tools.added.join(", ")}`);
    if (s.tools.removed.length) L.push(`  - removed tools: ${s.tools.removed.join(", ")}`);
    for (const t of s.changedTools) {
      const bits = [];
      if (t.capabilities.added.length) bits.push(`+${t.capabilities.added.map(label).join(", ")}`);
      if (t.capabilities.removed.length) bits.push(`-${t.capabilities.removed.map(label).join(", ")}`);
      if (t.injection.added.length) bits.push(`NEW description findings: ${t.injection.added.join(", ")}`);
      if (t.descriptionChanged) bits.push("description changed");
      if (t.paramCount[0] !== t.paramCount[1]) bits.push(`params ${t.paramCount[0]} -> ${t.paramCount[1]}`);
      L.push(`  - tool ${t.tool}: ${bits.join("; ")}`);
    }
    if (s.configFindings.added.length) L.push(`  - NEW config findings: ${s.configFindings.added.join(", ")}`);
    if (s.configFindings.removed.length) L.push(`  - resolved config findings: ${s.configFindings.removed.join(", ")}`);
  }
  return L.join("\n") + "\n";
}
