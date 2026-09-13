export const canonical = (v) => Array.isArray(v) ? v.map(canonical) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map(k => [k, canonical(v[k])])) : v;
export const markdownSafe = (v) => typeof v === "string" ? v.replace(/[\r\n\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, " ").replace(/[&<>|`\\*_[\]{}()!#]/g, c => `&#${c.charCodeAt(0)};`) : Array.isArray(v) ? v.map(markdownSafe) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, markdownSafe(x)])) : v;
const badge = (level) => ({ critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW" }[level]);

export function toMarkdown(scan) {
  scan = markdownSafe(scan);
  const L = [`# MCP permission scan`, "", `Scanned ${scan.servers.length} server(s) at ${scan.scannedAt}.`, ""];
  L.push("| Server | Transport | Tools | Risk | Score |", "|---|---|---|---|---|");
  for (const s of scan.servers) L.push(`| ${s.name} | ${s.transport} | ${s.enumerated === false ? "?" : s.toolCount} | ${badge(s.risk.level)} | ${s.risk.score} |`);
  for (const s of scan.servers) {
    L.push("", `## ${s.name} - ${badge(s.risk.level)} (${s.risk.score}/100)`, "");
    L.push(`Launch: \`${s.launch || "-"}\`${s.serverInfo?.name ? ` - reports as ${s.serverInfo.name} ${s.serverInfo.version || ""}` : ""}`);
    if (s.enumerated === false) L.push("", `**Could not enumerate tools:** ${s.error}. Findings below are config-only.`);
    if (s.enumerated === null) L.push("", "_Config-only scan (no live enumeration)._");
    L.push("", "### Why this score", "", ...s.risk.reasons.map((r) => `- ${r}`));
    if (s.configFindings.length) L.push("", "### Launch / config findings", "", ...s.configFindings.map((f) => `- **${f.severity}** \`${f.code}\`: ${f.why}`));
    if (s.tools.length) {
      L.push("", "### Tools", "", "| Tool | Capabilities | Description findings | Confirm gate |", "|---|---|---|---|");
      for (const t of s.tools) L.push(`| ${t.name} | ${t.capabilities.map((c) => c.label).join(", ") || "-"} | ${t.injection.map((i) => `${i.severity}: ${i.code}`).join(", ") || "-"} | ${t.hasConfirmGate ? "yes" : "no"} |`);
      const details = s.tools.filter((t) => t.injection.length || t.capabilities.length);
      if (details.length) {
        L.push("", "### Evidence", "");
        for (const t of details) {
          L.push(`- **${t.name}**`);
          for (const c of t.capabilities) L.push(`  - ${c.label}: matched \`${c.evidence}\``);
          for (const i of t.injection) L.push(`  - ${i.severity.toUpperCase()} ${i.code}: ${i.why}${i.evidence ? ` - \`${i.evidence}\`` : ""}`);
        }
      }
    }
    if (s.resources.length) L.push("", `Resources exposed: ${s.resources.length} (e.g. ${s.resources.slice(0, 3).map((r) => r.uri).join(", ")})`);
    if (s.prompts.length) L.push("", `Prompts exposed: ${s.prompts.join(", ")}`);
  }
  L.push("", "---", "", "Scores are heuristic: they rank *what a server could do if misused*, not whether it is malicious. Treat CRITICAL/HIGH as \"review before enabling\", and re-run after every update to diff changes.");
  return L.join("\n") + "\n";
}

/** Compact snapshot for diffing across versions. */
export function toSnapshot(scan) {
  return canonical({
    version: 1, scannedAt: scan.scannedAt,
    servers: Object.fromEntries(scan.servers.map((s) => [s.name, {
      launch: s.launch, launchFingerprint: s.launchFingerprint, enumerated: s.enumerated, transport: s.transport, score: s.risk.score, level: s.risk.level, serverInfo: s.serverInfo,
      capabilities: [...new Set(s.tools.flatMap((t) => t.capabilities.map((c) => c.id)))].sort(),
      configFindings: s.configFindings.map((f) => f.code).sort(),
      tools: Object.fromEntries(s.tools.map((t) => [t.name, { definition: t.definition, description: t.description, capabilities: t.capabilities.map((c) => c.id).sort(), injection: t.injection.map((i) => i.code).sort(), paramCount: t.paramCount }])),
    }])),
  });
}
