/**
 * Heuristic capability classification for MCP tools. Signals come from the tool name, description and the
 * input schema (property names + descriptions). Every finding carries an explanation so the report is auditable.
 */

export const CAPABILITIES = {
  fs_read:     { label: "Filesystem read",     weight: 2, re: /\b(read|open|cat|list|glob|search|find|stat|head|tail)\b.*\b(file|files|dir|directory|folder|path)\b|\b(file|path|directory)\b.*\b(read|list|contents?)\b|\bread_?file|list_?dir/i },
  fs_write:    { label: "Filesystem write",    weight: 3, re: /\b(write|create|save|edit|patch|append|move|rename|copy|mkdir|touch|upload)\b.*\b(file|files|dir|directory|folder|path)\b|\bwrite_?file|edit_?file|create_?file|save_?to/i },
  fs_delete:   { label: "Filesystem delete",   weight: 4, re: /\b(delete|remove|rm|unlink|rmdir|truncate|wipe|purge)\b.*\b(file|files|dir|directory|folder|path)\b|\bdelete_?file|remove_?file|\brm\b/i },
  shell:       { label: "Shell / process execution", weight: 6, re: /\b(shell|bash|sh|zsh|cmd|powershell|pwsh|terminal|exec|execute|spawn|subprocess|run_?command|command\s*line|system\()\b|\b(run|execute)\b.*\b(command|script|binary|program|process)\b/i },
  code_exec:   { label: "Code execution",      weight: 5, re: /\b(eval|execute|run)\b.*\b(code|python|javascript|js|node|snippet|script)\b|\b(python|node|js|javascript)[_\s]?(exec|repl)|\bcode_?(interpreter|runner|exec)/i },
  net_fetch:   { label: "Network fetch",       weight: 2, re: /\b(fetch|http|https|url|request|download|curl|wget|browse|crawl|scrape|api\s*call|webhook|endpoint)\b/i },
  net_send:    { label: "Network send / outbound data", weight: 4, re: /\b(post|put|send|upload|publish|submit|emit|transmit|sync|push)\b.*\b(http|url|server|remote|endpoint|api|cloud|webhook)\b|\bwebhook|\bsend_?(request|data|message)/i },
  browser:     { label: "Browser control",     weight: 4, re: /\b(browser|puppeteer|playwright|selenium|chrome|chromium|tab|navigate|click|screenshot|dom|cookie|cookies)\b/i },
  credentials: { label: "Credentials / secrets", weight: 6, re: /\b(password|passwd|secret|token|api[_\s-]?key|apikey|credential|credentials|private[_\s-]?key|ssh|\.ssh|id_rsa|keychain|wallet|seed\s*phrase|oauth|bearer|session\s*cookie|\.env\b|aws_access|access[_\s-]?key)\b/i },
  env:         { label: "Environment / config access", weight: 3, re: /\b(environment\s*variables?|env\s*vars?|process\.env|getenv|\benv\b|\.bashrc|\.profile|registry|config\s*file)\b/i },
  database:    { label: "Database access",     weight: 3, re: /\b(sql|query|database|db|postgres|mysql|sqlite|mongo|redis|table|collection)\b/i },
  db_write:    { label: "Database write",      weight: 4, re: /\b(insert|update|delete|drop|truncate|alter|upsert|write)\b.*\b(sql|table|database|db|row|record|collection|document)\b/i },
  messaging:   { label: "Messaging / email",   weight: 4, re: /\b(email|e-mail|smtp|send\s*mail|slack|discord|telegram|sms|whatsapp|send\s+message|direct\s+message|notify|notification|chat\s*post)\b/i },
  payments:    { label: "Payments / financial", weight: 6, re: /\b(payment|pay|charge|refund|invoice|stripe|paypal|transfer\s*funds|wallet|crypto|bank|card|purchase|order)\b/i },
  cloud:       { label: "Cloud / infrastructure", weight: 5, re: /\b(aws|gcp|azure|kubernetes|k8s|kubectl|docker|terraform|ec2|s3|lambda|iam|deploy|provision|cluster|vm|instance)\b/i },
  clipboard:   { label: "Clipboard / input devices", weight: 3, re: /\b(clipboard|keyboard|keystroke|mouse|type\s*text|screen\s*capture|screenshot)\b/i },
  destructive: { label: "Destructive / irreversible", weight: 4, re: /\b(delete|destroy|drop|wipe|purge|format\s+(disk|drive)|reset\s+(database|device)|overwrite|irreversible|permanent(ly)?|rm\s*-rf|shred)\b/i },
  memory:      { label: "Persistent memory / notes", weight: 1, re: /\b(memory|remember|memorize|persist|store\s*note|knowledge\s*base|save\s*context)\b/i },
};

/** Combinations that together enable a class of attack. Each adds points and an explanation. */
export const COMBOS = [
  { caps: ["memory", "net_send"], severity: "high", points: 20, why: "Stored context can be sent outbound." },
  { caps: ["code_exec", "credentials"], severity: "high", points: 25, why: "Executable code can consume or expose credentials." },
  { caps: ["shell", "credentials"], severity: "high", points: 25, why: "Shell execution can consume or expose credentials." },
  { caps: ["env", "net_send"], severity: "high", points: 20, why: "Environment data can be sent outbound." },
  { caps: ["fs_read", "net_send"], severity: "high", points: 25, why: "Reads local files and can send data out: a classic exfiltration path if a prompt injection steers the agent." },
  { caps: ["fs_read", "net_fetch"], severity: "medium", points: 10, why: "Reads local files and reaches the network: file contents can leak through crafted URLs (query strings, DNS)." },
  { caps: ["credentials", "net_fetch"], severity: "high", points: 30, why: "Handles secrets and talks to the network: credentials can be exfiltrated." },
  { caps: ["credentials", "net_send"], severity: "high", points: 30, why: "Handles secrets and sends data outbound." },
  { caps: ["shell", "net_fetch"], severity: "high", points: 25, why: "Shell execution plus network access: download-and-run and remote-control patterns become possible." },
  { caps: ["code_exec", "net_fetch"], severity: "high", points: 20, why: "Code execution plus network access." },
  { caps: ["fs_write", "shell"], severity: "high", points: 15, why: "Can write files and execute: persistence (drop a script, run it) is one step." },
  { caps: ["browser", "credentials"], severity: "high", points: 20, why: "Browser control with credential access can act as the user on authenticated sites." },
  { caps: ["browser", "net_send"], severity: "medium", points: 10, why: "Browser control can exfiltrate page contents." },
  { caps: ["env", "net_fetch"], severity: "high", points: 20, why: "Environment variables (often API keys) plus network access." },
  { caps: ["messaging", "fs_read"], severity: "medium", points: 12, why: "Can read files and send messages: data can leave via chat/email." },
  { caps: ["payments", "net_fetch"], severity: "medium", points: 10, why: "Financial actions driven by content fetched from the network." },
  { caps: ["destructive", "fs_write"], severity: "medium", points: 8, why: "Destructive filesystem operations without an obvious confirmation gate." },
  { caps: ["db_write", "net_fetch"], severity: "medium", points: 10, why: "Database writes driven by fetched content." },
];

/** Patterns that indicate a tool description is trying to instruct the model rather than describe the tool. */
export const INJECTION_PATTERNS = [
  { code: "override-instructions", severity: "high", re: /\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|system|all)\b.{0,20}\b(instructions?|rules?|prompts?)\b/i, why: "Attempts to override the model's instructions." },
  { code: "hide-from-user", severity: "high", re: /\b(do\s*not|don't|never)\b.{0,30}\b(tell|show|mention|reveal|inform|display)\b.{0,20}\b(the\s*)?(user|human|operator)\b|\b(hidden|secret|silent(ly)?|covert(ly)?|without\s*(the\s*)?user)\b.{0,30}\b(from\s*the\s*user|knowing|noticing)\b/i, why: "Asks the model to hide behaviour from the user." },
  { code: "always-call", severity: "high", re: /\b(always|must|you\s*must|required\s*to|make\s*sure\s*to)\b.{0,30}\b(call|invoke|use|run)\b.{0,30}\b(this|the)\s*tool\b.{0,30}\b(first|before|every|each|prior)\b|\bbefore\s*(using|calling)\s*(any|other)\s*tools?\b/i, why: "Coerces the model into calling this tool first/always - a hook for shadowing other tools." },
  { code: "cross-tool-hijack", severity: "high", re: /\b(when|whenever|if)\b.{0,40}\b(user|you)\b.{0,40}\b(uses?|calls?|invokes?)\b.{0,40}\b(tool|function)\b.{0,60}\b(also|instead|first|then)\b.{0,40}\b(call|send|pass|include)\b/i, why: "Conditions behaviour of other tools - tool shadowing / poisoning pattern." },
  { code: "reads-sensitive-paths", severity: "high", re: /(~\/\.ssh|\.ssh\/|id_rsa|\.aws\/credentials|\.env\b|\.npmrc|\.git-credentials|keychain|%APPDATA%|\/etc\/passwd|\/etc\/shadow|Local State|Login Data)/i, why: "References well-known secret locations." },
  { code: "exfil-instruction", severity: "high", re: /\b(send|post|upload|forward|transmit|include)\b.{0,60}\b(to|at)\s*(https?:\/\/|[a-z0-9-]+\.(com|net|io|xyz|ru|cn|top|dev))/i, why: "Instructs sending data to an external address." },
  { code: "role-injection", severity: "medium", re: /<\s*\/?\s*(system|assistant|instructions?|important)\s*>|\[(SYSTEM|IMPORTANT|INST)\]|^\s*SYSTEM\s*:|\bIMPORTANT\s*:.{0,10}(you|the\s*model|assistant)/im, why: "Uses system/role markup inside a description." },
  { code: "hidden-text", severity: "high", re: /[\u200B\u200C\u200D\u2060\uFEFF\u00AD\u202A-\u202E\u2066-\u2069]/, why: "Contains zero-width or bidi control characters that can hide text from human review." },
  { code: "encoded-blob", severity: "medium", re: /\b[A-Za-z0-9+/]{80,}={0,2}\b/, why: "Contains a long base64-like blob - obfuscated content in a description is a red flag." },
  { code: "urgency-pressure", severity: "low", re: /\b(urgent(ly)?|immediately|critical(ly)?\s*important|emergency|right\s*now)\b/i, why: "Urgency language aimed at the model rather than the user." },
  { code: "parameter-smuggling", severity: "medium", re: /\b(pass|include|add|set)\b.{0,40}\b(contents?|value|text)\b.{0,30}\bof\b.{0,30}\b(file|conversation|context|system\s*prompt|previous\s*messages|other\s*tools?)\b.{0,40}\b(as|in|into|to)\b.{0,20}\b(parameter|argument|field|input)\b/i, why: "Instructs the model to smuggle other data into this tool's parameters." },
];

const normalize = (s) => s.normalize("NFKC").replace(/[\u200B-\u200D\u2060\uFEFF\u00AD]/g, "").replace(/([a-z])([A-Z])/g, "$1 $2").replace(/[_-]/g, " ").replace(/\s+/g, " ");
const text = (tool) => {
  const schema = tool.inputSchema || tool.input_schema || tool.parameters || {};
  const props = schema.properties || {};
  const strings = [];
  const walk = (v) => { if (typeof v === "string") strings.push(v); else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) { if (["$schema", "$id", "$ref"].includes(k)) continue; strings.push(k); walk(x); } };
  walk(tool);
  const raw = strings.join(" ");
  return { raw, all: normalize(raw), paramNames: Object.keys(props), schema };
};

export function classifyTool(tool) {
  const serialized = JSON.stringify(tool);
  if (!tool || typeof tool.name !== "string" || serialized.length > 65536) throw new Error("Invalid or oversized tool definition (limit 64 KiB)");
  const t = text(tool);
  const capabilities = [];
  for (const [id, cap] of Object.entries(CAPABILITIES)) {
    const m = t.all.match(cap.re);
    if (m) capabilities.push({ id, label: cap.label, weight: cap.weight, evidence: m[0].slice(0, 80) });
  }
  // Parameter-shape signals: raw paths/commands/urls as free-text inputs.
  const p = t.paramNames.join(" ").toLowerCase();
  if (/\b(cmd|command|shell|script)\b/.test(p) && !capabilities.some((c) => c.id === "shell")) capabilities.push({ id: "shell", label: CAPABILITIES.shell.label, weight: CAPABILITIES.shell.weight, evidence: `parameter: ${p.match(/\b(cmd|command|shell|script)\b/)[0]}` });
  if (/\b(url|uri|endpoint|href)\b/.test(p) && !capabilities.some((c) => c.id === "net_fetch")) capabilities.push({ id: "net_fetch", label: CAPABILITIES.net_fetch.label, weight: CAPABILITIES.net_fetch.weight, evidence: `parameter: ${p.match(/\b(url|uri|endpoint|href)\b/)[0]}` });
  if (/\b(path|file|filename|filepath|dir|directory)\b/.test(p) && !capabilities.some((c) => c.id.startsWith("fs_"))) capabilities.push({ id: "fs_read", label: CAPABILITIES.fs_read.label, weight: CAPABILITIES.fs_read.weight, evidence: `parameter: ${p.match(/\b(path|file|filename|filepath|dir|directory)\b/)[0]}` });

  const injection = [];
  for (const pat of INJECTION_PATTERNS) {
    const m = t.raw.match(pat.re) || t.all.match(pat.re);
    if (m) injection.push({ code: pat.code, severity: pat.severity, why: pat.why, evidence: m[0].replace(/[\u200B\u200C\u200D\u2060\uFEFF\u00AD\u202A-\u202E\u2066-\u2069]/g, "?").slice(0, 100) });
  }
  const descLen = (tool.description || "").length;
  if (descLen > 1500) injection.push({ code: "oversized-description", severity: "low", why: `Description is ${descLen} chars; long descriptions are where hidden instructions live.`, evidence: `${descLen} chars` });
  if (!tool.description) injection.push({ code: "no-description", severity: "low", why: "Undocumented tool - the model (and you) cannot judge what it does.", evidence: "" });

  if (JSON.stringify(t.schema).length > 16000) injection.push({ code: "oversized-schema", severity: "medium", why: "Argument schema exceeds 16,000 characters.", evidence: "schema size" });
  if (/[a-z][\u0400-\u04ff]|[\u0400-\u04ff][a-z]/i.test(t.raw)) injection.push({ code: "mixed-script", severity: "medium", why: "Mixed Latin/Cyrillic text may disguise instructions with homoglyphs.", evidence: "mixed scripts" });
  const annotations = tool.annotations || {};
  const addCap = (id, evidence) => { if (!capabilities.some(c => c.id === id)) capabilities.push({ id, label: CAPABILITIES[id].label, weight: CAPABILITIES[id].weight, evidence }); };
  if (annotations.destructiveHint === true) addCap("destructive", "annotations.destructiveHint=true (untrusted)");
  if (annotations.openWorldHint === true) injection.push({ code: "open-world-hint", severity: "low", why: "Server declares interaction with external entities (untrusted hint).", evidence: "openWorldHint=true" });
  if ((annotations.readOnlyHint === true && capabilities.some(c => ["shell", "code_exec", "fs_write", "fs_delete", "db_write", "destructive", "payments"].includes(c.id))) || (annotations.destructiveHint === false && capabilities.some(c => ["fs_delete", "destructive"].includes(c.id)))) injection.push({ code: "annotation-conflict", severity: "high", why: "Safety hints conflict with detected capabilities; hints cannot enforce safety.", evidence: "annotations" });
  // A schema cannot establish that confirmation is enforced. Never discount risk for it.
  return { name: tool.name, description: tool.description || "", definition: tool, capabilities, injection, hasConfirmGate: false, paramCount: t.paramNames.length };

}

/** Score 0-100 for a set of classified tools plus server-config findings. Higher = riskier. Explains itself. */
export function scoreServer(tools, configFindings = []) {
  const capIds = new Set(tools.flatMap((t) => t.capabilities.map((c) => c.id)));
  const reasons = [];
  let points = 0;
  for (const id of capIds) { const w = CAPABILITIES[id].weight; points += w * 2; }
  reasons.push(`Capabilities present: ${[...capIds].map((id) => CAPABILITIES[id].label).join(", ") || "none detected"} (+${[...capIds].reduce((s, id) => s + CAPABILITIES[id].weight * 2, 0)})`);
  const combos = COMBOS.filter((c) => c.caps.every((x) => capIds.has(x)));
  for (const c of combos) { points += c.points; reasons.push(`${c.severity.toUpperCase()} combination ${c.caps.map((x) => CAPABILITIES[x].label).join(" + ")}: ${c.why} (+${c.points})`); }
  for (const t of tools) for (const i of t.injection) {
    const pts = i.severity === "high" ? 30 : i.severity === "medium" ? 12 : 3;
    points += pts; reasons.push(`Tool "${t.name}" description ${i.severity.toUpperCase()} ${i.code}: ${i.why} (+${pts})`);
  }
  for (const f of configFindings) { points += f.points; reasons.push(`Config ${f.severity.toUpperCase()} ${f.code}: ${f.why} (+${f.points})`); }
  const destructiveNoGate = tools.filter((t) => t.capabilities.some((c) => ["fs_delete", "destructive", "db_write", "payments"].includes(c.id)) && !t.hasConfirmGate);
  if (destructiveNoGate.length) { points += 5 * destructiveNoGate.length; reasons.push(`${destructiveNoGate.length} destructive tool(s) without a confirm/dry-run parameter: ${destructiveNoGate.map((t) => t.name).join(", ")} (+${5 * destructiveNoGate.length})`); }
  const score = Math.min(100, points);
  const level = score >= 70 ? "critical" : score >= 45 ? "high" : score >= 20 ? "medium" : "low";
  return { score, level, reasons, combos: combos.map((c) => ({ ...c, labels: c.caps.map((x) => CAPABILITIES[x].label) })) };
}
