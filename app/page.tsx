"use client";

import { ChangeEvent, useMemo, useState } from "react";

type Finding = {
  id: number;
  timestamp: string;
  ip: string;
  method: string;
  path: string;
  status: number;
  category: string;
  severity: "Critical" | "High" | "Medium";
  evidence: string;
};

type ParsedLog = {
  timestamp: string;
  ip: string;
  method: string;
  path: string;
  status: number;
  raw: string;
};

const RULES = [
  { category: "SQL injection", severity: "Critical" as const, pattern: /(?:union(?:\s+all)?\s+select|select.+from|\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1|sleep\s*\(|benchmark\s*\(|information_schema)/i },
  { category: "Cross-site scripting", severity: "High" as const, pattern: /(?:<script|%3cscript|onerror\s*=|onload\s*=|javascript:|alert\s*\()/i },
  { category: "Path traversal", severity: "High" as const, pattern: /(?:\.\.\/(?:\.\.\/)?|\.\.\\|%2e%2e%2f|\/etc\/passwd|win\.ini)/i },
  { category: "Sensitive-file probing", severity: "Medium" as const, pattern: /(?:\.env(?:\.|$)|\.git(?:\/|$)|id_rsa|wp-config\.php|\.bak(?:\?|$)|backup\.(?:zip|sql))/i },
  { category: "Command-injection probe", severity: "High" as const, pattern: /(?:;\s*(?:cat|whoami|id|curl|wget)\b|\|\s*(?:cat|whoami|id)\b|\$\{(?:IFS|PATH))/i },
];

const SAMPLE_LOG = `198.51.100.12 - - [01/Aug/2026:09:14:02 +0800] "GET /products?id=1 HTTP/1.1" 200 4120
198.51.100.12 - - [01/Aug/2026:09:14:08 +0800] "GET /products?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 500 219
203.0.113.44 - - [01/Aug/2026:09:17:35 +0800] "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 3814
203.0.113.44 - - [01/Aug/2026:09:18:04 +0800] "GET /../../../../etc/passwd HTTP/1.1" 403 153
192.0.2.7 - - [01/Aug/2026:09:21:12 +0800] "GET /.git/config HTTP/1.1" 404 153
198.51.100.12 - - [01/Aug/2026:09:23:29 +0800] "GET /admin HTTP/1.1" 302 0
198.51.100.12 - - [01/Aug/2026:09:24:01 +0800] "POST /login HTTP/1.1" 401 242
198.51.100.12 - - [01/Aug/2026:09:24:11 +0800] "POST /login HTTP/1.1" 401 242
198.51.100.12 - - [01/Aug/2026:09:24:21 +0800] "POST /login HTTP/1.1" 302 0`;

function parseLine(raw: string): ParsedLog | null {
  const match = raw.match(/^(?<ip>\S+)\s+\S+\s+\S+\s+\[(?<timestamp>[^\]]+)\]\s+"(?<method>[A-Z]+)\s+(?<path>\S+)(?:\s+[^"\s]+)?"\s+(?<status>\d{3})/);
  if (!match?.groups) return null;
  return { ...match.groups, status: Number(match.groups.status), raw };
}

function analyze(text: string) {
  const lines = text.split(/\r?\n/).filter(Boolean);
  const parsed = lines.map(parseLine).filter((item): item is ParsedLog => item !== null);
  const findings: Finding[] = [];
  parsed.forEach((entry, index) => {
    RULES.forEach((rule) => {
      if (rule.pattern.test(decodeURIComponent(entry.path))) {
        findings.push({ id: index * 10 + findings.length, timestamp: entry.timestamp, ip: entry.ip, method: entry.method, path: entry.path, status: entry.status, category: rule.category, severity: rule.severity, evidence: entry.raw });
      }
    });
  });
  const loginAttempts = new Map<string, ParsedLog[]>();
  parsed.filter((entry) => /\/(?:login|auth|sign-in|wp-login)/i.test(entry.path)).forEach((entry) => {
    const attempts = loginAttempts.get(entry.ip) ?? [];
    attempts.push(entry);
    loginAttempts.set(entry.ip, attempts);
  });
  loginAttempts.forEach((attempts, ip) => {
    if (attempts.length >= 3) {
      const last = attempts[attempts.length - 1];
      findings.push({ id: 9000 + findings.length, timestamp: last.timestamp, ip, method: last.method, path: last.path, status: last.status, category: "Suspected credential attack", severity: "High", evidence: `${attempts.length} login requests from ${ip}; final response status ${last.status}.` });
    }
  });
  return { parsed, findings: findings.sort((a, b) => a.timestamp.localeCompare(b.timestamp)) };
}

const severityWeight = { Critical: 3, High: 2, Medium: 1 };

export default function Home() {
  const [content, setContent] = useState("");
  const [fileName, setFileName] = useState("No log loaded");
  const [selected, setSelected] = useState<"All" | Finding["severity"]>("All");
  const result = useMemo(() => analyze(content), [content]);
  const filtered = result.findings.filter((item) => selected === "All" || item.severity === selected);
  const topIps = useMemo(() => [...new Set(result.findings.map((item) => item.ip))].map((ip) => ({ ip, count: result.findings.filter((item) => item.ip === ip).length })).sort((a, b) => b.count - a.count).slice(0, 4), [result.findings]);
  const riskScore = Math.min(100, result.findings.reduce((score, item) => score + severityWeight[item.severity] * 9, 0));

  function loadText(text: string, name: string) { setContent(text); setFileName(name); }
  function onFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => loadText(String(reader.result ?? ""), file.name);
    reader.readAsText(file);
  }
  function downloadReport() {
    const body = [`# LogSleuth Investigation Report`, ``, `- Source: ${fileName}`, `- Parsed requests: ${result.parsed.length}`, `- Findings: ${result.findings.length}`, `- Risk score: ${riskScore}/100`, ``, `## Findings`, ...result.findings.map((item) => `- **${item.severity} · ${item.category}** — ${item.timestamp} — ${item.ip} — \`${item.method} ${item.path}\` (HTTP ${item.status})`)].join("\n");
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([body], { type: "text/markdown" }));
    link.download = "logsleuth-report.md";
    link.click();
    URL.revokeObjectURL(link.href);
  }

  return <main>
    <section className="hero">
      <div className="eyebrow"><span className="pulse" /> LOCAL-FIRST SECURITY INVESTIGATION</div>
      <h1>Find the story<br />hidden in your logs.</h1>
      <p>LogSleuth turns web-server logs into a concise attack timeline. Analysis happens in this browser—your evidence never leaves this device.</p>
      <div className="actions">
        <label className="button primary">Upload access log<input aria-label="Upload access log" type="file" accept=".log,.txt,text/plain" onChange={onFile} /></label>
        <button className="button" onClick={() => loadText(SAMPLE_LOG, "demo-access.log")}>Load safe demo</button>
      </div>
      <div className="scope-note">Built for investigation and defense · Apache / Nginx common-log format</div>
    </section>

    <section className="dashboard" aria-live="polite">
      <div className="source-row"><span className="source-dot" /> <strong>{fileName}</strong><span>{result.parsed.length.toLocaleString()} parsed requests</span><button className="report" disabled={!content} onClick={downloadReport}>Export Markdown report ↗</button></div>
      {!content ? <div className="empty"><div className="empty-mark">⌁</div><h2>Start with an access log</h2><p>Upload a file or load the included safe demo to explore the investigation workspace.</p></div> : <>
        <div className="metrics">
          <article><span>Risk score</span><strong className={riskScore > 60 ? "danger" : ""}>{riskScore}<small>/100</small></strong><em>{riskScore > 60 ? "Immediate review recommended" : "No critical pattern detected"}</em></article>
          <article><span>Security findings</span><strong>{result.findings.length}</strong><em>{new Set(result.findings.map((item) => item.category)).size} rule types matched</em></article>
          <article><span>Observed sources</span><strong>{topIps.length}</strong><em>IPs with suspicious activity</em></article>
          <article><span>Highest severity</span><strong className="severity-word">{result.findings[0]?.severity ?? "—"}</strong><em>Deterministic local rules</em></article>
        </div>
        <div className="grid">
          <article className="panel timeline"><div className="panel-head"><div><span className="label">Incident timeline</span><h2>Events worth investigating</h2></div><div className="filters">{(["All", "Critical", "High", "Medium"] as const).map((level) => <button key={level} className={selected === level ? "active" : ""} onClick={() => setSelected(level)}>{level}</button>)}</div></div>
            {filtered.length ? <ol>{filtered.map((item) => <li key={item.id}><span className={`severity ${item.severity.toLowerCase()}`}>{item.severity}</span><div><strong>{item.category}</strong><p><code>{item.method} {item.path}</code></p><small>{item.timestamp} · {item.ip} · HTTP {item.status}</small></div></li>)}</ol> : <p className="muted">No findings for this filter.</p>}
          </article>
          <article className="panel sources"><span className="label">Source concentration</span><h2>Suspicious activity by IP</h2>{topIps.length ? topIps.map((entry) => <div className="source" key={entry.ip}><div><code>{entry.ip}</code><span>{entry.count} finding{entry.count !== 1 ? "s" : ""}</span></div><div className="bar"><i style={{ width: `${(entry.count / topIps[0].count) * 100}%` }} /></div></div>) : <p className="muted">No matched indicators yet.</p>}<div className="method"><span className="label">How it works</span><p>Rules identify high-signal request patterns. Findings preserve the original request context so an analyst can verify each conclusion.</p></div></article>
        </div>
      </>}
    </section>
  </main>;
}
