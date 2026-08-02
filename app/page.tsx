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

type Provider = "openai" | "deepseek" | "qwen" | "kimi" | "custom";

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

const zhCategories: Record<string, string> = {
  "SQL injection": "SQL 注入",
  "Cross-site scripting": "跨站脚本（XSS）",
  "Path traversal": "目录穿越",
  "Sensitive-file probing": "敏感文件探测",
  "Command-injection probe": "命令注入探测",
  "Suspected credential attack": "疑似凭据攻击",
};

const copy = {
  en: {
    eyebrow: "LOCAL-FIRST SECURITY INVESTIGATION", hero: <>Find the story<br />hidden in your logs.</>, intro: "LogSleuth turns web-server logs into a concise attack timeline. Analysis happens in this browser—your evidence never leaves this device.", upload: "Upload access log", demo: "Load safe demo", scope: "Built for investigation and defense · Apache / Nginx common-log format", noLog: "No log loaded", requests: "parsed requests", export: "Export Markdown report ↗", start: "Start with an access log", empty: "Upload a file or load the included safe demo to explore the investigation workspace.", risk: "Risk score", review: "Immediate review recommended", safe: "No critical pattern detected", findings: "Security findings", ruleTypes: "rule types matched", sources: "Observed sources", sourceHint: "IPs with suspicious activity", highest: "Highest severity", localRules: "Deterministic local rules", timeline: "Incident timeline", events: "Events worth investigating", noFindings: "No findings for this filter.", concentration: "Source concentration", suspicious: "Suspicious activity by IP", noIndicators: "No matched indicators yet.", how: "How it works", method: "Rules identify high-signal request patterns. Findings preserve the original request context so an analyst can verify each conclusion.", finding: "finding", source: "Source", reportTitle: "LogSleuth Investigation Report", parsed: "Parsed requests", reportFindings: "Findings", reportRisk: "Risk score", reportSection: "Findings",
  },
  zh: {
    eyebrow: "本地优先安全调查", hero: <>从日志中找出<br />攻击故事。</>, intro: "LogSleuth 将 Web 服务器日志转化为清晰的攻击时间线。分析完全在当前浏览器中完成，证据不会离开本设备。", upload: "上传访问日志", demo: "加载安全演示", scope: "用于安全调查与防御 · 支持 Apache / Nginx 常见日志格式", noLog: "尚未加载日志", requests: "条已解析请求", export: "导出 Markdown 报告 ↗", start: "从访问日志开始", empty: "上传日志文件，或加载内置安全演示，开始探索调查工作区。", risk: "风险评分", review: "建议立即人工复核", safe: "未发现严重攻击模式", findings: "安全发现", ruleTypes: "类规则命中", sources: "观察到的来源", sourceHint: "存在可疑活动的 IP", highest: "最高严重性", localRules: "确定性本地规则", timeline: "事件时间线", events: "值得调查的事件", noFindings: "当前筛选条件下没有发现。", concentration: "来源集中度", suspicious: "按 IP 统计的可疑活动", noIndicators: "尚未命中任何检测指标。", how: "工作原理", method: "规则识别高信号请求模式，并保留原始请求上下文，便于分析人员逐项核实结论。", finding: "项发现", source: "来源", reportTitle: "LogSleuth 调查报告", parsed: "已解析请求", reportFindings: "安全发现", reportRisk: "风险评分", reportSection: "发现详情",
  },
};

export default function Home() {
  const [content, setContent] = useState("");
  const [fileName, setFileName] = useState("");
  const [selected, setSelected] = useState<"All" | Finding["severity"]>("All");
  const [language, setLanguage] = useState<"en" | "zh">("zh");
  const [provider, setProvider] = useState<Provider>("openai");
  const [agentReport, setAgentReport] = useState("");
  const [agentError, setAgentError] = useState("");
  const [agentLoading, setAgentLoading] = useState(false);
  const t = copy[language];
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
    const body = [`# ${t.reportTitle}`, ``, `- ${t.source}: ${fileName}`, `- ${t.parsed}: ${result.parsed.length}`, `- ${t.reportFindings}: ${result.findings.length}`, `- ${t.reportRisk}: ${riskScore}/100`, ``, `## ${t.reportSection}`, ...result.findings.map((item) => `- **${item.severity} · ${language === "zh" ? zhCategories[item.category] : item.category}** — ${item.timestamp} — ${item.ip} — \`${item.method} ${item.path}\` (HTTP ${item.status})`)].join("\n");
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([body], { type: "text/markdown" }));
    link.download = "logsleuth-report.md";
    link.click();
    URL.revokeObjectURL(link.href);
  }
  async function runAgent() {
    setAgentError(""); setAgentReport(""); setAgentLoading(true);
    try {
      const response = await fetch("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ provider, findings: result.findings }) });
      const data = await response.json() as { analysis?: string; error?: string };
      if (!response.ok || !data.analysis) throw new Error(data.error ?? "AI analysis failed.");
      setAgentReport(data.analysis);
    } catch (error) {
      setAgentError(error instanceof Error ? error.message : "AI analysis failed.");
    } finally { setAgentLoading(false); }
  }

  return <main>
    <section className="hero">
      <button className="language" onClick={() => setLanguage(language === "en" ? "zh" : "en")}>{language === "en" ? "中文" : "EN"}</button>
      <div className="eyebrow"><span className="pulse" /> {t.eyebrow}</div>
      <h1>{t.hero}</h1>
      <p>{t.intro}</p>
      <div className="actions">
        <label className="button primary">{t.upload}<input aria-label={t.upload} type="file" accept=".log,.txt,text/plain" onChange={onFile} /></label>
        <button className="button" onClick={() => loadText(SAMPLE_LOG, "demo-access.log")}>{t.demo}</button>
      </div>
      <div className="scope-note">{t.scope}</div>
    </section>

    <section className="dashboard" aria-live="polite">
      <div className="source-row"><span className="source-dot" /> <strong>{fileName || t.noLog}</strong><span>{result.parsed.length.toLocaleString()} {t.requests}</span><button className="report" disabled={!content} onClick={downloadReport}>{t.export}</button></div>
      {!content ? <div className="empty"><div className="empty-mark">⌁</div><h2>{t.start}</h2><p>{t.empty}</p></div> : <>
        <div className="metrics">
          <article><span>{t.risk}</span><strong className={riskScore > 60 ? "danger" : ""}>{riskScore}<small>/100</small></strong><em>{riskScore > 60 ? t.review : t.safe}</em></article>
          <article><span>{t.findings}</span><strong>{result.findings.length}</strong><em>{new Set(result.findings.map((item) => item.category)).size} {t.ruleTypes}</em></article>
          <article><span>{t.sources}</span><strong>{topIps.length}</strong><em>{t.sourceHint}</em></article>
          <article><span>{t.highest}</span><strong className="severity-word">{result.findings[0]?.severity ?? "—"}</strong><em>{t.localRules}</em></article>
        </div>
        <div className="grid">
          <article className="panel timeline"><div className="panel-head"><div><span className="label">{t.timeline}</span><h2>{t.events}</h2></div><div className="filters">{(["All", "Critical", "High", "Medium"] as const).map((level) => <button key={level} className={selected === level ? "active" : ""} onClick={() => setSelected(level)}>{level}</button>)}</div></div>
            {filtered.length ? <ol>{filtered.map((item) => <li key={item.id}><span className={`severity ${item.severity.toLowerCase()}`}>{item.severity}</span><div><strong>{language === "zh" ? zhCategories[item.category] : item.category}</strong><p><code>{item.method} {item.path}</code></p><small>{item.timestamp} · {item.ip} · HTTP {item.status}</small></div></li>)}</ol> : <p className="muted">{t.noFindings}</p>}
          </article>
          <article className="panel sources"><span className="label">{t.concentration}</span><h2>{t.suspicious}</h2>{topIps.length ? topIps.map((entry) => <div className="source" key={entry.ip}><div><code>{entry.ip}</code><span>{entry.count} {t.finding}</span></div><div className="bar"><i style={{ width: `${(entry.count / topIps[0].count) * 100}%` }} /></div></div>) : <p className="muted">{t.noIndicators}</p>}<div className="method"><span className="label">{t.how}</span><p>{t.method}</p></div></article>
        </div>
        <article className="panel agent"><div><span className="label">AI AGENT · OPTIONAL</span><h2>AI 安全研判</h2><p className="muted">仅发送已结构化的规则命中结果；原始日志不会发送给模型。未配置 API 时，本地规则模式仍可正常使用。</p></div><div className="agent-controls"><select aria-label="选择 AI 供应商" value={provider} onChange={(event) => setProvider(event.target.value as Provider)}><option value="openai">OpenAI</option><option value="deepseek">DeepSeek</option><option value="qwen">通义千问</option><option value="kimi">Kimi</option><option value="custom">自定义兼容 API</option></select><button className="button primary" disabled={agentLoading || !result.findings.length} onClick={runAgent}>{agentLoading ? "正在研判…" : "生成 AI 调查摘要"}</button></div>{agentError && <p className="agent-error">{agentError} 请在服务端 `.env` 中配置该供应商。</p>}{agentReport && <div className="agent-report">{agentReport}</div>}</article>
      </>}
    </section>
  </main>;
}
