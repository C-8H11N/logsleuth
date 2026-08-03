"use client";

import { ChangeEvent, useEffect, useMemo, useState } from "react";
import { parseCapture, type PcapResult } from "./pcapng";
import { analyzeLog, type Finding } from "./log-analyzer";
import { correlateSessions, type AttackSession } from "./attack-sessions";

type Provider = "openai" | "deepseek" | "qwen" | "kimi" | "custom";
type ApiConfig = { apiKey: string; baseUrl: string; model: string };
type BackendLogResult = { parsedCount: number; unreadableLines: number; findings: Finding[]; sessions?: AttackSession[] };
type ChatEntry = { role: "user" | "assistant"; content: string };

const GO_ENGINE = "http://127.0.0.1:8787";

const EMPTY_CONFIGS: Record<Provider, ApiConfig> = {
  openai: { apiKey: "", baseUrl: "", model: "" },
  deepseek: { apiKey: "", baseUrl: "", model: "" },
  qwen: { apiKey: "", baseUrl: "", model: "" },
  kimi: { apiKey: "", baseUrl: "", model: "" },
  custom: { apiKey: "", baseUrl: "", model: "" },
};

function groupConsecutive(findings: Finding[]) {
  return findings.reduce<Array<{ key: string; items: Finding[] }>>((groups, finding) => {
    const key = `${finding.severity}|${finding.category}|${finding.ip}`;
    const last = groups[groups.length - 1];
    if (last?.key === key) last.items.push(finding);
    else groups.push({ key, items: [finding] });
    return groups;
  }, []);
}

const SAMPLE_LOG = `198.51.100.12 - - [01/Aug/2026:09:14:02 +0800] "GET /products?id=1 HTTP/1.1" 200 4120
198.51.100.12 - - [01/Aug/2026:09:14:08 +0800] "GET /products?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 500 219
203.0.113.44 - - [01/Aug/2026:09:17:35 +0800] "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 3814
203.0.113.44 - - [01/Aug/2026:09:18:04 +0800] "GET /../../../../etc/passwd HTTP/1.1" 403 153
192.0.2.7 - - [01/Aug/2026:09:21:12 +0800] "GET /.git/config HTTP/1.1" 404 153
198.51.100.12 - - [01/Aug/2026:09:23:29 +0800] "GET /admin HTTP/1.1" 302 0
198.51.100.12 - - [01/Aug/2026:09:24:01 +0800] "POST /login HTTP/1.1" 401 242
198.51.100.12 - - [01/Aug/2026:09:24:11 +0800] "POST /login HTTP/1.1" 401 242
198.51.100.12 - - [01/Aug/2026:09:24:21 +0800] "POST /login HTTP/1.1" 302 0`;

const severityWeight = { Critical: 3, High: 2, Medium: 1 };

const zhCategories: Record<string, string> = {
  "SQL injection": "SQL 注入",
  "Cross-site scripting": "跨站脚本（XSS）",
  "Path traversal": "目录穿越",
  "Sensitive-file probing": "敏感文件探测",
  "Command-injection probe": "命令注入探测",
  "Suspected credential attack": "疑似凭据攻击",
  "Log4Shell/JNDI probe": "Log4Shell/JNDI 探测",
  "Web shell probing": "WebShell 探测",
  "SSRF probe": "SSRF 探测",
};
const zhStages:Record<string,string>={"Reconnaissance":"侦察","Credential Access":"凭据访问","Persistence":"持久化","Exploitation":"利用尝试","Suspicious Activity":"可疑活动"};

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
  const [pcapResult, setPcapResult] = useState<PcapResult | null>(null);
  const [backendResult, setBackendResult] = useState<BackendLogResult | null>(null);
  const [fileName, setFileName] = useState("");
  const [selected, setSelected] = useState<"All" | Finding["severity"]>("All");
  const [language, setLanguage] = useState<"en" | "zh">("zh");
  const [provider, setProvider] = useState<Provider>("openai");
  const [apiConfigs, setApiConfigs] = useState<Record<Provider, ApiConfig>>(EMPTY_CONFIGS);
  const [agentMessages, setAgentMessages] = useState<ChatEntry[]>([]);
  const [agentQuestion, setAgentQuestion] = useState("");
  const [agentError, setAgentError] = useState("");
  const [agentLoading, setAgentLoading] = useState(false);
  const [fileLoading, setFileLoading] = useState(false);
  const [engineOnline, setEngineOnline] = useState(false);
  const t = copy[language];
  const textResult = useMemo(() => analyzeLog(content), [content]);
  const result = useMemo(() => pcapResult ? { parsed: Array(pcapResult.packets).fill({}), findings: pcapResult.findings } : backendResult ? { parsed: Array(backendResult.parsedCount).fill({}), findings: backendResult.findings } : textResult, [pcapResult, backendResult, textResult]);
  const filtered = useMemo(() => result.findings.filter((item) => selected === "All" || item.severity === selected), [result.findings, selected]);
  const groupedFindings = useMemo(() => groupConsecutive(filtered), [filtered]);
  const topIps = useMemo(() => [...new Set(result.findings.map((item) => item.ip))].map((ip) => ({ ip, count: result.findings.filter((item) => item.ip === ip).length })).sort((a, b) => b.count - a.count).slice(0, 4), [result.findings]);
  const riskScore = Math.min(100, result.findings.reduce((score, item) => score + severityWeight[item.severity] * 9, 0));
  const attackSessions = useMemo(() => backendResult?.sessions?.length ? backendResult.sessions : correlateSessions(result.findings), [backendResult, result.findings]);

  useEffect(() => {
    const controller = new AbortController();
    fetch(`${GO_ENGINE}/api/v1/health`, { signal: controller.signal }).then((response) => setEngineOnline(response.ok)).catch(() => setEngineOnline(false));
    return () => controller.abort();
  }, []);

  function resetAgent() { setAgentMessages([]); setAgentQuestion(""); setAgentError(""); }
  function loadText(text: string, name: string) { setPcapResult(null); setBackendResult(null); setContent(text); setFileName(name); resetAgent(); }
  function readLogInBrowser(file: File) {
    const reader = new FileReader();
    reader.onload = () => { loadText(String(reader.result ?? ""), file.name); setFileLoading(false); };
    reader.onerror = () => { setAgentError("日志文件读取失败，请确认文件未被其他程序锁定后重试。"); setFileLoading(false); };
    reader.readAsText(file);
  }
  function onFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    if (/\.pcap(?:ng)?$/i.test(file.name)) {
      const sampleLimit = 32 * 1024 * 1024;
      file.slice(0, sampleLimit).arrayBuffer().then((data) => {
        const parsed = parseCapture(data, file.size > sampleLimit);
        setContent("");
        setBackendResult(null);
        setPcapResult(parsed);
        setFileName(file.name);
        resetAgent();
      }).catch((error) => setAgentError(error instanceof Error ? error.message : "抓包解析失败。"));
      return;
    }
    setFileLoading(true);
    const form = new FormData();
    form.append("file", file);
    fetch(`${GO_ENGINE}/api/v1/analyze/log`, { method: "POST", body: form }).then(async (response) => {
      if (!response.ok) throw new Error("Go engine rejected the log.");
      const parsed = await response.json() as BackendLogResult;
      if (!Array.isArray(parsed.findings) || !Number.isFinite(parsed.parsedCount)) throw new Error("Invalid Go engine response.");
      setPcapResult(null); setBackendResult(parsed); setContent("__GO_ENGINE_RESULT__"); setFileName(file.name); resetAgent(); setEngineOnline(true); setFileLoading(false);
    }).catch(() => readLogInBrowser(file));
  }
  function downloadReport() {
    const body = [`# ${t.reportTitle}`, ``, `- ${t.source}: ${fileName}`, `- ${t.parsed}: ${result.parsed.length}`, `- ${t.reportFindings}: ${result.findings.length}`, `- ${t.reportRisk}: ${riskScore}/100`, ``, `## ${t.reportSection}`, ...result.findings.map((item) => `- **${item.severity} · ${language === "zh" ? zhCategories[item.category] : item.category}** — ${item.timestamp} — ${item.ip} — \`${item.method} ${item.path}\` (HTTP ${item.status})`)].join("\n");
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([body], { type: "text/markdown" }));
    link.download = "logsleuth-report.md";
    link.click();
    URL.revokeObjectURL(link.href);
  }
  function updateApiConfig(field: keyof ApiConfig, value: string) {
    setApiConfigs((current) => ({ ...current, [provider]: { ...current[provider], [field]: value } }));
  }
  function focusEvidence(id: number) {
    setSelected("All");
    const groupIndex = groupConsecutive(result.findings).findIndex((candidate) => candidate.items.some((item) => item.id === id));
    if (groupIndex >= 0) setTimeout(() => document.querySelectorAll(".timeline li")[groupIndex]?.scrollIntoView({ behavior: "smooth", block: "center" }), 0);
  }
  function renderAgentText(content: string) {
    return content.split(/(\[E#\d+\]|\[S#\d+\])/g).map((part, index) => {
      const evidence = part.match(/^\[E#(\d+)\]$/); if (evidence) return <button type="button" className="citation" key={`${part}-${index}`} onClick={() => focusEvidence(Number(evidence[1]))}>{part}</button>;
      const session = part.match(/^\[S#(\d+)\]$/); if (session) return <button type="button" className="citation session-citation" key={`${part}-${index}`} onClick={() => document.getElementById(`attack-session-${session[1]}`)?.scrollIntoView({ behavior: "smooth", block: "center" })}>{part}</button>;
      return part;
    });
  }
  async function runAgent(question?: string) {
    const prompt = question?.trim() || "生成首次调查报告，包括攻击会话、关键证据、可信度、限制和下一步建议。";
    const history = agentMessages;
    setAgentError(""); setAgentMessages((current) => [...current, { role: "user", content: prompt }]); setAgentQuestion(""); setAgentLoading(true);
    try {
      const request = { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ provider, findings: result.findings, sessions: attackSessions, question: prompt, history, config: apiConfigs[provider] }) };
      let response: Response;
      try {
        response = await fetch(`${GO_ENGINE}/api/v1/agent/analyze`, request);
        setEngineOnline(true);
      } catch {
        response = await fetch("/api/analyze", request);
      }
      const data = await response.json() as { analysis?: string; error?: string };
      if (!response.ok || !data.analysis) throw new Error(data.error ?? "AI analysis failed.");
      setAgentMessages((current) => [...current, { role: "assistant", content: data.analysis! }]);
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
        <label className="button primary">{fileLoading ? "正在分析…" : t.upload}<input aria-label={t.upload} disabled={fileLoading} type="file" accept=".log,.txt,.pcap,.pcapng,text/plain,application/vnd.tcpdump.pcap" onChange={onFile} /></label>
        <button className="button" onClick={() => loadText(SAMPLE_LOG, "demo-access.log")}>{t.demo}</button>
      </div>
      <div className="scope-note">{t.scope} · 支持 `.pcap` / `.pcapng` 基础网络取证</div>
    </section>

    <section className="dashboard" aria-live="polite">
      <div className="source-row"><span className="source-dot" /> <strong>{fileName || t.noLog}</strong><span>{result.parsed.length.toLocaleString()} {pcapResult?"个网络包":t.requests}</span>{backendResult && <span>{backendResult.unreadableLines.toLocaleString()} 行未识别</span>}<span className={`engine-state ${engineOnline ? "online" : "fallback"}`}>{engineOnline ? "GO ENGINE" : "BROWSER MODE"}</span><button className="report" disabled={!content&&!pcapResult} onClick={downloadReport}>{t.export}</button></div>
      {!content&&!pcapResult ? <div className="empty"><div className="empty-mark">⌁</div><h2>{t.start}</h2><p>{t.empty} 也可上传 `.pcap` / `.pcapng` 抓包文件。</p></div> : <>
        <div className="metrics">
          <article><span>{t.risk}</span><strong className={riskScore > 60 ? "danger" : ""}>{riskScore}<small>/100</small></strong><em>{riskScore > 60 ? t.review : t.safe}</em></article>
          <article><span>{t.findings}</span><strong>{result.findings.length}</strong><em>{new Set(result.findings.map((item) => item.category)).size} {t.ruleTypes}</em></article>
          <article><span>{t.sources}</span><strong>{topIps.length}</strong><em>{t.sourceHint}</em></article>
          <article><span>{t.highest}</span><strong className="severity-word">{result.findings[0]?.severity ?? "—"}</strong><em>{t.localRules}</em></article>
        </div>
        {pcapResult && <article className="panel pcap-summary"><div><span className="label">{pcapResult.format} 流量基线{pcapResult.sampled ? ` · 前 ${(pcapResult.analyzedBytes / 1024 / 1024).toFixed(0)} MiB 采样` : ""}</span><h2>{pcapResult.findings.length ? "已发现需要调查的网络活动" : "解析成功，当前规则未发现明显异常"}</h2></div><div className="pcap-counters"><span><strong>{pcapResult.stats.ipv4}</strong>IPv4</span><span><strong>{pcapResult.stats.tcp}</strong>TCP</span><span><strong>{pcapResult.stats.udp}</strong>UDP</span><span><strong>{pcapResult.stats.dns}</strong>DNS</span><span><strong>{pcapResult.stats.http}</strong>HTTP</span><span><strong>{pcapResult.stats.hosts}</strong>主机</span></div></article>}
        {attackSessions.length > 0 && <article className="panel session-panel"><div className="panel-head"><div><span className="label">CORRELATED ATTACK SESSIONS</span><h2>{language === "zh" ? "自动关联的攻击会话" : "Correlated attack sessions"}</h2></div><span className="session-total">{attackSessions.length} {language === "zh" ? "个会话" : "sessions"}</span></div><p className="muted session-note">{language === "zh" ? "按来源 IP 和 30 分钟活动窗口关联。可信度表示行为相关程度，不代表攻击已经成功。" : "Grouped by source IP and a 30-minute activity window. Confidence measures correlation, not successful compromise."}</p><div className="session-grid">{attackSessions.slice(0,8).map((session)=><details className="session-card" id={`attack-session-${session.id}`} key={session.id}><summary><span className={`severity ${session.severity.toLowerCase()}`}>{session.severity}</span><div><strong>S#{session.id} · <code>{session.ip}</code></strong><small>{session.startedAt} → {session.endedAt}</small></div><span className="confidence"><b>{session.confidence}%</b>{language === "zh" ? "关联度" : "confidence"}</span></summary><div className="session-body"><div className="stage-list">{session.stages.map((stage)=><span key={stage}>{language === "zh" ? zhStages[stage] ?? stage : stage}</span>)}</div><p>{session.count} {language === "zh" ? "条关联证据" : "correlated findings"}</p><div className="evidence-links">{session.evidenceIds.slice(0,12).map((id)=><button type="button" onClick={()=>focusEvidence(id)} key={id}>E#{id}</button>)}{session.evidenceIds.length>12&&<span>+{session.evidenceIds.length-12}</span>}</div></div></details>)}</div>{attackSessions.length>8&&<p className="muted session-more">{language === "zh" ? `当前展示关联度最高的 8 个会话，其余 ${attackSessions.length-8} 个会话仍会提供给 Agent。` : `Showing the top 8 sessions; ${attackSessions.length-8} more remain available to the agent.`}</p>}</article>}
        <div className="grid">
          <article className="panel timeline"><div className="panel-head"><div><span className="label">{t.timeline}</span><h2>{t.events}</h2></div><div className="filters">{(["All", "Critical", "High", "Medium"] as const).map((level) => <button key={level} className={selected === level ? "active" : ""} onClick={() => setSelected(level)}>{level}</button>)}</div></div>
            {groupedFindings.length ? <ol>{groupedFindings.map((group) => {
              const item = group.items[0];
              const title = language === "zh" ? zhCategories[item.category] : item.category;
              return <li key={`${group.key}-${item.id}`} className={group.items.length > 1 ? "finding-group" : ""}><span className={`severity ${item.severity.toLowerCase()}`}>{item.severity}</span><div>{group.items.length > 1 ? <details><summary><strong>{title}</strong><span className="repeat-count">{language === "zh" ? `连续 ${group.items.length} 条` : `${group.items.length} consecutive`}</span><p><code>{item.method} {item.path}</code></p><small>{item.timestamp} → {group.items[group.items.length - 1].timestamp} · {item.ip}</small></summary><div className="repeat-items">{group.items.slice(0, 30).map((entry) => <p key={entry.id}><code>{entry.method} {entry.path}</code><small>{entry.timestamp} · HTTP {entry.status}</small></p>)}{group.items.length > 30 && <p className="muted">{language === "zh" ? `其余 ${group.items.length - 30} 条已省略，可在导出报告中查看。` : `${group.items.length - 30} more are available in the exported report.`}</p>}</div></details> : <><strong>{title}</strong><p><code>{item.method} {item.path}</code></p><small>{item.timestamp} · {item.ip} · HTTP {item.status}</small></>}</div></li>;
            })}</ol> : <p className="muted">{t.noFindings}</p>}
          </article>
          <article className="panel sources"><span className="label">{t.concentration}</span><h2>{t.suspicious}</h2>{topIps.length ? topIps.map((entry) => <div className="source" key={entry.ip}><div><code>{entry.ip}</code><span>{entry.count} {t.finding}</span></div><div className="bar"><i style={{ width: `${(entry.count / topIps[0].count) * 100}%` }} /></div></div>) : <p className="muted">{t.noIndicators}</p>}<div className="method"><span className="label">{t.how}</span><p>{t.method}</p></div></article>
        </div>
        <article className="panel agent">
          <div><span className="label">CONVERSATIONAL INVESTIGATION AGENT</span><h2>与证据对话，持续追问攻击过程</h2><p className="muted">Agent 只基于本地规则发现和攻击会话回答。引用 `[E#]` 可定位证据，引用 `[S#]` 可定位攻击会话；结论仍需人工复核。</p></div>
          <div className="agent-controls"><select aria-label="选择 AI 供应商" value={provider} onChange={(event) => setProvider(event.target.value as Provider)}><option value="openai">OpenAI</option><option value="deepseek">DeepSeek</option><option value="qwen">通义千问</option><option value="kimi">Kimi</option><option value="custom">自定义兼容 API</option></select><button className="button primary" disabled={agentLoading || !result.findings.length} onClick={()=>runAgent()}>{agentLoading ? "正在研判…" : agentMessages.length ? "重新生成调查报告" : "生成首次调查报告"}</button></div>
          <details className="api-config"><summary>在页面中配置 API（仅本次会话）</summary><div className="api-fields"><label>API Key<input type="password" value={apiConfigs[provider].apiKey} autoComplete="off" spellCheck={false} onChange={(event) => updateApiConfig("apiKey", event.target.value)} placeholder="sk-…" /></label><label>Base URL<input type="url" value={apiConfigs[provider].baseUrl} spellCheck={false} onChange={(event) => updateApiConfig("baseUrl", event.target.value)} placeholder="https://api.example.com/v1" /></label><label>模型名称<input type="text" value={apiConfigs[provider].model} spellCheck={false} onChange={(event) => updateApiConfig("model", event.target.value)} placeholder="model-name" /></label></div><p className="config-note">远程接口必须使用 HTTPS；本机接口可使用 localhost。配置不会写入磁盘。</p></details>
          {agentMessages.length>0&&<div className="agent-transcript" aria-live="polite">{agentMessages.map((message,index)=><div className={`chat-message ${message.role}`} key={`${message.role}-${index}`}><span>{message.role==="assistant"?"AGENT":"YOU"}</span><div>{message.role==="assistant"?renderAgentText(message.content):message.content}</div></div>)}{agentLoading&&<div className="chat-message assistant pending"><span>AGENT</span><div>正在核对证据并组织回答…</div></div>}</div>}
          <form className="agent-question" onSubmit={(event)=>{event.preventDefault();if(agentQuestion.trim()&&!agentLoading)runAgent(agentQuestion);}}><label htmlFor="agent-question">继续追问</label><div><input id="agent-question" value={agentQuestion} onChange={(event)=>setAgentQuestion(event.target.value)} disabled={agentLoading||!result.findings.length} placeholder="例如：哪些请求可能成功？请引用证据。"/><button className="button primary" disabled={agentLoading||!agentQuestion.trim()||!result.findings.length} type="submit">发送</button></div></form>
          {agentError && <p className="agent-error">{agentError}</p>}
        </article>
      </>}
    </section>
  </main>;
}
