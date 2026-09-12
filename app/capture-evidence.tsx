import type { PcapResult } from "./pcapng";

export function CaptureEvidencePanel({ result, language }: { result: PcapResult; language: "zh" | "en" }) {
  const zh = language === "zh";
  const framing = { complete: zh ? "边界完整" : "Complete framing", incomplete: zh ? "内容不完整" : "Incomplete", unsupported: zh ? "边界未支持/有歧义" : "Unsupported / ambiguous" };
  return <article className="panel session-panel capture-evidence-panel" aria-label={zh ? "HTTP 包级证据" : "HTTP packet evidence"}>
    <div className="panel-head"><h2>{zh ? "HTTP 请求与响应证据" : "HTTP request and response evidence"}</h2><span>{result.httpAnalysis.paired} {zh ? "组推断关联" : "inferred pairs"}</span></div>
    <p className="muted">{zh ? "仅配对同一连接中边界清楚的单次请求/响应。关联和状态码不代表攻击成功。包编号按原始抓包顺序，引用范围为重组窗口（可能包含重传及多个消息）。" : "Only unambiguous single-request/response connections are paired. Association and status codes do not prove compromise. Packet numbers follow capture order; references cover the reconstruction window and may include retransmissions and multiple messages."}</p>
    <p>{result.httpAnalysis.requests} {zh ? "个请求" : "requests"} · {result.httpAnalysis.responses} {zh ? "个响应" : "responses"} · {result.httpAnalysis.incomplete + result.httpAnalysis.unsupported} {zh ? "项解析限制" : "framing limitations"}</p>
    {!result.httpObservations.length && <p className="muted">{zh ? "没有可展示的明文 HTTP/1.x 消息；不代表流量安全。" : "No plaintext HTTP/1.x messages available; this does not establish safety."}</p>}
    <div className="session-grid">{result.httpObservations.slice(0, 12).map((item) => <details className="session-card" key={item.id}>
      <summary><div><strong>H#{item.id} · {item.kind === "request" ? item.method : `HTTP ${item.status}`}</strong><small>{item.association === "inferred" ? (zh ? `推断关联 H#${item.peerId}` : `Inferred pair H#${item.peerId}`) : (zh ? "未配对 / 待复核" : "Unpaired / review required")}</small></div></summary>
      <div className="session-body">
        <p><code>{item.connection}</code></p>
        {item.path && <p><code>{item.path}</code></p>}
        <p>{framing[item.framing]} · {item.timestamp ?? (zh ? "时间未知" : "Unknown time")}</p>
        <p>{zh ? "接口范围" : "Interface scope"}: {item.scope}</p>
        <p>{zh ? "窗口包编号范围（非连续清单）" : "Window packet range (not a contiguous list)"}: {item.evidence.firstPacket}–{item.evidence.lastPacket}</p>
        <p>{zh ? "证据包样本" : "Evidence packet samples"}: {item.evidence.packets.map((packet) => `#${packet.packet}`).join(", ")}</p>
        {item.evidence.packetCount > item.evidence.packets.length && <p>{zh ? "包引用仅保留前 64 个样本" : "Packet references capped at the first 64 samples"}</p>}
        {item.evidence.uncertain && <p>{zh ? "存在缺口、冲突或窗口限制，需人工核对原始抓包。" : "Gaps, conflicts or window limits require review of the original capture."}</p>}
      </div>
    </details>)}</div>
    {result.httpObservations.length > 12 && <p className="muted">{zh ? "页面只显示前 12 项，保留的完整列表可导出调查 JSON 查看。" : "Showing the first 12 items; export investigation JSON for all retained observations."}</p>}
  </article>;
}
