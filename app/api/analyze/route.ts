type Provider = "openai" | "deepseek" | "qwen" | "kimi" | "custom";

const providerVariables: Record<Provider, { key: string; baseUrl: string; model: string }> = {
  openai: { key: "OPENAI_API_KEY", baseUrl: "OPENAI_BASE_URL", model: "OPENAI_MODEL" },
  deepseek: { key: "DEEPSEEK_API_KEY", baseUrl: "DEEPSEEK_BASE_URL", model: "DEEPSEEK_MODEL" },
  qwen: { key: "QWEN_API_KEY", baseUrl: "QWEN_BASE_URL", model: "QWEN_MODEL" },
  kimi: { key: "KIMI_API_KEY", baseUrl: "KIMI_BASE_URL", model: "KIMI_MODEL" },
  custom: { key: "CUSTOM_API_KEY", baseUrl: "CUSTOM_BASE_URL", model: "CUSTOM_MODEL" },
};

function isProvider(value: unknown): value is Provider {
  return typeof value === "string" && value in providerVariables;
}

export async function POST(request: Request) {
  try {
    const body = await request.json() as { provider?: unknown; findings?: unknown; sessions?: unknown; question?: unknown; history?: unknown; config?: { apiKey?: unknown; baseUrl?: unknown; model?: unknown } };
    if (!isProvider(body.provider) || !Array.isArray(body.findings)) {
      return Response.json({ error: "Invalid analysis request." }, { status: 400 });
    }

    const variables = providerVariables[body.provider];
    const suppliedKey = typeof body.config?.apiKey === "string" ? body.config.apiKey.trim() : "";
    const suppliedBaseUrl = typeof body.config?.baseUrl === "string" ? body.config.baseUrl.trim() : "";
    const suppliedModel = typeof body.config?.model === "string" ? body.config.model.trim() : "";
    const apiKey = suppliedKey || process.env[variables.key];
    const baseUrl = suppliedBaseUrl || process.env[variables.baseUrl];
    const model = suppliedModel || process.env[variables.model];
    if (!apiKey || !baseUrl || !model) {
      return Response.json({ error: `Provider '${body.provider}' is not configured on this server.` }, { status: 503 });
    }

    let configuredUrl: URL;
    try {
      configuredUrl = new URL(baseUrl);
    } catch {
      return Response.json({ error: "The API base URL is invalid." }, { status: 400 });
    }
    const localHttp = configuredUrl.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(configuredUrl.hostname);
    if (configuredUrl.username || configuredUrl.password || (configuredUrl.protocol !== "https:" && !localHttp)) {
      return Response.json({ error: "Use HTTPS for remote APIs; HTTP is allowed only for localhost." }, { status: 400 });
    }
    if (apiKey.length > 4096 || model.length > 200 || baseUrl.length > 1000) {
      return Response.json({ error: "The API configuration is too long." }, { status: 400 });
    }

    const findings = body.findings.slice(0, 80).map((finding) => ({
      id: Number(finding?.id ?? 0),
      severity: String(finding?.severity ?? "Unknown").slice(0, 16),
      category: String(finding?.category ?? "Unknown").slice(0, 100),
      timestamp: String(finding?.timestamp ?? "Unknown").slice(0, 80),
      ip: String(finding?.ip ?? "Unknown").slice(0, 100),
      method: String(finding?.method ?? "").slice(0, 12),
      path: String(finding?.path ?? "").slice(0, 500),
      status: Number(finding?.status ?? 0),
    }));
    const sessions = Array.isArray(body.sessions) ? body.sessions.slice(0, 20) : [];
    const history = Array.isArray(body.history) ? body.history.slice(-8).flatMap((message) => {
      const role = message?.role === "user" || message?.role === "assistant" ? message.role : null;
      const content = typeof message?.content === "string" ? message.content.slice(0, 4000) : "";
      return role && content ? [{ role, content }] : [];
    }) : [];
    const question = typeof body.question === "string" && body.question.trim() ? body.question.trim().slice(0, 2000) : "生成首次调查报告，包括事件摘要、攻击会话、关键证据、可信度、限制和安全的下一步调查建议。";

    const endpoint = new URL("chat/completions", baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`);
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model,
        temperature: 0.2,
        messages: [
          { role: "system", content: "You are LogSleuth, a defensive investigation agent. Base every conclusion only on supplied evidence. Cite findings as [E#id] and correlated sessions as [S#id]. Never invent citations. Separate fact, inference, confidence, and limitations. Do not provide exploit instructions. Respond in Chinese unless asked otherwise." },
          { role: "user", content: `Investigation context. Findings are leads, not proof of compromise.\nFINDINGS:\n${JSON.stringify(findings)}\nCORRELATED SESSIONS:\n${JSON.stringify(sessions)}` },
          ...history,
          { role: "user", content: question },
        ],
      }),
    });

    if (!response.ok) {
      return Response.json({ error: "The configured AI provider rejected the request." }, { status: 502 });
    }
    const result = await response.json() as { choices?: Array<{ message?: { content?: string } }> };
    const analysis = result.choices?.[0]?.message?.content;
    if (!analysis) return Response.json({ error: "The AI provider returned no analysis." }, { status: 502 });
    return Response.json({ analysis });
  } catch {
    return Response.json({ error: "Unable to complete AI analysis." }, { status: 500 });
  }
}
