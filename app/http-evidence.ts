import type { StreamEvidence } from "./tcp-reassembly.ts";

export type HttpObservation = {
  id: number;
  connection: string;
  scope: string;
  kind: "request" | "response";
  method: string;
  path: string;
  status: number;
  timestamp: string | null;
  evidence: StreamEvidence;
  suspicious: boolean;
  framing: "complete" | "incomplete" | "unsupported";
  association: "inferred" | "unpaired";
  peerId: number | null;
};

const decoder = new TextDecoder("latin1");
const requestLine = /^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) ([^\s]+) HTTP\/1\.[01]$/;
const responseLine = /^HTTP\/1\.[01] ([1-5]\d{2})(?: [^\r\n]*)?$/;
const suspiciousPattern = /union\s+(?:all\s+)?select|<script\b|(?:\.\.\/){2,}|(?:%2e){2}%2f|(?:cmd|powershell)(?:\.exe)?\b/i;

function safePath(target: string) {
  // Do not persist query values, fragments or URL userinfo in reports / model context.
  const path = target.replace(/^https?:\/\/[^/]+/i, "").split(/[?#]/, 1)[0];
  return (path || "/").slice(0, 512) + (target.includes("?") ? "?[REDACTED]" : "");
}

export class HttpEvidence {
  readonly observations: HttpObservation[] = [];
  readonly stats = { requests: 0, responses: 0, paired: 0, incomplete: 0, unsupported: 0, omitted: 0 };
  private groups = new Map<string, { directions: Set<string>; items: HttpObservation[]; windows: number; uncertain: boolean }>();

  ingest(key: string, data: Uint8Array, evidence: StreamEvidence) {
    const [scope, connection] = key.split("|");
    const endpoints = connection.split(" → ");
    const groupKey = scope + "|" + [...endpoints].sort().join(" ↔ ");
    const payload = decoder.decode(data);
    if (!/^(?:GET |POST |HEAD |PUT |DELETE |OPTIONS |PATCH |CONNECT |TRACE |HTTP\/1\.)/.test(payload)) return;
    if (!this.groups.has(groupKey) && this.groups.size >= 2048) { this.stats.omitted++; return; }
    const group = this.groups.get(groupKey) ?? { directions: new Set<string>(), items: [], windows: 0, uncertain: false };
    this.groups.set(groupKey, group);
    group.windows++;
    group.uncertain ||= evidence.uncertain || group.directions.has(connection);
    group.directions.add(connection);
    let offset = 0;
    let count = 0;
    while (offset < payload.length) {
      if (count++ >= 128 || this.observations.length >= 5000) {
        this.stats.omitted++;
        group.uncertain = true;
        break;
      }
      const headerEnd = payload.indexOf("\r\n\r\n", offset);
      const lineEnd = payload.indexOf("\r\n", offset);
      if (headerEnd < 0 || lineEnd < 0 || headerEnd - offset > 32768) {
        this.stats.incomplete++;
        group.uncertain = true;
        break;
      }
      const line = payload.slice(offset, lineEnd);
      const request = requestLine.exec(line);
      const response = responseLine.exec(line);
      if (!request && !response) { this.stats.unsupported++; group.uncertain = true; break; }
      const headers = payload.slice(lineEnd + 2, headerEnd).split("\r\n").filter(Boolean);
      const lengths: string[] = [];
      let transfer = false;
      let malformed = false;
      for (const header of headers) {
        if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\t\x20-\xff]*$/.test(header)) malformed = true;
        const colon = header.indexOf(":");
        const name = header.slice(0, colon).toLowerCase();
        if (name === "content-length") lengths.push(header.slice(colon + 1).trim());
        if (name === "transfer-encoding") transfer = true;
      }
      const status = Number(response?.[1] ?? 0);
      const bodyStart = headerEnd + 4;
      const noResponseBody = Boolean(response && (status < 200 || status === 204 || status === 304));
      const bodyLength = noResponseBody ? 0 : lengths.length === 1 && /^\d+$/.test(lengths[0]) ? Number(lengths[0]) : 0;
      let framing: HttpObservation["framing"] = "complete";
      // Deliberately decline ambiguous framing, chunking, tunnels and close-delimited bodies.
      if (malformed || transfer || lengths.length > 1 || (lengths.length === 1 && !/^\d+$/.test(lengths[0])) || !Number.isSafeInteger(bodyLength) ||
          (response && !noResponseBody && !lengths.length) || request?.[1] === "CONNECT" || status === 101) framing = "unsupported";
      else if (bodyStart + bodyLength > payload.length) framing = "incomplete";
      const end = framing === "complete" ? bodyStart + bodyLength : payload.length;
      let detectionText = payload.slice(offset, end);
      try { detectionText = decodeURIComponent(detectionText); } catch { /* Raw malformed encodings remain searchable. */ }
      const item: HttpObservation = {
        id: this.observations.length + 1, connection, scope,
        kind: request ? "request" : "response", method: request?.[1] ?? "HTTP",
        path: request ? (request[1] === "CONNECT" ? "[REDACTED AUTHORITY]" : safePath(request[2])) : "", status,
        timestamp: evidence.packets[0]?.timestamp ?? null, evidence,
        // Ordinary script tags in responses are not evidence of an XSS attempt.
        suspicious: Boolean(request && suspiciousPattern.test(detectionText)), framing,
        association: "unpaired", peerId: null,
      };
      this.observations.push(item);
      group.items.push(item);
      if (request) this.stats.requests++; else this.stats.responses++;
      if (framing !== "complete") {
        this.stats[framing]++;
        group.uncertain = true;
        break;
      }
      offset = end;
    }
  }

  seal(scope: string, endpoints?: string[]) {
    for (const [key, group] of this.groups) {
      if (!key.startsWith(scope + "|")) continue;
      if (endpoints && key !== scope + "|" + [...endpoints].sort().join(" ↔ ")) continue;
      const requests = group.items.filter((item) => item.kind === "request");
      const responses = group.items.filter((item) => item.kind === "response" && item.status >= 200);
      // Initial release pairs only a single unambiguous transaction per connection epoch.
      // Packet order is used, not wall clocks (interfaces can have unsynchronized clocks).
      if (!group.uncertain && group.windows === 2 && requests.length === 1 && responses.length === 1 &&
          !["HEAD", "CONNECT"].includes(requests[0].method) &&
          requests[0].connection.split(" → ").reverse().join(" → ") === responses[0].connection &&
          requests[0].evidence.lastPacket < responses[0].evidence.firstPacket) {
        const request = requests[0], response = responses[0];
        request.association = response.association = "inferred";
        request.peerId = response.id;
        response.peerId = request.id;
        this.stats.paired++;
      }
      this.groups.delete(key);
    }
  }

  finish() {
    for (const key of [...this.groups.keys()]) this.seal(key.split("|")[0]);
  }
}
