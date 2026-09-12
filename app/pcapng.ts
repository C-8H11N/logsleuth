import { TcpReassembly, type PacketReference, type StreamEvidence } from "./tcp-reassembly.ts";
import { HttpEvidence, type HttpObservation } from "./http-evidence.ts";

export type PcapFinding = {
  id: number;
  timestamp: string;
  ip: string;
  method: string;
  path: string;
  status: number;
  category: string;
  severity: "Critical" | "High" | "Medium";
  evidence: string;
  captureEvidence?: StreamEvidence;
  httpObservationId?: number;
};

export type CaptureProgress = {
  analyzedBytes: number;
  totalBytes: number;
  packets: number;
  percent: number;
};

export type PcapResult = {
  packets: number;
  findings: PcapFinding[];
  sampled: boolean;
  complete: boolean;
  analyzedBytes: number;
  fileBytes: number;
  findingsTruncated: number;
  warnings: string[];
  format: "PCAP" | "PCAPNG";
  httpObservations: HttpObservation[];
  httpAnalysis: HttpEvidence["stats"];
  stats: { ipv4: number; tcp: number; udp: number; dns: number; http: number; hosts: number };
};

type ParseState = {
  reassembly?: TcpReassembly;
  httpEvidence: HttpEvidence;
  nanosecondPcap: boolean;
  packets: number;
  ipv4: number;
  tcp: number;
  udp: number;
  http: number;
  findings: PcapFinding[];
  findingsTruncated: number;
  hosts: Set<string>;
  syn: Map<string, Set<number>>;
  dns: Map<string, number>;
  warnings: string[];
};

const CHUNK_BYTES = 8 * 1024 * 1024;
const MAX_RECORD_BYTES = 64 * 1024 * 1024;
const MAX_FINDINGS = 5000;
const MAX_TRACKED_HOSTS = 250000;
const MAX_TRACKED_SOURCES = 100000;

const ip = (v: DataView, o: number) =>
  v.getUint8(o) + "." + v.getUint8(o + 1) + "." + v.getUint8(o + 2) + "." + v.getUint8(o + 3);

const createState = (): ParseState => ({
  httpEvidence: new HttpEvidence(),
  nanosecondPcap: false,
  packets: 0,
  ipv4: 0,
  tcp: 0,
  udp: 0,
  http: 0,
  findings: [],
  findingsTruncated: 0,
  hosts: new Set(),
  syn: new Map(),
  dns: new Map(),
  warnings: [],
});

function addFinding(state: ParseState, category: string, severity: PcapFinding["severity"], source: string, detail: string) {
  if (state.findings.length >= MAX_FINDINGS) {
    state.findingsTruncated++;
    return;
  }
  state.findings.push({
    id: state.findings.length + 1,
    timestamp: "Packet capture",
    ip: source,
    method: "NET",
    path: detail,
    status: 0,
    category,
    severity,
    evidence: detail,
  });
}

function trackHost(state: ParseState, value: string) {
  if (state.hosts.size < MAX_TRACKED_HOSTS || state.hosts.has(value)) state.hosts.add(value);
  else if (!state.warnings.includes("Host cardinality limit reached.")) state.warnings.push("Host cardinality limit reached.");
}

function captureTime(packet: number, ticks: bigint, units: bigint, offsetSeconds = BigInt(0)): PacketReference {
  const nanos = ticks * BigInt(1000000000) / units + offsetSeconds * BigInt(1000000000);
  const date = new Date(Number(nanos / BigInt(1000000)));
  return { packet, epochNanoseconds: nanos.toString(), timestamp: Number.isNaN(date.getTime()) ? null : date.toISOString() };
}

function analyzeEthernetPacket(bytes: Uint8Array, state: ParseState, reference: PacketReference, scope: string) {
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let end = v.byteLength;
  if (end < 34) return;
  let l3 = 14;
  let etherType = v.getUint16(12, false);
  if (etherType === 0x8100 && end >= 18) {
    etherType = v.getUint16(16, false);
    l3 += 4;
  }
  if (etherType !== 0x0800 || l3 + 20 > end) return;
  const ihl = (v.getUint8(l3) & 15) * 4;
  if (ihl < 20 || l3 + ihl > end) return;
  const totalLength = v.getUint16(l3 + 2, false);
  if (totalLength < ihl) return;
  if (l3 + totalLength > end) {
    reference.truncated = true;
    const warning = "截断的 IPv4 包 / Truncated IPv4 packet.";
    if (!state.warnings.includes(warning)) state.warnings.push(warning);
  }
  end = Math.min(end, l3 + totalLength);
  if ((v.getUint16(l3 + 6, false) & 0x3fff) !== 0) {
    const warning = "未重组 IP 分片 / IP fragments were not reassembled.";
    if (!state.warnings.includes(warning)) state.warnings.push(warning);
    return;
  }
  const protocol = v.getUint8(l3 + 9);
  const source = ip(v, l3 + 12);
  const destination = ip(v, l3 + 16);
  const l4 = l3 + ihl;
  state.ipv4++;
  trackHost(state, source);
  trackHost(state, destination);
  if (protocol === 6) state.tcp++;
  if (protocol === 17) state.udp++;
  if ((protocol !== 6 && protocol !== 17) || l4 + 4 > end) return;

  const sourcePort = v.getUint16(l4, false);
  const destinationPort = v.getUint16(l4 + 2, false);
  if (protocol === 6 && l4 + 14 <= end) {
    const flags = v.getUint8(l4 + 13);
    if ((flags & 2) !== 0 && (flags & 16) === 0 && (state.syn.has(source) || state.syn.size < MAX_TRACKED_SOURCES)) {
      const ports = state.syn.get(source) ?? new Set<number>();
      ports.add(destinationPort);
      state.syn.set(source, ports);
    }
  }
  if ((sourcePort === 53 || destinationPort === 53) && (state.dns.has(source) || state.dns.size < MAX_TRACKED_SOURCES)) {
    state.dns.set(source, (state.dns.get(source) ?? 0) + 1);
  }

  if (protocol === 6 && l4 + 20 <= end) {
    const headerLength = (v.getUint8(l4 + 12) >> 4) * 4;
    if (headerLength < 20 || l4 + headerLength > end) return;
    const endpoints = [source + ":" + sourcePort, destination + ":" + destinationPort];
    const key = scope + "|" + endpoints.join(" → ");
    state.reassembly ??= new TcpReassembly((connection, data, evidence) => {
      state.httpEvidence.ingest(connection, data, evidence);
    });
    const flags = v.getUint8(l4 + 13);
    if ((flags & 2) && !(flags & 16)) {
      state.reassembly.flush(key);
      state.reassembly.flush(scope + "|" + [...endpoints].reverse().join(" → "));
      state.httpEvidence.seal(scope, endpoints);
    }
    state.reassembly.push(key, (v.getUint32(l4 + 4, false) + ((flags & 2) ? 1 : 0)) >>> 0, bytes.subarray(l4 + headerLength, end), reference);
  }
}

function finish(state: ParseState, format: PcapResult["format"], fileBytes: number, complete = true): PcapResult {
  state.reassembly?.finish();
  state.httpEvidence.finish();
  for (const observation of state.httpEvidence.observations) {
    if (!observation.suspicious) continue;
    const before = state.findings.length;
    addFinding(state, "Suspicious HTTP payload", "High", observation.connection.split(":")[0], observation.connection);
    if (state.findings.length === before) continue;
    const finding = state.findings[state.findings.length - 1];
    finding.method = observation.method;
    finding.path = observation.path;
    finding.timestamp = observation.timestamp ?? "Unknown capture time";
    finding.httpObservationId = observation.id;
    finding.captureEvidence = observation.evidence;
    finding.evidence = `${observation.connection} · capture packets ${observation.evidence.firstPacket}–${observation.evidence.lastPacket} · ${observation.framing} · ${observation.association}`;
    if (observation.peerId) finding.status = state.httpEvidence.observations[observation.peerId - 1].status;
  }
  state.http = state.httpEvidence.stats.requests + state.httpEvidence.stats.responses;
  const transport = state.reassembly?.stats;
  state.warnings.push("仅分析 Ethernet/IPv4 明文流量；TLS 未解密。全文件读取不等于完整协议覆盖。 / Ethernet/IPv4 plaintext only; TLS is not decrypted. Full-file reading does not imply full protocol coverage.");
  if (transport?.gaps) state.warnings.push(`TCP 缺口 / TCP gaps: ${transport.gaps}`);
  if (transport?.limitedFlows) state.warnings.push(`TCP 内存窗口截断 / TCP window limits: ${transport.limitedFlows}`);
  if (transport?.conflicts) state.warnings.push(`TCP 重叠内容冲突，需人工复核 / Conflicting TCP overlaps, review required: ${transport.conflicts}`);
  if (state.httpEvidence.stats.incomplete) state.warnings.push(`HTTP 不完整边界 / Incomplete HTTP framing: ${state.httpEvidence.stats.incomplete}`);
  if (state.httpEvidence.stats.unsupported) state.warnings.push(`HTTP 未支持或歧义边界 / Unsupported or ambiguous HTTP framing: ${state.httpEvidence.stats.unsupported}`);
  if (state.httpEvidence.stats.omitted) state.warnings.push(`HTTP 记录达到上限 / HTTP observation limit: ${state.httpEvidence.stats.omitted}`);
  state.syn.forEach((ports, source) => {
    if (ports.size >= 10) addFinding(state, "Possible TCP port scan", "High", source, "SYN packets to " + ports.size + " distinct destination ports");
  });
  state.dns.forEach((count, source) => {
    if (count >= 30) addFinding(state, "High-volume DNS activity", "Medium", source, count + " DNS packets observed");
  });
  return {
    packets: state.packets,
    findings: state.findings,
    sampled: false,
    complete,
    analyzedBytes: fileBytes,
    fileBytes,
    findingsTruncated: state.findingsTruncated,
    warnings: state.warnings,
    format,
    httpObservations: state.httpEvidence.observations,
    httpAnalysis: state.httpEvidence.stats,
    stats: {
      ipv4: state.ipv4,
      tcp: state.tcp,
      udp: state.udp,
      dns: [...state.dns.values()].reduce((a, b) => a + b, 0),
      http: state.http,
      hosts: state.hosts.size,
    },
  };
}

function concat(left: Uint8Array, right: Uint8Array) {
  if (!left.byteLength) return right;
  const output = new Uint8Array(left.byteLength + right.byteLength);
  output.set(left);
  output.set(right, left.byteLength);
  return output;
}

function detectFormat(header: Uint8Array): { format: PcapResult["format"]; little: boolean } {
  if (header.byteLength < 12) throw new Error("抓包文件为空或不完整。");
  const v = new DataView(header.buffer, header.byteOffset, header.byteLength);
  if (v.getUint32(0, false) === 0x0a0d0d0a) {
    const little = v.getUint32(8, true) === 0x1a2b3c4d;
    const big = v.getUint32(8, false) === 0x1a2b3c4d;
    if (!little && !big) throw new Error("PCAPNG 字节序标记无效。");
    return { format: "PCAPNG", little };
  }
  if (header.byteLength < 24) throw new Error("PCAP 文件不完整。");
  const littleMagic = v.getUint32(0, true);
  const bigMagic = v.getUint32(0, false);
  if (littleMagic === 0xa1b2c3d4 || littleMagic === 0xa1b23c4d) return { format: "PCAP", little: true };
  if (bigMagic === 0xa1b2c3d4 || bigMagic === 0xa1b23c4d) return { format: "PCAP", little: false };
  throw new Error("无法识别抓包格式，请上传 PCAP 或 PCAPNG 文件。");
}

function consumePcap(data: Uint8Array, little: boolean, state: ParseState, initialized: boolean) {
  const v = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let offset = 0;
  if (!initialized) {
    if (data.byteLength < 24) return { consumed: 0, initialized: false };
    const linkType = v.getUint32(20, little);
    if (linkType !== 1) throw new Error("暂不支持 PCAP 链路类型 " + linkType + "，目前支持 Ethernet。");
    state.nanosecondPcap = v.getUint32(0, little) === 0xa1b23c4d;
    offset = 24;
    initialized = true;
  }
  while (offset + 16 <= data.byteLength) {
    const capturedLength = v.getUint32(offset + 8, little);
    if (capturedLength > MAX_RECORD_BYTES) throw new Error("PCAP 数据包长度超过安全上限。");
    const start = offset + 16;
    if (start + capturedLength > data.byteLength) break;
    state.packets++;
    const units = BigInt(state.nanosecondPcap ? 1000000000 : 1000000);
    const ticks = BigInt(v.getUint32(offset, little)) * units + BigInt(v.getUint32(offset + 4, little));
    const reference = captureTime(state.packets, ticks, units);
    if (capturedLength < v.getUint32(offset + 12, little)) reference.truncated = true;
    analyzeEthernetPacket(data.subarray(start, start + capturedLength), state, reference, "pcap");
    offset = start + capturedLength;
  }
  return { consumed: offset, initialized };
}

type PcapngContext = { little: boolean; endianKnown: boolean; links: { type: number; units: bigint; offset: bigint }[]; section: number };

function consumePcapng(data: Uint8Array, state: ParseState, context: PcapngContext) {
  let offset = 0;
  while (offset + 12 <= data.byteLength) {
    const v = new DataView(data.buffer, data.byteOffset + offset, data.byteLength - offset);
    const isSection = v.getUint32(0, false) === 0x0a0d0d0a;
    if (isSection) {
      const little = v.getUint32(8, true) === 0x1a2b3c4d;
      const big = v.getUint32(8, false) === 0x1a2b3c4d;
      if (!little && !big) throw new Error("PCAPNG 字节序标记无效。");
      context.little = little;
      context.endianKnown = true;
    } else if (!context.endianKnown) {
      throw new Error("PCAPNG 缺少 Section Header Block。");
    }
    const length = v.getUint32(4, context.little);
    if (length < 12 || length % 4 || length > MAX_RECORD_BYTES) throw new Error("PCAPNG 数据块长度无效或超过安全上限。");
    if (offset + length > data.byteLength) break;
    const trailing = new DataView(data.buffer, data.byteOffset + offset + length - 4, 4).getUint32(0, context.little);
    if (trailing !== length) throw new Error("PCAPNG 数据块长度校验失败。");
    const type = v.getUint32(0, context.little);
    if (isSection) {
      if (length < 28) throw new Error("PCAPNG Section Header is truncated.");
      state.reassembly?.finish();
      state.httpEvidence.finish();
      context.links = [];
      context.section++;
    }
    if (type === 1 && length >= 20) {
      if (context.links.length >= 4096) throw new Error("PCAPNG interface limit exceeded.");
      const link = { type: v.getUint16(8, context.little), units: BigInt(1000000), offset: BigInt(0) };
      for (let option = 16; option + 4 <= length - 4;) {
        const code = v.getUint16(option, context.little);
        const size = v.getUint16(option + 2, context.little);
        option += 4;
        if (option + size > length - 4) throw new Error("PCAPNG interface option is truncated.");
        if (code === 0) break;
        if (code === 9 && size === 1) {
          const resolution = v.getUint8(option);
          link.units = BigInt(resolution & 128 ? 2 : 10) ** BigInt(resolution & 127);
        }
        if (code === 14 && size === 8) link.offset = v.getBigInt64(option, context.little);
        option += Math.ceil(size / 4) * 4;
      }
      context.links.push(link);
    }
    if (type === 6 && length >= 32) {
      const interfaceId = v.getUint32(8, context.little);
      const capturedLength = v.getUint32(20, context.little);
      const start = 28;
      if (capturedLength > MAX_RECORD_BYTES) throw new Error("PCAPNG 数据包长度超过安全上限。");
      if (start + Math.ceil(capturedLength / 4) * 4 > length - 4) throw new Error("PCAPNG packet exceeds block boundary.");
      state.packets++;
      const link = context.links[interfaceId];
      if (!link) throw new Error("PCAPNG packet references an unknown interface.");
      if (link.type === 1) {
        const ticks = (BigInt(v.getUint32(12, context.little)) << BigInt(32)) | BigInt(v.getUint32(16, context.little));
        const reference = captureTime(state.packets, ticks, link.units, link.offset);
        if (capturedLength < v.getUint32(24, context.little)) reference.truncated = true;
        analyzeEthernetPacket(data.subarray(offset + start, offset + start + capturedLength), state,
          reference, `pcapng-${context.section}-${interfaceId}`);
      } else if (!state.warnings.includes("未解析非 Ethernet 接口 / Non-Ethernet interface skipped.")) state.warnings.push("未解析非 Ethernet 接口 / Non-Ethernet interface skipped.");
    }
    if (type === 3 || type === 2) {
      state.packets++;
      if (!state.warnings.includes("跳过旧式/简单数据包块 / Legacy/simple packet blocks skipped.")) state.warnings.push("跳过旧式/简单数据包块 / Legacy/simple packet blocks skipped.");
    }
    offset += length;
  }
  return offset;
}

export function parseCapture(buffer: ArrayBuffer): PcapResult {
  const bytes = new Uint8Array(buffer);
  const detected = detectFormat(bytes);
  const state = createState();
  if (detected.format === "PCAP") {
    const parsed = consumePcap(bytes, detected.little, state, false);
    const complete = parsed.consumed === bytes.byteLength;
    if (!complete) state.warnings.push("Trailing incomplete PCAP record was ignored.");
    return finish(state, "PCAP", bytes.byteLength, complete);
  }
  const context: PcapngContext = { little: detected.little, endianKnown: true, links: [], section: 0 };
  const consumed = consumePcapng(bytes, state, context);
  const complete = consumed === bytes.byteLength;
  if (!complete) state.warnings.push("Trailing incomplete PCAPNG block was ignored.");
  return finish(state, "PCAPNG", bytes.byteLength, complete);
}

export async function parseCaptureFile(
  file: File,
  onProgress?: (progress: CaptureProgress) => void,
  signal?: AbortSignal,
): Promise<PcapResult> {
  if (!file.size) throw new Error("抓包文件为空。");
  const header = new Uint8Array(await file.slice(0, 32).arrayBuffer());
  const detected = detectFormat(header);
  const state = createState();
  const pcapng: PcapngContext = { little: detected.little, endianKnown: detected.format === "PCAPNG", links: [], section: 0 };
  let initialized = false;
  let carry = new Uint8Array(0);
  let readOffset = 0;
  while (readOffset < file.size) {
    if (signal?.aborted) throw new DOMException("Analysis cancelled.", "AbortError");
    const end = Math.min(file.size, readOffset + CHUNK_BYTES);
    const chunk = new Uint8Array(await file.slice(readOffset, end).arrayBuffer());
    const data = concat(carry, chunk);
    let consumed = 0;
    if (detected.format === "PCAP") {
      const result = consumePcap(data, detected.little, state, initialized);
      consumed = result.consumed;
      initialized = result.initialized;
    } else {
      consumed = consumePcapng(data, state, pcapng);
    }
    carry = data.slice(consumed);
    if (carry.byteLength > MAX_RECORD_BYTES) throw new Error("抓包中存在超过安全上限的未完成数据块。");
    readOffset = end;
    onProgress?.({
      analyzedBytes: readOffset,
      totalBytes: file.size,
      packets: state.packets,
      percent: Math.min(100, Math.round((readOffset / file.size) * 100)),
    });
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }
  if (signal?.aborted) throw new DOMException("Analysis cancelled.", "AbortError");
  const complete = carry.byteLength === 0;
  if (!complete) state.warnings.push("文件末尾存在不完整的数据包或数据块，已忽略尾部残片。");
  return finish(state, detected.format, file.size, complete);
}
