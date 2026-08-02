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
};

export type PcapResult = {
  packets: number;
  findings: PcapFinding[];
  sampled: boolean;
  analyzedBytes: number;
  format: "PCAP" | "PCAPNG";
  stats: { ipv4: number; tcp: number; udp: number; dns: number; http: number; hosts: number };
};

type ParseState = {
  packets: number;
  ipv4: number;
  tcp: number;
  udp: number;
  http: number;
  findings: PcapFinding[];
  hosts: Set<string>;
  syn: Map<string, Set<number>>;
  dns: Map<string, number>;
};

const ip = (v: DataView, o: number) => `${v.getUint8(o)}.${v.getUint8(o + 1)}.${v.getUint8(o + 2)}.${v.getUint8(o + 3)}`;
const createState = (): ParseState => ({ packets: 0, ipv4: 0, tcp: 0, udp: 0, http: 0, findings: [], hosts: new Set(), syn: new Map(), dns: new Map() });

function addFinding(state: ParseState, category: string, severity: PcapFinding["severity"], source: string, detail: string) {
  state.findings.push({ id: state.findings.length + 1, timestamp: "Packet capture", ip: source, method: "NET", path: detail, status: 0, category, severity, evidence: detail });
}

function analyzeEthernetPacket(v: DataView, start: number, capturedLength: number, state: ParseState) {
  const end = Math.min(start + capturedLength, v.byteLength);
  if (capturedLength < 34 || start + 14 > end) return;
  state.packets++;
  let l3 = start + 14;
  let etherType = v.getUint16(start + 12, false);
  if (etherType === 0x8100 && start + 18 <= end) {
    etherType = v.getUint16(start + 16, false);
    l3 += 4;
  }
  if (etherType !== 0x0800 || l3 + 20 > end) return;

  const ihl = (v.getUint8(l3) & 15) * 4;
  if (ihl < 20 || l3 + ihl > end) return;
  const protocol = v.getUint8(l3 + 9);
  const source = ip(v, l3 + 12);
  const destination = ip(v, l3 + 16);
  const l4 = l3 + ihl;
  state.ipv4++;
  state.hosts.add(source);
  state.hosts.add(destination);
  if (protocol === 6) state.tcp++;
  if (protocol === 17) state.udp++;
  if ((protocol !== 6 && protocol !== 17) || l4 + 4 > end) return;

  const sourcePort = v.getUint16(l4, false);
  const destinationPort = v.getUint16(l4 + 2, false);
  if (protocol === 6 && l4 + 14 <= end) {
    const flags = v.getUint8(l4 + 13);
    if ((flags & 2) !== 0 && (flags & 16) === 0) {
      const ports = state.syn.get(source) ?? new Set<number>();
      ports.add(destinationPort);
      state.syn.set(source, ports);
    }
  }
  if (sourcePort === 53 || destinationPort === 53) state.dns.set(source, (state.dns.get(source) ?? 0) + 1);

  if (protocol === 6 && [80, 8080, 8000].some((port) => port === sourcePort || port === destinationPort)) {
    state.http++;
    const tcpHeaderLength = l4 + 13 < end ? ((v.getUint8(l4 + 12) >> 4) & 15) * 4 : 20;
    const payloadStart = Math.min(l4 + Math.max(tcpHeaderLength, 20), end);
    const payload = new TextDecoder("latin1").decode(new Uint8Array(v.buffer, v.byteOffset + payloadStart, Math.min(512, end - payloadStart)));
    if (/union\s+(?:all\s+)?select|<script\b|(?:\.\.\/){2,}|(?:%2e){2}%2f|(?:cmd|powershell)(?:\.exe)?\b/i.test(payload)) {
      addFinding(state, "Suspicious HTTP payload", "High", source, `${source}:${sourcePort} → ${destination}:${destinationPort}`);
    }
  }
}

function finish(state: ParseState, format: PcapResult["format"], sampled: boolean, analyzedBytes: number): PcapResult {
  state.syn.forEach((ports, source) => {
    if (ports.size >= 10) addFinding(state, "Possible TCP port scan", "High", source, `SYN packets to ${ports.size} distinct destination ports`);
  });
  state.dns.forEach((count, source) => {
    if (count >= 30) addFinding(state, "High-volume DNS activity", "Medium", source, `${count} DNS packets observed`);
  });
  return {
    packets: state.packets,
    findings: state.findings,
    sampled,
    analyzedBytes,
    format,
    stats: { ipv4: state.ipv4, tcp: state.tcp, udp: state.udp, dns: [...state.dns.values()].reduce((a, b) => a + b, 0), http: state.http, hosts: state.hosts.size },
  };
}

function parsePcapng(v: DataView, sampled: boolean): PcapResult {
  if (v.byteLength < 28) throw new Error("PCAPNG 文件不完整。");
  const little = v.getUint32(8, true) === 0x1a2b3c4d;
  const u32 = (offset: number) => v.getUint32(offset, little);
  const u16 = (offset: number) => v.getUint16(offset, little);
  const links: number[] = [];
  const state = createState();
  let offset = 0;
  while (offset + 12 <= v.byteLength) {
    const type = u32(offset);
    const length = u32(offset + 4);
    if (length < 12 || offset + length > v.byteLength) break;
    if (type === 1 && offset + 10 <= v.byteLength) links.push(u16(offset + 8));
    if (type === 6 && offset + 28 <= v.byteLength) {
      const interfaceId = u32(offset + 8);
      const capturedLength = u32(offset + 20);
      const start = offset + 28;
      if (links[interfaceId] === 1 && start + capturedLength <= offset + length - 4) analyzeEthernetPacket(v, start, capturedLength, state);
    }
    offset += length;
  }
  return finish(state, "PCAPNG", sampled, v.byteLength);
}

function parsePcap(v: DataView, sampled: boolean, little: boolean): PcapResult {
  if (v.byteLength < 24) throw new Error("PCAP 文件不完整。");
  const state = createState();
  const linkType = v.getUint32(20, little);
  if (linkType !== 1) throw new Error(`暂不支持 PCAP 链路类型 ${linkType}，目前支持 Ethernet。`);
  let offset = 24;
  while (offset + 16 <= v.byteLength) {
    const capturedLength = v.getUint32(offset + 8, little);
    const start = offset + 16;
    if (capturedLength > v.byteLength - start) break;
    analyzeEthernetPacket(v, start, capturedLength, state);
    offset = start + capturedLength;
  }
  return finish(state, "PCAP", sampled, v.byteLength);
}

export function parseCapture(buffer: ArrayBuffer, sampled = false): PcapResult {
  const v = new DataView(buffer);
  if (v.byteLength < 4) throw new Error("抓包文件为空或不完整。");
  if (v.getUint32(0, false) === 0x0a0d0d0a) return parsePcapng(v, sampled);
  const littleMagic = v.getUint32(0, true);
  const bigMagic = v.getUint32(0, false);
  if (littleMagic === 0xa1b2c3d4 || littleMagic === 0xa1b23c4d) return parsePcap(v, sampled, true);
  if (bigMagic === 0xa1b2c3d4 || bigMagic === 0xa1b23c4d) return parsePcap(v, sampled, false);
  throw new Error("无法识别抓包格式，请上传 PCAP 或 PCAPNG 文件。");
}
