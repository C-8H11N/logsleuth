export type PacketReference = { packet: number; timestamp: string | null; epochNanoseconds: string | null; truncated?: boolean };
export type StreamEvidence = {
  packets: PacketReference[];
  packetCount: number;
  firstPacket: number;
  lastPacket: number;
  uncertain: boolean;
};

// Offline, bounded directional TCP windows. Gaps are never concatenated.
export class TcpReassembly {
  private flows = new Map<string, { anchor: number; segments: { offset: number; data: Uint8Array; reference?: PacketReference }[]; bytes: number }>();
  private bytes = 0;
  private coverageLimited = false;
  readonly stats = { segments: 0, duplicateBytes: 0, gaps: 0, limitedFlows: 0, conflicts: 0 };
  private emit: (key: string, payload: Uint8Array, evidence: StreamEvidence) => void;
  private maxFlowBytes: number;
  private maxBytes: number;
  private maxFlows: number;
  private maxSegments: number;
  constructor(emit: (key: string, payload: Uint8Array, evidence: StreamEvidence) => void,
    maxFlowBytes = 256 * 1024, maxBytes = 16 * 1024 * 1024,
    maxFlows = 2048, maxSegments = 2048) {
    this.emit = emit;
    this.maxFlowBytes = maxFlowBytes;
    this.maxBytes = maxBytes;
    this.maxFlows = maxFlows;
    this.maxSegments = maxSegments;
  }

  push(key: string, sequence: number, payload: Uint8Array, reference?: PacketReference) {
    if (!payload.length) return;
    this.stats.segments++;
    let flow = this.flows.get(key);
    if (flow && (flow.bytes + payload.length > this.maxFlowBytes || flow.segments.length >= this.maxSegments)) {
      this.stats.limitedFlows++;
      this.coverageLimited = true;
      this.flush(key, true);
      flow = undefined;
    }
    while (this.flows.size && (this.bytes + payload.length > this.maxBytes || (!flow && this.flows.size >= this.maxFlows))) {
      this.stats.limitedFlows++;
      this.coverageLimited = true;
      this.flush(this.flows.keys().next().value!, true);
      flow = this.flows.get(key);
    }
    if (payload.length > this.maxFlowBytes || payload.length > this.maxBytes) {
      this.stats.limitedFlows++;
      this.coverageLimited = true;
      return;
    }
    if (!flow) {
      flow = { anchor: sequence, segments: [], bytes: 0 };
      this.flows.set(key, flow);
    }
    // Signed modular distance handles sequence wrap within the bounded window.
    flow.segments.push({ offset: (sequence - flow.anchor) | 0, data: payload.slice(), reference });
    flow.bytes += payload.length;
    this.bytes += payload.length;
  }

  flush(key: string, limited = false) {
    const flow = this.flows.get(key);
    if (!flow) return;
    this.flows.delete(key);
    this.bytes -= flow.bytes;
    const segments = flow.segments.sort((a, b) => a.offset - b.offset);
    // Mark every emitted run uncertain if any gap exists in the window.
    let covered = segments[0]?.offset ?? 0;
    let uncertain = limited || this.coverageLimited;
    for (const segment of segments) {
      if (segment.offset > covered) uncertain = true;
      if (segment.reference?.truncated) uncertain = true;
      covered = Math.max(covered, segment.offset + segment.data.length);
    }
    let start = 0;
    let length = 0;
    let buffer = new Uint8Array(flow.bytes);
    let references: PacketReference[] = [];
    let conflict = false;
    const emit = () => {
      const ordered = references.sort((a, b) => a.packet - b.packet);
      this.emit(key, buffer.subarray(0, length), {
        packets: ordered.slice(0, 64), packetCount: ordered.length,
        firstPacket: ordered[0]?.packet ?? 0, lastPacket: ordered.at(-1)?.packet ?? 0,
        uncertain: uncertain || conflict,
      });
    };
    for (const segment of segments) {
      if (length && segment.offset > start + length) {
        this.stats.gaps++;
        emit();
        buffer = new Uint8Array(flow.bytes);
        length = 0;
        references = [];
        conflict = false;
      }
      if (!length) start = segment.offset;
      const overlap = Math.max(0, start + length - segment.offset);
      const duplicate = Math.min(overlap, segment.data.length);
      this.stats.duplicateBytes += duplicate;
      for (let i = 0; i < duplicate; i++) {
        if (buffer[segment.offset - start + i] !== segment.data[i]) {
          this.stats.conflicts++;
          conflict = true;
          break;
        }
      }
      if (overlap < segment.data.length) {
        buffer.set(segment.data.subarray(overlap), length);
        length += segment.data.length - overlap;
      }
      if (segment.reference) references.push(segment.reference);
    }
    if (length) emit();
  }

  finish() {
    for (const key of this.flows.keys()) this.flush(key);
  }
}
