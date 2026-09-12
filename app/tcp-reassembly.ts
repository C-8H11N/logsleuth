// Offline, bounded directional TCP windows. Gaps are never concatenated.
export class TcpReassembly {
  private flows = new Map<string, { anchor: number; segments: { offset: number; data: Uint8Array }[]; bytes: number }>();
  private bytes = 0;
  readonly stats = { segments: 0, duplicateBytes: 0, gaps: 0, limitedFlows: 0, conflicts: 0 };
  private emit: (key: string, payload: Uint8Array) => void;
  private maxFlowBytes: number;
  private maxBytes: number;
  private maxFlows: number;
  private maxSegments: number;
  constructor(emit: (key: string, payload: Uint8Array) => void,
    maxFlowBytes = 256 * 1024, maxBytes = 16 * 1024 * 1024,
    maxFlows = 2048, maxSegments = 2048) {
    this.emit = emit;
    this.maxFlowBytes = maxFlowBytes;
    this.maxBytes = maxBytes;
    this.maxFlows = maxFlows;
    this.maxSegments = maxSegments;
  }

  push(key: string, sequence: number, payload: Uint8Array) {
    if (!payload.length) return;
    this.stats.segments++;
    let flow = this.flows.get(key);
    if (flow && (flow.bytes + payload.length > this.maxFlowBytes || flow.segments.length >= this.maxSegments)) {
      this.stats.limitedFlows++;
      this.flush(key);
      flow = undefined;
    }
    while (this.flows.size && (this.bytes + payload.length > this.maxBytes || (!flow && this.flows.size >= this.maxFlows))) {
      this.stats.limitedFlows++;
      this.flush(this.flows.keys().next().value!);
      flow = this.flows.get(key);
    }
    if (payload.length > this.maxFlowBytes || payload.length > this.maxBytes) {
      this.stats.limitedFlows++;
      return;
    }
    if (!flow) {
      flow = { anchor: sequence, segments: [], bytes: 0 };
      this.flows.set(key, flow);
    }
    // Signed modular distance handles sequence wrap within the bounded window.
    flow.segments.push({ offset: (sequence - flow.anchor) | 0, data: payload.slice() });
    flow.bytes += payload.length;
    this.bytes += payload.length;
  }

  flush(key: string) {
    const flow = this.flows.get(key);
    if (!flow) return;
    this.flows.delete(key);
    this.bytes -= flow.bytes;
    const segments = flow.segments.sort((a, b) => a.offset - b.offset);
    let start = 0;
    let length = 0;
    let buffer = new Uint8Array(flow.bytes);
    for (const segment of segments) {
      if (length && segment.offset > start + length) {
        this.stats.gaps++;
        this.emit(key, buffer.subarray(0, length));
        buffer = new Uint8Array(flow.bytes);
        length = 0;
      }
      if (!length) start = segment.offset;
      const overlap = Math.max(0, start + length - segment.offset);
      const duplicate = Math.min(overlap, segment.data.length);
      this.stats.duplicateBytes += duplicate;
      for (let i = 0; i < duplicate; i++) {
        if (buffer[segment.offset - start + i] !== segment.data[i]) {
          this.stats.conflicts++;
          break;
        }
      }
      if (overlap < segment.data.length) {
        buffer.set(segment.data.subarray(overlap), length);
        length += segment.data.length - overlap;
      }
    }
    if (length) this.emit(key, buffer.subarray(0, length));
  }

  finish() {
    for (const key of this.flows.keys()) this.flush(key);
  }
}
