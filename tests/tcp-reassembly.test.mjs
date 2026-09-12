import assert from "node:assert/strict";
import test from "node:test";
import { TcpReassembly } from "../app/tcp-reassembly.ts";
import { parseCapture, parseCaptureFile } from "../app/pcapng.ts";

const bytes = (text) => new TextEncoder().encode(text);
test("out of order segments and retransmission are reconstructed once", () => {
  const output = [];
  const tcp = new TcpReassembly((_, data) => output.push(new TextDecoder().decode(data)));
  tcp.push("flow", 105, bytes("world"));
  tcp.push("flow", 100, bytes("hello"));
  tcp.push("flow", 100, bytes("hello"));
  tcp.finish();
  assert.deepEqual(output, ["helloworld"]);
  assert.equal(tcp.stats.duplicateBytes, 5);
});
test("gaps stay separate and sequence wrap is handled", () => {
  const output = [];
  const tcp = new TcpReassembly((_, data) => output.push(new TextDecoder().decode(data)));
  tcp.push("flow", 0xfffffffe, bytes("ab"));
  tcp.push("flow", 0, bytes("cd"));
  tcp.push("flow", 5, bytes("ef"));
  tcp.finish();
  assert.deepEqual(output, ["abcd", "ef"]);
  assert.equal(tcp.stats.gaps, 1);
});
test("limits and conflicting retransmissions are observable", () => {
  const tcp = new TcpReassembly(() => {}, 8, 16, 2, 2);
  tcp.push("a", 0, bytes("abcd"));
  tcp.push("a", 0, bytes("xxxx"));
  tcp.push("a", 4, bytes("ef"));
  tcp.finish();
  assert.equal(tcp.stats.conflicts, 1);
  assert.equal(tcp.stats.limitedFlows, 1);
});

function capture(parts) {
  const packets = parts.map(([seq, text]) => {
    const body = bytes(text);
    const packet = new Uint8Array(54 + body.length);
    const view = new DataView(packet.buffer);
    view.setUint16(12, 0x0800);
    packet[14] = 0x45;
    view.setUint16(16, 40 + body.length);
    packet[23] = 6;
    packet.set([127, 0, 0, 1], 26);
    packet.set([127, 0, 0, 2], 30);
    view.setUint16(34, 12345);
    view.setUint16(36, 9999);
    view.setUint32(38, seq);
    packet[46] = 0x50;
    packet[47] = 0x18;
    packet.set(body, 54);
    return packet;
  });
  const result = new Uint8Array(24 + packets.reduce((n, p) => n + 16 + p.length, 0));
  const view = new DataView(result.buffer);
  view.setUint32(0, 0xa1b2c3d4, true);
  view.setUint16(4, 2, true);
  view.setUint16(6, 4, true);
  view.setUint32(16, 65535, true);
  view.setUint32(20, 1, true);
  let offset = 24;
  for (const packet of packets) {
    view.setUint32(offset + 8, packet.length, true);
    view.setUint32(offset + 12, packet.length, true);
    result.set(packet, offset + 16);
    offset += packet.length + 16;
  }
  return result;
}
test("capture detects split HTTP on a nonstandard port without duplicate findings", async () => {
  const first = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 12\r\n\r\nunion ";
  const second = "select";
  const data = capture([[100 + first.length, second], [100, first], [100, first]]);
  const result = parseCapture(data.buffer);
  assert.equal(result.findings.length, 1);
  assert.equal(result.stats.http, 1);
  assert.equal(result.packets, 3);
  const streamed = await parseCaptureFile(new File([data], "local.pcap"));
  assert.deepEqual(streamed, result);
});
test("capture does not bridge missing bytes into a detection", () => {
  const first = "GET /?q=uni";
  const result = parseCapture(capture([[100, first], [100 + first.length + 3, "on select HTTP/1.1\r\n\r\n"]]).buffer);
  assert.equal(result.findings.length, 0);
  assert.ok(result.warnings.some((w) => w.includes("TCP gaps")));
});
