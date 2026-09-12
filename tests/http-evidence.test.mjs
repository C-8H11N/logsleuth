import assert from "node:assert/strict";
import test from "node:test";
import { parseCapture, parseCaptureFile } from "../app/pcapng.ts";
import { HttpEvidence } from "../app/http-evidence.ts";
import { correlateSessions } from "../app/attack-sessions.ts";
import { encode, pcap, pcapng, request, response } from "./capture-fixtures.mjs";

test("pairs a single transaction, preserving capture provenance but not credentials", () => {
  const result = parseCapture(pcap([{ text: request }, { text: response, reverse: true }]).buffer);
  assert.equal(result.httpAnalysis.paired, 1);
  assert.equal(result.httpObservations[0].peerId, 2);
  assert.equal(result.findings[0].status, 200);
  assert.equal(result.findings[0].timestamp, "2023-11-14T22:13:20.123Z");
  assert.equal(result.findings[0].captureEvidence.packets[0].epochNanoseconds, "1700000000123456000");
  assert.equal(result.findings[0].captureEvidence.firstPacket, 1);
  assert.doesNotMatch(JSON.stringify(result), /synthetic-secret|synthetic-cookie|synthetic-token/);
  assert.equal(result.httpObservations[0].path, "/?[REDACTED]");
});
test("missing responses and multiple requests remain unpaired", () => {
  for (const text of [request, request + request]) {
    const result = parseCapture(pcap([{ text }]).buffer);
    assert.equal(result.httpAnalysis.paired, 0);
    assert.ok(result.httpObservations.every((o) => o.peerId === null));
  }
  const result = parseCapture(pcap([{ text: request + request }, { text: response + response, reverse: true }]).buffer);
  assert.equal(result.httpAnalysis.requests, 2);
  assert.equal(result.httpAnalysis.responses, 2);
  assert.equal(result.httpAnalysis.paired, 0);
});
test("response scripts are not flagged as request attacks", () => {
  const body = "<script>test</script>";
  const result = parseCapture(pcap([{ reverse: true, text: `HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n${body}` }]).buffer);
  assert.equal(result.findings.length, 0);
});
test("HTTP-looking body is not parsed as another message", () => {
  const text = `POST / HTTP/1.1\r\nContent-Length: ${request.length}\r\n\r\n${request}`;
  const result = parseCapture(pcap([{ text }]).buffer);
  assert.equal(result.httpAnalysis.requests, 1);
});
test("truncated, chunked and duplicate-length framing never produces a paired result", () => {
  const variants = [
    "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nOK",
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nOK",
  ];
  for (const text of variants) {
    const result = parseCapture(pcap([{ text: request }, { text, reverse: true }]).buffer);
    assert.equal(result.httpAnalysis.paired, 0);
    assert.ok(result.httpAnalysis.incomplete + result.httpAnalysis.unsupported > 0);
  }
});
test("truncated IP and capture snaplen make evidence uncertain", () => {
  for (const extra of [{ totalExtra: 10 }, { originalExtra: 10 }]) {
    const result = parseCapture(pcap([{ text: request, ...extra }, { text: response, reverse: true }]).buffer);
    assert.equal(result.httpAnalysis.paired, 0);
    assert.equal(result.httpObservations[0].evidence.uncertain, true);
  }
});
test("new SYN seals old connection epoch before tuple reuse", () => {
  const result = parseCapture(pcap([
    { text: request }, { text: response, reverse: true },
    { flags: 2, seq: 1000 }, { seq: 1001, text: request }, { seq: 9000, text: response, reverse: true },
  ]).buffer);
  assert.equal(result.httpAnalysis.paired, 2);
  assert.equal(result.httpObservations[0].peerId, 2);
  assert.equal(result.httpObservations[2].peerId, 4);
});
test("PCAP timestamps preserve micro/nanoseconds in either byte order", () => {
  for (const little of [true, false]) for (const nano of [true, false]) {
    const result = parseCapture(pcap([{ text: request, fraction: nano ? 123456789 : 123456 }], { little, nano }).buffer);
    assert.equal(result.findings[0].captureEvidence.packets[0].epochNanoseconds, nano ? "1700000000123456789" : "1700000000123456000");
  }
});
test("PCAPNG default, decimal and binary resolutions plus signed offsets", async () => {
  for (const little of [true, false]) for (const [resolution, ticks, offset, expected] of [
    [6, 1000001n, 0n, "1000001000"], [9, 1000000001n, 2n, "3000000001"], [138, 1536n, -1n, "500000000"],
  ]) {
    const data = pcapng([{ text: request, ticks }], { little, resolution, offset });
    const result = parseCapture(data.buffer);
    assert.equal(result.findings[0].captureEvidence.packets[0].epochNanoseconds, expected);
    assert.deepEqual(await parseCaptureFile(new File([data], "local.pcapng")), result);
  }
});
test("PCAPNG interface and section boundaries cannot cross-correlate", () => {
  const result = parseCapture(pcapng([{ text: request, interfaceId: 0 }, { text: response, reverse: true, interfaceId: 1 }], { interfaces: 2 }).buffer);
  assert.equal(result.httpAnalysis.paired, 0);
  const first = pcapng([{ text: request }]), second = pcapng([{ text: response, reverse: true }]);
  const combined = new Uint8Array(first.length + second.length);
  combined.set(first); combined.set(second, first.length);
  const sections = parseCapture(combined.buffer);
  assert.equal(sections.httpAnalysis.paired, 0);
  assert.equal(sections.httpObservations[1].evidence.firstPacket, 2);
});
test("PCAPNG out-of-bounds packet lengths are rejected", () => {
  const data = pcapng([{ text: request }]);
  new DataView(data.buffer).setUint32(28 + 44 + 20, 1000000, true);
  assert.throws(() => parseCapture(data.buffer), /boundary/);
});
test("HTTP observation budget is bounded and reported", () => {
  const collector = new HttpEvidence();
  const evidence = { packets: [], firstPacket: 1, lastPacket: 1, packetCount: 0, uncertain: false };
  const many = encode("GET / HTTP/1.1\r\n\r\n".repeat(200));
  collector.ingest("pcap|127.0.0.1:1 → 127.0.0.2:2", many, evidence);
  assert.equal(collector.observations.length, 128);
  assert.equal(collector.stats.omitted, 1);
});

test("capture timestamps participate in the 30-minute investigation windows", () => {
  const first = parseCapture(pcap([{ text: request, seconds: 1700000000 }]).buffer).findings[0];
  const second = { ...first, id: 2, timestamp: "2023-11-15T02:00:00.000Z" };
  assert.equal(correlateSessions([first, second]).length, 2);
});

test("8 MiB chunk boundary preserves packet numbering and HTTP evidence", async () => {
  const base = pcap([{ text: request }, { text: response, reverse: true }]);
  const fillerSize = 8 * 1024 * 1024 - 24 - 16 - 10;
  const data = new Uint8Array(base.length + fillerSize + 16);
  data.set(base.subarray(0, 24));
  const v = new DataView(data.buffer);
  v.setUint32(24 + 8, fillerSize, true);
  v.setUint32(24 + 12, fillerSize, true);
  data.set(base.subarray(24), 24 + 16 + fillerSize);
  const expected = parseCapture(data.buffer);
  const progress = [];
  const streamed = await parseCaptureFile(new File([data], "boundary.pcap"), (p) => progress.push(p.percent));
  assert.deepEqual(streamed, expected);
  assert.equal(streamed.httpObservations[0].evidence.firstPacket, 2);
  assert.equal(streamed.httpAnalysis.paired, 1);
  assert.equal(progress.at(-1), 100);
  assert.ok(progress.length > 1);
});
test("cancellation at final progress does not publish a completed report", async () => {
  const controller = new AbortController();
  await assert.rejects(parseCaptureFile(new File([pcap([{ text: request }])], "cancel.pcap"), () => controller.abort(), controller.signal), { name: "AbortError" });
});

test("conflicting retransmissions and response-before-request do not pair", () => {
  for (const packets of [
    [{ text: request }, { text: request.replace("token=", "other=") }, { text: response, reverse: true }],
    [{ text: response, reverse: true }, { text: request }],
  ]) assert.equal(parseCapture(pcap(packets).buffer).httpAnalysis.paired, 0);
});

test("HEAD and CONNECT remain unpaired and CONNECT authority is redacted", () => {
  for (const method of ["HEAD", "CONNECT"]) {
    const text = `${method} ${method === "CONNECT" ? "synthetic-secret@localhost:443" : "/"} HTTP/1.1\r\nHost: localhost\r\n\r\n`;
    const result = parseCapture(pcap([{ text }, { text: response, reverse: true }]).buffer);
    assert.equal(result.httpAnalysis.paired, 0);
    assert.doesNotMatch(JSON.stringify(result), /synthetic-secret/);
  }
});
