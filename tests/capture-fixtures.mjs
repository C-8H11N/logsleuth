// Synthetic offline frames only: no sockets and no real credentials.
export const encode = (text) => new TextEncoder().encode(text);
export function ethernet({ text = "", seq = 100, reverse = false, flags = 0x18, totalExtra = 0 } = {}) {
  const body = encode(text), frame = new Uint8Array(54 + body.length);
  const view = new DataView(frame.buffer);
  view.setUint16(12, 0x0800);
  frame[14] = 0x45;
  view.setUint16(16, 40 + body.length + totalExtra);
  frame[23] = 6;
  frame.set(reverse ? [127,0,0,2] : [127,0,0,1], 26);
  frame.set(reverse ? [127,0,0,1] : [127,0,0,2], 30);
  view.setUint16(34, reverse ? 9999 : 12345);
  view.setUint16(36, reverse ? 12345 : 9999);
  view.setUint32(38, seq);
  frame[46] = 0x50;
  frame[47] = flags;
  frame.set(body, 54);
  return frame;
}
function join(parts) {
  const data = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { data.set(part, offset); offset += part.length; }
  return data;
}
export function pcap(packets, { little = true, nano = false } = {}) {
  const header = new Uint8Array(24), view = new DataView(header.buffer);
  view.setUint32(0, nano ? 0xa1b23c4d : 0xa1b2c3d4, little);
  view.setUint16(4, 2, little); view.setUint16(6, 4, little);
  view.setUint32(16, 65535, little); view.setUint32(20, 1, little);
  return join([header, ...packets.map((packet, i) => {
    const frame = ethernet(packet), record = new Uint8Array(16 + frame.length), v = new DataView(record.buffer);
    v.setUint32(0, packet.seconds ?? 1700000000 + i, little);
    v.setUint32(4, packet.fraction ?? 123456, little);
    v.setUint32(8, frame.length, little);
    v.setUint32(12, frame.length + (packet.originalExtra ?? 0), little);
    record.set(frame, 16);
    return record;
  })]);
}
export function pcapng(packets, { little = true, resolution = 6, offset = 0n, interfaces = 1 } = {}) {
  function block(type, size) {
    const data = new Uint8Array(size), v = new DataView(data.buffer);
    v.setUint32(0, type, little); v.setUint32(4, size, little); v.setUint32(size - 4, size, little);
    return [data, v];
  }
  const [header, h] = block(0x0a0d0d0a, 28);
  h.setUint32(8, 0x1a2b3c4d, little); h.setUint16(12, 1, little); h.setBigInt64(16, -1n, little);
  const descriptions = Array.from({ length: interfaces }, () => {
    const [idb, v] = block(1, 44);
    v.setUint16(8, 1, little); v.setUint32(12, 65535, little);
    v.setUint16(16, 9, little); v.setUint16(18, 1, little); v.setUint8(20, resolution);
    v.setUint16(24, 14, little); v.setUint16(26, 8, little); v.setBigInt64(28, offset, little);
    return idb;
  });
  return join([header, ...descriptions, ...packets.map((packet, i) => {
    const frame = ethernet(packet), [epb, v] = block(6, 32 + Math.ceil(frame.length / 4) * 4);
    const ticks = packet.ticks ?? 1700000000000000n + BigInt(i) * 1000000n;
    v.setUint32(8, packet.interfaceId ?? 0, little);
    v.setUint32(12, Number(ticks >> 32n), little); v.setUint32(16, Number(ticks & 0xffffffffn), little);
    v.setUint32(20, frame.length, little); v.setUint32(24, frame.length, little);
    epb.set(frame, 28);
    return epb;
  })]);
}
export const request = "GET /?token=synthetic-secret&q=union%20select HTTP/1.1\r\nHost: localhost\r\nCookie: sid=synthetic-cookie\r\nAuthorization: Bearer synthetic-token\r\n\r\n";
export const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
