/** Bytes-like input accepted throughout the SDK. */
export type BytesLike = Uint8Array | ArrayBuffer;

export function toBuffer(data: BytesLike | ArrayBufferView): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
}

/** Copy into a standalone ArrayBuffer (asn1 libraries expect exact-length ArrayBuffers). */
export function toArrayBuffer(data: BytesLike | ArrayBufferView): ArrayBuffer {
  if (data instanceof ArrayBuffer) return data;
  const out = new ArrayBuffer(data.byteLength);
  new Uint8Array(out).set(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
  return out;
}

export function bytesEqual(a: BytesLike, b: BytesLike): boolean {
  return toBuffer(a).equals(toBuffer(b));
}

/** Strip leading zero bytes so that INTEGER encodings with and without sign padding compare equal. */
export function normalizeInteger(data: BytesLike): Buffer {
  const buf = toBuffer(data);
  let i = 0;
  while (i < buf.length - 1 && buf[i] === 0) i++;
  return buf.subarray(i);
}

/** Convert PEM text to DER. If several blocks are present, all are returned. */
export function pemToDerList(pem: string, label?: string): Buffer[] {
  const re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
  const out: Buffer[] = [];
  for (const m of pem.matchAll(re)) {
    if (label && m[1] !== label) continue;
    out.push(Buffer.from(m[2]!.replace(/\s+/g, ""), "base64"));
  }
  return out;
}

export function derToPem(der: BytesLike, label: string): string {
  const b64 = toBuffer(der).toString("base64");
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}
