/**
 * Reads the entries of an evidence export (a zip of stored entries, as
 * app/lib/evidence/zip.ts writes them) from its central directory. Pure.
 * Anything else (compressed entries, zip64, a broken archive) is refused.
 */
export class ZipReadError extends Error {
  constructor() {
    super("zip: unreadable");
    this.name = "ZipReadError";
  }
}

export function readZip(bytes: Uint8Array): Map<string, Uint8Array> {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u32 = (at: number) => {
    if (at < 0 || at + 4 > bytes.length) throw new ZipReadError();
    return view.getUint32(at, true);
  };
  const u16 = (at: number) => {
    if (at < 0 || at + 2 > bytes.length) throw new ZipReadError();
    return view.getUint16(at, true);
  };
  // The end of central directory record: the last 22 bytes when there is no comment, as the export writes it.
  let end = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 22 - 0xffff); i--) {
    if (u32(i) === 0x06054b50) {
      end = i;
      break;
    }
  }
  if (end < 0) throw new ZipReadError();
  const count = u16(end + 10);
  let at = u32(end + 16);
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const files = new Map<string, Uint8Array>();
  for (let n = 0; n < count; n++) {
    if (u32(at) !== 0x02014b50) throw new ZipReadError();
    const method = u16(at + 10);
    const size = u32(at + 20);
    const stored = u32(at + 24);
    const nameLength = u16(at + 28);
    const extraLength = u16(at + 30);
    const commentLength = u16(at + 32);
    const offset = u32(at + 42);
    if (method !== 0 || size !== stored || at + 46 + nameLength > bytes.length) throw new ZipReadError();
    const name = decoder.decode(bytes.subarray(at + 46, at + 46 + nameLength));
    if (u32(offset) !== 0x04034b50) throw new ZipReadError();
    const start = offset + 30 + u16(offset + 26) + u16(offset + 28);
    if (start + size > bytes.length || files.has(name)) throw new ZipReadError();
    files.set(name, bytes.slice(start, start + size));
    at += 46 + nameLength + extraLength + commentLength;
  }
  return files;
}
