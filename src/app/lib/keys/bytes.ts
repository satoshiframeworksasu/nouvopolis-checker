/**
 * Byte helpers for the key layer. Pure functions, no logging.
 *
 * `encodeParts` is the one way the key layer joins a fixed label and
 * variable fields (the "‖" of docs/plans/keys.md): the label's UTF-8 bytes,
 * then each field as a 4-byte big-endian length followed by its bytes. The
 * lengths keep the encoding unambiguous ("ab" ‖ "c" never equals "a" ‖ "bc").
 */
export type Part = string | number | Uint8Array;

const encoder = new TextEncoder();

export function utf8(text: string): Uint8Array {
  return encoder.encode(text);
}

export function concatBytes(...chunks: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

function partBytes(part: Part): Uint8Array {
  if (part instanceof Uint8Array) return part;
  if (typeof part === "number") {
    if (!Number.isSafeInteger(part) || part < 0)
      throw new RangeError("part must be a non-negative integer");
    return utf8(String(part));
  }
  return utf8(part);
}

export function encodeParts(
  label: string,
  ...parts: readonly Part[]
): Uint8Array {
  const chunks: Uint8Array[] = [utf8(label)];
  for (const part of parts) {
    const bytes = partBytes(part);
    const length = new Uint8Array(4);
    new DataView(length.buffer).setUint32(0, bytes.length);
    chunks.push(length, bytes);
  }
  return concatBytes(...chunks);
}

export function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

/** A copy backed by its own ArrayBuffer, as WebCrypto's BufferSource types expect. */
export function buf(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromBase64(text: string): Uint8Array {
  const s = atob(text);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
