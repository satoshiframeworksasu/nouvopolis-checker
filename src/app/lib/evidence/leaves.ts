/**
 * The input bytes of each snapshot leaf (docs/plans/snapshots.md 2.2), from
 * an exported item's content and salt. Pure: shared by the evidence export,
 * which writes these bytes into each item file so that OpenSSL alone can hash
 * them (check.sh), and by the checker page, which rebuilds them from the
 * content to check that the bytes are what the item says.
 *
 * The leaf value is SHA-256 of these bytes, except for a document leaf
 * (fp-doc-v1 = SHA-256(salt ‖ original bytes)), whose bytes are not in a
 * snapshot export.
 */
import { encodeParts, fromBase64, utf8 } from "~/lib/keys/bytes";
import { canonicalJson } from "~/lib/keys/jcs";
import type { LeafType } from "~/lib/snapshots/format";

export const hexToBytes = (hex: string): Uint8Array => {
  if (!/^(?:[0-9a-f]{2})*$/.test(hex)) throw new Error("hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};

export const bytesToHex = (bytes: Uint8Array): string => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

const jcs = (value: unknown) => utf8(canonicalJson(value));

function withoutKeys(value: object, ...keys: string[]): Record<string, unknown> {
  const copy: Record<string, unknown> = { ...(value as Record<string, unknown>) };
  for (const k of keys) delete copy[k];
  return copy;
}

type Content = Record<string, unknown>;

/**
 * The bytes a leaf hashes, from the content and salt (hex) an item file
 * gives, or null when the item carries no content (a claim not opened, a
 * document). Throws on content of the wrong shape.
 */
export function leafInput(type: LeafType, content: unknown, saltHex: string | null): Uint8Array | null {
  if (content === null || content === undefined) return null;
  const c = content as Content;
  const salt = () => {
    if (!saltHex) throw new Error("salt");
    const s = hexToBytes(saltHex);
    if (s.length !== 32) throw new Error("salt");
    return s;
  };
  const text = (v: unknown) => {
    if (typeof v !== "string") throw new Error("content");
    return v;
  };
  const num = (v: unknown) => {
    if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) throw new Error("content");
    return v;
  };
  switch (type) {
    case "header":
      return encodeParts("nouvopolis/snap-v1/header", salt(), jcs(c.header));
    case "rule-version":
      return encodeParts("nouvopolis/snap-v1/rule", text(c.owner), text(c.ruleId), num(c.version), text(c.contentHash));
    case "pending-rule":
      return encodeParts("nouvopolis/snap-v1/pending-rule", text(c.owner), text(c.ruleId), num(c.version), text(c.contentHash));
    case "radar-version":
      return encodeParts("nouvopolis/v1/radar-leaf", text(c.owner), text(c.id), num(c.version), text(c.contentHash));
    case "radar-check":
      return encodeParts("nouvopolis/snap-v1/radar-check", text(c.owner), text(c.id), num(c.version), text(c.checkedOn));
    case "claim": {
      const claim = c.claim as { commitment?: { salt?: string } } | undefined;
      if (!claim || typeof claim !== "object") throw new Error("content");
      // The claim keeps its own salt (base64url); the item file repeats it in hex.
      const own = claim.commitment?.salt;
      if (typeof own !== "string") throw new Error("salt");
      const b64 = own.replace(/-/g, "+").replace(/_/g, "/");
      const fromClaim = fromBase64(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
      if (bytesToHex(fromClaim) !== saltHex) throw new Error("salt");
      return encodeParts("nouvopolis/v1/claim-commitment", salt(), jcs(withoutKeys(claim, "commitment", "proof")));
    }
    case "conclusion":
      return encodeParts("nouvopolis/snap-v1/conclusion", salt(), jcs(c.conclusion));
    case "document":
      return null;
  }
}
