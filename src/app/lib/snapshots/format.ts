/**
 * The sealed event snapshot, format `snap-v1` (docs/plans/snapshots.md 1, 2;
 * D12, D14). Pure and country-agnostic: the core knows an event type from
 * the file's list, layers by owner, and leaves by type, never a country.
 *
 * - The snapshot is composed in the browser (compose.ts), encrypted under its
 *   own data key and sent with its Merkle root only. The server never sees a
 *   leaf, a salt, the event date or the conclusion (1.3).
 * - Every item is a leaf (2.2), ordered by leaf type then by value (2.3); the
 *   root is the RFC 9162 tree hash (merkle.ts) and every leaf keeps its
 *   inclusion proof inside the snapshot.
 * - Canonical form: JCS (RFC 8785, app/lib/keys/jcs.ts). Domain separation:
 *   every hash takes a versioned label through encodeParts.
 *
 * Errors carry a code, never content (CLAUDE.md rule 4).
 */
import type { NotYetCovered, RadarItem, Rule } from "@packs/types";

import { buf, encodeParts, equalBytes, fromBase64, randomBytes, toBase64, utf8 } from "../keys/bytes";
import { fromBase64Url, toBase64Url, type DataIntegrityProof } from "../keys/claims";
import { canonicalJson } from "../keys/jcs";
import { inclusionProofs, merkleRoot, verifyInclusion } from "./merkle";

export const SNAPSHOT_FORMAT = "snap-v1" as const;
export const SNAPSHOT_SALT_BYTES = 32;

/**
 * Leaf types, in tree order (plan 2.2). A pending rule or a radar leaf can
 * never be read as a rule in force: each has its own type and label.
 */
export const LEAF_TYPES = ["header", "rule-version", "pending-rule", "radar-version", "radar-check", "claim", "document", "conclusion"] as const;
export type LeafType = (typeof LEAF_TYPES)[number];

/** A layer of the composed case, by its owner in packs/versioning.ts ("pack:xa/origin", "treaty:xa-xb", …). */
export type SnapshotLayer =
  | { readonly kind: "origin"; readonly country: string; readonly owner: string; readonly notYetCovered: readonly NotYetCovered[] }
  | { readonly kind: "residence"; readonly country: string; readonly owner: string; readonly notYetCovered: readonly NotYetCovered[] }
  | { readonly kind: "treaty"; readonly countries: readonly [string, string]; readonly owner: string; readonly notYetCovered: readonly NotYetCovered[] };

/** What the composed case does not cover (D9 rule 3, D12): shown under "Not yet covered". */
export type SnapshotGap =
  | { readonly kind: "residence-not-recorded" }
  | { readonly kind: "residence-not-covered"; readonly country: string; readonly reason: "return-to-origin" | "not-held" }
  | { readonly kind: "treaty-not-recorded"; readonly countries: readonly [string, string] };

export interface SnapshotHeader {
  readonly format: typeof SNAPSHOT_FORMAT;
  readonly snapshotId: string;
  readonly clientId: string;
  readonly firmId: string;
  /** The core "departure" or one of the origin's departure events (D12; plan answer 9.1). */
  readonly eventType: string;
  /** The event's exact date (encrypted; the server keeps its year only). On or before the sealing date. */
  readonly eventDate: string;
  readonly originPack: string;
  /** The declared country of residence recorded by the adviser, or null. Never a residence conclusion. */
  readonly residence: string | null;
  readonly taggedJurisdictions: readonly string[];
  readonly layers: readonly SnapshotLayer[];
  readonly gaps: readonly SnapshotGap[];
  /** Who sealed it: an assigned adviser or an admin, with the signing key version of the conclusion. */
  readonly sealedBy: { readonly userId: string; readonly keyVersion: number };
  /** When it was composed (ISO timestamp, UTC). */
  readonly composedAt: string;
  /** The sealing date: "Not in force yet" is as known on this date (plan 1.2, answer 9.3). */
  readonly shownOn: string;
  /** The snapshot this one corrects (same file and event type), or null (plan answer 9.2). */
  readonly follows: string | null;
}

/** One condition of a rule and what the file recorded for its tag: a reference, never a verdict (D7). */
export interface SnapshotCondition {
  readonly key: string;
  readonly state: "not_recorded" | "none" | "recorded";
  readonly values: readonly string[];
}

/** A rule version in force on the event date, with its full text and hash (D8). */
export interface SnapshotRule {
  /** Index in header.layers. */
  readonly layer: number;
  readonly owner: string;
  readonly contentHash: string;
  readonly rule: Rule;
  readonly conditions: readonly SnapshotCondition[];
}

/**
 * A rule version known on the sealing date that was not in force on the
 * event date: proposed, adopted, or enacted with an in-force date after the
 * event date (even one reached by the sealing date). "Not in force yet, as
 * known on <sealing date>", never among the rules in force (D21).
 */
export interface SnapshotPendingRule {
  /** Index in header.layers. */
  readonly layer: number;
  readonly owner: string;
  readonly contentHash: string;
  readonly rule: Rule;
  /** The procedural stage as the pack writes it, or null. */
  readonly stage: { readonly en: string } | null;
  readonly conditions: readonly SnapshotCondition[];
}

/** A radar version shown on the file at sealing time: "Not in force yet", never among the rules. */
export interface SnapshotRadar {
  readonly owner: string;
  readonly contentHash: string;
  readonly item: RadarItem;
  /** The current version of its item, or an earlier one shown as its history. */
  readonly shownAs: "current" | "earlier";
  /** Where the file shows it: a layer, or an international instrument naming recorded jurisdictions. */
  readonly context:
    | { readonly kind: "layer"; readonly layer: number }
    | { readonly kind: "instrument"; readonly body: string; readonly basis: string; readonly recorded: readonly string[] };
  /** "Last checked" as shown for this version, or null when none was shown. */
  readonly checkedOn: string | null;
}

/** A claim current at sealing time, by its stored salted commitment (cm-v1). The claim stays in the fact record. */
export interface SnapshotClaim {
  readonly id: string;
  /** base64 of the 32-byte commitment. */
  readonly commitment: string;
  /** From the claim's encrypted validFrom/validUntil: true, false, or null when it gives no dates or was not opened. */
  readonly validOnEventDate: boolean | null;
}

/** A document relied on (D7 step 6): its salted fingerprint, fp-doc-v1. Empty until uploads exist. */
export interface SnapshotDocument {
  readonly id: string;
  /** base64 of the 32-byte fp-doc-v1. */
  readonly fingerprint: string;
}

/** The adviser's conclusion: written by the adviser, signed with their signing key, never generated (D7). */
export interface SnapshotConclusion {
  readonly "@context": readonly ["https://www.w3.org/ns/credentials/v2", "https://nouvopolis.com/ns/snapshots/v1"];
  readonly type: readonly ["VerifiableCredential", "AdviserConclusion"];
  /** "urn:uuid:<random id>". */
  readonly id: string;
  /** "urn:uuid:<author user id>". */
  readonly issuer: string;
  readonly credentialSubject: {
    /** The client file: "urn:uuid:<client id>". */
    readonly id: string;
    /** "urn:uuid:<snapshot id>". */
    readonly snapshot: string;
    readonly text: string;
  };
  readonly proof?: DataIntegrityProof;
}

export interface SnapshotBody {
  readonly header: SnapshotHeader;
  /** base64url, 32 bytes. */
  readonly headerSalt: string;
  readonly inForce: readonly SnapshotRule[];
  /** "Not in force yet", as known on the sealing date: rule versions not in force on the event date, then radar versions. */
  readonly pendingRules: readonly SnapshotPendingRule[];
  readonly notInForceYet: readonly SnapshotRadar[];
  readonly claims: readonly SnapshotClaim[];
  readonly documents: readonly SnapshotDocument[];
  readonly conclusion: { readonly document: SnapshotConclusion; readonly salt: string };
}

export interface SnapshotLeaf {
  readonly type: LeafType;
  /** base64 of the 32-byte leaf value. */
  readonly value: string;
  /** What the leaf stands for, e.g. "rule:pack:xa/origin xa-exit@1" or "claim:<id>". */
  readonly ref: string;
  /** Its inclusion proof, base64 each. */
  readonly proof: readonly string[];
}

export interface SealedSnapshot {
  readonly format: typeof SNAPSHOT_FORMAT;
  readonly body: SnapshotBody;
  readonly tree: { readonly root: string; readonly leaves: readonly SnapshotLeaf[] };
}

export class SnapshotError extends Error {
  constructor(readonly code: "invalid" | "root_mismatch" | "proof_invalid" | "duplicate_leaf") {
    super(`snapshot: ${code}`);
    this.name = "SnapshotError";
  }
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf(bytes)));
}

const json = (value: unknown) => utf8(canonicalJson(value));

export const newSalt = () => toBase64Url(randomBytes(SNAPSHOT_SALT_BYTES));

function saltBytes(salt: string): Uint8Array {
  const bytes = fromBase64Url(salt);
  if (bytes.length !== SNAPSHOT_SALT_BYTES) throw new SnapshotError("invalid");
  return bytes;
}

function bytes32(b64: string): Uint8Array {
  const bytes = fromBase64(b64);
  if (bytes.length !== 32) throw new SnapshotError("invalid");
  return bytes;
}

// Leaf values (plan 2.2).
export const headerLeaf = (header: SnapshotHeader, salt: string) =>
  sha256(encodeParts("nouvopolis/snap-v1/header", saltBytes(salt), json(header)));
export const ruleLeaf = (owner: string, ruleId: string, version: number, contentHash: string) =>
  sha256(encodeParts("nouvopolis/snap-v1/rule", owner, ruleId, version, contentHash));
export const pendingRuleLeaf = (owner: string, ruleId: string, version: number, contentHash: string) =>
  sha256(encodeParts("nouvopolis/snap-v1/pending-rule", owner, ruleId, version, contentHash));
export const radarVersionLeaf = (owner: string, id: string, version: number, contentHash: string) =>
  sha256(encodeParts("nouvopolis/v1/radar-leaf", owner, id, version, contentHash));
export const radarCheckLeaf = (owner: string, id: string, version: number, checkedOn: string) =>
  sha256(encodeParts("nouvopolis/snap-v1/radar-check", owner, id, version, checkedOn));
export const conclusionLeaf = (conclusion: SnapshotConclusion, salt: string) =>
  sha256(encodeParts("nouvopolis/snap-v1/conclusion", saltBytes(salt), json(conclusion)));

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
  return a.length - b.length;
}

interface RawLeaf {
  readonly type: LeafType;
  readonly value: Uint8Array;
  readonly ref: string;
}

/** Every leaf of a body, in tree order: by type (LEAF_TYPES), then by value. */
export async function snapshotLeaves(body: SnapshotBody): Promise<RawLeaf[]> {
  const leaves: RawLeaf[] = [{ type: "header", value: await headerLeaf(body.header, body.headerSalt), ref: "header" }];
  for (const r of body.inForce) {
    leaves.push({ type: "rule-version", value: await ruleLeaf(r.owner, r.rule.id, r.rule.version, r.contentHash), ref: `rule:${r.owner} ${r.rule.id}@${r.rule.version}` });
  }
  for (const r of body.pendingRules) {
    leaves.push({
      type: "pending-rule",
      value: await pendingRuleLeaf(r.owner, r.rule.id, r.rule.version, r.contentHash),
      ref: `pending-rule:${r.owner} ${r.rule.id}@${r.rule.version}`,
    });
  }
  for (const r of body.notInForceYet) {
    const id = `${r.owner} ${r.item.id}@${r.item.version}`;
    leaves.push({ type: "radar-version", value: await radarVersionLeaf(r.owner, r.item.id, r.item.version, r.contentHash), ref: `radar:${id}` });
    if (r.checkedOn) leaves.push({ type: "radar-check", value: await radarCheckLeaf(r.owner, r.item.id, r.item.version, r.checkedOn), ref: `radar-check:${id} ${r.checkedOn}` });
  }
  for (const c of body.claims) leaves.push({ type: "claim", value: bytes32(c.commitment), ref: `claim:${c.id}` });
  for (const d of body.documents) leaves.push({ type: "document", value: bytes32(d.fingerprint), ref: `document:${d.id}` });
  leaves.push({ type: "conclusion", value: await conclusionLeaf(body.conclusion.document, body.conclusion.salt), ref: "conclusion" });
  leaves.sort((a, b) => LEAF_TYPES.indexOf(a.type) - LEAF_TYPES.indexOf(b.type) || compareBytes(a.value, b.value));
  for (let i = 1; i < leaves.length; i++) {
    if (leaves[i]!.type === leaves[i - 1]!.type && equalBytes(leaves[i]!.value, leaves[i - 1]!.value)) throw new SnapshotError("duplicate_leaf");
  }
  return leaves;
}

/** Builds the tree of a body: its root and every leaf with its inclusion proof. */
export async function sealSnapshotTree(body: SnapshotBody): Promise<SealedSnapshot> {
  const leaves = await snapshotLeaves(body);
  const values = leaves.map((l) => l.value);
  const [root, proofs] = await Promise.all([merkleRoot(values), inclusionProofs(values)]);
  return {
    format: SNAPSHOT_FORMAT,
    body,
    tree: {
      root: toBase64(root),
      leaves: leaves.map((l, i) => ({ type: l.type, value: toBase64(l.value), ref: l.ref, proof: proofs[i]!.map(toBase64) })),
    },
  };
}

/**
 * Checks a snapshot against a sealed root: rebuilds every leaf from the
 * body, the tree and its root, and verifies each stored inclusion proof.
 * Throws a SnapshotError code; returns nothing on success.
 */
export async function checkSnapshot(snapshot: SealedSnapshot, sealedRoot: Uint8Array): Promise<void> {
  if (snapshot.format !== SNAPSHOT_FORMAT || snapshot.body?.header?.format !== SNAPSHOT_FORMAT) throw new SnapshotError("invalid");
  const leaves = await snapshotLeaves(snapshot.body);
  const root = await merkleRoot(leaves.map((l) => l.value));
  if (!equalBytes(root, sealedRoot) || !equalBytes(bytes32(snapshot.tree.root), sealedRoot)) throw new SnapshotError("root_mismatch");
  if (snapshot.tree.leaves.length !== leaves.length) throw new SnapshotError("proof_invalid");
  for (const [i, stored] of snapshot.tree.leaves.entries()) {
    const leaf = leaves[i]!;
    if (stored.type !== leaf.type || stored.ref !== leaf.ref || !equalBytes(bytes32(stored.value), leaf.value)) throw new SnapshotError("proof_invalid");
    if (!(await verifyInclusion(leaf.value, i, leaves.length, stored.proof.map(fromBase64), sealedRoot))) throw new SnapshotError("proof_invalid");
  }
}

// Encryption envelope (plan 1.3, answer 9.18): the JCS bytes, padded to 4 KiB blocks.
export const SNAPSHOT_PAD_BLOCK = 4096;
/** The largest padded plaintext the database takes (4 MiB). */
export const SNAPSHOT_MAX_PADDED = 4 * 1024 * 1024;

export function padSnapshot(plaintext: Uint8Array): Uint8Array {
  const size = Math.ceil((plaintext.length + 1) / SNAPSHOT_PAD_BLOCK) * SNAPSHOT_PAD_BLOCK;
  if (size > SNAPSHOT_MAX_PADDED) throw new SnapshotError("invalid");
  const out = new Uint8Array(size);
  out.set(plaintext);
  out[plaintext.length] = 0x80;
  return out;
}

export function unpadSnapshot(padded: Uint8Array): Uint8Array {
  if (padded.length === 0 || padded.length % SNAPSHOT_PAD_BLOCK !== 0) throw new SnapshotError("invalid");
  let end = padded.length - 1;
  while (end >= 0 && padded[end] === 0) end--;
  if (end < 0 || padded[end] !== 0x80) throw new SnapshotError("invalid");
  return padded.slice(0, end);
}

export const snapshotPlaintext = (snapshot: SealedSnapshot) => padSnapshot(json(snapshot));

export function parseSnapshot(padded: Uint8Array): SealedSnapshot {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(unpadSnapshot(padded)));
  } catch {
    throw new SnapshotError("invalid");
  }
  const s = value as SealedSnapshot;
  if (typeof s !== "object" || s === null || s.format !== SNAPSHOT_FORMAT || !s.body || !s.tree) throw new SnapshotError("invalid");
  return s;
}
