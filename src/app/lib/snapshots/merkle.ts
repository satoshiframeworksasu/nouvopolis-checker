/**
 * The Merkle tree hash of RFC 9162 (Certificate Transparency v2), section
 * 2.1, and its inclusion proofs (docs/plans/snapshots.md 2.3). Published
 * construction, checked against the published vectors
 * (tests/vectors/merkle-rfc6962.json): no new cryptography (D1).
 *
 * - leaf hash: SHA-256(0x00 ‖ leaf)
 * - node hash: SHA-256(0x01 ‖ left ‖ right)
 * - a tree of n > 1 leaves splits at k, the largest power of two below n.
 *
 * WebCrypto only; browsers, Workers and Node. Nothing here logs.
 */
import { buf, concatBytes, equalBytes } from "../keys/bytes";

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf(bytes)));
}

export const leafHash = (leaf: Uint8Array) => sha256(concatBytes(new Uint8Array([0x00]), leaf));
export const nodeHash = (left: Uint8Array, right: Uint8Array) => sha256(concatBytes(new Uint8Array([0x01]), left, right));

/** The largest power of two strictly below n (n > 1). */
function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

async function subtreeHash(hashes: readonly Uint8Array[]): Promise<Uint8Array> {
  if (hashes.length === 1) return hashes[0]!;
  const k = split(hashes.length);
  return nodeHash(await subtreeHash(hashes.slice(0, k)), await subtreeHash(hashes.slice(k)));
}

/** MTH(D[n]): the root of the leaves, in their order. The empty tree is SHA-256 of nothing. */
export async function merkleRoot(leaves: readonly Uint8Array[]): Promise<Uint8Array> {
  if (leaves.length === 0) return sha256(new Uint8Array());
  return subtreeHash(await Promise.all(leaves.map(leafHash)));
}

async function path(m: number, hashes: readonly Uint8Array[]): Promise<Uint8Array[]> {
  if (hashes.length <= 1) return [];
  const k = split(hashes.length);
  if (m < k) return [...(await path(m, hashes.slice(0, k))), await subtreeHash(hashes.slice(k))];
  return [...(await path(m - k, hashes.slice(k))), await subtreeHash(hashes.slice(0, k))];
}

/** The inclusion proof PATH(index, D[n]) of every leaf, in leaf order. */
export async function inclusionProofs(leaves: readonly Uint8Array[]): Promise<Uint8Array[][]> {
  const hashes = await Promise.all(leaves.map(leafHash));
  return Promise.all(hashes.map((_, i) => path(i, hashes)));
}

/**
 * Verifies an inclusion proof (RFC 9162 2.1.3.2): true when the leaf at
 * `index` of a tree of `size` leaves, with this proof, gives `root`.
 */
export async function verifyInclusion(leaf: Uint8Array, index: number, size: number, proof: readonly Uint8Array[], root: Uint8Array): Promise<boolean> {
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || index < 0 || index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = await leafHash(leaf);
  for (const p of proof) {
    if (p.length !== 32 || sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = await nodeHash(p, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = await nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && equalBytes(r, root);
}
