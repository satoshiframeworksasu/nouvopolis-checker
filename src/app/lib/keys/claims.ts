/**
 * The crypto of a claim (docs/plans/facts.md 1.2, D14). Browser only.
 *
 * - **Salted commitment (cm-v1):** SHA-256 of "nouvopolis/v1/claim-commitment"
 *   ‖ salt ‖ JCS(claim without "commitment" and "proof"). The 32-byte salt is
 *   random per claim and kept inside the claim, so it travels only in the
 *   encrypted record. The commitment itself is stored in clear (the future
 *   Merkle leaf) and reveals nothing without the salt.
 * - **Author proof:** a W3C Data Integrity proof, cryptosuite eddsa-jcs-2022,
 *   made with the author's Ed25519 signing key: SHA-256(JCS(proof options)) ‖
 *   SHA-256(JCS(claim without proof)), signed; the value is multibase base58btc.
 * - **Encryption:** AES-256-GCM under the file's fact-record DEK, with
 *   `aad = "nouvopolis/v1/fact-claim" ‖ object kind ‖ record id ‖ DEK version
 *   ‖ claim id`, so a ciphertext cannot move to another claim, record or
 *   version. Adviser-only notes (facts.md 3.5) are sealed the same way under
 *   the file's notes-record DEK, with the label "nouvopolis/v1/adviser-note",
 *   so a note never opens as a claim, nor a claim as a note. The plaintext is padded to a multiple of 256 bytes (0x80, then
 *   zeros) so its length says little about the claim.
 *
 * Errors carry a code only (KeyError), never a claim's content.
 */
import { ALG, assertAlg } from "./alg";
import { decodeBase58, encodeBase58 } from "./base58";
import { buf, concatBytes, encodeParts, equalBytes, fromBase64, randomBytes, toBase64, utf8 } from "./bytes";
import type { DataKeyObject } from "./data-keys";
import { KeyError } from "./errors";
import { canonicalJson } from "./jcs";
import { importSigningPublicKey } from "./key-set";

export const CLAIM_SALT_BYTES = 32;
export const CLAIM_PAD_BLOCK = 256;
/** The largest ciphertext the database takes (64 KiB), less the GCM tag, rounded down to a pad block. */
export const CLAIM_MAX_PADDED = Math.floor((64 * 1024 - 16) / CLAIM_PAD_BLOCK) * CLAIM_PAD_BLOCK;

export interface ClaimCommitmentInfo {
  readonly alg: typeof ALG.commitment;
  /** 32 random bytes, base64url without padding. */
  readonly salt: string;
}

export interface DataIntegrityProof {
  readonly type: "DataIntegrityProof";
  readonly cryptosuite: "eddsa-jcs-2022";
  readonly created: string;
  /** "urn:uuid:<author user id>#key-<key version>". */
  readonly verificationMethod: string;
  readonly proofPurpose: "assertionMethod";
  /** Multibase base58btc ("z…") of the 64-byte Ed25519 signature. */
  readonly proofValue: string;
}

/** What signing needs of a document: a claim, an adviser-only note, a snapshot's conclusion. */
export interface SignedDocument {
  readonly "@context": readonly string[];
  readonly id: string;
  readonly issuer: string;
  readonly proof?: DataIntegrityProof;
}

/** What the crypto needs of a claim; the full shape is app/lib/facts/claim.ts. */
export interface ClaimDocument extends SignedDocument {
  readonly commitment: ClaimCommitmentInfo;
}

export const toBase64Url = (bytes: Uint8Array) => toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export function fromBase64Url(text: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new KeyError("input_invalid");
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  return fromBase64(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf(bytes)));
}

/** A new random salt for one claim. */
export function newClaimCommitmentInfo(): ClaimCommitmentInfo {
  return { alg: ALG.commitment, salt: toBase64Url(randomBytes(CLAIM_SALT_BYTES)) };
}

function withoutKeys<T extends object>(value: T, ...keys: string[]): Record<string, unknown> {
  const copy: Record<string, unknown> = { ...(value as Record<string, unknown>) };
  for (const k of keys) delete copy[k];
  return copy;
}

/** The claim's salted commitment (32 bytes). Throws input_invalid for a salt of the wrong length. */
export async function claimCommitment(claim: ClaimDocument): Promise<Uint8Array> {
  assertAlg(ALG.commitment, claim.commitment.alg);
  const salt = fromBase64Url(claim.commitment.salt);
  if (salt.length !== CLAIM_SALT_BYTES) throw new KeyError("input_invalid");
  const body = utf8(canonicalJson(withoutKeys(claim, "commitment", "proof")));
  return sha256(encodeParts("nouvopolis/v1/claim-commitment", salt, body));
}

/** True when the disclosed claim (with its salt) matches a stored commitment. */
export async function checkClaimCommitment(claim: ClaimDocument, commitment: Uint8Array): Promise<boolean> {
  return equalBytes(await claimCommitment(claim), commitment);
}

export const verificationMethodFor = (userId: string, keyVersion: number) => `urn:uuid:${userId}#key-${keyVersion}`;

async function proofHash(claim: SignedDocument, options: Omit<DataIntegrityProof, "proofValue">): Promise<Uint8Array> {
  const config = { "@context": claim["@context"], ...options };
  return concatBytes(await sha256(utf8(canonicalJson(config))), await sha256(utf8(canonicalJson(withoutKeys(claim, "proof")))));
}

/** Signs a claim as its author. The claim's issuer must be "urn:uuid:<userId>". */
export async function signClaim<T extends SignedDocument>(
  claim: T,
  author: { readonly userId: string; readonly keyVersion: number; readonly signingKey: CryptoKey },
  created: Date = new Date(),
): Promise<T & { readonly proof: DataIntegrityProof }> {
  if (claim.issuer !== `urn:uuid:${author.userId}` || claim.proof) throw new KeyError("input_invalid");
  const options: Omit<DataIntegrityProof, "proofValue"> = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    created: created.toISOString().replace(/\.\d{3}Z$/, "Z"),
    verificationMethod: verificationMethodFor(author.userId, author.keyVersion),
    proofPurpose: "assertionMethod",
  };
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, author.signingKey, buf(await proofHash(claim, options))));
  return { ...claim, proof: { ...options, proofValue: `z${encodeBase58(signature)}` } };
}

/**
 * Throws signature_invalid unless the claim carries a proof by this author's
 * key version that verifies: the issuer, the verification method and the
 * signature must all match.
 */
export async function verifyClaimProof(
  claim: SignedDocument,
  author: { readonly userId: string; readonly keyVersion: number; readonly signingPublicKey: Uint8Array },
): Promise<void> {
  const proof = claim.proof;
  if (
    !proof ||
    proof.type !== "DataIntegrityProof" ||
    proof.cryptosuite !== "eddsa-jcs-2022" ||
    proof.proofPurpose !== "assertionMethod" ||
    claim.issuer !== `urn:uuid:${author.userId}` ||
    proof.verificationMethod !== verificationMethodFor(author.userId, author.keyVersion) ||
    !proof.proofValue?.startsWith("z")
  ) {
    throw new KeyError("signature_invalid");
  }
  const signature = decodeBase58(proof.proofValue.slice(1));
  if (!signature || signature.length !== 64) throw new KeyError("signature_invalid");
  const { proofValue: _value, ...options } = proof;
  const key = await importSigningPublicKey(author.signingPublicKey);
  if (!(await crypto.subtle.verify({ name: "Ed25519" }, key, buf(signature), buf(await proofHash(claim, options))))) {
    throw new KeyError("signature_invalid");
  }
}

export function padClaim(bytes: Uint8Array): Uint8Array {
  const size = Math.ceil((bytes.length + 1) / CLAIM_PAD_BLOCK) * CLAIM_PAD_BLOCK;
  if (size > CLAIM_MAX_PADDED) throw new KeyError("input_invalid");
  const out = new Uint8Array(size);
  out.set(bytes);
  out[bytes.length] = 0x80;
  return out;
}

export function unpadClaim(bytes: Uint8Array): Uint8Array {
  if (bytes.length === 0 || bytes.length % CLAIM_PAD_BLOCK !== 0) throw new KeyError("input_invalid");
  let end = bytes.length - 1;
  while (end >= 0 && bytes[end] === 0) end--;
  if (end < 0 || bytes[end] !== 0x80) throw new KeyError("input_invalid");
  return bytes.slice(0, end);
}

export type FactRecord = Pick<DataKeyObject, "objectKind" | "objectId" | "dekVersion"> & { readonly objectKind: "fact_record" };
/** The file's adviser-only notes record (facts.md 3.5): never wrapped for the client. */
export type NotesRecord = Pick<DataKeyObject, "objectKind" | "objectId" | "dekVersion"> & { readonly objectKind: "adviser_note" };
/** A record whose items are signed documents sealed one by one: claims, or adviser-only notes. */
export type SealedRecord = FactRecord | NotesRecord;

const AAD_LABEL = { fact_record: "nouvopolis/v1/fact-claim", adviser_note: "nouvopolis/v1/adviser-note" } as const;

export interface SealedClaim {
  readonly alg: typeof ALG.content;
  /** 12 bytes. */
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
}

const claimAad = (record: SealedRecord, claimId: string) =>
  encodeParts(AAD_LABEL[record.objectKind], record.objectKind, record.objectId, record.dekVersion, claimId);

function importDek(dek: Uint8Array, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  if (dek.length !== 32) throw new KeyError("input_invalid");
  return crypto.subtle.importKey("raw", buf(dek), { name: "AES-GCM" }, false, [usage]);
}

/** The claim id as the database stores it: the uuid of "urn:uuid:<id>". */
export function claimUuid(claim: Pick<ClaimDocument, "id">): string {
  const m = /^urn:uuid:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/.exec(claim.id);
  if (!m) throw new KeyError("input_invalid");
  return m[1]!;
}

/** Encrypts a signed claim (or adviser-only note) under its record's DEK. */
export async function sealClaim(dek: Uint8Array, record: SealedRecord, claim: ClaimDocument): Promise<SealedClaim> {
  if (!claim.proof) throw new KeyError("input_invalid");
  const key = await importDek(dek, "encrypt");
  const nonce = randomBytes(12);
  const plaintext = padClaim(utf8(canonicalJson(claim)));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: buf(nonce), additionalData: buf(claimAad(record, claimUuid(claim))) }, key, buf(plaintext)),
  );
  return { alg: ALG.content, nonce, ciphertext };
}

/**
 * Decrypts the claim stored as `claimId`. Throws unlock_failed for another
 * DEK, record, version or claim id, or a changed ciphertext; input_invalid if
 * the content is not a claim with that id. The caller then checks the proof
 * (verifyClaimProof) against the row's author before showing anything.
 */
export async function openClaim(dek: Uint8Array, record: SealedRecord, claimId: string, sealed: SealedClaim): Promise<ClaimDocument> {
  assertAlg(ALG.content, sealed.alg);
  if (sealed.nonce.length !== 12) throw new KeyError("wrap_invalid");
  const key = await importDek(dek, "decrypt");
  let plaintext: Uint8Array;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf(sealed.nonce), additionalData: buf(claimAad(record, claimId)) }, key, buf(sealed.ciphertext)),
    );
  } catch {
    throw new KeyError("unlock_failed");
  }
  let claim: unknown;
  try {
    claim = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(unpadClaim(plaintext)));
  } catch {
    throw new KeyError("input_invalid");
  }
  if (typeof claim !== "object" || claim === null || claimUuid(claim as ClaimDocument) !== claimId) throw new KeyError("input_invalid");
  return claim as ClaimDocument;
}
