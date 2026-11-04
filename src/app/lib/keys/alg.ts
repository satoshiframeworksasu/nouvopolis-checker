/**
 * Versioned algorithm identifiers (docs/plans/keys.md, decision 1.3). Every
 * wrapped value, signature and fingerprint carries one, so a later version
 * (for example a post-quantum hybrid) can be added without changing old rows.
 */
import { KeyError } from "./errors";

export const ALG = {
  /** Personal key set: X25519 encryption + Ed25519 signing. */
  keySet: "ks-v1:x25519+ed25519",
  /** Private keys wrapped under a KEK from HKDF-SHA-256, with AES-256-GCM. */
  privateKeyWrap: "kek-v1:hkdfsha256-aes256gcm",
  /** HPKE (RFC 9180), base mode: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM. */
  hpke: "hpke-v1:x25519-hkdfsha256-aes256gcm",
  /** Ed25519 signatures over key statements (the firm chain, pins; and, as statement v1, a person's encryption key). */
  signature: "sig-v1:ed25519",
  /** Ed25519 firm signature over a person's encryption and signing public keys (statement v2, docs/plans/keys.md 2.3a). */
  personKey: "sig-v2:ed25519",
  /** Content under a DEK (2.5): AES-256-GCM, random 96-bit nonce, aad naming the object. */
  content: "aead-v1:aes256gcm",
  /** Salted claim commitment (docs/plans/facts.md 1.2): SHA-256 over a label, a 32-byte salt and the claim in JCS. */
  commitment: "cm-v1",
  /** SHA-256 of a raw public key, first 150 bits as 6 groups of 5 Crockford base32 characters: the firm's security code (its signing key) and pins. */
  fingerprint: "fp-v1:sha256-b32x30",
  /** A person's security code (docs/plans/keys.md 2.3b): SHA-256 over a label, the encryption and the signing public keys; same display as fp-v1. */
  securityCode: "fp-v2:sha256-b32x30",
} as const;

export type Alg = (typeof ALG)[keyof typeof ALG];

export function assertAlg(expected: Alg, actual: string): void {
  if (actual !== expected) throw new KeyError("alg_unknown");
}
