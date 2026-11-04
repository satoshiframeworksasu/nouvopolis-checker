/**
 * Key sets (docs/plans/keys.md, section 2.1 and 2.4): an X25519 encryption
 * pair and an Ed25519 signing pair, generated in the browser. Used for a
 * person and, with the same shape, for a firm key version.
 *
 * Private keys are generated extractable only so they can be wrapped once
 * (privateKeys.ts); everything that uses them afterwards gets non-extractable
 * copies from the unwrap.
 */
import { ALG } from "./alg";
import { buf } from "./bytes";
import { KeyError } from "./errors";
import { generateKeyPair } from "./retry";

export interface KeySet {
  readonly alg: typeof ALG.keySet;
  readonly encryption: CryptoKeyPair;
  readonly signing: CryptoKeyPair;
}

export interface PublicKeys {
  readonly alg: typeof ALG.keySet;
  /** Raw X25519 public key, 32 bytes. */
  readonly encryption: Uint8Array;
  /** Raw Ed25519 public key, 32 bytes. */
  readonly signing: Uint8Array;
}

export async function generateKeySet(): Promise<KeySet> {
  const encryption = await generateKeyPair(crypto.subtle, "X25519", true, [
    "deriveBits",
  ]);
  const signing = await generateKeyPair(crypto.subtle, "Ed25519", true, [
    "sign",
    "verify",
  ]);
  return { alg: ALG.keySet, encryption, signing };
}

export async function exportPublicKeys(
  set: Pick<KeySet, "encryption" | "signing">,
): Promise<PublicKeys> {
  return {
    alg: ALG.keySet,
    encryption: new Uint8Array(
      await crypto.subtle.exportKey("raw", set.encryption.publicKey),
    ),
    signing: new Uint8Array(
      await crypto.subtle.exportKey("raw", set.signing.publicKey),
    ),
  };
}

function checkLength(raw: Uint8Array): void {
  if (raw.length !== 32) throw new KeyError("input_invalid");
}

export async function importEncryptionPublicKey(
  raw: Uint8Array,
): Promise<CryptoKey> {
  checkLength(raw);
  return crypto.subtle.importKey("raw", buf(raw), { name: "X25519" }, true, []);
}

export async function importSigningPublicKey(
  raw: Uint8Array,
): Promise<CryptoKey> {
  checkLength(raw);
  return crypto.subtle.importKey("raw", buf(raw), { name: "Ed25519" }, true, [
    "verify",
  ]);
}
