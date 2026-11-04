/**
 * Errors from the key layer carry a fixed code and nothing else: never a key,
 * a wrapped value, a code or any plaintext (docs/plans/keys.md, section 7).
 */
export type KeyErrorCode =
  | "unsupported_browser"
  | "unlock_failed"
  | "wrap_invalid"
  | "signature_invalid"
  | "chain_invalid"
  | "alg_unknown"
  | "input_invalid"
  | "checksum_invalid"
  | "confirmation_mismatch"
  | "key_mismatch"
  | "not_set_up";

export class KeyError extends Error {
  readonly code: KeyErrorCode;

  constructor(code: KeyErrorCode) {
    super(code);
    this.name = "KeyError";
    this.code = code;
  }
}
