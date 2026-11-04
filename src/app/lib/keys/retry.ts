/**
 * Retrying transient WebCrypto failures.
 *
 * WebKit 26.6 (Playwright's Linux build) sometimes fails to generate an
 * X25519 or Ed25519 key pair with an OperationError, about 3 to 6 times in
 * 1,000; an immediate second attempt succeeds. The same failure surfaces from
 * HPKE wraps, which generate a fresh ephemeral key each time. Retrying a few
 * times keeps one unlucky call from failing a key operation or the feature
 * check, while a real gap (NotSupportedError, bad input) still fails at once.
 */
const ATTEMPTS = 3;

export async function retryTransient<T>(
  op: () => Promise<T>,
  isTransient: (error: unknown) => boolean,
): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await op();
    } catch (error) {
      if (attempt >= ATTEMPTS || !isTransient(error)) throw error;
    }
  }
}

export function isOperationError(error: unknown): boolean {
  return (error as { name?: unknown } | null)?.name === "OperationError";
}

/** generateKey for X25519 or Ed25519, retried on a transient OperationError. */
export function generateKeyPair(
  subtle: SubtleCrypto,
  name: "X25519" | "Ed25519",
  extractable: boolean,
  usages: KeyUsage[],
): Promise<CryptoKeyPair> {
  return retryTransient(
    async () =>
      (await subtle.generateKey(
        { name },
        extractable,
        usages,
      )) as CryptoKeyPair,
    isOperationError,
  );
}
