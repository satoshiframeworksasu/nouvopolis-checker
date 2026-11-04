/**
 * JSON Canonicalization Scheme (RFC 8785), for claim commitments and proofs
 * (docs/plans/facts.md 1.2). Object members are sorted by their UTF-16 code
 * units, numbers and strings are written as ECMAScript's JSON.stringify
 * writes them (which is what RFC 8785 specifies), and there is no whitespace.
 * Only JSON values are accepted: anything else (undefined, a function, a
 * non-finite number, a class instance) throws input_invalid.
 */
import { KeyError } from "./errors";

export type JsonValue = null | boolean | number | string | readonly JsonValue[] | { readonly [key: string]: JsonValue };

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new KeyError("input_invalid");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.some(([, v]) => v === undefined)) throw new KeyError("input_invalid");
    // Default sort compares UTF-16 code units, as RFC 8785 section 3.2.3 requires.
    entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
  }
  throw new KeyError("input_invalid");
}
