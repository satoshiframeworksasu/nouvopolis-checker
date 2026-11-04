/**
 * The checks of the standalone checker page (docs/plans/snapshots.md 8.2),
 * on an export's files, with no network: WebCrypto, PKI.js/asn1js (BSD-3)
 * and @otskit/core (MIT); no LGPL code (answer 9.13). Pure, so the tests
 * run it directly and the page only renders its lines.
 *
 * What it checks:
 * - every file against manifest.json (SHA-256);
 * - a whole snapshot (snapshot.json): every leaf rebuilt from its content and
 *   the whole tree, against root.txt;
 * - every item file: its leaf rebuilt here from its content and salt, its
 *   inclusion proof (RFC 9162) up to the root, and that root against the
 *   sealed fingerprint the evidence covers;
 * - each original qualified token (token.der): its message imprint is the
 *   sealed fingerprint, the provider's CMS signature is valid, and the
 *   signer's chain leads to the trust anchor at the token's time; the token
 *   inside token.tsr is token.der; renewals and revocation data read;
 * - each .ots file: its file digest is the sealed fingerprint; its
 *   attestations listed (pending calendars; Bitcoin blocks with the Merkle
 *   root to compare, since the page asks no block explorer);
 * - a document: its salt and original bytes give the sealed fp-doc-v1.
 *
 * The trust anchor is the provider's root the user gives (from the EU
 * Trusted List); without one, the chain's own last certificate stands in and
 * its fingerprint is shown for comparison. Never "verified" (D6).
 */
import { DetachedTimestampFile } from "@otskit/core";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

import { buf, concatBytes, equalBytes } from "~/lib/keys/bytes";
import { verifyInclusion } from "~/lib/snapshots/merkle";
import { checkSnapshot, type LeafType, type SealedSnapshot } from "~/lib/snapshots/format";

import { bytesToHex, hexToBytes, leafInput } from "../leaves";
import type { CheckerMessageKey } from "./texts";

export type LineStatus = "ok" | "fail" | "note";
export interface Line {
  readonly status: LineStatus;
  readonly key: CheckerMessageKey;
  readonly params?: Readonly<Record<string, string>>;
  /** The file or value the line is about (code, not wording). */
  readonly subject: string;
}

const SHA256 = "2.16.840.1.101.3.4.2.1";
const TST_INFO = "1.2.840.113549.1.9.16.1.4";
const CMS_DATA = "1.2.840.113549.1.7.1";
const SIGNED_DATA = "1.2.840.113549.1.7.2";
const COMMON_NAME = "2.5.4.3";

let engineSet = false;
function engine(): void {
  if (engineSet) return;
  pkijs.setEngine("checker", new pkijs.CryptoEngine({ name: "checker", crypto: globalThis.crypto }));
  engineSet = true;
}

const sha256 = async (bytes: Uint8Array) => new Uint8Array(await crypto.subtle.digest("SHA-256", buf(bytes)));
const text = (bytes: Uint8Array) => new TextDecoder("utf-8", { fatal: true }).decode(bytes);
const json = (bytes: Uint8Array): unknown => JSON.parse(text(bytes));
const dirOf = (path: string) => (path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "");
const join = (dir: string, name: string) => (dir ? `${dir}/${name}` : name);

/** PEM certificates to DER. */
export function pemToDer(pem: string): Uint8Array[] {
  return [...pem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)].map((m) =>
    Uint8Array.from(atob(m[1]!.replace(/\s+/g, "")), (c) => c.charCodeAt(0)),
  );
}

const certificate = (der: Uint8Array) => pkijs.Certificate.fromBER(der.slice().buffer);
const commonName = (cert: pkijs.Certificate) => String(cert.subject.typesAndValues.find((t) => t.type === COMMON_NAME)?.value.valueBlock.value ?? "");
const fingerprint = async (der: Uint8Array) => (bytesToHex(await sha256(der)).toUpperCase().match(/../g) ?? []).join(":");

/** The evidence directory that seals an item file's root: `<dir>/evidence`, from `<dir>/items/<file>` or `<dir>/item.json`. */
function evidenceFor(path: string): string {
  const dir = dirOf(path);
  const base = dir.endsWith("/items") ? dir.slice(0, -"/items".length) : dir === "items" ? "" : dir;
  return join(base, "evidence");
}

interface TokenResult {
  readonly ok: boolean;
  readonly signer: string;
  readonly time: string;
}

/** An original token over the digest: imprint, provider signature and chain to the anchor at the token's time. */
async function checkToken(der: Uint8Array, digest: Uint8Array, chain: Uint8Array[], anchor: Uint8Array): Promise<TokenResult> {
  engine();
  try {
    const parsed = asn1js.fromBER(der.slice().buffer);
    if (parsed.offset === -1) return { ok: false, signer: "", time: "" };
    const info = new pkijs.ContentInfo({ schema: parsed.result });
    if (info.contentType !== SIGNED_DATA) return { ok: false, signer: "", time: "" };
    const signed = new pkijs.SignedData({ schema: info.content });
    if (signed.encapContentInfo.eContentType !== TST_INFO || !signed.encapContentInfo.eContent) return { ok: false, signer: "", time: "" };
    const tst = pkijs.TSTInfo.fromBER(signed.encapContentInfo.eContent.valueBlock.valueHexView.slice().buffer);
    const imprintOk =
      tst.messageImprint.hashAlgorithm.algorithmId === SHA256 && equalBytes(new Uint8Array(tst.messageImprint.hashedMessage.valueBlock.valueHexView), digest);
    // The signature and the chain, on the same SignedData read as plain CMS data (as the sealing Worker checks it).
    const plain = new pkijs.SignedData({ schema: info.content });
    plain.encapContentInfo.eContentType = CMS_DATA;
    const own = (plain.certificates ?? []).filter((c): c is pkijs.Certificate => c instanceof pkijs.Certificate);
    const ownDer = own.map((c) => bytesToHex(new Uint8Array(c.toSchema().toBER())));
    plain.certificates = [...own, ...chain.filter((c) => !ownDer.includes(bytesToHex(c))).map(certificate)];
    const result = await plain.verify({ signer: 0, trustedCerts: [certificate(anchor)], checkChain: true, extendedMode: true, checkDate: tst.genTime });
    const signer = result.signerCertificate ? commonName(result.signerCertificate) : "";
    return { ok: imprintOk && result.signatureVerified === true && result.signerCertificateVerified === true, signer, time: tst.genTime.toISOString() };
  } catch {
    return { ok: false, signer: "", time: "" };
  }
}

/** The token inside a rebuilt TimeStampResp, as its exact bytes. */
function tokenInEnvelope(tsr: Uint8Array): Uint8Array | null {
  const parsed = asn1js.fromBER(tsr.slice().buffer);
  if (parsed.offset === -1 || !(parsed.result instanceof asn1js.Sequence)) return null;
  const [status, token] = parsed.result.valueBlock.value;
  if (!status || !token) return null;
  return new Uint8Array(token.valueBeforeDecodeView);
}

function revocationReads(der: Uint8Array, path: string): boolean {
  engine();
  try {
    if (path.endsWith(".crl")) pkijs.CertificateRevocationList.fromBER(der.slice().buffer);
    else if (path.endsWith(".ocsp")) pkijs.OCSPResponse.fromBER(der.slice().buffer);
    else return false;
    return true;
  } catch {
    return false;
  }
}

export interface CheckOptions {
  /** The provider's root certificate (PEM), from the EU Trusted List. */
  readonly anchorPem?: string;
}

/** Checks an export's files. Returns the lines to show; a line with status "fail" means something did not match. */
export async function checkArchive(files: ReadonlyMap<string, Uint8Array>, options: CheckOptions = {}): Promise<Line[]> {
  const lines: Line[] = [];
  const add = (status: LineStatus, key: CheckerMessageKey, subject: string, params?: Record<string, string>) => lines.push({ status, key, subject, params });
  const paths = [...files.keys()].sort();

  // 1. Every file against the manifest.
  const manifestBytes = files.get("manifest.json");
  if (manifestBytes) {
    const manifest = json(manifestBytes) as { files?: { path: string; sha256: string }[] };
    for (const f of manifest.files ?? []) {
      const bytes = files.get(f.path);
      add(bytes && bytesToHex(await sha256(bytes)) === f.sha256 ? "ok" : "fail", bytes && bytesToHex(await sha256(bytes)) === f.sha256 ? "evidenceCheck.msg.manifestOk" : "evidenceCheck.msg.manifestBad", f.path);
    }
  } else {
    add("fail", "evidenceCheck.msg.manifestBad", "manifest.json");
  }

  const sealedDigest = (dir: string): Uint8Array | null => {
    const bytes = files.get(join(dir, "sealed-digest.txt"));
    const hex = bytes ? text(bytes).trim().split(/\s+/)[1] : undefined;
    return hex && /^[0-9a-f]{64}$/.test(hex) ? hexToBytes(hex) : null;
  };

  // 2. Whole snapshots: every leaf rebuilt from the content, and the tree, against root.txt.
  for (const path of paths.filter((p) => p === "snapshot.json" || p.endsWith("/snapshot.json"))) {
    const rootBytes = files.get(join(dirOf(path), "root.txt"));
    try {
      if (!rootBytes) throw new Error("root");
      await checkSnapshot(json(files.get(path)!) as SealedSnapshot, hexToBytes(text(rootBytes).trim()));
      add("ok", "evidenceCheck.page.snapshotOk", path);
    } catch {
      add("fail", "evidenceCheck.page.snapshotBad", path);
    }
  }

  // 3. Items: leaf rebuilt from content and salt, inclusion proof, root against the sealed fingerprint.
  for (const path of paths.filter((p) => p === "item.json" || /(^|\/)items\/[^/]+\.json$/.test(p))) {
    let item: {
      item: { type: LeafType };
      content: unknown;
      salt: string | null;
      leaf: { value: string };
      inclusionProof: { leafIndex: number; treeSize: number; path: string[] };
      root: string;
    };
    try {
      item = json(files.get(path)!) as typeof item;
    } catch {
      add("fail", "evidenceCheck.page.leafRebuiltBad", path);
      continue;
    }
    const leaf = hexToBytes(item.leaf.value);
    let input: Uint8Array | null = null;
    let rebuilt = true;
    try {
      input = leafInput(item.item.type, item.content, item.salt);
    } catch {
      rebuilt = false;
    }
    if (!rebuilt) add("fail", "evidenceCheck.page.leafRebuiltBad", path);
    else if (input === null) add("note", "evidenceCheck.msg.leafNone", path);
    else add(equalBytes(await sha256(input), leaf) ? "ok" : "fail", equalBytes(await sha256(input), leaf) ? "evidenceCheck.page.leafRebuilt" : "evidenceCheck.page.leafRebuiltBad", path);
    const root = hexToBytes(item.root);
    let proofOk = false;
    try {
      proofOk = await verifyInclusion(leaf, item.inclusionProof.leafIndex, item.inclusionProof.treeSize, item.inclusionProof.path.map(hexToBytes), root);
    } catch {
      proofOk = false;
    }
    add(proofOk ? "ok" : "fail", proofOk ? "evidenceCheck.msg.proofOk" : "evidenceCheck.msg.proofBad", path);
    const sealed = sealedDigest(evidenceFor(path));
    const rootOk = sealed !== null && equalBytes(sealed, root);
    add(rootOk ? "ok" : "fail", rootOk ? "evidenceCheck.msg.rootOk" : "evidenceCheck.msg.rootBad", path);
  }

  // 4. The evidence of each seal.
  const anchorGiven = options.anchorPem ? pemToDer(options.anchorPem)[0] : undefined;
  if (options.anchorPem && !anchorGiven) add("fail", "evidenceCheck.msg.anchorGiven", "PEM");
  for (const digestPath of paths.filter((p) => p.endsWith("sealed-digest.txt"))) {
    const ev = dirOf(digestPath);
    const digest = sealedDigest(ev);
    if (!digest) continue;
    const tokenDirs = paths.filter((p) => p.startsWith(`${ev}/qualified-timestamp-`) && p.endsWith("/token.der")).map(dirOf).sort((a, b) => Number(a.split("-").pop()) - Number(b.split("-").pop()));
    for (const at of tokenDirs) {
      const der = files.get(join(at, "token.der"))!;
      const tsr = files.get(join(at, "token.tsr"));
      const inner = tsr ? tokenInEnvelope(tsr) : null;
      add(inner && equalBytes(inner, der) ? "ok" : "fail", inner && equalBytes(inner, der) ? "evidenceCheck.msg.envelopeOk" : "evidenceCheck.msg.envelopeBad", join(at, "token.tsr"));
      const chain = pemToDer(text(files.get(join(at, "chain.pem")) ?? new Uint8Array()));
      if (at.endsWith("qualified-timestamp-1")) {
        const anchor = anchorGiven ?? chain[chain.length - 1];
        if (!anchor) {
          add("fail", "evidenceCheck.page.tokenBad", join(at, "token.der"));
        } else {
          if (anchorGiven) add("note", "evidenceCheck.msg.anchorGiven", await fingerprint(anchorGiven));
          else add("note", "evidenceCheck.msg.anchorArchive", await fingerprint(anchor));
          const result = await checkToken(der, digest, chain, anchor);
          add(result.ok ? "ok" : "fail", result.ok ? "evidenceCheck.page.tokenOk" : "evidenceCheck.page.tokenBad", join(at, "token.der"));
          if (result.ok) {
            add("note", "evidenceCheck.page.tokenTime", result.time);
            add("note", "evidenceCheck.page.signer", result.signer);
          }
        }
      } else {
        add("note", "evidenceCheck.msg.renewal", join(at, "token.der"));
      }
      for (const r of paths.filter((p) => p.startsWith(`${at}/revocation-`))) {
        const reads = revocationReads(files.get(r)!, r);
        add(reads ? "ok" : "fail", reads ? "evidenceCheck.msg.revocationOk" : "evidenceCheck.msg.revocationBad", r);
      }
    }
    for (const proofPath of paths.filter((p) => p.startsWith(`${ev}/bitcoin/`) && p.endsWith(".ots"))) {
      try {
        const ots = DetachedTimestampFile.deserialize(files.get(proofPath)!);
        if (!equalBytes(ots.fileDigest(), digest)) throw new Error("digest");
        add("ok", "evidenceCheck.page.otsOk", proofPath);
        for (const { msg, attestation } of ots.timestamp.allAttestations()) {
          if (attestation.kind === "pending") add("note", "evidenceCheck.page.otsPending", attestation.uri);
          // Bitcoin's Merkle root as block explorers show it: the attested message, byte-reversed.
          else if (attestation.kind === "bitcoin") add("note", "evidenceCheck.page.otsBitcoin", bytesToHex(msg.slice().reverse()), { height: String(attestation.height) });
        }
      } catch {
        add("fail", "evidenceCheck.page.otsBad", proofPath);
      }
    }
    // A document: its salt and original bytes give the sealed fp-doc-v1.
    const doc = dirOf(ev);
    const original = files.get(join(doc, "original"));
    const salt = files.get(join(doc, "salt.bin"));
    if (original && salt) {
      const ok = equalBytes(await sha256(concatBytes(salt, original)), digest);
      add(ok ? "ok" : "fail", ok ? "evidenceCheck.msg.documentOk" : "evidenceCheck.msg.documentBad", join(doc, "original"));
    }
  }
  return lines;
}
