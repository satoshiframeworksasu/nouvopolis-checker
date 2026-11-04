#!/bin/sh
# Nouvopolis evidence export: the standalone check (docs/plans/snapshots.md 8.2).
#
# Needs only: OpenSSL, a POSIX shell with od, awk and sed, and, for the .ots
# files, the official OpenTimestamps client (`ots`). No network: `ots` is run
# with no calendar allowed, and asks a Bitcoin node only if one runs locally.
#
# Usage, from the unpacked archive:
#   sh check.sh [--root provider-root.pem] [directory]
#
# --root: the provider's root certificate, taken from the EU Trusted List.
# Without it, each certificate chain is checked against the root certificate
# found in the archive, and its fingerprint is printed for comparison.
#
# Checks: every file against manifest.json; every item's leaf input against
# its leaf value; every inclusion proof (RFC 9162) up to the sealed
# fingerprint; each qualified token in both forms (token.der, token.tsr)
# with OpenSSL; the revocation data; each .ots file with `ots`; a document's
# salt and bytes against its fp-doc-v1. Exit status 0 only if nothing failed.

# The text below is filled in from the export's locale when it is built.
MSG_TITLE={{evidenceCheck.msg.title}}
MSG_VERSION={{evidenceCheck.msg.version}}
MSG_COMPARE={{evidenceCheck.msg.compare}}
MSG_MISSING={{evidenceCheck.msg.missingTool}}
MSG_NO_OTS={{evidenceCheck.msg.noOts}}
MSG_MANIFEST_OK={{evidenceCheck.msg.manifestOk}}
MSG_MANIFEST_BAD={{evidenceCheck.msg.manifestBad}}
MSG_LEAF_OK={{evidenceCheck.msg.leafOk}}
MSG_LEAF_BAD={{evidenceCheck.msg.leafBad}}
MSG_LEAF_NONE={{evidenceCheck.msg.leafNone}}
MSG_PROOF_OK={{evidenceCheck.msg.proofOk}}
MSG_PROOF_BAD={{evidenceCheck.msg.proofBad}}
MSG_ROOT_OK={{evidenceCheck.msg.rootOk}}
MSG_ROOT_BAD={{evidenceCheck.msg.rootBad}}
MSG_TOKEN_OK={{evidenceCheck.msg.tokenOk}}
MSG_TOKEN_BAD={{evidenceCheck.msg.tokenBad}}
MSG_ENVELOPE_OK={{evidenceCheck.msg.envelopeOk}}
MSG_ENVELOPE_BAD={{evidenceCheck.msg.envelopeBad}}
MSG_RENEWAL={{evidenceCheck.msg.renewal}}
MSG_ANCHOR_ARCHIVE={{evidenceCheck.msg.anchorArchive}}
MSG_ANCHOR_GIVEN={{evidenceCheck.msg.anchorGiven}}
MSG_REVOCATION_OK={{evidenceCheck.msg.revocationOk}}
MSG_REVOCATION_BAD={{evidenceCheck.msg.revocationBad}}
MSG_OTS_OK={{evidenceCheck.msg.otsOk}}
MSG_OTS_BAD={{evidenceCheck.msg.otsBad}}
MSG_OTS_ANSWER={{evidenceCheck.msg.otsAnswer}}
MSG_DOCUMENT_OK={{evidenceCheck.msg.documentOk}}
MSG_DOCUMENT_BAD={{evidenceCheck.msg.documentBad}}
MSG_SUMMARY_OK={{evidenceCheck.msg.summaryOk}}
MSG_SUMMARY_BAD={{evidenceCheck.msg.summaryBad}}

LC_ALL=C
export LC_ALL

ROOT_PEM=""
DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --root) ROOT_PEM="$2"; shift 2 ;;
    *) DIR="$1"; shift ;;
  esac
done
[ -n "$DIR" ] || DIR=$(dirname "$0")
cd "$DIR" || exit 2

FAILED=0
ok() { printf 'OK    %s %s\n' "$1" "$2"; }
bad() { printf 'FAIL  %s %s\n' "$1" "$2"; FAILED=1; }
note() { printf 'NOTE  %s %s\n' "$1" "$2"; }

printf '%s\n%s\n%s\n\n' "$MSG_TITLE" "$MSG_VERSION" "$MSG_COMPARE"
for tool in openssl od awk sed; do
  command -v "$tool" >/dev/null 2>&1 || { printf '%s %s\n' "$MSG_MISSING" "$tool"; exit 2; }
done
HAVE_OTS=0
command -v ots >/dev/null 2>&1 && HAVE_OTS=1

TMP=$(mktemp -d) || exit 2
trap 'rm -rf "$TMP"' EXIT

# Hex text to bytes on stdout (octal escapes, which every POSIX printf reads).
unhex() {
  printf "$(printf '%s' "$1" | awk '{
    h = "0123456789abcdef"
    for (i = 1; i < length($0); i += 2)
      printf "\\%03o", (index(h, substr($0, i, 1)) - 1) * 16 + index(h, substr($0, i + 1, 1)) - 1
  }')"
}
# SHA-256 of a file, as lowercase hex.
sha_file() { openssl dgst -sha256 -binary "$1" | od -An -v -tx1 | tr -d ' \n'; }
# SHA-256 of hex bytes, as lowercase hex.
sha_hex() { unhex "$1" > "$TMP/h"; sha_file "$TMP/h"; }

# --- 1. Every file against the manifest -----------------------------------------------------------
if [ -f manifest.json ]; then
  awk '
    /^      "path": / { p = $2; gsub(/[",]/, "", p) }
    /^      "sha256": / { s = $2; gsub(/[",]/, "", s); print s, p }
  ' manifest.json > "$TMP/manifest"
  while read -r want path; do
    if [ -f "$path" ] && [ "$(sha_file "$path")" = "$want" ]; then ok "$MSG_MANIFEST_OK" "$path"; else bad "$MSG_MANIFEST_BAD" "$path"; fi
  done < "$TMP/manifest"
fi

# --- 2. Items: leaf input -> leaf value -> inclusion proof -> root ---------------------------------
# Reads the fields of an item file written by the export (two-space JSON).
item_fields() {
  awk '
    /^  "[A-Za-z]+": / { sec = $1; gsub(/[":]/, "", sec) }
    sec == "leaf" && /^    "value": / { v = $2; gsub(/[",]/, "", v); print "value " v }
    sec == "leaf" && /^    "input": / { v = $2; gsub(/[",]/, "", v); print "input " v }
    sec == "inclusionProof" && /^    "leafIndex": / { v = $2; gsub(/,/, "", v); print "index " v }
    sec == "inclusionProof" && /^    "treeSize": / { v = $2; gsub(/,/, "", v); print "size " v }
    sec == "inclusionProof" && /^      "[0-9a-f]+",?$/ { v = $1; gsub(/[",]/, "", v); print "path " v }
    /^  "root": / { v = $2; gsub(/[",]/, "", v); print "root " v }
  ' "$1"
}

# The evidence directory that seals an item file's root.
evidence_for() {
  d=$(dirname "$1")
  case "$d" in */items) d=$(dirname "$d") ;; items) d=. ;; esac
  printf '%s/evidence' "$d"
}

for item in $(find . -name '*.json' \( -path '*/items/*' -o -name item.json \) | sort); do
  item_fields "$item" > "$TMP/f"
  value=$(awk '$1 == "value" { print $2 }' "$TMP/f")
  input=$(awk '$1 == "input" { print $2 }' "$TMP/f")
  index=$(awk '$1 == "index" { print $2 }' "$TMP/f")
  size=$(awk '$1 == "size" { print $2 }' "$TMP/f")
  root=$(awk '$1 == "root" { print $2 }' "$TMP/f")
  if [ "$input" = "null" ] || [ -z "$input" ]; then
    note "$MSG_LEAF_NONE" "$item"
  elif [ "$(sha_hex "$input")" = "$value" ]; then
    ok "$MSG_LEAF_OK" "$item"
  else
    bad "$MSG_LEAF_BAD" "$item"
  fi
  # RFC 9162 section 2.1.3.2.
  fn=$index; sn=$((size - 1)); r=$(sha_hex "00$value"); valid=1
  for p in $(awk '$1 == "path" { print $2 }' "$TMP/f"); do
    if [ "$sn" -eq 0 ]; then valid=0; break; fi
    if [ $((fn % 2)) -eq 1 ] || [ "$fn" -eq "$sn" ]; then
      r=$(sha_hex "01$p$r")
      if [ $((fn % 2)) -eq 0 ]; then
        while [ $((fn % 2)) -eq 0 ] && [ "$fn" -ne 0 ]; do fn=$((fn / 2)); sn=$((sn / 2)); done
      fi
    else
      r=$(sha_hex "01$r$p")
    fi
    fn=$((fn / 2)); sn=$((sn / 2))
  done
  if [ "$valid" -eq 1 ] && [ "$sn" -eq 0 ] && [ "$r" = "$root" ]; then ok "$MSG_PROOF_OK" "$item"; else bad "$MSG_PROOF_BAD" "$item"; fi
  sealed=$(awk '{ print $2 }' "$(evidence_for "$item")/sealed-digest.txt" 2>/dev/null)
  if [ -n "$sealed" ] && [ "$sealed" = "$root" ]; then ok "$MSG_ROOT_OK" "$item"; else bad "$MSG_ROOT_BAD" "$item"; fi
done

# --- 3. The evidence of each seal -------------------------------------------------------------------
for digest_file in $(find . -name sealed-digest.txt | sort); do
  ev=$(dirname "$digest_file")
  digest=$(awk '{ print $2 }' "$digest_file")
  for der in $(find "$ev" -path '*/qualified-timestamp-*/token.der' | sort); do
    at=$(dirname "$der")
    if [ -n "$ROOT_PEM" ]; then
      anchor="$ROOT_PEM"; note "$MSG_ANCHOR_GIVEN" "$ROOT_PEM"
    else
      # The last certificate of the chain stands in for the trust anchor; its fingerprint is printed.
      anchor="$TMP/anchor.pem"
      awk '/BEGIN CERTIFICATE/ { buf = "" } { buf = buf $0 "\n" } END { printf "%s", buf }' "$at/chain.pem" > "$anchor"
      note "$MSG_ANCHOR_ARCHIVE" "$(openssl x509 -in "$anchor" -noout -fingerprint -sha256 | sed 's/.*=//')"
    fi
    openssl ts -reply -in "$at/token.tsr" -token_out -out "$TMP/inner.der" 2>/dev/null
    if cmp -s "$TMP/inner.der" "$der"; then ok "$MSG_ENVELOPE_OK" "$at/token.tsr"; else bad "$MSG_ENVELOPE_BAD" "$at/token.tsr"; fi
    case "$at" in
      *qualified-timestamp-1)
        if openssl ts -verify -token_in -in "$der" -digest "$digest" -CAfile "$anchor" -untrusted "$at/chain.pem" 2>/dev/null | grep -q 'Verification: OK'; then
          ok "$MSG_TOKEN_OK" "$der"
        else
          bad "$MSG_TOKEN_BAD" "$der"
        fi
        if openssl ts -verify -in "$at/token.tsr" -digest "$digest" -CAfile "$anchor" -untrusted "$at/chain.pem" 2>/dev/null | grep -q 'Verification: OK'; then
          ok "$MSG_TOKEN_OK" "$at/token.tsr"
        else
          bad "$MSG_TOKEN_BAD" "$at/token.tsr"
        fi
        ;;
      *)
        if openssl ts -reply -in "$der" -token_in -text >/dev/null 2>&1; then note "$MSG_RENEWAL" "$der"; else bad "$MSG_TOKEN_BAD" "$der"; fi
        ;;
    esac
    for r in "$at"/revocation-*; do
      [ -f "$r" ] || continue
      case "$r" in
        *.crl) openssl crl -inform DER -in "$r" -noout >/dev/null 2>&1 && ok "$MSG_REVOCATION_OK" "$r" || bad "$MSG_REVOCATION_BAD" "$r" ;;
        *.ocsp) openssl ocsp -respin "$r" -resp_text -noverify >/dev/null 2>&1 && ok "$MSG_REVOCATION_OK" "$r" || bad "$MSG_REVOCATION_BAD" "$r" ;;
        *) bad "$MSG_REVOCATION_BAD" "$r" ;;
      esac
    done
  done
  for proof in $(find "$ev" -path '*/bitcoin/*.ots' | sort); do
    if [ "$HAVE_OTS" -eq 0 ]; then note "$MSG_NO_OTS" "$proof"; continue; fi
    if ots --no-cache --no-default-whitelist info "$proof" 2>/dev/null | grep -q "^File sha256 hash: $digest\$"; then
      ok "$MSG_OTS_OK" "$proof"
      answer=$(ots --no-cache --no-default-whitelist verify -d "$digest" "$proof" 2>&1 | tail -n 2 | tr '\n' ' ')
      note "$MSG_OTS_ANSWER" "$answer"
    else
      bad "$MSG_OTS_BAD" "$proof"
    fi
  done
  # A document: its salt and original bytes give the sealed fp-doc-v1.
  doc=$(dirname "$ev")
  if [ -f "$doc/original" ] && [ -f "$doc/salt.bin" ]; then
    cat "$doc/salt.bin" "$doc/original" > "$TMP/doc"
    if [ "$(sha_file "$TMP/doc")" = "$digest" ]; then ok "$MSG_DOCUMENT_OK" "$doc/original"; else bad "$MSG_DOCUMENT_BAD" "$doc/original"; fi
  fi
done

printf '\n'
if [ "$FAILED" -eq 0 ]; then printf '%s\n' "$MSG_SUMMARY_OK"; else printf '%s\n' "$MSG_SUMMARY_BAD"; fi
exit "$FAILED"
