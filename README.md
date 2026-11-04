# Nouvopolis evidence checker

Two tools that check a Nouvopolis evidence export without Nouvopolis and without the timestamp provider's software:

- **`check.html`**: one self-contained page that works offline in any recent web browser. Open it, choose the export's zip file and, optionally, the provider's root certificate. Its Content Security Policy allows no connection: it cannot send anything anywhere.
- **`check.sh`**: a POSIX shell script that uses OpenSSL, `od`, `awk` and `sed`, plus the official OpenTimestamps client (`ots`) for the `.ots` files. Run it in the unpacked export: `sh check.sh [--root provider-root.pem]`.

Every Nouvopolis evidence export carries a copy of both. Each published version is listed, with the SHA-256 of its files and a download of each, at **https://nouvopolis.com/check**. Compare a copy's SHA-256 with the published one, or use the published copy.

## What they check

- every file of the export against its `manifest.json`;
- every item of a sealed snapshot: its leaf, rebuilt from its content and salt; its inclusion proof (RFC 9162) up to the sealed fingerprint (Merkle root); and that root against the fingerprint the timestamps cover;
- each qualified timestamp (RFC 3161): its message imprint is the sealed fingerprint; the provider's signature is valid; its certificate chain leads to the trust anchor (the provider's root from the EU Trusted List, given with `--root` or in the page; otherwise the root in the archive, with its fingerprint shown for comparison). Also that `token.tsr` holds exactly `token.der`, and that the revocation data reads;
- each OpenTimestamps proof (`.ots`): it timestamps the sealed fingerprint. A Bitcoin anchor is shown with its block height and the Merkle root that block must have;
- a document: its salt and original bytes give its sealed fingerprint.

A seal shows that an item existed in exactly this form by the time of its timestamp. It says nothing about whether the item's content is correct, and it is not a legal opinion.

## Each release, anchored in Bitcoin

`releases/<version>/` holds, for each published version:

- `SHA256SUMS`: the SHA-256 of `check.html` and `check.sh`, in `sha256sum` format. In a folder holding the two files, `sha256sum -c SHA256SUMS` compares them.
- `SHA256SUMS.ots`: an OpenTimestamps proof of `SHA256SUMS`. This proof shows the file existed in this form by the time of its Bitcoin block; check it with the official `ots` client (`ots verify SHA256SUMS.ots`, with a Bitcoin node, or `ots info SHA256SUMS.ots` to read it). A proof is first pending at its calendars, then completed once Bitcoin has confirmed it.

The same files are published next to each version at https://nouvopolis.com/check.

## Building, byte for byte

The published files are reproducible from this repository:

```sh
npm ci          # the exact versions in package-lock.json
npm run build   # writes dist/check.html and dist/check.sh, and prints their SHA-256
```

The output depends only on this repository's content and the locked dependencies, not on the time, the machine or the path. Compare the printed SHA-256 with `releases.json` and with https://nouvopolis.com/check. Node.js 22 or later.

## Layout

- `build.mjs`: the build. It bundles the page's script with Vite and inlines it, sets the page's Content Security Policy by hash, embeds the licence of every bundled package (and refuses GPL or LGPL code), and fills in the wording of both tools.
- `src/app/lib/...`: the checker's source. These files are copied byte for byte from the Nouvopolis application, at the same paths, so the code that checks an export is the code that builds it. The entry point is `src/app/lib/evidence/checker/page.ts`; the script's template is `src/app/lib/evidence/checker/check.sh`. One import is for types only (`@packs/types` in `snapshots/format.ts`); the build drops it, and it is not part of this repository.
- `src/texts.en.json`: the wording, from the Nouvopolis English locale.
- `releases.json`: every published version with the SHA-256 and size of its files, the SHA-256 of its `SHA256SUMS` and, once its proof is complete, its Bitcoin block.
- `releases/<version>/`: each version's `SHA256SUMS` and `SHA256SUMS.ots`.
- `package.json`, `package-lock.json`: the version, and the exact dependencies.

## Licence

MIT (see `LICENSE`). The page bundles PKI.js, asn1js, bytestreamjs, pvtsutils, pvutils, @noble/hashes and @otskit/core, under the MIT or BSD licences; each licence text is embedded in `check.html`.
