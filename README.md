# OfficeUnlocker

A single‑page web app that removes **editing restrictions** from common
document types, directly in your browser. It only clears protection that is
stored as a *flag or property* — **it does not break, crack or bypass real
encryption.**

- **Microsoft Office** — modern (`.xlsx`/`.docx`/`.pptx`, incl. macro‑enabled
  `.xlsm`/`.docm`/`.pptm` and binary `.xlsb`) and legacy (`.xls`/`.doc`): sheet,
  workbook and document protection ("Restrict Editing").
- **OpenDocument** (`.ods`/`.odt`/`.odp`, LibreOffice) — sheet and section
  protection.
- **VBA macro projects** — the "lock project for viewing" password inside
  macro‑enabled Office files.
- **Outlook** (`.pst`) — the message‑store password.

**Everything runs locally. Your files are never uploaded to any server.**

**[Open the app](https://michaelkrisper.github.io/OfficeUnlocker/)**

[![CI](https://github.com/michaelkrisper/OfficeUnlocker/actions/workflows/ci.yml/badge.svg)](https://github.com/michaelkrisper/OfficeUnlocker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Live demo](https://img.shields.io/badge/demo-GitHub%20Pages-4f46e5)](https://michaelkrisper.github.io/OfficeUnlocker/)

## How it works

The file is routed by its content (magic bytes), not its extension, and handled
by the matching unlocker — all in memory, nothing uploaded:

- **Office (OOXML)** — these files are ZIP archives of XML, and the protection is
  just a plain XML flag. The archive is unzipped with
  [JSZip](https://stuk.github.io/jszip/), the relevant elements are stripped
  (`workbookProtection` / `sheetProtection` / `fileSharing` for Excel,
  `w:documentProtection` / `w:writeProtection` for Word, `p:modifyVerifier` for
  PowerPoint) and it is re‑zipped. Binary `.xlsb` workbooks store the same
  protection as BIFF12 records inside `.bin` parts (`BrtSheetProtection`,
  `BrtBookProtection`, `BrtFileSharing`, plus their ISO/agile variants); those
  records are dropped from the part and it is re‑zipped.
- **OpenDocument** — also a ZIP, but protection is stored as XML *attributes*
  (`table:protected`, `text:protected`) guarded by a hashed `protection-key`.
  The flags are flipped off and the key hashes removed.
- **Legacy binary Office** (`.xls`/`.doc`) — these are OLE2 compound files. For
  Excel the BIFF protection records (`PROTECT`, `PASSWORD`, `WINDOWPROTECT`,
  `OBJECTPROTECT`, …) are zeroed in place. For Word, "Restrict Editing" is
  removed by clearing the `Dop.fProtEnabled` switch (located via the FIB's
  `fcDop`). Legacy PowerPoint (`.ppt`) has no flag‑based editing restriction —
  it is only ever plain or fully encrypted — so it is checked for encryption
  (via the `CurrentUserAtom` header token) and otherwise passed through
  untouched.
- **VBA projects** — the project password lives in the `PROJECT` stream's `DPB`
  key; renaming it (a same‑length edit) makes the VBA editor treat the project as
  unprotected. Works for macro‑enabled OOXML (`vbaProject.bin`) and legacy files.
- **PST** — Outlook does not encrypt mail with the password; it only stores a
  CRC of it as `PidTagPstPassword`. That property is located in the message
  store and set to `0`, which removes the password outright. Works for the
  none, compressible (permute) and high (cyclic) data encodings.

The result is downloaded as `unlocked_<yourfile>` — your original is never
touched.

## What it can and cannot do

| Protection type | Supported |
| --- | --- |
| Sheet / workbook / document protection (Office OOXML) | Yes |
| Binary Excel protection (`.xlsb`, BIFF12 records incl. ISO/agile) | Yes |
| OpenDocument sheet / section protection (`.ods`/`.odt`/`.odp`) | Yes |
| Legacy Excel protection records (`.xls`, BIFF) | Yes |
| Legacy Word "Restrict Editing" (`.doc`, `Dop.fProtEnabled`) | Yes |
| VBA macro project password (OOXML &amp; legacy) | Yes |
| Outlook PST password — ANSI &amp; Unicode, none/compressible/cyclic encoding | Yes |
| Legacy PowerPoint (`.ppt`) editing restriction | n/a: no such flag exists; encryption is detected |
| **Open / view password (real, full‑file encryption)** | No: detected, never decrypted |

Files protected with an **open password** (AES‑encrypted Office documents, or
anything that needs a password just to open/view) are real encryption.
OfficeUnlocker **does not attempt to break them** — it detects them and tells you
so, instead of producing a corrupt file.

> **Note:** Only use this tool on files you own or are authorised to modify.

## Disclaimer

OfficeUnlocker removes editing restrictions that are stored as flags or
properties; it does **not** break, crack or circumvent real encryption, and it
does not recover or reveal passwords. It is provided **"as is", under the MIT
license, without warranty of any kind**, for the legitimate recovery of
documents you own or are authorised to modify. You are solely responsible for
ensuring your use complies with applicable law and any agreements covering the
files. The author accepts no liability for misuse.

## Development

The unlocking logic is split into small UMD modules, so the exact same code
powers both the browser app and the Node.js test suite.

```bash
npm install     # install dev dependencies (JSZip, ESLint)
npm run lint    # lint with ESLint
npm test        # run the automated test suite
npm run check   # lint + test (used in CI)
```

### Project structure

```
index.html                  # The web app (UI + glue code)
utils.js                    # Little-endian byte readers shared by the modules (UMD)
unlock.js                   # Format dispatcher + Office/OOXML & ODF logic (UMD)
ole2.js                     # OLE2 / Compound File reader + in-place patcher (UMD)
olelock.js                  # Legacy .xls/.doc + VBA project unlocker (UMD)
pstunlock.js                # Outlook PST password remover (UMD)
vendor/jszip.min.js         # Vendored JSZip (no CDN)
fonts/outfit-*.woff2        # Self-hosted Outfit font (no Google Fonts)
test/unlock.test.js         # Automated tests (build → unlock → verify)
test/fixtures.js            # Synthetic protected-file builders for the tests
eslint.config.js            # ESLint flat config
.github/workflows/ci.yml    # Lint + test on every push / PR, deploy from main
```

## Deployment

Every push to `main` runs the [CI workflow](.github/workflows/ci.yml); once lint
and tests pass, it publishes the files the page loads (`index.html`, the five
modules, `vendor/`, `fonts/`) to GitHub Pages and checks them on the live site.
To enable it once:
**Settings → Pages → Build and deployment → Source: GitHub Actions**.

## Tech stack

Plain HTML, CSS and JavaScript — no framework, no bundler. The only runtime
dependency is [JSZip](https://stuk.github.io/jszip/) `3.10.1`, vendored locally
at `vendor/jszip.min.js`. The page loads **no external resources at all** — the
Outfit font is self-hosted in `fonts/` and there is no analytics or CDN — so it
works fully offline and makes zero third-party requests.

## License

[MIT](LICENSE) © Michael Krisper
