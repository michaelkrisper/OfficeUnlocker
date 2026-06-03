# 🔓 OfficeUnlocker

A single‑page web app that removes protection from several file types directly
in your browser:

- **Microsoft Office** — Excel (`.xlsx`), Word (`.docx`), PowerPoint (`.pptx`):
  editing, sheet, workbook and document protection.
- **PDF** (`.pdf`) — usage restrictions (printing, copying, editing) from a
  permissions / "owner" password.
- **Outlook** (`.pst`) — the message‑store password.

**Everything runs locally. Your files are never uploaded to any server.**

👉 **Live site:** https://michaelkrisper.github.io/OfficeUnlocker/

[![CI](https://github.com/michaelkrisper/OfficeUnlocker/actions/workflows/ci.yml/badge.svg)](https://github.com/michaelkrisper/OfficeUnlocker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## How it works

The file is routed by its content (magic bytes), not its extension, and handled
by the matching unlocker — all in memory, nothing uploaded:

- **Office (OOXML)** — these files are ZIP archives of XML, and most protection
  is just a plain XML flag. The archive is unzipped with
  [JSZip](https://stuk.github.io/jszip/), the relevant elements are stripped
  (`workbookProtection` / `sheetProtection` / `fileSharing` for Excel,
  `w:documentProtection` / `w:writeProtection` for Word, `p:modifyVerifier` for
  PowerPoint) and it is re‑zipped.
- **PDF** — a permissions‑password PDF is genuinely encrypted, but when there is
  no *open* password the encryption key is derivable from the standard padding
  string. The document is decrypted (Standard Security Handler, RC4 or AES‑128)
  and re‑saved without `/Encrypt`, so the restrictions are gone.
- **PST** — Outlook does not encrypt mail with the password; it only stores a
  CRC of it as `PidTagPstPassword`. That property is located in the message
  store and set to `0`, which removes the password outright.

The result is downloaded as `unlocked_<yourfile>` — your original is never
touched.

## What it can and cannot do

| Protection type | Supported |
| --- | :---: |
| Sheet / workbook protection (Excel) | ✅ |
| Restrict editing / read‑only (Word) | ✅ |
| Modify / write protection (PowerPoint) | ✅ |
| PDF usage restrictions — RC4 / AES‑128, empty user password | ✅ |
| PDF AES‑256 (newer Acrobat, V5/R6) | ❌ (not yet) |
| Outlook PST password — ANSI &amp; Unicode, none/compressible encoding | ✅ |
| Outlook PST "high" (cyclic) encoding | ❌ |
| **Open password (full‑file encryption / PDF view password)** | ❌ |

Files protected with an **open password** (AES‑encrypted OLE2 Office documents,
or PDFs that need a password just to view) cannot be opened without the
password. OfficeUnlocker detects these automatically and tells you so instead of
producing a corrupt file.

> ℹ️ PDF and PST support is newer than the Office path. The crypto primitives are
> verified against published test vectors and the logic against synthetic
> fixtures, but since your original file is never modified, keep it until you've
> confirmed the unlocked copy opens correctly.

> ⚠️ Only use this tool on files you are authorised to modify.

## Usage

Just open the [live site](https://michaelkrisper.github.io/OfficeUnlocker/),
or run it locally — no build step required:

```bash
git clone https://github.com/michaelkrisper/OfficeUnlocker.git
cd OfficeUnlocker
# Serve the folder with any static server, e.g.:
npx serve .
# then open the printed URL in your browser
```

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
unlock.js                   # Format dispatcher + Office (OOXML) logic (UMD)
pdfunlock.js                # PDF Standard Security Handler decryptor (UMD)
pstunlock.js                # Outlook PST password remover (UMD)
bincrypto.js                # MD5 / RC4 / AES primitives for the PDF handler (UMD)
test/unlock.test.js         # Automated tests (build → unlock → verify)
test/fixtures.js            # Synthetic protected-file builders for the tests
eslint.config.js            # ESLint flat config
.github/workflows/ci.yml    # Lint + test on every push / PR
.github/workflows/deploy.yml# Deploy to GitHub Pages on push to main
```

## Deployment

Pushing to `main` triggers the **Deploy to GitHub Pages** workflow, which lints,
tests and then publishes the static files to GitHub Pages. To enable it once:
**Settings → Pages → Build and deployment → Source: GitHub Actions**.

## Tech stack

Plain HTML, CSS and JavaScript — no framework, no bundler. Runtime dependencies,
loaded from a CDN with Subresource Integrity:
[JSZip](https://stuk.github.io/jszip/) `3.10.1` (Office ZIP handling) and
[pako](https://github.com/nodeca/pako) `2.1.0` (inflate for PDF object streams).

## License

[MIT](LICENSE) © Michael Krisper
