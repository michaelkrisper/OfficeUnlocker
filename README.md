# 🔓 OfficeUnlocker

A single‑page web app that removes **editing, sheet, workbook and document
protection** from Microsoft Office files — **Excel (`.xlsx`), Word (`.docx`) and
PowerPoint (`.pptx`)** — directly in your browser.

**Everything runs locally. Your files are never uploaded to any server.**

👉 **Live site:** https://michaelkrisper.github.io/officeunlocker/

[![CI](https://github.com/michaelkrisper/officeunlocker/actions/workflows/ci.yml/badge.svg)](https://github.com/michaelkrisper/officeunlocker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## How it works

Modern Office files are really just ZIP archives containing XML. Most
"protection" is stored as plain flags inside that XML, so it can be removed
without knowing the password:

1. You select (or drag &amp; drop) a file — it stays on your device.
2. The browser unzips it in memory using [JSZip](https://stuk.github.io/jszip/).
3. The protection elements are stripped from the relevant XML parts:
   - **Excel** — `workbookProtection`, `sheetProtection`, `fileSharing`
   - **Word** — `w:documentProtection`, `w:writeProtection`
   - **PowerPoint** — `p:modifyVerifier`
4. The archive is re-zipped into a valid Office file.
5. The unlocked file is downloaded as `unlocked_<yourfile>`.

## What it can and cannot do

| Protection type | Supported |
| --- | :---: |
| Sheet / workbook protection (Excel) | ✅ |
| Restrict editing / read‑only (Word) | ✅ |
| Modify / write protection (PowerPoint) | ✅ |
| **Open password (full‑file encryption)** | ❌ |

Files protected with an **open password** are fully AES‑encrypted and stored in
an OLE2 container — they are not ZIP files at all and cannot be opened without
the password. OfficeUnlocker detects these automatically and tells you so
instead of producing a corrupt file.

> ⚠️ Only use this tool on files you are authorised to modify.

## Usage

Just open the [live site](https://michaelkrisper.github.io/officeunlocker/),
or run it locally — no build step required:

```bash
git clone https://github.com/michaelkrisper/officeunlocker.git
cd officeunlocker
# Serve the folder with any static server, e.g.:
npx serve .
# then open the printed URL in your browser
```

## Development

The unlocking logic lives in [`unlock.js`](unlock.js) as a UMD module, so the
exact same code powers both the browser app and the Node.js test suite.

```bash
npm install     # install dev dependencies (JSZip, ESLint)
npm run lint    # lint with ESLint
npm test        # run the automated test suite
npm run check   # lint + test (used in CI)
```

### Project structure

```
index.html                  # The web app (UI + glue code)
unlock.js                   # Shared, testable unlocking logic (UMD)
test/unlock.test.js         # Automated tests (build → unlock → verify)
eslint.config.js            # ESLint flat config
.github/workflows/ci.yml    # Lint + test on every push / PR
.github/workflows/deploy.yml# Deploy to GitHub Pages on push to main
```

## Deployment

Pushing to `main` triggers the **Deploy to GitHub Pages** workflow, which lints,
tests and then publishes `index.html` + `unlock.js` to GitHub Pages. To enable
it once: **Settings → Pages → Build and deployment → Source: GitHub Actions**.

## Tech stack

Plain HTML, CSS and JavaScript — no framework, no bundler. The only runtime
dependency is [JSZip](https://stuk.github.io/jszip/) `3.10.1`, loaded from a CDN
with Subresource Integrity.

## License

[MIT](LICENSE) © Michael Krisper
