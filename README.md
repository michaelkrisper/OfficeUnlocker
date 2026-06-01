# Office Unlocker 🔓

A single-page web app that removes the **editing protection** from Microsoft
**Excel (.xlsx)**, **Word (.docx)** and **PowerPoint (.pptx)** files —
entirely in your browser. No file is ever uploaded.

## How it works

Modern Office files are ZIP archives containing XML parts. The protection
(read-only restrictions, sheet/workbook/document protection) is stored as XML
elements inside those parts. The app:

1. **Unzips** the uploaded file in the browser ([JSZip](https://stuk.github.io/jszip/)).
2. **Removes** the protection elements from the relevant XML parts.
3. **Re-zips** the archive back into a valid `.xlsx` / `.docx` / `.pptx`.
4. **Downloads** the unlocked file — all locally, nothing leaves your device.

| Type   | Part(s) edited            | Elements removed                         |
|--------|---------------------------|------------------------------------------|
| xlsx   | `xl/workbook.xml`, `xl/worksheets/sheet*.xml` | `workbookProtection`, `fileSharing`, `sheetProtection` |
| docx   | `word/settings.xml`       | `w:documentProtection`, `w:writeProtection` |
| pptx   | `ppt/presentation.xml`    | `p:modifyVerifier`                       |

## Usage

Open the [live site](https://michaelkrisper.github.io/officeunlocker/), drop a
file in, and download the unlocked copy. Or run it locally:

```bash
git clone https://github.com/michaelkrisper/officeunlocker
cd officeunlocker
# just open index.html in a browser, or serve the folder:
python3 -m http.server
```

## What it can and cannot do

- ✅ Removes **editing / sheet / workbook / document protection** and the
  read-only "modify password".
- ❌ Cannot decrypt files protected with an **open password**. Those are not
  ZIP archives — they use AES-encrypted OLE/CFB containers and require the
  password to open.

## Development & tests

The unlock logic lives in [`unlock.js`](unlock.js) (shared by the browser and
the test suite). Tests build real protected archives, run the logic, and assert
the protection is gone while the archive stays a valid ZIP:

```bash
npm install
npm test
```

## Deployment

Pushing to `main` triggers the
[`deploy.yml`](.github/workflows/deploy.yml) GitHub Actions workflow, which runs
the tests and publishes `index.html` + `unlock.js` to **GitHub Pages**.

> One-time setup: in the repo's **Settings → Pages**, set **Source** to
> **GitHub Actions**.

## Privacy

All processing happens in your browser. No files or data are uploaded to any
server.

## License

MIT
