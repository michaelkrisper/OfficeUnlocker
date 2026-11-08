# CLAUDE.md

OfficeUnlocker: a single-page, fully client-side web app that strips editing
restrictions (flags/properties) from Office OOXML, `.xlsb`, OpenDocument, legacy OLE2
`.xls`/`.doc`, VBA projects and Outlook `.pst`. Plain HTML/CSS/JS, no framework, no
bundler, no build step. CI deploys the page files to GitHub Pages
(https://michaelkrisper.github.io/OfficeUnlocker/).

It never breaks real encryption: open-password / AES-encrypted files are detected and
reported, not decrypted, and no password is recovered. Keep that boundary; it is the
project's legal and ethical position and is stated in the README, the UI and every
module header.

## Commands

```sh
npm ci          # dev dependencies: ESLint, JSZip (for the Node tests)
npm run lint    # eslint . (flat config)
npm test        # node test/unlock.test.js
npm run check   # lint + test = what CI runs
```

- No test framework: `test/unlock.test.js` is a hand-rolled runner over `node:assert`
  that prints a check mark per case and exits 1 on any failure. No filter flag; run
  the whole file.
- No dev server needed: open `index.html` directly or serve the repo root with any
  static server. All paths are relative.
- CI (`.github/workflows/ci.yml`, job `check`): Node `lts/*`, `npm ci`, lint, test on
  every push and PR. On `main` it then tags the version, deploys and curls every
  published file on the live site.

## Architecture

Five UMD modules form the core; `index.html` holds the UI plus inline glue. The same
files run in the browser as globals and in Node via `require`; that is why they are
UMD, use `var` and avoid modern syntax. Do not convert them to ESM or add build
tooling: the Node tests exercise exactly the code the site ships.

- Browser load order in `index.html` is the dependency order: `vendor/jszip.min.js` ->
  `utils.js` -> `ole2.js` -> `olelock.js` -> `pstunlock.js` -> `unlock.js`. Globals:
  `Utils`, `Ole2`, `OleLock`, `PstUnlock`, `OfficeUnlocker`.
- `unlock.js` is the dispatcher: routes by magic bytes, not extension (OLE2
  `D0 CF 11 E0 ...`, PST `!BDN`, otherwise ZIP), then delegates. `unlock()` resolves to
  `{ blob, removed: [labels], kind }`. OOXML/ODF: unzip with JSZip, edit XML text,
  re-zip; `.xlsb`: drop BIFF12 protection records from the `.bin` parts.
- `ole2.js`: minimal CFB reader with in-place byte patching. Every edit must keep the
  stream length identical, so FAT and directory never need rewriting. Example: the
  VBA password is removed by renaming `DPB=` to `DPx=` (same length), not deleting it.
  Any new legacy-format edit must be length-preserving, or `ole2.js` first needs real
  rewrite support.
- `olelock.js`: legacy `.xls` BIFF records, Word `Dop.fProtEnabled`, VBA `PROJECT`
  stream, `.ppt` encryption detection. `pstunlock.js`: sets `PidTagPstPassword` to 0
  for none/permute/cyclic encodings, re-applies the encoding and fixes the block CRC.
- `test/fixtures.js` builds synthetic protected files from scratch (CFB containers,
  BIFF/BIFF12 records, Unicode PST stores). No binary sample documents are committed;
  new format support needs a matching fixture builder there.

## Conventions

- ESLint lints the five core modules (`sourceType: script`, `no-var`/`prefer-const`
  off on purpose) plus `test/` and the config. `vendor/` is ignored and the inline
  script in `index.html` is not linted at all: keep real logic in the modules.
- Match the surrounding ES5-ish style in the core modules; 2 spaces, single quotes.
- New code arrives with tests, including failure paths (malformed input, encrypted
  files, pass-through of unknown data).
- The page loads no external resources (fonts self-hosted in `fonts/`, JSZip vendored,
  no analytics). Never add a CDN link or third-party request.
- Output text that comes from a file goes into the DOM as text (`textContent` /
  text nodes), never via `innerHTML`.

## Rules and pitfalls

- JSZip exists twice: `vendor/jszip.min.js` (browser) and the `jszip` devDependency
  (Node tests). A test asserts both have the same version, so a Dependabot bump of
  `jszip` fails CI until the vendored file is replaced with the same release.
- Adding a module means: a `<script>` tag at the right position in `index.html`, a
  `require` branch in the UMD header, the file in the `cp` line of the "Assemble site"
  step and in the smoke-test list in `ci.yml`. Only listed files are published.
- Regexes over document XML must stay linear (a ReDoS in `stripElement` was fixed
  before); avoid nested quantifiers on untrusted input.
- Never commit real protected documents; extend `test/fixtures.js` instead.

## Workflow

- Every change starts with a GitHub issue. Branch `<issue>-<slug>` from `main`,
  open a PR with `Closes #<issue>`. Never push to `main` directly.
- PRs auto-merge (squash) once CI and the "Linked ticket" check pass; drafts are not merged.
- Versions exist only as git tags `vX.Y.Z`. Every merge to `main` tags the next patch;
  never edit version numbers in files. Minor/major releases: Actions -> Release.
- Merging to `main` deploys to GitHub Pages automatically.
- Details: CONTRIBUTING.md.
