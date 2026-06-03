'use strict';

/*
 * Automated verification of the OfficeUnlocker core logic.
 * Builds real OOXML-shaped ZIP archives that contain protection elements,
 * runs them through unlock(), and asserts the protection is gone while the
 * rest of the document is preserved.
 */

const assert = require('assert');
const JSZip = require('jszip');
const OfficeUnlocker = require('../unlock.js');
const PdfUnlock = require('../pdfunlock.js');
const PstUnlock = require('../pstunlock.js');
const BinCrypto = require('../bincrypto.js');
const fixtures = require('./fixtures.js');

const fromHex = (h) => new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)));
const toHex = (u8) => Array.from(u8).map((b) => b.toString(16).padStart(2, '0')).join('');
const latin1 = (u8) => Buffer.from(u8).toString('latin1');

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log('  ✓ ' + name);
  } catch (err) {
    failed++;
    console.log('  ✗ ' + name);
    console.log('      ' + (err && err.message ? err.message : err));
  }
}

// --- Builders for protected sample documents -------------------------------

const CONTENT_TYPES =
  '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
  '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>';

async function buildProtectedXlsx() {
  const zip = new JSZip();
  zip.file('[Content_Types].xml', CONTENT_TYPES);
  zip.file(
    'xl/workbook.xml',
    '<?xml version="1.0"?><workbook>' +
      '<fileSharing readOnlyRecommended="1"/>' +
      '<workbookProtection workbookPassword="ABCD" lockStructure="1"/>' +
      '<sheets><sheet name="Data" sheetId="1" r:id="rId1"/></sheets>' +
      '</workbook>'
  );
  // sheet1 uses the self-closing form of sheetProtection ...
  zip.file(
    'xl/worksheets/sheet1.xml',
    '<?xml version="1.0"?><worksheet>' +
      '<sheetData><row r="1"><c r="A1" t="str"><v>keepme</v></c></row></sheetData>' +
      '<sheetProtection sheet="1" password="CC3F" objects="1" scenarios="1"/>' +
      '</worksheet>'
  );
  // ... while sheet2 uses the rarer paired form: <sheetProtection ...></sheetProtection>
  zip.file(
    'xl/worksheets/sheet2.xml',
    '<?xml version="1.0"?><worksheet><sheetData/>' +
      '<sheetProtection algorithmName="SHA-512" hashValue="x" sheet="1"></sheetProtection>' +
      '</worksheet>'
  );
  return zip.generateAsync({ type: 'nodebuffer' });
}

async function buildProtectedDocx() {
  const zip = new JSZip();
  zip.file('[Content_Types].xml', CONTENT_TYPES);
  zip.file(
    'word/settings.xml',
    '<?xml version="1.0"?><w:settings xmlns:w="http://x">' +
      '<w:writeProtection w:cryptProviderType="rsaAES"/>' +
      '<w:documentProtection w:edit="readOnly" w:enforcement="1" w:hash="abc"/>' +
      '<w:defaultTabStop w:val="708"/>' +
      '</w:settings>'
  );
  zip.file('word/document.xml', '<?xml version="1.0"?><w:document>keepme</w:document>');
  return zip.generateAsync({ type: 'nodebuffer' });
}

async function buildProtectedPptx() {
  const zip = new JSZip();
  zip.file('[Content_Types].xml', CONTENT_TYPES);
  zip.file(
    'ppt/presentation.xml',
    '<?xml version="1.0"?><p:presentation xmlns:p="http://x">' +
      '<p:modifyVerifier p:algorithmName="SHA-512" p:hashValue="xyz"/>' +
      '<p:sldIdLst><p:sldId id="256"/></p:sldIdLst>' +
      '</p:presentation>'
  );
  return zip.generateAsync({ type: 'nodebuffer' });
}

async function readEntry(buffer, path) {
  const zip = await JSZip.loadAsync(buffer);
  return zip.file(path).async('string');
}

// --- Tests -----------------------------------------------------------------

(async function run() {
  console.log('\nOfficeUnlocker tests\n');

  await test('removes workbook + sheet protection from .xlsx', async () => {
    const input = await buildProtectedXlsx();
    const { blob, removed } = await OfficeUnlocker.unlock(input);

    const workbook = await readEntry(blob, 'xl/workbook.xml');
    const sheet1 = await readEntry(blob, 'xl/worksheets/sheet1.xml');
    const sheet2 = await readEntry(blob, 'xl/worksheets/sheet2.xml');

    assert.ok(!/workbookProtection/.test(workbook), 'workbookProtection still present');
    assert.ok(!/fileSharing/.test(workbook), 'fileSharing still present');
    assert.ok(!/sheetProtection/.test(sheet1), 'self-closing sheetProtection still present');
    assert.ok(!/sheetProtection/.test(sheet2), 'paired sheetProtection still present');
    assert.ok(/keepme/.test(sheet1), 'sheet data was lost');
    assert.ok(/Data/.test(workbook), 'sheet definition was lost');
    assert.ok(removed.includes('workbookProtection') && removed.includes('sheetProtection'));
    assert.ok(removed.includes('fileSharing'), 'fileSharing not reported as removed');
  });

  await test('removes document + write protection from .docx', async () => {
    const input = await buildProtectedDocx();
    const { blob, removed } = await OfficeUnlocker.unlock(input);

    const settings = await readEntry(blob, 'word/settings.xml');
    assert.ok(!/documentProtection/.test(settings), 'documentProtection still present');
    assert.ok(!/writeProtection/.test(settings), 'writeProtection still present');
    assert.ok(/defaultTabStop/.test(settings), 'other settings were lost');
    const doc = await readEntry(blob, 'word/document.xml');
    assert.ok(/keepme/.test(doc), 'document body was lost');
    assert.ok(removed.includes('w:documentProtection') && removed.includes('w:writeProtection'));
  });

  await test('removes modify verifier from .pptx', async () => {
    const input = await buildProtectedPptx();
    const { blob, removed } = await OfficeUnlocker.unlock(input);

    const pres = await readEntry(blob, 'ppt/presentation.xml');
    assert.ok(!/modifyVerifier/.test(pres), 'modifyVerifier still present');
    assert.ok(/sldId/.test(pres), 'slide list was lost');
    assert.ok(removed.includes('p:modifyVerifier'));
  });

  await test('output remains a valid, openable ZIP archive', async () => {
    const input = await buildProtectedXlsx();
    const { blob } = await OfficeUnlocker.unlock(input);
    const reopened = await JSZip.loadAsync(blob);
    assert.ok(reopened.file('[Content_Types].xml'), 'Content_Types missing from output');
  });

  await test('detects encrypted (OLE2 open-password) files', async () => {
    const ole2 = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, 0x00, 0x00]);
    await assert.rejects(
      () => OfficeUnlocker.unlock(ole2),
      (err) => err.code === 'ENCRYPTED'
    );
  });

  await test('rejects non-Office/invalid input gracefully', async () => {
    const junk = Buffer.from('this is not a zip file at all');
    await assert.rejects(
      () => OfficeUnlocker.unlock(junk),
      (err) => err.code === 'INVALID'
    );
  });

  await test('isSupported recognises the right extensions', () => {
    assert.ok(OfficeUnlocker.isSupported('Budget.xlsx'));
    assert.ok(OfficeUnlocker.isSupported('Report.DOCX'));
    assert.ok(OfficeUnlocker.isSupported('Deck.pptx'));
    assert.ok(!OfficeUnlocker.isSupported('image.png'));
    assert.ok(!OfficeUnlocker.isSupported('noextension'));
  });

  await test('leaves an unprotected file functionally unchanged', async () => {
    const zip = new JSZip();
    zip.file('[Content_Types].xml', CONTENT_TYPES);
    zip.file('xl/worksheets/sheet1.xml', '<worksheet><sheetData/></worksheet>');
    const input = await zip.generateAsync({ type: 'nodebuffer' });

    const { removed } = await OfficeUnlocker.unlock(input);
    assert.deepStrictEqual(removed, [], 'reported removals on an unprotected file');
  });

  // --- Crypto primitives (known-answer vectors) ----------------------------

  await test('crypto primitives match published test vectors', () => {
    assert.strictEqual(toHex(BinCrypto.md5(new Uint8Array(0))), 'd41d8cd98f00b204e9800998ecf8427e');
    assert.strictEqual(toHex(BinCrypto.md5(fromHex('616263'))), '900150983cd24fb0d6963f7d28e17f72');
    assert.strictEqual(
      toHex(BinCrypto.rc4(fromHex('4b6579'), fromHex('506c61696e74657874'))).toUpperCase(),
      'BBF316E8D940AF0AD3'
    );
    // FIPS-197 single block, AES-128 and AES-256.
    assert.strictEqual(
      toHex(BinCrypto._decryptBlockForTest(fromHex('69c4e0d86a7b0430d8cdb78070b4c55a'), fromHex('000102030405060708090a0b0c0d0e0f'))),
      '00112233445566778899aabbccddeeff'
    );
    assert.strictEqual(
      toHex(BinCrypto._decryptBlockForTest(fromHex('8ea2b7ca516745bfeafc49904b496089'), fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'))),
      '00112233445566778899aabbccddeeff'
    );
  });

  // --- PDF ------------------------------------------------------------------

  await test('removes RC4 restrictions and decrypts a PDF', () => {
    const { bytes, secretContent, secretString } = fixtures.buildRc4Pdf();
    const res = PdfUnlock.unlock(bytes);
    const out = latin1(res.bytes);
    assert.ok(res.changed, 'unlock did not report a change');
    assert.ok(!/\/Encrypt/.test(out), '/Encrypt still present');
    assert.ok(out.includes(secretContent), 'content stream was not decrypted');
    assert.ok(out.toLowerCase().includes(Buffer.from(secretString, 'latin1').toString('hex')),
      'string was not decrypted');
  });

  await test('removes AES-128 restrictions and expands object streams', () => {
    const { bytes, secretContent } = fixtures.buildAesPdfWithObjStm();
    const res = PdfUnlock.unlock(bytes);
    const out = latin1(res.bytes);
    assert.ok(res.changed);
    assert.ok(!/\/Encrypt/.test(out), '/Encrypt still present');
    assert.ok(out.includes(secretContent), 'AES content stream was not decrypted');
    assert.ok(/\/Marker/.test(out), 'object-stream object was not promoted');
    assert.ok(out.toLowerCase().includes(Buffer.from('objstm-worked', 'latin1').toString('hex')),
      'object-stream string was not decrypted');
  });

  await test('refuses a PDF that needs an open password', () => {
    const bytes = fixtures.buildUserPasswordPdf();
    assert.throws(() => PdfUnlock.unlock(bytes), (err) => err.code === 'ENCRYPTED');
  });

  await test('reports AES-256 PDFs as unsupported', () => {
    const bytes = fixtures.buildAes256Pdf();
    assert.throws(() => PdfUnlock.unlock(bytes), (err) => err.code === 'UNSUPPORTED');
  });

  await test('leaves an unencrypted PDF unchanged', () => {
    const plain = new Uint8Array(Buffer.from(
      '%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n', 'latin1'));
    const res = PdfUnlock.unlock(plain);
    assert.ok(!res.changed, 'reported a change on an unencrypted PDF');
  });

  // --- PST ------------------------------------------------------------------

  await test('removes the password from a Unicode PST', () => {
    const pst = fixtures.buildUnicodePst(0x12345678);
    assert.ok(PstUnlock.isPst(pst));
    const res = PstUnlock.unlock(pst);
    assert.ok(res.changed && res.hadPassword, 'password was not removed');
    assert.strictEqual(fixtures.readPstPassword(res.bytes), 0, 'password value not zeroed');
    // The rewritten block must carry a consistent CRC.
    const cb = 46, tOff = 0x800 + Math.ceil((cb + 16) / 64) * 64 - 16;
    const stored = (res.bytes[tOff + 4] | (res.bytes[tOff + 5] << 8) | (res.bytes[tOff + 6] << 16) | (res.bytes[tOff + 7] << 24)) >>> 0;
    assert.strictEqual(stored, fixtures.pstCrc(res.bytes, 0x800, cb), 'block CRC not recomputed');
  });

  await test('treats a PST with no password as already unlocked', () => {
    const pst = fixtures.buildUnicodePst(0);
    const res = PstUnlock.unlock(pst);
    assert.ok(!res.changed && !res.hadPassword, 'reported a change on a password-less PST');
  });

  await test('PST removal is idempotent', () => {
    const pst = fixtures.buildUnicodePst(0xdeadbeef);
    const once = PstUnlock.unlock(pst);
    const twice = PstUnlock.unlock(once.bytes);
    assert.ok(once.changed && !twice.changed, 'second pass should be a no-op');
  });

  // --- Dispatcher routing ---------------------------------------------------

  await test('OfficeUnlocker.unlock routes PDF and PST by content', async () => {
    const pdf = fixtures.buildRc4Pdf().bytes;
    const pdfRes = await OfficeUnlocker.unlock(pdf);
    assert.strictEqual(pdfRes.kind, 'pdf');
    assert.deepStrictEqual(pdfRes.removed, ['PDF restrictions']);

    const pst = fixtures.buildUnicodePst(0x12345678);
    const pstRes = await OfficeUnlocker.unlock(pst);
    assert.strictEqual(pstRes.kind, 'pst');
    assert.deepStrictEqual(pstRes.removed, ['PST password']);
  });

  await test('isSupported recognises pdf and pst', () => {
    assert.ok(OfficeUnlocker.isSupported('statement.pdf'));
    assert.ok(OfficeUnlocker.isSupported('archive.PST'));
  });

  console.log('\n' + passed + ' passed, ' + failed + ' failed\n');
  process.exit(failed === 0 ? 0 : 1);
})();
