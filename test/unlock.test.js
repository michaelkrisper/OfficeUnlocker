'use strict';

/*
 * Automated verification of the OfficeUnlocker core logic.
 * Builds protected sample documents, runs them through unlock(), and asserts
 * the protection is gone while the rest of the document is preserved.
 */

const assert = require('assert');
const JSZip = require('jszip');
const OfficeUnlocker = require('../unlock.js');
const PstUnlock = require('../pstunlock.js');
const Ole2 = require('../ole2.js');
const OleLock = require('../olelock.js');
const fixtures = require('./fixtures.js');

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
  zip.file(
    'xl/worksheets/sheet1.xml',
    '<?xml version="1.0"?><worksheet>' +
      '<sheetData><row r="1"><c r="A1" t="str"><v>keepme</v></c></row></sheetData>' +
      '<sheetProtection sheet="1" password="CC3F" objects="1" scenarios="1"/>' +
      '</worksheet>'
  );
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
    assert.ok(OfficeUnlocker.isSupported('Sheet.ods'));
    assert.ok(OfficeUnlocker.isSupported('Old.xls'));
    assert.ok(OfficeUnlocker.isSupported('archive.PST'));
    assert.ok(!OfficeUnlocker.isSupported('image.png'));
    assert.ok(!OfficeUnlocker.isSupported('statement.pdf'), 'pdf is no longer supported');
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

  // --- PST ------------------------------------------------------------------

  await test('removes the password from a Unicode PST', () => {
    const pst = fixtures.buildUnicodePst(0x12345678);
    assert.ok(PstUnlock.isPst(pst));
    const res = PstUnlock.unlock(pst);
    assert.ok(res.changed && res.hadPassword, 'password was not removed');
    assert.strictEqual(fixtures.readPstPassword(res.bytes), 0, 'password value not zeroed');
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

  await test('removes the password from a cyclic ("high") encoded PST', () => {
    const pst = fixtures.buildUnicodePst(0xcafef00d, 2); // crypt = cyclic
    const res = PstUnlock.unlock(pst);
    assert.ok(res.changed && res.hadPassword, 'cyclic password not removed');
    assert.strictEqual(fixtures.readPstPassword(res.bytes, 2), 0, 'cyclic password not zeroed');
  });

  await test('removes the password from a multi-block (XBLOCK) message store', () => {
    const pst = fixtures.buildUnicodePstMultiBlock(0xabad1dea);
    const res = PstUnlock.unlock(pst);
    assert.ok(res.changed && res.hadPassword, 'multi-block password not removed');
    assert.strictEqual(fixtures.readMultiBlockPassword(res.bytes), 0, 'password (block 1) not zeroed');
  });

  await test('OfficeUnlocker routes PST by content', async () => {
    const pst = fixtures.buildUnicodePst(0x12345678);
    const res = await OfficeUnlocker.unlock(pst);
    assert.strictEqual(res.kind, 'pst');
    assert.deepStrictEqual(res.removed, ['PST password']);
  });

  // --- OpenDocument ---------------------------------------------------------

  await test('removes sheet protection from an .ods (OpenDocument)', async () => {
    const input = await fixtures.buildProtectedOds();
    const { blob, removed, kind } = await OfficeUnlocker.unlock(input);
    assert.strictEqual(kind, 'odf');
    const content = await readEntry(blob, 'content.xml');
    assert.ok(/table:protected="false"/.test(content), 'protection flag not cleared');
    assert.ok(!/protection-key/.test(content), 'protection-key not removed');
    assert.ok(/keepme/.test(content), 'cell data was lost');
    assert.ok(removed.includes('document protection'));
  });

  await test('detects an encrypted OpenDocument file', async () => {
    const input = await fixtures.buildEncryptedOdt();
    await assert.rejects(() => OfficeUnlocker.unlock(input), (err) => err.code === 'ENCRYPTED');
  });

  // --- Legacy OLE2 (.xls / .doc) + VBA -------------------------------------

  await test('removes protection records from a legacy .xls', () => {
    const input = fixtures.buildProtectedXls();
    assert.ok(!PstUnlock.isPst(input), 'should not be detected as PST');
    const out = OleLock.unlock(input);
    assert.ok(out.removed.includes('worksheet/workbook protection'));
    const cfb = Ole2.parse(out.bytes);
    const wb = cfb.readStream('Workbook');
    let pos = 0, sawProtect = false;
    while (pos + 4 <= wb.length) {
      const id = wb[pos] | (wb[pos + 1] << 8);
      const len = wb[pos + 2] | (wb[pos + 3] << 8);
      if ([0x12, 0x13, 0x19, 0x63].includes(id) && len > 0) {
        sawProtect = true;
        for (let k = 0; k < len; k++) assert.strictEqual(wb[pos + 4 + k], 0, 'record not zeroed');
      }
      if (id === 0 && len === 0) break;
      pos += 4 + len;
    }
    assert.ok(sawProtect, 'no protection records were seen');
  });

  await test('removes "Restrict Editing" from a legacy .doc', () => {
    const input = fixtures.buildProtectedDoc();
    const out = OleLock.unlock(input);
    assert.ok(out.removed.includes('document protection'));
    const tbl = Ole2.parse(out.bytes).readStream('0Table');
    assert.strictEqual(tbl[16 + 0x07] & 0x02, 0, 'fProtEnabled not cleared');
    assert.strictEqual(tbl[16 + 0x07], 0x09, 'other Dop bits were disturbed');
  });

  await test('detects an encrypted legacy .xls (FILEPASS)', () => {
    const input = fixtures.buildEncryptedXls();
    assert.throws(() => OleLock.unlock(input), (err) => err.code === 'ENCRYPTED');
  });

  await test('detects encrypted OOXML stored in OLE2 (not decrypted)', async () => {
    const input = fixtures.buildEncryptedOoxmlOle2();
    assert.throws(() => OleLock.unlock(input), (err) => err.code === 'ENCRYPTED');
    await assert.rejects(() => OfficeUnlocker.unlock(input), (err) => err.code === 'ENCRYPTED');
  });

  await test('detects encrypted OOXML stored in OLE2 (EncryptedPackage only)', async () => {
    const input = fixtures.buildEncryptedPackageOle2();
    assert.throws(() => OleLock.unlock(input), (err) => err.code === 'ENCRYPTED');
    await assert.rejects(() => OfficeUnlocker.unlock(input), (err) => err.code === 'ENCRYPTED');
  });

  await test('removes a VBA project password (DPB -> DPx)', () => {
    const input = fixtures.buildVbaCfb();
    const res = OleLock.unlockVbaProjectBin(input);
    assert.ok(res.changed, 'no change made to the VBA project');
    const project = latin1(Ole2.parse(res.bytes).readStream('PROJECT'));
    assert.ok(!/\bDPB=/.test(project), 'DPB key still present');
    assert.ok(/\bDPx=/.test(project), 'DPB was not renamed to DPx');
  });

  await test('OfficeUnlocker routes legacy OLE2 by content', async () => {
    const input = fixtures.buildProtectedXls();
    const out = await OfficeUnlocker.unlock(input);
    assert.strictEqual(out.kind, 'ole2');
    assert.ok(out.removed.includes('worksheet/workbook protection'));
  });

  console.log('\n' + passed + ' passed, ' + failed + ' failed\n');
  process.exit(failed === 0 ? 0 : 1);
})();
