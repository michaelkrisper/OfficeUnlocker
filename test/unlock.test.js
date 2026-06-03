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
  // It also carries a password-protected "allow edit ranges" definition.
  zip.file(
    'xl/worksheets/sheet2.xml',
    '<?xml version="1.0"?><worksheet><sheetData/>' +
      '<sheetProtection algorithmName="SHA-512" hashValue="x" sheet="1"></sheetProtection>' +
      '<protectedRanges>' +
      '<protectedRange password="83AF" sqref="A1:B2" name="Range1"/>' +
      '</protectedRanges>' +
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
  zip.file(
    'word/document.xml',
    '<?xml version="1.0"?><w:document><w:body>' +
      '<w:permStart w:id="1" w:edGrp="everyone"/>keepme<w:permEnd w:id="1"/>' +
      '</w:body></w:document>'
  );
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
    assert.ok(!/protectedRange/.test(sheet2), 'protectedRanges (allow-edit ranges) still present');
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
    assert.ok(!/permStart|permEnd/.test(doc), 'editable-region markers still present');
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

  console.log('\n' + passed + ' passed, ' + failed + ' failed\n');
  process.exit(failed === 0 ? 0 : 1);
})();
