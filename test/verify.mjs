// Verification test: builds minimal but valid Office archives that contain
// protection elements, runs the unlock logic, and asserts the protection is
// gone while the archive remains a readable ZIP. Run with: node test/verify.mjs
import JSZip from 'jszip';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { unlockOfficeZip } = require('../unlock.js');

let failures = 0;
function assert(cond, msg) {
    if (cond) {
        console.log('  ✓ ' + msg);
    } else {
        console.error('  ✗ ' + msg);
        failures++;
    }
}

const CONTENT_TYPES = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>';

async function roundTrip(buildFiles) {
    const zip = new JSZip();
    const files = buildFiles();
    for (const [path, content] of Object.entries(files)) {
        zip.file(path, content);
    }
    return zip;
}

async function reopen(zip) {
    const blob = await zip.generateAsync({ type: 'nodebuffer' });
    return JSZip.loadAsync(blob); // throws if the produced archive is corrupt
}

async function testXlsx() {
    console.log('xlsx:');
    const zip = await roundTrip(() => ({
        '[Content_Types].xml': CONTENT_TYPES,
        'xl/workbook.xml': '<?xml version="1.0"?><workbook><fileSharing readOnlyRecommended="1"/><workbookProtection workbookPassword="ABCD" lockStructure="1"/><sheets><sheet name="S1" r:id="rId1"/></sheets></workbook>',
        'xl/worksheets/sheet1.xml': '<?xml version="1.0"?><worksheet><sheetData/><sheetProtection password="ABCD" sheet="1"/></worksheet>',
        'xl/worksheets/sheet2.xml': '<?xml version="1.0"?><worksheet><sheetData/><sheetProtection algorithmName="SHA-512" hashValue="x" sheet="1"></sheetProtection></worksheet>',
    }));

    const res = await unlockOfficeZip(zip, 'xlsx');
    assert(res.changed, 'reports a change was made');

    const wb = await zip.file('xl/workbook.xml').async('string');
    assert(!/workbookProtection/.test(wb), 'workbookProtection removed');
    assert(!/fileSharing/.test(wb), 'fileSharing removed');
    assert(/<sheets>/.test(wb), 'workbook content preserved (sheets intact)');

    const s1 = await zip.file('xl/worksheets/sheet1.xml').async('string');
    const s2 = await zip.file('xl/worksheets/sheet2.xml').async('string');
    assert(!/sheetProtection/.test(s1), 'self-closing sheetProtection removed');
    assert(!/sheetProtection/.test(s2), 'paired sheetProtection removed');
    assert(/<sheetData\/>/.test(s1), 'sheet data preserved');

    const reopened = await reopen(zip);
    assert(!!reopened.file('xl/workbook.xml'), 'archive re-zips and re-opens cleanly');
}

async function testDocx() {
    console.log('docx:');
    const zip = await roundTrip(() => ({
        '[Content_Types].xml': CONTENT_TYPES,
        'word/settings.xml': '<?xml version="1.0"?><w:settings xmlns:w="x"><w:writeProtection w:cryptProviderType="rsaAES"/><w:documentProtection w:edit="readOnly" w:enforcement="1" w:hash="abc"/><w:defaultTabStop w:val="708"/></w:settings>',
    }));

    const res = await unlockOfficeZip(zip, 'docx');
    assert(res.changed, 'reports a change was made');

    const settings = await zip.file('word/settings.xml').async('string');
    assert(!/documentProtection/.test(settings), 'documentProtection removed');
    assert(!/writeProtection/.test(settings), 'writeProtection removed');
    assert(/defaultTabStop/.test(settings), 'other settings preserved');

    const reopened = await reopen(zip);
    assert(!!reopened.file('word/settings.xml'), 'archive re-zips and re-opens cleanly');
}

async function testPptx() {
    console.log('pptx:');
    const zip = await roundTrip(() => ({
        '[Content_Types].xml': CONTENT_TYPES,
        'ppt/presentation.xml': '<?xml version="1.0"?><p:presentation xmlns:p="x"><p:modifyVerifier p:algorithmName="SHA-512" p:hashValue="x" p:saltValue="y" p:spinCount="100000"/><p:sldIdLst><p:sldId id="256"/></p:sldIdLst></p:presentation>',
    }));

    const res = await unlockOfficeZip(zip, 'pptx');
    assert(res.changed, 'reports a change was made');

    const pres = await zip.file('ppt/presentation.xml').async('string');
    assert(!/modifyVerifier/.test(pres), 'modifyVerifier removed');
    assert(/sldIdLst/.test(pres), 'slide list preserved');

    const reopened = await reopen(zip);
    assert(!!reopened.file('ppt/presentation.xml'), 'archive re-zips and re-opens cleanly');
}

async function testNoProtection() {
    console.log('unprotected file (no-op):');
    const zip = await roundTrip(() => ({
        '[Content_Types].xml': CONTENT_TYPES,
        'xl/workbook.xml': '<?xml version="1.0"?><workbook><sheets><sheet name="S1"/></sheets></workbook>',
    }));
    const res = await unlockOfficeZip(zip, 'xlsx');
    assert(!res.changed, 'reports no change for an already-unprotected file');
}

async function main() {
    await testXlsx();
    await testDocx();
    await testPptx();
    await testNoProtection();
    console.log('');
    if (failures > 0) {
        console.error(failures + ' assertion(s) failed.');
        process.exit(1);
    }
    console.log('All checks passed.');
}

main().catch((e) => { console.error(e); process.exit(1); });
