'use strict';

/*
 * Builders for synthetic protected files used by the test suite:
 *   • OpenDocument ZIPs (protection attributes / encryption marker)
 *   • OLE2 / CFB documents (legacy .xls / .doc, VBA project, encrypted marker)
 *   • Unicode PST message stores (single-block, cyclic, and multi-block)
 */

const JSZip = require('jszip');
const PstUnlock = require('../pstunlock.js');

// --- OpenDocument ----------------------------------------------------------

async function buildProtectedOds() {
  const zip = new JSZip();
  zip.file('mimetype', 'application/vnd.oasis.opendocument.spreadsheet');
  zip.file('META-INF/manifest.xml',
    '<?xml version="1.0"?><manifest:manifest xmlns:manifest="urn:x"/>');
  zip.file('content.xml',
    '<?xml version="1.0"?><office:document-content xmlns:office="urn:o" xmlns:table="urn:t">' +
    '<office:body><office:spreadsheet>' +
    '<table:table table:name="Sheet1" table:protected="true" ' +
    'table:protection-key="abc123==" table:protection-key-digest-algorithm="urn:sha256">' +
    '<table:table-row><table:table-cell><text:p>keepme</text:p></table:table-cell></table:table-row>' +
    '</table:table>' +
    '</office:spreadsheet></office:body></office:document-content>');
  return zip.generateAsync({ type: 'nodebuffer' });
}

async function buildEncryptedOdt() {
  const zip = new JSZip();
  zip.file('mimetype', 'application/vnd.oasis.opendocument.text');
  zip.file('META-INF/manifest.xml',
    '<?xml version="1.0"?><manifest:manifest xmlns:manifest="urn:x">' +
    '<manifest:file-entry manifest:full-path="content.xml">' +
    '<manifest:encryption-data manifest:checksum="x"/></manifest:file-entry></manifest:manifest>');
  zip.file('content.xml', 'encrypted-bytes');
  return zip.generateAsync({ type: 'nodebuffer' });
}

// --- OLE2 / CFB ------------------------------------------------------------

const SECTOR = 512;
const FREESECT = 0xffffffff, ENDOFCHAIN = 0xfffffffe, FATSECT = 0xfffffffd;

// Build a minimal CFB. Every stream is stored via the FAT (size >= 4096) so the
// reader never needs the mini stream. streams: [{ name, type=2, data }].
function buildCfb(streams) {
  const w16 = (b, o, v) => { b[o] = v & 0xff; b[o + 1] = (v >>> 8) & 0xff; };
  const w32 = (b, o, v) => { b[o] = v & 0xff; b[o + 1] = (v >>> 8) & 0xff; b[o + 2] = (v >>> 16) & 0xff; b[o + 3] = (v >>> 24) & 0xff; };

  const numEntries = 1 + streams.length;
  const dirSectors = Math.ceil(numEntries / 4);
  const layout = [];
  let next = 1 + dirSectors;
  for (const s of streams) {
    const ns = Math.ceil(s.data.length / SECTOR);
    layout.push({ start: next, ns });
    next += ns;
  }
  const totalSectors = next;
  const buf = new Uint8Array(SECTOR + totalSectors * SECTOR);

  [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1].forEach((b, i) => { buf[i] = b; });
  w16(buf, 0x1e, 9); w16(buf, 0x20, 6);
  w32(buf, 0x2c, 1); w32(buf, 0x30, 1); w32(buf, 0x38, 4096);
  w32(buf, 0x3c, ENDOFCHAIN); w32(buf, 0x40, 0); w32(buf, 0x44, ENDOFCHAIN); w32(buf, 0x48, 0);
  for (let i = 0; i < 109; i++) w32(buf, 0x4c + i * 4, i === 0 ? 0 : FREESECT);

  const fat = new Uint32Array(128).fill(FREESECT);
  fat[0] = FATSECT;
  for (let k = 1; k <= dirSectors; k++) fat[k] = (k < dirSectors) ? k + 1 : ENDOFCHAIN;
  layout.forEach((l) => {
    for (let j = 0; j < l.ns; j++) fat[l.start + j] = (j < l.ns - 1) ? l.start + j + 1 : ENDOFCHAIN;
  });
  for (let i = 0; i < 128; i++) w32(buf, SECTOR + i * 4, fat[i]);

  function writeEntry(idx, name, type, start, size) {
    const base = SECTOR + SECTOR + idx * 128;
    for (let c = 0; c < name.length; c++) w16(buf, base + c * 2, name.charCodeAt(c));
    w16(buf, base + 0x40, name.length * 2 + 2);
    buf[base + 0x42] = type;
    w32(buf, base + 0x44, FREESECT); w32(buf, base + 0x48, FREESECT); w32(buf, base + 0x4c, FREESECT);
    w32(buf, base + 0x74, start); w32(buf, base + 0x78, size);
  }
  writeEntry(0, 'Root Entry', 5, ENDOFCHAIN, 0);
  streams.forEach((s, i) => writeEntry(i + 1, s.name, s.type || 2, layout[i].start, s.data.length));
  streams.forEach((s, i) => { buf.set(s.data, SECTOR + layout[i].start * SECTOR); });

  return buf;
}

function biffRecord(id, data) {
  const out = new Uint8Array(4 + data.length);
  out[0] = id & 0xff; out[1] = (id >> 8) & 0xff;
  out[2] = data.length & 0xff; out[3] = (data.length >> 8) & 0xff;
  out.set(data, 4);
  return out;
}
function padTo(bytes, n) { const out = new Uint8Array(Math.max(n, bytes.length)); out.set(bytes); return out; }
function concatBytes(arr) {
  let total = 0; arr.forEach((a) => { total += a.length; });
  const out = new Uint8Array(total); let o = 0;
  arr.forEach((a) => { out.set(a, o); o += a.length; });
  return out;
}

function buildProtectedXls() {
  const wb = concatBytes([
    biffRecord(0x0809, new Uint8Array(16)),           // BOF
    biffRecord(0x0012, new Uint8Array([1, 0])),       // PROTECT
    biffRecord(0x0013, new Uint8Array([0xcd, 0xab])), // PASSWORD hash
    biffRecord(0x0019, new Uint8Array([1, 0])),       // WINDOWPROTECT
    biffRecord(0x0063, new Uint8Array([1, 0])),       // OBJECTPROTECT
    biffRecord(0x000a, new Uint8Array(0))             // EOF
  ]);
  return buildCfb([{ name: 'Workbook', data: padTo(wb, 4096) }]);
}

function buildEncryptedXls() {
  const wb = concatBytes([
    biffRecord(0x0809, new Uint8Array(16)),
    biffRecord(0x002f, new Uint8Array([1, 0, 1, 0]))  // FILEPASS
  ]);
  return buildCfb([{ name: 'Workbook', data: padTo(wb, 4096) }]);
}

function buildProtectedDoc() {
  const w16 = (b, o, v) => { b[o] = v & 0xff; b[o + 1] = (v >>> 8) & 0xff; };
  const w32 = (b, o, v) => { b[o] = v & 0xff; b[o + 1] = (v >>> 8) & 0xff; b[o + 2] = (v >>> 16) & 0xff; b[o + 3] = (v >>> 24) & 0xff; };
  const fib = new Uint8Array(4096);
  w16(fib, 0x00, 0xa5ec);   // wIdent
  w16(fib, 0x02, 0x00c1);   // nFib
  w16(fib, 0x0a, 0x0000);   // flags: fEncrypted off, fWhichTblStm=0 -> "0Table"
  const fcDop = 16;
  w32(fib, 0x192, fcDop);   // fcDop
  w32(fib, 0x196, 0x20);    // lcbDop
  const table = new Uint8Array(4096);
  table[fcDop + 0x07] = 0x0b; // fProtEnabled (0x02) + a couple of other bits
  return buildCfb([{ name: 'WordDocument', data: fib }, { name: '0Table', data: table }]);
}

function buildVbaCfb() {
  const text =
    'ID="{00000000-0000-0000-0000-000000000000}"\r\n' +
    'CMG="0123456789ABCDEF0123"\r\n' +
    'DPB="00112233445566778899AABB"\r\n' +
    'GC="1A2B3C4D5E"\r\n';
  const data = padTo(new Uint8Array(Buffer.from(text, 'latin1')), 4096);
  return buildCfb([{ name: 'PROJECT', type: 2, data }]);
}

function buildEncryptedOoxmlOle2() {
  return buildCfb([
    { name: 'EncryptionInfo', data: new Uint8Array(4096) },
    { name: 'EncryptedPackage', data: new Uint8Array(4096) }
  ]);
}

function buildEncryptedPackageOle2() {
  return buildCfb([
    { name: 'EncryptedPackage', data: new Uint8Array(4096) }
  ]);
}

// --- PST -------------------------------------------------------------------

function pstCrc(bytes, start, len) {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) { let c = i; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1); table[i] = c >>> 0; }
  let r = 0; for (let i = 0; i < len; i++) r = (table[(r ^ bytes[start + i]) & 0xff] ^ (r >>> 8)) >>> 0; return r >>> 0;
}

// Builds a minimal Unicode PST whose message store has PidTagPstPassword set.
// crypt: 0 = none, 1 = permute (default), 2 = cyclic ("high").
function buildUnicodePst(passwordCrc, crypt = 1) {
  const NBT = 0x400, BBT = 0x600, BLOCK = 0x800;
  const file = new Uint8Array(0x1000);
  const w16 = (b, o, v) => { b[o] = v & 0xff; b[o + 1] = (v >>> 8) & 0xff; };
  const w32 = (b, o, v) => { b[o] = v & 0xff; b[o + 1] = (v >>> 8) & 0xff; b[o + 2] = (v >>> 16) & 0xff; b[o + 3] = (v >>> 24) & 0xff; };

  file[0] = 0x21; file[1] = 0x42; file[2] = 0x44; file[3] = 0x4e; // !BDN
  w16(file, 0x0a, 23);            // Unicode
  file[0x201] = crypt;
  w32(file, 0xd8, 0x10); file[0xe0] = NBT & 0xff; file[0xe1] = (NBT >> 8) & 0xff;
  w32(file, 0xe8, 0x20); file[0xf0] = BBT & 0xff; file[0xf1] = (BBT >> 8) & 0xff;

  const B = 4;
  w32(file, NBT + 0, 0x21); file[NBT + 8] = B;
  file[NBT + 488] = 1; file[NBT + 489] = 1; file[NBT + 490] = 32; file[NBT + 491] = 0;

  const cb = 46;
  file[BLOCK + 2] = 0xec; file[BLOCK + 3] = 0xbc; w32(file, BLOCK + 4, 0x20);
  file[BLOCK + 12] = 0xb5; file[BLOCK + 13] = 2; file[BLOCK + 14] = 6; file[BLOCK + 15] = 0; w32(file, BLOCK + 16, 0x40);
  w16(file, BLOCK + 20, 0x67ff); w16(file, BLOCK + 22, 0x0003); w32(file, BLOCK + 24, passwordCrc);
  w16(file, BLOCK + 28, 0x3001); w16(file, BLOCK + 30, 0x001f); w32(file, BLOCK + 32, 0x40);
  w16(file, BLOCK + 36, 2); w16(file, BLOCK + 38, 0); w16(file, BLOCK + 40, 12); w16(file, BLOCK + 42, 20); w16(file, BLOCK + 44, 36);
  w16(file, BLOCK + 0, 36); // ibHnpm
  PstUnlock._encodeBlock(file, BLOCK, cb, crypt, B);

  const aligned = Math.ceil((cb + 16) / 64) * 64;
  const tOff = BLOCK + aligned - 16;
  w16(file, tOff, cb); w32(file, tOff + 4, pstCrc(file, BLOCK, cb)); w32(file, tOff + 8, B);

  file[BBT + 0] = B; file[BBT + 8] = BLOCK & 0xff; file[BBT + 9] = (BLOCK >> 8) & 0xff;
  w16(file, BBT + 16, cb); w16(file, BBT + 18, 2);
  file[BBT + 488] = 1; file[BBT + 489] = 1; file[BBT + 490] = 24; file[BBT + 491] = 0;

  return file;
}

// Two-block message store: BTH header in block 0, password record in block 1
// (reached via a HID whose block index is 1), tied together by an XBLOCK.
function buildUnicodePstMultiBlock(passwordCrc) {
  const NBT = 0x400, BBT = 0x600, XB = 0x800, B0 = 0x900, B1 = 0xa00;
  const file = new Uint8Array(0x1000);
  const w16 = (b, o, v) => { b[o] = v & 0xff; b[o + 1] = (v >>> 8) & 0xff; };
  const w32 = (b, o, v) => { b[o] = v & 0xff; b[o + 1] = (v >>> 8) & 0xff; b[o + 2] = (v >>> 16) & 0xff; b[o + 3] = (v >>> 24) & 0xff; };

  file[0] = 0x21; file[1] = 0x42; file[2] = 0x44; file[3] = 0x4e;
  w16(file, 0x0a, 23); file[0x201] = 1;
  w32(file, 0xd8, 0x10); file[0xe0] = NBT & 0xff; file[0xe1] = (NBT >> 8) & 0xff;
  w32(file, 0xe8, 0x20); file[0xf0] = BBT & 0xff; file[0xf1] = (BBT >> 8) & 0xff;

  const STORE = 6, BID0 = 8, BID1 = 12; // STORE is internal (bit 1 set); leaves clear

  w32(file, NBT + 0, 0x21); file[NBT + 8] = STORE;
  file[NBT + 488] = 1; file[NBT + 489] = 1; file[NBT + 490] = 32; file[NBT + 491] = 0;

  const xcb = 24;
  file[XB + 0] = 0x01; file[XB + 1] = 0x01; w16(file, XB + 2, 2); w32(file, XB + 4, 46);
  file[XB + 8] = BID0; file[XB + 16] = BID1;
  trailer(XB, xcb, STORE);

  const d0 = new Uint8Array(28);
  w16(d0, 0, 20); d0[2] = 0xec; d0[3] = 0xbc; w32(d0, 4, 0x20);
  d0[12] = 0xb5; d0[13] = 2; d0[14] = 6; d0[15] = 0; w32(d0, 16, 0x10020); // hidRoot=idx1/blk1
  w16(d0, 20, 1); w16(d0, 22, 0); w16(d0, 24, 12); w16(d0, 26, 20);
  file.set(d0, B0); PstUnlock._encodeBlock(file, B0, 28, 1, BID0); trailer(B0, 28, BID0);

  const d1 = new Uint8Array(18);
  w16(d1, 0, 10);
  w16(d1, 2, 0x67ff); w16(d1, 4, 0x0003); w32(d1, 6, passwordCrc);
  w16(d1, 10, 1); w16(d1, 12, 0); w16(d1, 14, 2); w16(d1, 16, 10);
  file.set(d1, B1); PstUnlock._encodeBlock(file, B1, 18, 1, BID1); trailer(B1, 18, BID1);

  const ent = [[STORE, XB, xcb], [BID0, B0, 28], [BID1, B1, 18]];
  ent.forEach((e, i) => {
    const o = BBT + i * 24;
    file[o] = e[0]; file[o + 8] = e[1] & 0xff; file[o + 9] = (e[1] >> 8) & 0xff;
    w16(file, o + 16, e[2]); w16(file, o + 18, 2);
  });
  file[BBT + 488] = 3; file[BBT + 489] = 3; file[BBT + 490] = 24; file[BBT + 491] = 0;

  return file;

  function trailer(ib, cb, bid) {
    const aligned = Math.ceil((cb + 16) / 64) * 64;
    const t = ib + aligned - 16;
    w16(file, t, cb); w32(file, t + 4, pstCrc(file, ib, cb)); w32(file, t + 8, bid);
  }
}

function readPstPassword(bytes, crypt = 1, BLOCK = 0x800, cb = 46) {
  const dec = bytes.slice(BLOCK, BLOCK + cb);
  PstUnlock._decodeBlock(dec, 0, cb, crypt, 4);
  return (dec[24] | (dec[25] << 8) | (dec[26] << 16) | (dec[27] << 24)) >>> 0;
}

function readMultiBlockPassword(bytes) {
  const dec = bytes.slice(0xa00, 0xa00 + 18);
  PstUnlock._decodeBlock(dec, 0, 18, 1, 12);
  return (dec[6] | (dec[7] << 8) | (dec[8] << 16) | (dec[9] << 24)) >>> 0;
}

module.exports = {
  buildProtectedOds, buildEncryptedOdt,
  buildCfb, buildProtectedXls, buildEncryptedXls, buildProtectedDoc, buildVbaCfb, buildEncryptedOoxmlOle2, buildEncryptedPackageOle2,
  buildUnicodePst, buildUnicodePstMultiBlock, readPstPassword, readMultiBlockPassword, pstCrc
};
