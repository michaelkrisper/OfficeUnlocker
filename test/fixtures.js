'use strict';

/*
 * Builders for synthetic protected files used by the test suite.
 *
 * For PDF we construct genuinely encrypted documents (Standard Security Handler
 * with an empty user password) so the unlocker has to actually derive the key
 * and decrypt — RC4 via the project's own primitive, AES-128 via Node's crypto
 * to cross-validate the pure-JS AES decryptor.
 *
 * For PST we hand-build a minimal Unicode message store whose property context
 * carries PidTagPstPassword, encoded with the "compressible" (permute) scheme.
 */

const crypto = require('crypto');
const zlib = require('zlib');
const bc = require('../bincrypto.js');

const PAD = Buffer.from([
  0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56,
  0xFF, 0xFA, 0x01, 0x08, 0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
  0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A]);
const md5 = (b) => Buffer.from(bc.md5(new Uint8Array(b)));
const rc4 = (k, d) => Buffer.from(bc.rc4(new Uint8Array(k), new Uint8Array(d)));
const hex = (b) => '<' + Buffer.from(b).toString('hex') + '>';

// Standard Security Handler key material for an empty user/owner password.
function standardSecurity(R, keyLen, id, P) {
  let rk = md5(PAD);
  if (R >= 3) for (let i = 0; i < 50; i++) rk = md5(rk.subarray(0, keyLen));
  rk = rk.subarray(0, keyLen);
  let O = rc4(rk, PAD);
  if (R >= 3) for (let i = 1; i <= 19; i++) O = rc4(Buffer.from(rk.map(b => b ^ i)), O);

  let input = Buffer.concat([PAD, O, Buffer.from([P & 0xff, (P >>> 8) & 0xff, (P >>> 16) & 0xff, (P >>> 24) & 0xff]), id]);
  let hash = md5(input);
  if (R >= 3) for (let i = 0; i < 50; i++) hash = md5(hash.subarray(0, keyLen));
  const key = hash.subarray(0, keyLen);

  let U;
  if (R === 2) {
    U = rc4(key, PAD);
  } else {
    let uh = md5(Buffer.concat([PAD, id]));
    U = rc4(key, uh);
    for (let i = 1; i <= 19; i++) U = rc4(Buffer.from(key.map(b => b ^ i)), U);
    U = Buffer.concat([U, Buffer.alloc(16)]);
  }
  return { key, O, U, keyLen };
}

function objKey(key, keyLen, num, gen, aes) {
  let ext = Buffer.concat([key, Buffer.from([num & 0xff, (num >> 8) & 0xff, (num >> 16) & 0xff, gen & 0xff, (gen >> 8) & 0xff])]);
  if (aes) ext = Buffer.concat([ext, Buffer.from('sAlT', 'latin1')]);
  return md5(ext).subarray(0, Math.min(keyLen + 5, 16));
}

function assemble(objs, order, trailer, version) {
  let buf = Buffer.from('%PDF-' + (version || '1.5') + '\n', 'latin1');
  const offsets = {};
  for (const i of order) {
    offsets[i] = buf.length;
    const o = objs[i];
    if (typeof o === 'string') {
      buf = Buffer.concat([buf, Buffer.from(`${i} 0 obj\n${o}\nendobj\n`, 'latin1')]);
    } else {
      buf = Buffer.concat([buf, Buffer.from(`${i} 0 obj\n${o.dict}\nstream\n`, 'latin1'), o.raw, Buffer.from('\nendstream\nendobj\n', 'latin1')]);
    }
  }
  const xrefStart = buf.length;
  const size = Math.max(...order) + 1;
  let tail = `xref\n0 ${size}\n0000000000 65535 f \n`;
  for (let i = 1; i < size; i++) tail += (offsets[i] != null ? String(offsets[i]).padStart(10, '0') + ' 00000 n \n' : '0000000000 65535 f \n');
  tail += `trailer\n<< /Size ${size} ${trailer} >>\nstartxref\n${xrefStart}\n%%EOF\n`;
  return new Uint8Array(Buffer.concat([buf, Buffer.from(tail, 'latin1')]));
}

// RC4-encrypted PDF (V2 / R3). Returns { bytes, secretContent, secretString }.
function buildRc4Pdf() {
  const keyLen = 16, R = 3;
  const id = Buffer.from('0123456789abcdef', 'latin1');
  const P = -44;
  const sec = standardSecurity(R, keyLen, id, P);
  const content = 'BT /F1 24 Tf 100 700 Td (RC4 Secret) Tj ET';
  const str = 'string-secret';
  const objs = {
    1: `<< /Type /Catalog /Pages 2 0 R /T ${hex(rc4(objKey(sec.key, keyLen, 1, 0, false), Buffer.from(str, 'latin1')))} >>`,
    2: '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    3: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 5 0 R >>',
    4: `<< /Filter /Standard /V 2 /R ${R} /Length 128 /P ${P} /O ${hex(sec.O)} /U ${hex(sec.U)} >>`,
    5: null
  };
  const enc = rc4(objKey(sec.key, keyLen, 5, 0, false), Buffer.from(content, 'latin1'));
  objs[5] = { dict: '<< /Length ' + enc.length + ' >>', raw: enc };
  const bytes = assemble(objs, [1, 2, 3, 4, 5],
    `/Root 1 0 R /Encrypt 4 0 R /ID [${hex(id)} ${hex(id)}]`);
  return { bytes, secretContent: content, secretString: str };
}

// AES-128 (V4 / R4 / AESV2) PDF that also stores an object inside an object stream.
function buildAesPdfWithObjStm() {
  const keyLen = 16, R = 4;
  const id = Buffer.from('FEDCBA9876543210', 'latin1');
  const P = -3904;
  const sec = standardSecurity(R, keyLen, id, P);
  const aesEnc = (num, plain) => {
    const iv = crypto.randomBytes(16);
    const c = crypto.createCipheriv('aes-128-cbc', objKey(sec.key, keyLen, num, 0, true), iv);
    return Buffer.concat([iv, c.update(Buffer.from(plain)), c.final()]);
  };
  const content = 'BT (AES Secret Content) Tj ET';
  const encContent = aesEnc(5, content);

  const payload = '<< /Marker (objstm-worked) >>';
  const header = '6 0 ';
  const objStmPlain = header + payload;
  const objStmEnc = aesEnc(7, zlib.deflateSync(Buffer.from(objStmPlain, 'latin1')));

  const objs = {
    1: '<< /Type /Catalog /Pages 2 0 R >>',
    2: '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    3: '<< /Type /Page /Parent 2 0 R /Contents 5 0 R >>',
    4: `<< /Filter /Standard /V 4 /R 4 /Length 128 /P ${P} /O ${hex(sec.O)} /U ${hex(sec.U)} /StmF /StdCF /StrF /StdCF /CF << /StdCF << /CFM /AESV2 /Length 16 >> >> >>`,
    5: { dict: '<< /Length ' + encContent.length + ' >>', raw: encContent },
    7: { dict: `<< /Type /ObjStm /N 1 /First ${header.length} /Length ${objStmEnc.length} /Filter /FlateDecode >>`, raw: objStmEnc }
  };
  const bytes = assemble(objs, [1, 2, 3, 4, 5, 7],
    `/Root 1 0 R /Encrypt 4 0 R /ID [${hex(id)} ${hex(id)}]`, '1.6');
  return { bytes, secretContent: content };
}

// PDF that genuinely needs an "open" (user) password — /U won't validate empty.
function buildUserPasswordPdf() {
  const keyLen = 16, R = 3;
  const id = Buffer.from('0123456789abcdef', 'latin1');
  const sec = standardSecurity(R, keyLen, id, -44);
  const badU = Buffer.alloc(32, 0x99); // deliberately wrong -> empty pw fails
  const objs = {
    1: '<< /Type /Catalog /Pages 2 0 R >>',
    2: '<< /Type /Pages /Kids [] /Count 0 >>',
    4: `<< /Filter /Standard /V 2 /R 3 /Length 128 /P -44 /O ${hex(sec.O)} /U ${hex(badU)} >>`
  };
  return assemble(objs, [1, 2, 4], `/Root 1 0 R /Encrypt 4 0 R /ID [${hex(id)} ${hex(id)}]`);
}

// Genuinely AES-256 (V5 / R6) encrypted PDF with an empty user password.
function hashR6(R, password, salt, udata) {
  const cat = (arr) => Buffer.concat(arr.map((a) => Buffer.from(a)));
  let K = Buffer.from(bc.sha256(cat([password, salt, udata])));
  if (R === 5) return K;
  let round = 0;
  while (true) {
    const block = cat([password, K, udata]);
    const K1 = Buffer.alloc(block.length * 64);
    for (let i = 0; i < 64; i++) block.copy(K1, i * block.length);
    const E = Buffer.from(bc.aesCbcEncryptNoPad(new Uint8Array(K.subarray(0, 16)), new Uint8Array(K.subarray(16, 32)), new Uint8Array(K1)));
    let sum = 0; for (let i = 0; i < 16; i++) sum += E[i];
    const mod = sum % 3;
    K = Buffer.from(mod === 0 ? bc.sha256(E) : (mod === 1 ? bc.sha384(E) : bc.sha512(E)));
    round++;
    if (round >= 64 && E[E.length - 1] <= round - 32) break;
  }
  return K.subarray(0, 32);
}

function buildAes256R6Pdf() {
  const R = 6;
  const id = Buffer.from('0123456789abcdef', 'latin1');
  const P = -44;
  const fileKey = crypto.randomBytes(32);
  const empty = Buffer.alloc(0);
  const valSalt = crypto.randomBytes(8), keySalt = crypto.randomBytes(8);
  const U = Buffer.concat([hashR6(R, empty, valSalt, empty), valSalt, keySalt]); // 48 bytes
  const intermediate = hashR6(R, empty, keySalt, empty);
  const UE = Buffer.from(bc.aesCbcEncryptNoPad(new Uint8Array(intermediate), new Uint8Array(16), new Uint8Array(fileKey)));
  // Owner key material (empty owner password), for a realistic dictionary.
  const oVal = crypto.randomBytes(8), oKey = crypto.randomBytes(8);
  const O = Buffer.concat([hashR6(R, empty, oVal, U), oVal, oKey]);
  const oInter = hashR6(R, empty, oKey, U);
  const OE = Buffer.from(bc.aesCbcEncryptNoPad(new Uint8Array(oInter), new Uint8Array(16), new Uint8Array(fileKey)));

  const aesEnc = (plain) => {
    const iv = crypto.randomBytes(16);
    const c = crypto.createCipheriv('aes-256-cbc', fileKey, iv);
    return Buffer.concat([iv, c.update(Buffer.from(plain)), c.final()]);
  };
  const content = 'BT (AES-256 R6 Secret) Tj ET';
  const encContent = aesEnc(content);

  const objs = {
    1: `<< /Type /Catalog /Pages 2 0 R /T ${hex(aesEnc('aes256-string'))} >>`,
    2: '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    3: '<< /Type /Page /Parent 2 0 R /Contents 5 0 R >>',
    4: `<< /Filter /Standard /V 5 /R 6 /Length 256 /P ${P} /O ${hex(O)} /U ${hex(U)} /OE ${hex(OE)} /UE ${hex(UE)} /StmF /StdCF /StrF /StdCF /CF << /StdCF << /CFM /AESV3 /Length 32 >> >> >>`,
    5: { dict: '<< /Length ' + encContent.length + ' >>', raw: encContent }
  };
  const bytes = assemble(objs, [1, 2, 3, 4, 5],
    `/Root 1 0 R /Encrypt 4 0 R /ID [${hex(id)} ${hex(id)}]`, '2.0');
  return { bytes, secretContent: content, secretString: 'aes256-string' };
}

// --- PST -------------------------------------------------------------------

const PERMUTE_DECODE = [
  71, 241, 180, 230, 11, 106, 114, 72, 133, 78, 158, 235, 226, 248, 148, 83, 224, 187, 160, 2, 232, 90, 9, 171, 219, 227, 186, 198, 124, 195, 16, 221,
  57, 5, 150, 48, 245, 55, 96, 130, 140, 201, 19, 74, 107, 29, 243, 251, 143, 38, 151, 202, 145, 23, 1, 196, 50, 45, 110, 49, 149, 255, 217, 35,
  209, 0, 94, 121, 220, 68, 59, 26, 40, 197, 97, 87, 32, 144, 61, 131, 185, 67, 190, 103, 210, 70, 66, 118, 192, 109, 91, 126, 178, 15, 22, 41,
  60, 169, 3, 84, 13, 218, 93, 223, 246, 183, 199, 98, 205, 141, 6, 211, 105, 92, 134, 214, 20, 247, 165, 102, 117, 172, 177, 233, 69, 33, 112, 12,
  135, 159, 116, 164, 34, 76, 111, 191, 31, 86, 170, 46, 179, 120, 51, 80, 176, 163, 146, 188, 207, 25, 28, 167, 99, 203, 30, 77, 62, 75, 27, 155,
  79, 231, 240, 238, 173, 58, 181, 89, 4, 234, 64, 85, 37, 81, 229, 122, 137, 56, 104, 82, 123, 252, 39, 174, 215, 189, 250, 7, 244, 204, 142, 95,
  239, 53, 156, 132, 43, 21, 213, 119, 52, 73, 182, 18, 10, 127, 113, 136, 253, 157, 24, 65, 125, 147, 216, 88, 44, 206, 254, 36, 175, 222, 184, 54,
  200, 161, 128, 166, 153, 152, 168, 47, 14, 129, 101, 115, 228, 194, 162, 138, 212, 225, 17, 208, 8, 139, 42, 242, 237, 154, 100, 63, 193, 108, 249, 236];
const PERMUTE_ENCODE = new Uint8Array(256);
for (let e = 0; e < 256; e++) PERMUTE_ENCODE[PERMUTE_DECODE[e]] = e;

function pstCrc(bytes, start, len) {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) { let c = i; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1); table[i] = c >>> 0; }
  let r = 0; for (let i = 0; i < len; i++) r = (table[(r ^ bytes[start + i]) & 0xff] ^ (r >>> 8)) >>> 0; return r >>> 0;
}

// Builds a minimal Unicode PST whose message store has PidTagPstPassword set.
function buildUnicodePst(passwordCrc) {
  const NBT = 0x400, BBT = 0x600, BLOCK = 0x800;
  const file = new Uint8Array(0x1000);
  const w16 = (b, o, v) => { b[o] = v & 0xff; b[o + 1] = (v >>> 8) & 0xff; };
  const w32 = (b, o, v) => { b[o] = v & 0xff; b[o + 1] = (v >>> 8) & 0xff; b[o + 2] = (v >>> 16) & 0xff; b[o + 3] = (v >>> 24) & 0xff; };

  file[0] = 0x21; file[1] = 0x42; file[2] = 0x44; file[3] = 0x4e; // !BDN
  w16(file, 0x0a, 23);            // Unicode
  file[0x201] = 1;               // permute
  w32(file, 0xd8, 0x10); file[0xe0] = NBT & 0xff; file[0xe1] = (NBT >> 8) & 0xff; // NBT root
  w32(file, 0xe8, 0x20); file[0xf0] = BBT & 0xff; file[0xf1] = (BBT >> 8) & 0xff; // BBT root

  const B = 4;
  // NBT leaf
  w32(file, NBT + 0, 0x21); file[NBT + 8] = B;
  file[NBT + 488] = 1; file[NBT + 489] = 1; file[NBT + 490] = 32; file[NBT + 491] = 0;

  // Heap-on-Node / PC block payload
  const d = new Uint8Array(64);
  d[2] = 0xec; d[3] = 0xbc; w32(d, 4, 0x20);          // HNHDR (hidUserRoot = idx1)
  d[12] = 0xb5; d[13] = 2; d[14] = 6; d[15] = 0; w32(d, 16, 0x40); // BTHHEADER (hidRoot = idx2)
  w16(d, 20, 0x67ff); w16(d, 22, 0x0003); w32(d, 24, passwordCrc);  // PidTagPstPassword
  w16(d, 28, 0x3001); w16(d, 30, 0x001f); w32(d, 32, 0x40);         // display name (dummy)
  w16(d, 36, 2); w16(d, 38, 0); w16(d, 40, 12); w16(d, 42, 20); w16(d, 44, 36); // HNPAGEMAP
  w16(d, 0, 36);                                                    // ibHnpm
  const cb = 46;
  for (let i = 0; i < cb; i++) file[BLOCK + i] = PERMUTE_ENCODE[d[i]];
  const aligned = Math.ceil((cb + 16) / 64) * 64;
  const tOff = BLOCK + aligned - 16;
  w16(file, tOff, cb); w32(file, tOff + 4, pstCrc(file, BLOCK, cb)); w32(file, tOff + 8, B);

  // BBT leaf
  file[BBT + 0] = B; file[BBT + 8] = BLOCK & 0xff; file[BBT + 9] = (BLOCK >> 8) & 0xff;
  w16(file, BBT + 16, cb); w16(file, BBT + 18, 2);
  file[BBT + 488] = 1; file[BBT + 489] = 1; file[BBT + 490] = 24; file[BBT + 491] = 0;

  return file;
}

function readPstPassword(bytes, BLOCK = 0x800, cb = 46) {
  const dec = new Uint8Array(cb);
  for (let i = 0; i < cb; i++) dec[i] = PERMUTE_DECODE[bytes[BLOCK + i]];
  return (dec[24] | (dec[25] << 8) | (dec[26] << 16) | (dec[27] << 24)) >>> 0;
}

// --- ODF -------------------------------------------------------------------

const JSZip = require('jszip');

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
  let next = 1 + dirSectors; // sector 0 = FAT, then directory
  for (const s of streams) {
    const ns = Math.ceil(s.data.length / SECTOR);
    layout.push({ start: next, ns });
    next += ns;
  }
  const totalSectors = next;
  const buf = new Uint8Array(SECTOR + totalSectors * SECTOR);

  // Header.
  [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1].forEach((b, i) => { buf[i] = b; });
  w16(buf, 0x1e, 9);            // sector shift -> 512
  w16(buf, 0x20, 6);            // mini sector shift -> 64
  w32(buf, 0x2c, 1);            // number of FAT sectors
  w32(buf, 0x30, 1);            // first directory sector
  w32(buf, 0x38, 4096);         // mini stream cutoff
  w32(buf, 0x3c, ENDOFCHAIN);   // first mini FAT
  w32(buf, 0x40, 0);            // number of mini FAT sectors
  w32(buf, 0x44, ENDOFCHAIN);   // first DIFAT
  w32(buf, 0x48, 0);            // number of DIFAT sectors
  for (let i = 0; i < 109; i++) w32(buf, 0x4c + i * 4, i === 0 ? 0 : FREESECT);

  // FAT (sector 0).
  const fat = new Uint32Array(128).fill(FREESECT);
  fat[0] = FATSECT;
  for (let k = 1; k <= dirSectors; k++) fat[k] = (k < dirSectors) ? k + 1 : ENDOFCHAIN;
  layout.forEach((l) => {
    for (let j = 0; j < l.ns; j++) fat[l.start + j] = (j < l.ns - 1) ? l.start + j + 1 : ENDOFCHAIN;
  });
  const fatBase = SECTOR + 0 * SECTOR;
  for (let i = 0; i < 128; i++) w32(buf, fatBase + i * 4, fat[i]);

  // Directory entries.
  function writeEntry(idx, name, type, start, size) {
    const base = SECTOR + (1 * SECTOR) + idx * 128;
    for (let c = 0; c < name.length; c++) w16(buf, base + c * 2, name.charCodeAt(c));
    w16(buf, base + 0x40, name.length * 2 + 2); // name length incl. null
    buf[base + 0x42] = type;
    w32(buf, base + 0x44, FREESECT); // left
    w32(buf, base + 0x48, FREESECT); // right
    w32(buf, base + 0x4c, FREESECT); // child
    w32(buf, base + 0x74, start);
    w32(buf, base + 0x78, size);
  }
  writeEntry(0, 'Root Entry', 5, ENDOFCHAIN, 0);
  streams.forEach((s, i) => writeEntry(i + 1, s.name, s.type || 2, layout[i].start, s.data.length));

  // Stream data.
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
    biffRecord(0x0809, new Uint8Array(16)),         // BOF
    biffRecord(0x0012, new Uint8Array([1, 0])),     // PROTECT
    biffRecord(0x0013, new Uint8Array([0xcd, 0xab])), // PASSWORD hash
    biffRecord(0x0019, new Uint8Array([1, 0])),     // WINDOWPROTECT
    biffRecord(0x0063, new Uint8Array([1, 0])),     // OBJECTPROTECT
    biffRecord(0x000a, new Uint8Array(0))           // EOF
  ]);
  return buildCfb([{ name: 'Workbook', data: padTo(wb, 4096) }]);
}

function buildEncryptedXls() {
  const wb = concatBytes([
    biffRecord(0x0809, new Uint8Array(16)),
    biffRecord(0x002f, new Uint8Array([1, 0, 1, 0])) // FILEPASS
  ]);
  return buildCfb([{ name: 'Workbook', data: padTo(wb, 4096) }]);
}

// Legacy Word doc with "Restrict Editing" (Dop.fProtEnabled) turned on.
function buildProtectedDoc() {
  const w16 = (b, o, v) => { b[o] = v & 0xff; b[o + 1] = (v >>> 8) & 0xff; };
  const w32 = (b, o, v) => { b[o] = v & 0xff; b[o + 1] = (v >>> 8) & 0xff; b[o + 2] = (v >>> 16) & 0xff; b[o + 3] = (v >>> 24) & 0xff; };
  const fib = new Uint8Array(4096);
  w16(fib, 0x00, 0xa5ec);   // wIdent
  w16(fib, 0x02, 0x00c1);   // nFib (Word 97+)
  w16(fib, 0x0a, 0x0000);   // flags: fEncrypted off, fWhichTblStm=0 -> "0Table"
  const fcDop = 16;
  w32(fib, 0x192, fcDop);   // fcDop
  w32(fib, 0x196, 0x20);    // lcbDop

  const table = new Uint8Array(4096);
  table[fcDop + 0x07] = 0x0b; // fProtEnabled (0x02) + a couple of other bits

  return buildCfb([
    { name: 'WordDocument', data: fib },
    { name: '0Table', data: table }
  ]);
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

module.exports = {
  buildRc4Pdf, buildAesPdfWithObjStm, buildUserPasswordPdf, buildAes256R6Pdf,
  buildUnicodePst, readPstPassword, pstCrc,
  buildProtectedOds, buildEncryptedOdt,
  buildCfb, buildProtectedXls, buildEncryptedXls, buildProtectedDoc, buildVbaCfb, buildEncryptedOoxmlOle2
};
