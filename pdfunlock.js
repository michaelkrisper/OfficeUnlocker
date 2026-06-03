/*
 * PDF unlocker — removes usage restrictions (printing, copying, editing) from
 * PDFs that are protected with a permissions / "owner" password.
 *
 * How PDF protection works: unlike Office files (where the restriction is a
 * plain XML flag), a restricted PDF is genuinely *encrypted* with the Standard
 * Security Handler. When there is no "open" (user) password, the encryption key
 * is derivable from the standard padding string, so the whole document can be
 * decrypted and re-saved without restrictions — without knowing the owner
 * password. That is exactly what this module does.
 *
 * Supported: Standard Security Handler V1/V2 (RC4) and V4 (RC4 or AES-128),
 * revisions 2–4, with an empty user password. NOT supported: documents that
 * need an "open" password to view (true user-password encryption) and AES-256
 * (V5/R6) — those throw a clear error.
 *
 * UMD: `require('./pdfunlock.js')` in Node, `window.PdfUnlock` in the browser.
 * Depends on BinCrypto (md5/rc4/aes) and an inflate() implementation (Node's
 * zlib, or `window.pako`) for object/cross-reference streams.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('./bincrypto.js'), nodeInflate());
  } else {
    root.PdfUnlock = factory(root.BinCrypto, browserInflate());
  }

  function nodeInflate() {
    var zlib = require('zlib');
    return function (bytes) {
      try { return new Uint8Array(zlib.inflateSync(Buffer.from(bytes))); }
      catch { return new Uint8Array(zlib.inflateRawSync(Buffer.from(bytes))); }
    };
  }
  function browserInflate() {
    return function (bytes) {
      if (root.pako && root.pako.inflate) {
        try { return root.pako.inflate(bytes); }
        catch { return root.pako.inflateRaw(bytes); }
      }
      throw new Error('No inflate implementation available (pako not loaded).');
    };
  }
})(typeof self !== 'undefined' ? self : this, function (BinCrypto, inflate) {
  'use strict';

  var md5 = BinCrypto.md5;
  var rc4 = BinCrypto.rc4;
  var aesCbcDecrypt = BinCrypto.aesCbcDecrypt;

  // 32-byte padding string from the PDF spec (Algorithm 2).
  var PAD = new Uint8Array([
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56,
    0xFF, 0xFA, 0x01, 0x08, 0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
    0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A
  ]);

  function isWhite(b) { return b === 0 || b === 9 || b === 10 || b === 12 || b === 13 || b === 32; }
  function isDelim(b) {
    return b === 0x28 || b === 0x29 || b === 0x3C || b === 0x3E || b === 0x5B ||
      b === 0x5D || b === 0x7B || b === 0x7D || b === 0x2F || b === 0x25;
  }

  // ---- Recursive-descent parser over a byte buffer --------------------------

  function Parser(buf, pos) {
    this.buf = buf;
    this.pos = pos || 0;
  }
  Parser.prototype.skipWs = function () {
    var b = this.buf;
    while (this.pos < b.length) {
      var c = b[this.pos];
      if (c === 0x25) { // comment until EOL
        while (this.pos < b.length && b[this.pos] !== 10 && b[this.pos] !== 13) this.pos++;
      } else if (isWhite(c)) {
        this.pos++;
      } else break;
    }
  };
  Parser.prototype.parseValue = function () {
    this.skipWs();
    var b = this.buf, c = b[this.pos];
    if (c === 0x3C && b[this.pos + 1] === 0x3C) return this.parseDict();
    if (c === 0x3C) return this.parseHexString();
    if (c === 0x28) return this.parseLiteralString();
    if (c === 0x2F) return this.parseName();
    if (c === 0x5B) return this.parseArray();
    if (c === 0x5D || c === 0x3E) return null; // end of array/dict marker handled by caller
    return this.parseKeywordOrNumber();
  };
  Parser.prototype.parseName = function () {
    var b = this.buf;
    this.pos++; // skip /
    var s = '';
    while (this.pos < b.length && !isWhite(b[this.pos]) && !isDelim(b[this.pos])) {
      var ch = b[this.pos++];
      if (ch === 0x23) { // #xx hex escape
        var hex = String.fromCharCode(b[this.pos], b[this.pos + 1]);
        s += String.fromCharCode(parseInt(hex, 16));
        this.pos += 2;
      } else {
        s += String.fromCharCode(ch);
      }
    }
    return { t: 'name', name: s };
  };
  Parser.prototype.parseLiteralString = function () {
    var b = this.buf;
    this.pos++; // skip (
    var out = [];
    var depth = 1;
    while (this.pos < b.length) {
      var ch = b[this.pos++];
      if (ch === 0x5C) { // backslash escape
        var n = b[this.pos++];
        if (n === 0x6E) out.push(10);
        else if (n === 0x72) out.push(13);
        else if (n === 0x74) out.push(9);
        else if (n === 0x62) out.push(8);
        else if (n === 0x66) out.push(12);
        else if (n === 0x28) out.push(0x28);
        else if (n === 0x29) out.push(0x29);
        else if (n === 0x5C) out.push(0x5C);
        else if (n >= 0x30 && n <= 0x37) { // octal
          var oct = String.fromCharCode(n);
          for (var k = 0; k < 2 && b[this.pos] >= 0x30 && b[this.pos] <= 0x37; k++) oct += String.fromCharCode(b[this.pos++]);
          out.push(parseInt(oct, 8) & 0xff);
        } else if (n === 10) { /* line continuation */ }
        else if (n === 13) { if (b[this.pos] === 10) this.pos++; }
        else out.push(n);
      } else if (ch === 0x28) { depth++; out.push(ch); }
      else if (ch === 0x29) { depth--; if (depth === 0) break; out.push(ch); }
      else out.push(ch);
    }
    return { t: 'string', bytes: new Uint8Array(out) };
  };
  Parser.prototype.parseHexString = function () {
    var b = this.buf;
    this.pos++; // skip <
    var hex = '';
    while (this.pos < b.length && b[this.pos] !== 0x3E) {
      var c = b[this.pos++];
      if (!isWhite(c)) hex += String.fromCharCode(c);
    }
    this.pos++; // skip >
    if (hex.length % 2) hex += '0';
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return { t: 'string', bytes: out };
  };
  Parser.prototype.parseArray = function () {
    this.pos++; // skip [
    var items = [];
    while (true) {
      this.skipWs();
      if (this.buf[this.pos] === 0x5D) { this.pos++; break; }
      if (this.pos >= this.buf.length) break;
      items.push(this.parseValue());
    }
    return { t: 'array', items: items };
  };
  Parser.prototype.parseDict = function () {
    this.pos += 2; // skip <<
    var entries = [];
    while (true) {
      this.skipWs();
      if (this.buf[this.pos] === 0x3E && this.buf[this.pos + 1] === 0x3E) { this.pos += 2; break; }
      if (this.pos >= this.buf.length) break;
      var key = this.parseName();
      var val = this.parseValue();
      entries.push([key.name, val]);
    }
    var dict = { t: 'dict', entries: entries };
    // Peek for a following stream.
    var save = this.pos;
    this.skipWs();
    if (this.matchKeyword('stream')) {
      // stream data begins after CRLF or LF
      if (this.buf[this.pos] === 13) this.pos++;
      if (this.buf[this.pos] === 10) this.pos++;
      var start = this.pos;
      var len = this.directInt(dictGet(dict, 'Length'));
      var raw;
      if (len !== null && start + len <= this.buf.length) {
        raw = this.buf.subarray(start, start + len);
        this.pos = start + len;
        this.skipWs();
        if (!this.matchKeyword('endstream')) {
          // Length was wrong; fall back to scanning.
          raw = this.scanStream(start);
        }
      } else {
        raw = this.scanStream(start);
      }
      return { t: 'stream', dict: dict, raw: raw };
    }
    this.pos = save;
    return dict;
  };
  Parser.prototype.scanStream = function (start) {
    var b = this.buf;
    var idx = indexOf(b, ENDSTREAM, start);
    var end = idx === -1 ? b.length : idx;
    // Trim a single trailing EOL that precedes "endstream".
    var e = end;
    if (b[e - 1] === 10) e--;
    if (b[e - 1] === 13) e--;
    var raw = b.subarray(start, e);
    this.pos = (idx === -1 ? b.length : idx + ENDSTREAM.length);
    return raw;
  };
  Parser.prototype.directInt = function (v) {
    if (v && v.t === 'num' && /^-?\d+$/.test(v.text)) return parseInt(v.text, 10);
    return null;
  };
  Parser.prototype.matchKeyword = function (kw) {
    var b = this.buf;
    for (var i = 0; i < kw.length; i++) {
      if (b[this.pos + i] !== kw.charCodeAt(i)) return false;
    }
    this.pos += kw.length;
    return true;
  };
  Parser.prototype.parseKeywordOrNumber = function () {
    var b = this.buf;
    var startPos = this.pos;
    var s = '';
    while (this.pos < b.length && !isWhite(b[this.pos]) && !isDelim(b[this.pos])) {
      s += String.fromCharCode(b[this.pos++]);
    }
    if (s === 'true') return { t: 'bool', value: true };
    if (s === 'false') return { t: 'bool', value: false };
    if (s === 'null') return { t: 'null' };
    if (/^[-+]?[\d.]+$/.test(s)) {
      // Could be "N G R" or "N G obj" — look ahead.
      var save = this.pos;
      if (/^\d+$/.test(s)) {
        this.skipWs();
        var s2 = '';
        while (this.pos < b.length && b[this.pos] >= 0x30 && b[this.pos] <= 0x39) s2 += String.fromCharCode(b[this.pos++]);
        if (s2.length) {
          this.skipWs();
          if (b[this.pos] === 0x52 && (isWhite(b[this.pos + 1]) || isDelim(b[this.pos + 1]) || this.pos + 1 >= b.length)) {
            this.pos += 1;
            return { t: 'ref', num: parseInt(s, 10), gen: parseInt(s2, 10) };
          }
        }
        this.pos = save;
      }
      return { t: 'num', text: s };
    }
    // Unknown keyword (e.g. stray token); return as name-ish token.
    this.pos = startPos + Math.max(1, s.length);
    return { t: 'num', text: s || '0' };
  };

  var ENDSTREAM = strBytes('endstream');
  function strBytes(s) {
    var u = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
    return u;
  }
  function indexOf(hay, needle, from) {
    outer:
    for (var i = from; i <= hay.length - needle.length; i++) {
      for (var j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
      return i;
    }
    return -1;
  }
  function dictGet(dict, key) {
    if (!dict || dict.t !== 'dict') return undefined;
    for (var i = 0; i < dict.entries.length; i++) if (dict.entries[i][0] === key) return dict.entries[i][1];
    return undefined;
  }
  function dictSet(dict, key, val) {
    for (var i = 0; i < dict.entries.length; i++) {
      if (dict.entries[i][0] === key) { dict.entries[i][1] = val; return; }
    }
    dict.entries.push([key, val]);
  }
  // ---- Object collection ----------------------------------------------------

  // Find every "N G obj" in the file and parse the object that follows. This
  // tolerates broken/rebuilt cross-reference tables.
  function collectObjects(buf) {
    var objects = {}; // num -> { gen, value }
    var re = /(\d+)\s+(\d+)\s+obj\b/g;
    var text = latin1(buf);
    var m;
    while ((m = re.exec(text)) !== null) {
      var num = parseInt(m[1], 10);
      var gen = parseInt(m[2], 10);
      var p = new Parser(buf, m.index + m[0].length);
      var value;
      try { value = p.parseValue(); } catch { continue; }
      // Latest definition wins (incremental updates appended later in the file).
      objects[num] = { gen: gen, value: value };
    }
    return objects;
  }

  function latin1(buf) {
    var CHUNK = 0x8000, parts = [];
    for (var i = 0; i < buf.length; i += CHUNK) {
      parts.push(String.fromCharCode.apply(null, buf.subarray(i, i + CHUNK)));
    }
    return parts.join('');
  }

  function findTrailerDict(buf, objects) {
    // 1) Classic `trailer << ... >>`.
    var text = latin1(buf);
    var idx = text.lastIndexOf('trailer');
    var merged = { t: 'dict', entries: [] };
    if (idx !== -1) {
      var p = new Parser(buf, idx + 'trailer'.length);
      var d = p.parseValue();
      if (d && d.t === 'dict') mergeTrailer(merged, d);
    }
    // 2) Cross-reference streams (/Type /XRef) carry the same keys.
    Object.keys(objects).forEach(function (num) {
      var v = objects[num].value;
      if (v && v.t === 'stream') {
        var ty = dictGet(v.dict, 'Type');
        if (ty && ty.t === 'name' && ty.name === 'XRef') mergeTrailer(merged, v.dict);
      }
    });
    return merged;
  }
  function mergeTrailer(into, from) {
    ['Root', 'Info', 'Encrypt', 'ID', 'Size'].forEach(function (k) {
      if (dictGet(into, k) === undefined) {
        var v = dictGet(from, k);
        if (v !== undefined) dictSet(into, k, v);
      }
    });
  }

  function resolve(v, objects) {
    var seen = 0;
    while (v && v.t === 'ref' && objects[v.num] && seen < 50) {
      v = objects[v.num].value; seen++;
    }
    return v;
  }

  // ---- Encryption handling ---------------------------------------------------

  function buildHandler(encDict, idBytes, objects) {
    var filter = resolve(dictGet(encDict, 'Filter'), objects);
    if (!filter || filter.t !== 'name' || filter.name !== 'Standard') {
      throw fail('UNSUPPORTED', 'This PDF uses a non-standard security handler that cannot be removed.');
    }
    var V = numOf(resolve(dictGet(encDict, 'V'), objects), 0);
    var R = numOf(resolve(dictGet(encDict, 'R'), objects), 0);
    if (R >= 5 || V >= 5) {
      throw fail('UNSUPPORTED', 'This PDF uses AES-256 (newer Acrobat) encryption, which is not yet supported.');
    }
    var O = strOf(resolve(dictGet(encDict, 'O'), objects));
    var P = numOf(resolve(dictGet(encDict, 'P'), objects), 0) | 0;
    var lengthBits = numOf(resolve(dictGet(encDict, 'Length'), objects), 40);
    var keyLen = V === 1 ? 5 : Math.floor(lengthBits / 8);
    var encryptMetadata = true;
    var em = resolve(dictGet(encDict, 'EncryptMetadata'), objects);
    if (em && em.t === 'bool') encryptMetadata = em.value;

    // Decide cipher (RC4 vs AESV2) for V4 via crypt filters.
    var useAES = false;
    if (V >= 4) {
      var cf = resolve(dictGet(encDict, 'CF'), objects);
      var stmF = resolve(dictGet(encDict, 'StmF'), objects);
      var name = stmF && stmF.t === 'name' ? stmF.name : 'Identity';
      if (cf && cf.t === 'dict') {
        var filterDef = resolve(dictGet(cf, name), objects);
        var cfm = filterDef && filterDef.t === 'dict' ? resolve(dictGet(filterDef, 'CFM'), objects) : null;
        if (cfm && cfm.t === 'name' && cfm.name === 'AESV2') useAES = true;
      }
    }

    // Algorithm 2: compute the encryption key for an empty user password.
    var input = [];
    pushAll(input, PAD);
    pushAll(input, O);
    input.push(P & 0xff, (P >>> 8) & 0xff, (P >>> 16) & 0xff, (P >>> 24) & 0xff);
    pushAll(input, idBytes);
    if (R >= 4 && !encryptMetadata) input.push(0xff, 0xff, 0xff, 0xff);
    var hash = md5(new Uint8Array(input));
    if (R >= 3) {
      for (var i = 0; i < 50; i++) hash = md5(hash.subarray(0, keyLen));
    }
    var key = hash.subarray(0, keyLen);

    // Verify the empty user password actually unlocks the document (Algorithm 6).
    if (!verifyUserPassword(key, R, idBytes, strOf(resolve(dictGet(encDict, 'U'), objects)))) {
      throw fail('ENCRYPTED', 'This PDF needs an "open" password to view it; it cannot be unlocked without that password.');
    }

    return {
      key: key, keyLen: keyLen, useAES: useAES, R: R, encryptMetadata: encryptMetadata
    };
  }

  function verifyUserPassword(key, R, idBytes, U) {
    if (!U) return true; // can't verify; assume ok
    if (R === 2) {
      var enc = rc4(key, PAD);
      return bytesEqual(enc, U, 32);
    }
    // R >= 3
    var input = [];
    pushAll(input, PAD);
    pushAll(input, idBytes);
    var h = md5(new Uint8Array(input));
    var data = rc4(key, h);
    for (var i = 1; i <= 19; i++) {
      var k2 = new Uint8Array(key.length);
      for (var j = 0; j < key.length; j++) k2[j] = key[j] ^ i;
      data = rc4(k2, data);
    }
    return bytesEqual(data, U, 16);
  }

  function objectKey(handler, num, gen) {
    var ext = [];
    pushAll(ext, handler.key);
    ext.push(num & 0xff, (num >>> 8) & 0xff, (num >>> 16) & 0xff);
    ext.push(gen & 0xff, (gen >>> 8) & 0xff);
    if (handler.useAES) ext.push(0x73, 0x41, 0x6c, 0x54); // "sAlT"
    var h = md5(new Uint8Array(ext));
    return h.subarray(0, Math.min(handler.keyLen + 5, 16));
  }

  function decryptBytes(handler, num, gen, bytes) {
    var ok = objectKey(handler, num, gen);
    return handler.useAES ? aesCbcDecrypt(ok, bytes) : rc4(ok, bytes);
  }

  // Walk a value, decrypting every string in place (used for top-level objects).
  function decryptStringsIn(value, handler, num, gen) {
    if (!value) return;
    if (value.t === 'string') {
      value.bytes = decryptBytes(handler, num, gen, value.bytes);
    } else if (value.t === 'array') {
      value.items.forEach(function (it) { decryptStringsIn(it, handler, num, gen); });
    } else if (value.t === 'dict') {
      value.entries.forEach(function (e) { decryptStringsIn(e[1], handler, num, gen); });
    } else if (value.t === 'stream') {
      decryptStringsIn(value.dict, handler, num, gen);
    }
  }

  // ---- Object streams --------------------------------------------------------

  // Decompose an object stream into its contained indirect objects.
  function expandObjectStream(streamObj, objects, out) {
    var dict = streamObj.dict;
    var data = streamObj.raw;
    if (hasFlate(dict)) data = inflate(data);
    var n = numOf(resolve(dictGet(dict, 'N'), objects), 0);
    var first = numOf(resolve(dictGet(dict, 'First'), objects), 0);
    var header = new Parser(data, 0);
    var entries = [];
    for (var i = 0; i < n; i++) {
      header.skipWs();
      var onum = header.parseKeywordOrNumber();
      var ooff = header.parseKeywordOrNumber();
      entries.push({ num: parseInt(onum.text, 10), off: parseInt(ooff.text, 10) });
    }
    for (i = 0; i < entries.length; i++) {
      var p = new Parser(data, first + entries[i].off);
      var val;
      try { val = p.parseValue(); } catch { continue; }
      // Objects inside an object stream are NOT separately encrypted.
      out[entries[i].num] = { gen: 0, value: val, fromObjStm: true };
    }
  }

  function hasFlate(dict) {
    var f = dictGet(dict, 'Filter');
    if (!f) return false;
    if (f.t === 'name') return f.name === 'FlateDecode';
    if (f.t === 'array') return f.items.some(function (x) { return x.t === 'name' && x.name === 'FlateDecode'; });
    return false;
  }

  // ---- Serialization ---------------------------------------------------------

  function serializeValue(v, parts) {
    if (!v) { parts.push('null'); return; }
    switch (v.t) {
      case 'null': parts.push('null'); break;
      case 'bool': parts.push(v.value ? 'true' : 'false'); break;
      case 'num': parts.push(v.text); break;
      case 'name': parts.push('/' + encodeName(v.name)); break;
      case 'ref': parts.push(v.num + ' ' + v.gen + ' R'); break;
      case 'string': parts.push(hexString(v.bytes)); break;
      case 'array':
        parts.push('[');
        for (var i = 0; i < v.items.length; i++) { if (i) parts.push(' '); serializeValue(v.items[i], parts); }
        parts.push(']');
        break;
      case 'dict':
        serializeDict(v, parts);
        break;
      case 'stream':
        serializeDict(v.dict, parts);
        parts.push('\nstream\n');
        parts.push(v.raw);
        parts.push('\nendstream');
        break;
      default: parts.push('null');
    }
  }
  function serializeDict(d, parts) {
    parts.push('<<');
    for (var i = 0; i < d.entries.length; i++) {
      parts.push('/' + encodeName(d.entries[i][0]) + ' ');
      serializeValue(d.entries[i][1], parts);
      parts.push(' ');
    }
    parts.push('>>');
  }
  function encodeName(name) {
    var out = '';
    for (var i = 0; i < name.length; i++) {
      var c = name.charCodeAt(i);
      if (c < 0x21 || c > 0x7e || isDelim(c) || c === 0x23 || c === 0x20) {
        out += '#' + c.toString(16).padStart(2, '0');
      } else out += name[i];
    }
    return out;
  }
  function hexString(bytes) {
    var s = '<';
    for (var i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
    return s + '>';
  }

  // ---- Main ------------------------------------------------------------------

  function unlock(buf) {
    if (!(buf instanceof Uint8Array)) buf = new Uint8Array(buf);
    var objects = collectObjects(buf);
    var trailer = findTrailerDict(buf, objects);
    var encRef = dictGet(trailer, 'Encrypt');

    if (encRef === undefined) {
      // No encryption — nothing to remove. Return the original bytes unchanged.
      return { bytes: buf, changed: false };
    }

    var encNum = encRef.t === 'ref' ? encRef.num : -1;
    var encDict = resolve(encRef, objects);
    if (!encDict || encDict.t !== 'dict') {
      throw fail('INVALID', 'The PDF declares encryption but its security dictionary is missing.');
    }

    // The first element of the document /ID is part of the key derivation.
    var idArr = resolve(dictGet(trailer, 'ID'), objects);
    var idBytes = new Uint8Array(0);
    if (idArr && idArr.t === 'array' && idArr.items[0] && idArr.items[0].t === 'string') {
      idBytes = idArr.items[0].bytes;
    }

    var handler = buildHandler(encDict, idBytes, objects);

    // First expand any object streams (their contents are not separately encrypted).
    var objStmNums = [];
    Object.keys(objects).forEach(function (numStr) {
      var o = objects[numStr];
      if (o.value && o.value.t === 'stream') {
        var ty = dictGet(o.value.dict, 'Type');
        if (ty && ty.t === 'name' && ty.name === 'ObjStm') objStmNums.push(parseInt(numStr, 10));
      }
    });
    objStmNums.forEach(function (n) {
      // The ObjStm stream itself IS encrypted — decrypt before expanding.
      var o = objects[n];
      o.value.raw = decryptBytes(handler, n, o.gen, o.value.raw);
      try { expandObjectStream(o.value, objects, objects); } catch { /* leave as-is */ }
      delete objects[n]; // drop the now-redundant object stream container
    });

    // Decrypt every remaining top-level object's strings and streams.
    Object.keys(objects).forEach(function (numStr) {
      var num = parseInt(numStr, 10);
      var o = objects[num];
      if (num === encNum || o.fromObjStm) return; // /Encrypt dict + decompressed objs: not encrypted
      var v = o.value;
      if (!v) return;
      var dictPart = v.t === 'stream' ? v.dict : v;
      var ty = dictPart && dictPart.t === 'dict' ? dictGet(dictPart, 'Type') : undefined;
      var isXRef = ty && ty.t === 'name' && ty.name === 'XRef';
      var isMeta = ty && ty.t === 'name' && ty.name === 'Metadata';
      decryptStringsIn(v, handler, num, o.gen);
      if (v.t === 'stream' && !isXRef && !(isMeta && !handler.encryptMetadata)) {
        v.raw = decryptBytes(handler, num, o.gen, v.raw);
      }
    });

    // Drop cross-reference streams: we emit a classic xref table instead.
    Object.keys(objects).forEach(function (numStr) {
      var v = objects[numStr].value;
      if (v && v.t === 'stream') {
        var ty = dictGet(v.dict, 'Type');
        if (ty && ty.t === 'name' && ty.name === 'XRef') delete objects[numStr];
      }
    });
    // Drop the now-removed /Encrypt object.
    if (encNum >= 0) delete objects[encNum];

    var output = rebuild(objects, trailer);
    return { bytes: output, changed: true };
  }

  function rebuild(objects, trailer) {
    var nums = Object.keys(objects).map(Number).sort(function (a, b) { return a - b; });
    var maxNum = nums.length ? nums[nums.length - 1] : 0;
    var size = maxNum + 1;

    var chunks = [];
    var offsets = new Array(size).fill(0);
    var cursor = 0;
    function emit(strOrBytes) {
      var bytes = typeof strOrBytes === 'string' ? strBytes(strOrBytes) : strOrBytes;
      chunks.push(bytes);
      cursor += bytes.length;
    }

    emit('%PDF-1.7\n%\xE2\xE3\xCF\xD3\n');

    for (var i = 0; i < nums.length; i++) {
      var num = nums[i];
      offsets[num] = cursor;
      var o = objects[num];
      var parts = [];
      parts.push(num + ' ' + (o.gen || 0) + ' obj\n');
      serializeValue(o.value, parts);
      parts.push('\nendobj\n');
      for (var k = 0; k < parts.length; k++) emit(parts[k]);
    }

    var xrefStart = cursor;
    var lines = ['xref\n', '0 ' + size + '\n', '0000000000 65535 f \n'];
    for (num = 1; num < size; num++) {
      if (objects[num]) {
        lines.push(pad10(offsets[num]) + ' 00000 n \n');
      } else {
        lines.push('0000000000 65535 f \n');
      }
    }
    emit(lines.join(''));

    var tparts = ['trailer\n<<'];
    tparts.push(' /Size ' + size);
    ['Root', 'Info', 'ID'].forEach(function (k) {
      var v = dictGet(trailer, k);
      if (v !== undefined) {
        var p = [];
        serializeValue(v, p);
        tparts.push(' /' + k + ' ' + p.join(''));
      }
    });
    tparts.push(' >>\nstartxref\n' + xrefStart + '\n%%EOF\n');
    emit(tparts.join(''));

    return concat(chunks);
  }

  // ---- helpers ---------------------------------------------------------------

  function numOf(v, dflt) {
    if (v && v.t === 'num') { var n = parseFloat(v.text); return isNaN(n) ? dflt : n; }
    return dflt;
  }
  function strOf(v) { return v && v.t === 'string' ? v.bytes : null; }
  function pushAll(arr, bytes) { if (bytes) for (var i = 0; i < bytes.length; i++) arr.push(bytes[i]); }
  function bytesEqual(a, b, n) {
    if (!a || !b) return false;
    for (var i = 0; i < n; i++) if (a[i] !== b[i]) return false;
    return true;
  }
  function pad10(n) { return String(n).padStart(10, '0'); }
  function concat(chunks) {
    var total = 0;
    for (var i = 0; i < chunks.length; i++) total += chunks[i].length;
    var out = new Uint8Array(total), off = 0;
    for (i = 0; i < chunks.length; i++) { out.set(chunks[i], off); off += chunks[i].length; }
    return out;
  }
  function fail(code, message) { var e = new Error(message); e.code = code; return e; }

  return { unlock: unlock };
});
