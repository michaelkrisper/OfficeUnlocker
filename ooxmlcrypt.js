/*
 * Decrypts ECMA-376 "encrypted" Office documents (.xlsx/.docx/.pptx stored in
 * an OLE2 wrapper) when they use a *known* password — most importantly Excel's
 * default password "VelvetSweatshop", which Office applies automatically and
 * opens without prompting, and the empty password.
 *
 * Supports both the Agile (Office 2010+) and Standard (Office 2007) schemes of
 * the Standard encryption. On success the decrypted inner OOXML ZIP is returned
 * so the normal protection-stripping can run on it afterwards.
 *
 * UMD: `require('./ooxmlcrypt.js')` in Node, `window.OoxmlCrypt` in the browser.
 * Depends on BinCrypto (hashes + AES) and Ole2 (to read the streams).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('./bincrypto.js'), require('./ole2.js'));
  } else {
    root.OoxmlCrypt = factory(root.BinCrypto, root.Ole2);
  }
})(typeof self !== 'undefined' ? self : this, function (BinCrypto, Ole2) {
  'use strict';

  var DEFAULT_PASSWORDS = ['VelvetSweatshop', ''];

  var BLOCK_VERIFIER_INPUT = new Uint8Array([0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79]);
  var BLOCK_VERIFIER_VALUE = new Uint8Array([0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e]);
  var BLOCK_KEY_VALUE = new Uint8Array([0x14, 0x6e, 0x0b, 0xe7, 0xab, 0xac, 0xd0, 0xd6]);

  function u16(b, o) { return b[o] | (b[o + 1] << 8); }
  function u32(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }

  function hashByName(name) {
    switch (String(name).toUpperCase().replace('-', '')) {
      case 'SHA1': return BinCrypto.sha1;
      case 'SHA256': return BinCrypto.sha256;
      case 'SHA384': return BinCrypto.sha384;
      case 'SHA512': return BinCrypto.sha512;
      default: return null;
    }
  }

  function utf16le(str) {
    var out = new Uint8Array(str.length * 2);
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      out[i * 2] = c & 0xff; out[i * 2 + 1] = (c >>> 8) & 0xff;
    }
    return out;
  }
  function le32(n) { return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]); }
  function concat(arrs) {
    var total = 0, i;
    for (i = 0; i < arrs.length; i++) total += arrs[i].length;
    var out = new Uint8Array(total), o = 0;
    for (i = 0; i < arrs.length; i++) { out.set(arrs[i], o); o += arrs[i].length; }
    return out;
  }
  function b64(str) {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    str = String(str).replace(/[^A-Za-z0-9+/]/g, '');
    var out = [];
    for (var i = 0; i < str.length; i += 4) {
      var n = (chars.indexOf(str[i]) << 18) | (chars.indexOf(str[i + 1]) << 12) |
        ((chars.indexOf(str[i + 2]) & 63) << 6) | (chars.indexOf(str[i + 3]) & 63);
      out.push((n >> 16) & 0xff);
      if (str[i + 2] !== undefined && i + 2 < str.length) out.push((n >> 8) & 0xff);
      if (str[i + 3] !== undefined && i + 3 < str.length) out.push(n & 0xff);
    }
    return new Uint8Array(out);
  }
  function bytesEqual(a, b, n) {
    for (var i = 0; i < n; i++) if (a[i] !== b[i]) return false;
    return true;
  }
  function err(code, message) { var e = new Error(message); e.code = code; return e; }

  // --- Agile encryption ------------------------------------------------------

  function attr(xml, name) {
    var m = xml.match(new RegExp(name + '="([^"]*)"'));
    return m ? m[1] : null;
  }

  function deriveAgileSpin(pw, salt, hashFn, spinCount) {
    var h = hashFn(concat([salt, utf16le(pw)]));
    for (var i = 0; i < spinCount; i++) h = hashFn(concat([le32(i), h]));
    return h;
  }
  function agileKey(hSpin, hashFn, blockKey, keyLen) {
    var h = hashFn(concat([hSpin, blockKey]));
    return fitKey(h, keyLen);
  }
  function fitKey(h, keyLen) {
    if (h.length >= keyLen) return h.subarray(0, keyLen);
    var out = new Uint8Array(keyLen).fill(0x36);
    out.set(h);
    return out;
  }

  function tryAgile(xml, encPackage, pw) {
    var keyDataXml = (xml.match(/<keyData[^>]*\/?>/) || [])[0] || '';
    var ekXml = (xml.match(/<[a-z]*:?encryptedKey[^>]*\/?>/) || [])[0] || '';
    if (!keyDataXml || !ekXml) return null;

    var kdHash = attr(keyDataXml, 'hashAlgorithm');
    var kdSalt = b64(attr(keyDataXml, 'saltValue'));
    var kdKeyBits = parseInt(attr(keyDataXml, 'keyBits'), 10);
    var kdBlock = parseInt(attr(keyDataXml, 'blockSize'), 10) || 16;

    var ekHashFn = hashByName(attr(ekXml, 'hashAlgorithm'));
    var kdHashFn = hashByName(kdHash);
    if (!ekHashFn || !kdHashFn) throw err('UNSUPPORTED', 'Unsupported Office encryption hash.');
    var ekSalt = b64(attr(ekXml, 'saltValue'));
    var ekKeyBits = parseInt(attr(ekXml, 'keyBits'), 10);
    var spin = parseInt(attr(ekXml, 'spinCount'), 10);
    var saltSize = parseInt(attr(ekXml, 'saltSize'), 10) || ekSalt.length;
    var encVerInput = b64(attr(ekXml, 'encryptedVerifierHashInput'));
    var encVerValue = b64(attr(ekXml, 'encryptedVerifierHashValue'));
    var encKeyValue = b64(attr(ekXml, 'encryptedKeyValue'));

    var ekKeyLen = ekKeyBits / 8;
    var hSpin = deriveAgileSpin(pw, ekSalt, ekHashFn, spin);

    var kVerIn = agileKey(hSpin, ekHashFn, BLOCK_VERIFIER_INPUT, ekKeyLen);
    var kVerVal = agileKey(hSpin, ekHashFn, BLOCK_VERIFIER_VALUE, ekKeyLen);
    var verInput = BinCrypto.aesCbcDecryptNoPad(kVerIn, ekSalt, encVerInput);
    var verValue = BinCrypto.aesCbcDecryptNoPad(kVerVal, ekSalt, encVerValue);
    var calc = ekHashFn(verInput.subarray(0, saltSize));
    if (!bytesEqual(calc, verValue, calc.length)) return null; // wrong password

    var kKey = agileKey(hSpin, ekHashFn, BLOCK_KEY_VALUE, ekKeyLen);
    var secretKey = BinCrypto.aesCbcDecryptNoPad(kKey, ekSalt, encKeyValue).subarray(0, kdKeyBits / 8);

    // Decrypt the package: 8-byte size prefix, then 4096-byte segments.
    var total = u32(encPackage, 0) + u32(encPackage, 4) * 0x100000000;
    var out = new Uint8Array(total);
    var segLen = 4096;
    var pos = 8, seg = 0, outPos = 0;
    while (pos < encPackage.length) {
      var chunk = encPackage.subarray(pos, pos + segLen);
      var iv = fitKey(kdHashFn(concat([kdSalt, le32(seg)])), kdBlock);
      var dec = BinCrypto.aesCbcDecryptNoPad(secretKey, iv, chunk);
      var n = Math.min(dec.length, total - outPos);
      out.set(dec.subarray(0, n), outPos);
      outPos += n; pos += segLen; seg++;
      if (outPos >= total) break;
    }
    return out;
  }

  // --- Standard encryption ---------------------------------------------------

  function tryStandard(info, encPackage, pw) {
    var headerSize = u32(info, 8);
    var hOff = 12;
    var algId = u32(info, hOff + 8);
    var keyBits = u32(info, hOff + 16);
    if (algId !== 0x660e && algId !== 0x660f && algId !== 0x6610) {
      throw err('UNSUPPORTED', 'Unsupported Office Standard cipher (only AES is supported).');
    }
    var keyLen = keyBits / 8;

    var vOff = 12 + headerSize;
    var saltSize = u32(info, vOff);
    var salt = info.subarray(vOff + 4, vOff + 4 + saltSize);
    var encVerifier = info.subarray(vOff + 4 + saltSize, vOff + 4 + saltSize + 16);
    var verifierHashSize = u32(info, vOff + 4 + saltSize + 16);
    var encVerifierHash = info.subarray(vOff + 4 + saltSize + 20, vOff + 4 + saltSize + 20 + 32);

    var sha1 = BinCrypto.sha1;
    var h = sha1(concat([salt, utf16le(pw)]));
    for (var i = 0; i < 50000; i++) h = sha1(concat([le32(i), h]));
    h = sha1(concat([h, le32(0)]));
    // Derive key (X1/X2 method).
    var b1 = new Uint8Array(64), b2 = new Uint8Array(64);
    for (var j = 0; j < 64; j++) { b1[j] = 0x36 ^ (j < h.length ? h[j] : 0); b2[j] = 0x5c ^ (j < h.length ? h[j] : 0); }
    var key = concat([sha1(b1), sha1(b2)]).subarray(0, keyLen);

    var verifier = ecbDecrypt(key, encVerifier);
    var verifierHash = ecbDecrypt(key, encVerifierHash);
    var calc = sha1(verifier);
    if (!bytesEqual(calc, verifierHash, Math.min(verifierHashSize, calc.length))) return null;

    var total = u32(encPackage, 0) + u32(encPackage, 4) * 0x100000000;
    var dec = ecbDecrypt(key, encPackage.subarray(8));
    return dec.subarray(0, total);
  }

  function ecbDecrypt(key, data) {
    var out = new Uint8Array(data.length - (data.length % 16));
    for (var off = 0; off + 16 <= data.length; off += 16) {
      out.set(BinCrypto.aesEcbDecryptBlock(key, data.subarray(off, off + 16)), off);
    }
    return out;
  }

  // --- entry point -----------------------------------------------------------

  /**
   * If `bytes` is an ECMA-376 encrypted Office package, attempt to decrypt it
   * with the default passwords.
   * @returns {Uint8Array|null} decrypted inner ZIP, or null if not such a package
   * @throws {Error} code 'ENCRYPTED' if encrypted but no default password works
   */
  function tryDecrypt(bytes) {
    if (!Ole2 || !Ole2.isOle2(bytes)) return null;
    var cfb;
    try { cfb = Ole2.parse(bytes); } catch { return null; }
    var info = cfb.readStream('EncryptionInfo');
    var pkg = cfb.readStream('EncryptedPackage');
    if (!info || !pkg) return null;

    var verMajor = u16(info, 0);
    var verMinor = u16(info, 2);
    var isAgile = verMajor === 4 && verMinor === 4;

    for (var i = 0; i < DEFAULT_PASSWORDS.length; i++) {
      var pw = DEFAULT_PASSWORDS[i];
      var result;
      if (isAgile) {
        var xml = '';
        for (var k = 8; k < info.length; k++) xml += String.fromCharCode(info[k]);
        result = tryAgile(xml, pkg, pw);
      } else {
        result = tryStandard(info, pkg, pw);
      }
      if (result) return result;
    }
    throw err('ENCRYPTED', 'This file is encrypted with an "open password" and cannot be unlocked without it.');
  }

  return { tryDecrypt: tryDecrypt, DEFAULT_PASSWORDS: DEFAULT_PASSWORDS };
});
