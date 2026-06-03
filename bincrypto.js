/*
 * Small, dependency-free binary crypto primitives used by the PDF unlocker.
 *
 * The PDF "Standard Security Handler" needs MD5, RC4 and AES-128-CBC to derive
 * keys and decrypt strings/streams. None of these are available synchronously
 * across both Node and the browser (Web Crypto has no MD5/RC4 and is async), so
 * we ship compact, self-contained implementations and verify them against
 * published test vectors in the test suite.
 *
 * UMD style: works as `require('./bincrypto.js')` in Node and as the global
 * `window.BinCrypto` in the browser.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.BinCrypto = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // --- MD5 -----------------------------------------------------------------
  // Compact, standard RFC 1321 implementation operating on byte arrays.

  function md5(bytes) {
    var msg = bytes;
    var n = msg.length;

    function rotl(x, c) { return (x << c) | (x >>> (32 - c)); }
    function add(a, b) { return (a + b) & 0xffffffff; }

    // Pre-processing: append 0x80, pad with zeros, append 64-bit length.
    var withOne = n + 1;
    var padded = Math.ceil((withOne + 8) / 64) * 64;
    var buf = new Uint8Array(padded);
    buf.set(msg);
    buf[n] = 0x80;
    var bitLen = n * 8;
    // little-endian 64-bit length (low 32 bits + high 32 bits)
    buf[padded - 8] = bitLen & 0xff;
    buf[padded - 7] = (bitLen >>> 8) & 0xff;
    buf[padded - 6] = (bitLen >>> 16) & 0xff;
    buf[padded - 5] = (bitLen >>> 24) & 0xff;
    var hi = Math.floor(n / 0x20000000); // n*8 high bits
    buf[padded - 4] = hi & 0xff;
    buf[padded - 3] = (hi >>> 8) & 0xff;
    buf[padded - 2] = (hi >>> 16) & 0xff;
    buf[padded - 1] = (hi >>> 24) & 0xff;

    var s = [
      7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
      5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    ];
    var K = [];
    for (var i = 0; i < 64; i++) {
      K[i] = (Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296)) & 0xffffffff;
    }

    var a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;

    for (var off = 0; off < padded; off += 64) {
      var M = new Array(16);
      for (var j = 0; j < 16; j++) {
        M[j] = buf[off + j * 4] | (buf[off + j * 4 + 1] << 8) |
          (buf[off + j * 4 + 2] << 16) | (buf[off + j * 4 + 3] << 24);
      }
      var A = a0, B = b0, C = c0, D = d0;
      for (var k = 0; k < 64; k++) {
        var F, g;
        if (k < 16) { F = (B & C) | (~B & D); g = k; }
        else if (k < 32) { F = (D & B) | (~D & C); g = (5 * k + 1) % 16; }
        else if (k < 48) { F = B ^ C ^ D; g = (3 * k + 5) % 16; }
        else { F = C ^ (B | ~D); g = (7 * k) % 16; }
        F = add(add(add(F, A), K[k]), M[g]);
        A = D; D = C; C = B;
        B = add(B, rotl(F, s[k]));
      }
      a0 = add(a0, A); b0 = add(b0, B); c0 = add(c0, C); d0 = add(d0, D);
    }

    var out = new Uint8Array(16);
    var words = [a0, b0, c0, d0];
    for (var w = 0; w < 4; w++) {
      out[w * 4] = words[w] & 0xff;
      out[w * 4 + 1] = (words[w] >>> 8) & 0xff;
      out[w * 4 + 2] = (words[w] >>> 16) & 0xff;
      out[w * 4 + 3] = (words[w] >>> 24) & 0xff;
    }
    return out;
  }

  // --- RC4 -----------------------------------------------------------------

  function rc4(key, data) {
    var S = new Uint8Array(256);
    for (var i = 0; i < 256; i++) S[i] = i;
    var j = 0;
    for (i = 0; i < 256; i++) {
      j = (j + S[i] + key[i % key.length]) & 0xff;
      var t = S[i]; S[i] = S[j]; S[j] = t;
    }
    var out = new Uint8Array(data.length);
    i = 0; j = 0;
    for (var k = 0; k < data.length; k++) {
      i = (i + 1) & 0xff;
      j = (j + S[i]) & 0xff;
      var tmp = S[i]; S[i] = S[j]; S[j] = tmp;
      out[k] = data[k] ^ S[(S[i] + S[j]) & 0xff];
    }
    return out;
  }

  // --- AES (decryption only, 128/256-bit, CBC) -----------------------------
  // Table-driven inverse cipher per FIPS-197. Verified against the FIPS-197
  // single-block known-answer test in the test suite.

  var SBOX = (function () {
    var p = 1, q = 1, sbox = new Uint8Array(256);
    do {
      // multiply p by 3
      p = p ^ (p << 1) ^ (p & 0x80 ? 0x11b : 0);
      p &= 0xff;
      // divide q by 3 (multiply by 0xf6)
      q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff;
      if (q & 0x80) q ^= 0x09;
      var xformed = q ^ ((q << 1) | (q >>> 7)) ^ ((q << 2) | (q >>> 6)) ^
        ((q << 3) | (q >>> 5)) ^ ((q << 4) | (q >>> 4));
      sbox[p] = (xformed ^ 0x63) & 0xff;
    } while (p !== 1);
    sbox[0] = 0x63;
    return sbox;
  })();

  var INV_SBOX = (function () {
    var inv = new Uint8Array(256);
    for (var i = 0; i < 256; i++) inv[SBOX[i]] = i;
    return inv;
  })();

  function mul(a, b) {
    var r = 0;
    for (var i = 0; i < 8; i++) {
      if (b & 1) r ^= a;
      var hi = a & 0x80;
      a = (a << 1) & 0xff;
      if (hi) a ^= 0x1b;
      b >>= 1;
    }
    return r & 0xff;
  }

  var RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x6c, 0xd8, 0xab, 0x4d];

  function keyExpansion(key) {
    var Nk = key.length / 4;       // 4 (128) or 8 (256)
    var Nr = Nk + 6;               // 10 or 14
    var totalWords = 4 * (Nr + 1);
    var w = new Array(totalWords);
    for (var i = 0; i < Nk; i++) {
      w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
    }
    for (i = Nk; i < totalWords; i++) {
      var temp = w[i - 1].slice();
      if (i % Nk === 0) {
        // rotword
        var t0 = temp[0]; temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t0;
        // subword
        for (var b = 0; b < 4; b++) temp[b] = SBOX[temp[b]];
        temp[0] ^= RCON[(i / Nk) - 1];
      } else if (Nk > 6 && i % Nk === 4) {
        for (b = 0; b < 4; b++) temp[b] = SBOX[temp[b]];
      }
      w[i] = [
        w[i - Nk][0] ^ temp[0],
        w[i - Nk][1] ^ temp[1],
        w[i - Nk][2] ^ temp[2],
        w[i - Nk][3] ^ temp[3]
      ];
    }
    return { w: w, Nr: Nr };
  }

  function decryptBlock(block, ks) {
    var Nr = ks.Nr, w = ks.w;
    // state is column-major: s[r][c]
    var s = [[], [], [], []];
    for (var c = 0; c < 4; c++) {
      for (var r = 0; r < 4; r++) s[r][c] = block[c * 4 + r];
    }
    function addRoundKey(round) {
      for (var col = 0; col < 4; col++) {
        var word = w[round * 4 + col];
        for (var row = 0; row < 4; row++) s[row][col] ^= word[row];
      }
    }
    function invShiftRows() {
      for (var row = 1; row < 4; row++) {
        var tmp = [s[row][0], s[row][1], s[row][2], s[row][3]];
        for (var col = 0; col < 4; col++) s[row][col] = tmp[(col - row + 4) % 4];
      }
    }
    function invSubBytes() {
      for (var row = 0; row < 4; row++)
        for (var col = 0; col < 4; col++) s[row][col] = INV_SBOX[s[row][col]];
    }
    function invMixColumns() {
      for (var col = 0; col < 4; col++) {
        var a0 = s[0][col], a1 = s[1][col], a2 = s[2][col], a3 = s[3][col];
        s[0][col] = mul(a0, 14) ^ mul(a1, 11) ^ mul(a2, 13) ^ mul(a3, 9);
        s[1][col] = mul(a0, 9) ^ mul(a1, 14) ^ mul(a2, 11) ^ mul(a3, 13);
        s[2][col] = mul(a0, 13) ^ mul(a1, 9) ^ mul(a2, 14) ^ mul(a3, 11);
        s[3][col] = mul(a0, 11) ^ mul(a1, 13) ^ mul(a2, 9) ^ mul(a3, 14);
      }
    }

    addRoundKey(Nr);
    for (var round = Nr - 1; round >= 1; round--) {
      invShiftRows();
      invSubBytes();
      addRoundKey(round);
      invMixColumns();
    }
    invShiftRows();
    invSubBytes();
    addRoundKey(0);

    var out = new Uint8Array(16);
    for (c = 0; c < 4; c++)
      for (r = 0; r < 4; r++) out[c * 4 + r] = s[r][c];
    return out;
  }

  /**
   * AES-CBC decrypt. The IV is the first 16 bytes of `data` (as used by the
   * PDF AESV2/AESV3 security handlers). Returns the plaintext with PKCS#7
   * padding removed.
   */
  function aesCbcDecrypt(key, data) {
    if (data.length < 32 || data.length % 16 !== 0) {
      // Not a valid AES-CBC payload; return as-is to avoid throwing on odd data.
      return data.slice(0);
    }
    var ks = keyExpansion(key);
    var iv = data.subarray(0, 16);
    var out = new Uint8Array(data.length - 16);
    var prev = iv;
    for (var off = 16; off < data.length; off += 16) {
      var ct = data.subarray(off, off + 16);
      var pt = decryptBlock(ct, ks);
      for (var i = 0; i < 16; i++) out[off - 16 + i] = pt[i] ^ prev[i];
      prev = ct;
    }
    // Strip PKCS#7 padding.
    var pad = out[out.length - 1];
    if (pad >= 1 && pad <= 16 && pad <= out.length) {
      return out.subarray(0, out.length - pad);
    }
    return out;
  }

  return {
    md5: md5,
    rc4: rc4,
    aesCbcDecrypt: aesCbcDecrypt,
    _decryptBlockForTest: function (block, key) {
      return decryptBlock(block, keyExpansion(key));
    }
  };
});
