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

  function encryptBlock(block, ks) {
    var Nr = ks.Nr, w = ks.w;
    var s = [[], [], [], []];
    for (var c = 0; c < 4; c++) for (var r = 0; r < 4; r++) s[r][c] = block[c * 4 + r];
    function addRoundKey(round) {
      for (var col = 0; col < 4; col++) {
        var word = w[round * 4 + col];
        for (var row = 0; row < 4; row++) s[row][col] ^= word[row];
      }
    }
    function subBytes() {
      for (var row = 0; row < 4; row++) for (var col = 0; col < 4; col++) s[row][col] = SBOX[s[row][col]];
    }
    function shiftRows() {
      for (var row = 1; row < 4; row++) {
        var tmp = [s[row][0], s[row][1], s[row][2], s[row][3]];
        for (var col = 0; col < 4; col++) s[row][col] = tmp[(col + row) % 4];
      }
    }
    function mixColumns() {
      for (var col = 0; col < 4; col++) {
        var a0 = s[0][col], a1 = s[1][col], a2 = s[2][col], a3 = s[3][col];
        s[0][col] = mul(a0, 2) ^ mul(a1, 3) ^ a2 ^ a3;
        s[1][col] = a0 ^ mul(a1, 2) ^ mul(a2, 3) ^ a3;
        s[2][col] = a0 ^ a1 ^ mul(a2, 2) ^ mul(a3, 3);
        s[3][col] = mul(a0, 3) ^ a1 ^ a2 ^ mul(a3, 2);
      }
    }
    addRoundKey(0);
    for (var round = 1; round < Nr; round++) { subBytes(); shiftRows(); mixColumns(); addRoundKey(round); }
    subBytes(); shiftRows(); addRoundKey(Nr);
    var out = new Uint8Array(16);
    for (c = 0; c < 4; c++) for (r = 0; r < 4; r++) out[c * 4 + r] = s[r][c];
    return out;
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

  // CBC with an explicit IV and no padding (used by the PDF R6 key derivation).
  function aesCbcEncryptNoPad(key, iv, data) {
    var ks = keyExpansion(key);
    var out = new Uint8Array(data.length);
    var prev = iv;
    for (var off = 0; off < data.length; off += 16) {
      var blk = new Uint8Array(16);
      for (var i = 0; i < 16; i++) blk[i] = data[off + i] ^ prev[i];
      var ct = encryptBlock(blk, ks);
      out.set(ct, off);
      prev = ct;
    }
    return out;
  }
  function aesCbcDecryptNoPad(key, iv, data) {
    var ks = keyExpansion(key);
    var out = new Uint8Array(data.length);
    var prev = iv;
    for (var off = 0; off < data.length; off += 16) {
      var ct = data.subarray(off, off + 16);
      var pt = decryptBlock(ct, ks);
      for (var i = 0; i < 16; i++) out[off + i] = pt[i] ^ prev[i];
      prev = ct;
    }
    return out;
  }

  // --- SHA-256 -------------------------------------------------------------

  var SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);

  function sha256(msg) {
    var H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    var ml = msg.length;
    var withOne = ml + 1;
    var total = Math.ceil((withOne + 8) / 64) * 64;
    var buf = new Uint8Array(total);
    buf.set(msg);
    buf[ml] = 0x80;
    var bits = ml * 8;
    for (var b = 0; b < 4; b++) buf[total - 1 - b] = (bits >>> (8 * b)) & 0xff;
    var hi = Math.floor(ml / 0x20000000);
    for (b = 0; b < 4; b++) buf[total - 5 - b] = (hi >>> (8 * b)) & 0xff;

    var w = new Uint32Array(64);
    function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
    for (var off = 0; off < total; off += 64) {
      for (var t = 0; t < 16; t++) {
        w[t] = (buf[off + t * 4] << 24) | (buf[off + t * 4 + 1] << 16) | (buf[off + t * 4 + 2] << 8) | buf[off + t * 4 + 3];
      }
      for (t = 16; t < 64; t++) {
        var s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
        var s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
      }
      var a = H[0], c2 = H[1], d2 = H[2], e2 = H[3], f2 = H[4], g2 = H[5], h2 = H[6], i2 = H[7];
      for (t = 0; t < 64; t++) {
        var S1 = rotr(f2, 6) ^ rotr(f2, 11) ^ rotr(f2, 25);
        var ch = (f2 & g2) ^ (~f2 & h2);
        var temp1 = (i2 + S1 + ch + SHA256_K[t] + w[t]) | 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & c2) ^ (a & d2) ^ (c2 & d2);
        var temp2 = (S0 + maj) | 0;
        i2 = h2; h2 = g2; g2 = f2; f2 = (e2 + temp1) | 0; e2 = d2; d2 = c2; c2 = a; a = (temp1 + temp2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + c2) | 0; H[2] = (H[2] + d2) | 0; H[3] = (H[3] + e2) | 0;
      H[4] = (H[4] + f2) | 0; H[5] = (H[5] + g2) | 0; H[6] = (H[6] + h2) | 0; H[7] = (H[7] + i2) | 0;
    }
    var out = new Uint8Array(32);
    for (var k = 0; k < 8; k++) {
      out[k * 4] = (H[k] >>> 24) & 0xff; out[k * 4 + 1] = (H[k] >>> 16) & 0xff;
      out[k * 4 + 2] = (H[k] >>> 8) & 0xff; out[k * 4 + 3] = H[k] & 0xff;
    }
    return out;
  }

  // --- SHA-512 / SHA-384 (BigInt; only used in the PDF R6 derivation) -------

  var MASK64 = (1n << 64n) - 1n;
  var SHA512_K = [
    '428a2f98d728ae22', '7137449123ef65cd', 'b5c0fbcfec4d3b2f', 'e9b5dba58189dbbc', '3956c25bf348b538', '59f111f1b605d019', '923f82a4af194f9b', 'ab1c5ed5da6d8118',
    'd807aa98a3030242', '12835b0145706fbe', '243185be4ee4b28c', '550c7dc3d5ffb4e2', '72be5d74f27b896f', '80deb1fe3b1696b1', '9bdc06a725c71235', 'c19bf174cf692694',
    'e49b69c19ef14ad2', 'efbe4786384f25e3', '0fc19dc68b8cd5b5', '240ca1cc77ac9c65', '2de92c6f592b0275', '4a7484aa6ea6e483', '5cb0a9dcbd41fbd4', '76f988da831153b5',
    '983e5152ee66dfab', 'a831c66d2db43210', 'b00327c898fb213f', 'bf597fc7beef0ee4', 'c6e00bf33da88fc2', 'd5a79147930aa725', '06ca6351e003826f', '142929670a0e6e70',
    '27b70a8546d22ffc', '2e1b21385c26c926', '4d2c6dfc5ac42aed', '53380d139d95b3df', '650a73548baf63de', '766a0abb3c77b2a8', '81c2c92e47edaee6', '92722c851482353b',
    'a2bfe8a14cf10364', 'a81a664bbc423001', 'c24b8b70d0f89791', 'c76c51a30654be30', 'd192e819d6ef5218', 'd69906245565a910', 'f40e35855771202a', '106aa07032bbd1b8',
    '19a4c116b8d2d0c8', '1e376c085141ab53', '2748774cdf8eeb99', '34b0bcb5e19b48a8', '391c0cb3c5c95a63', '4ed8aa4ae3418acb', '5b9cca4f7763e373', '682e6ff3d6b2b8a3',
    '748f82ee5defb2fc', '78a5636f43172f60', '84c87814a1f0ab72', '8cc702081a6439ec', '90befffa23631e28', 'a4506cebde82bde9', 'bef9a3f7b2c67915', 'c67178f2e372532b',
    'ca273eceea26619c', 'd186b8c721c0c207', 'eada7dd6cde0eb1e', 'f57d4f7fee6ed178', '06f067aa72176fba', '0a637dc5a2c898a6', '113f9804bef90dae', '1b710b35131c471b',
    '28db77f523047d84', '32caab7b40c72493', '3c9ebe0a15c9bebc', '431d67c49c100d4c', '4cc5d4becb3e42b6', '597f299cfc657e2a', '5fcb6fab3ad6faec', '6c44198c4a475817'
  ].map(function (h) { return BigInt('0x' + h); });

  function sha512core(msg, H) {
    function rotr(x, n) { return ((x >> n) | (x << (64n - n))) & MASK64; }
    var ml = msg.length;
    var withOne = ml + 1;
    var total = Math.ceil((withOne + 16) / 128) * 128;
    var buf = new Uint8Array(total);
    buf.set(msg);
    buf[ml] = 0x80;
    var bits = BigInt(ml) * 8n;
    for (var b = 0; b < 8; b++) buf[total - 1 - b] = Number((bits >> BigInt(8 * b)) & 0xffn);

    var w = new Array(80);
    for (var off = 0; off < total; off += 128) {
      for (var t = 0; t < 16; t++) {
        var v = 0n;
        for (var j = 0; j < 8; j++) v = (v << 8n) | BigInt(buf[off + t * 8 + j]);
        w[t] = v;
      }
      for (t = 16; t < 80; t++) {
        var s0 = rotr(w[t - 15], 1n) ^ rotr(w[t - 15], 8n) ^ (w[t - 15] >> 7n);
        var s1 = rotr(w[t - 2], 19n) ^ rotr(w[t - 2], 61n) ^ (w[t - 2] >> 6n);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & MASK64;
      }
      var a = H[0], c2 = H[1], d2 = H[2], e2 = H[3], f2 = H[4], g2 = H[5], h2 = H[6], i2 = H[7];
      for (t = 0; t < 80; t++) {
        var S1 = rotr(f2, 14n) ^ rotr(f2, 18n) ^ rotr(f2, 41n);
        var ch = (f2 & g2) ^ (~f2 & MASK64 & h2);
        var temp1 = (i2 + S1 + ch + SHA512_K[t] + w[t]) & MASK64;
        var S0 = rotr(a, 28n) ^ rotr(a, 34n) ^ rotr(a, 39n);
        var maj = (a & c2) ^ (a & d2) ^ (c2 & d2);
        var temp2 = (S0 + maj) & MASK64;
        i2 = h2; h2 = g2; g2 = f2; f2 = (e2 + temp1) & MASK64; e2 = d2; d2 = c2; c2 = a; a = (temp1 + temp2) & MASK64;
      }
      H[0] = (H[0] + a) & MASK64; H[1] = (H[1] + c2) & MASK64; H[2] = (H[2] + d2) & MASK64; H[3] = (H[3] + e2) & MASK64;
      H[4] = (H[4] + f2) & MASK64; H[5] = (H[5] + g2) & MASK64; H[6] = (H[6] + h2) & MASK64; H[7] = (H[7] + i2) & MASK64;
    }
    var out = new Uint8Array(H.length * 8);
    for (var k = 0; k < H.length; k++) {
      for (b = 0; b < 8; b++) out[k * 8 + b] = Number((H[k] >> BigInt(56 - 8 * b)) & 0xffn);
    }
    return out;
  }
  function sha512(msg) {
    return sha512core(msg, [
      0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
      0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n]);
  }
  function sha384(msg) {
    return sha512core(msg, [
      0xcbbb9d5dc1059ed8n, 0x629a292a367cd507n, 0x9159015a3070dd17n, 0x152fecd8f70e5939n,
      0x67332667ffc00b31n, 0x8eb44a8768581511n, 0xdb0c2e0d64f98fa7n, 0x47b5481dbefa4fa4n]).subarray(0, 48);
  }

  return {
    md5: md5,
    rc4: rc4,
    aesCbcDecrypt: aesCbcDecrypt,
    aesCbcEncryptNoPad: aesCbcEncryptNoPad,
    aesCbcDecryptNoPad: aesCbcDecryptNoPad,
    sha256: sha256,
    sha384: sha384,
    sha512: sha512,
    _decryptBlockForTest: function (block, key) {
      return decryptBlock(block, keyExpansion(key));
    },
    _encryptBlockForTest: function (block, key) {
      return encryptBlock(block, keyExpansion(key));
    }
  };
});
