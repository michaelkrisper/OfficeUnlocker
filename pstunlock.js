/*
 * Outlook PST unlocker — removes the password from .pst (and .ost-style) files.
 *
 * Unlike full-file encryption, a PST "password" does NOT encrypt the mail data.
 * Outlook merely stores a CRC-32 of the password as the property
 * PidTagPstPassword (0x67FF) in the message store and refuses to open the file
 * unless the entered password hashes to the same value. Setting that property
 * to 0 removes the password entirely — no knowledge of the password required.
 *
 * This module parses just enough of the MS-PST Node/Block B-tree structures to
 * locate the message store's property context, zeroes the password property,
 * re-applies the file's data encoding and fixes the block CRC.
 *
 * Supports both ANSI (Outlook 97–2002) and Unicode (Outlook 2003+) PSTs, with
 * the "none" and "compressible" (permute) data encodings. The rarely used
 * "high" (cyclic) encoding is reported as unsupported rather than guessed at.
 *
 * Constant tables (the permute table and the CRC polynomial) are factual values
 * from Microsoft's open [MS-PST] specification.
 *
 * UMD: `require('./pstunlock.js')` in Node, `window.PstUnlock` in the browser.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PstUnlock = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var PROP_PST_PASSWORD = 0x67ff;
  var NID_MESSAGE_STORE = 0x21;

  // NDB_CRYPT methods (HEADER.bCryptMethod). 0x00 = none (handled implicitly).
  var CRYPT_PERMUTE = 0x01;
  var CRYPT_CYCLIC = 0x02;

  // Permute / "compressible" decode table from [MS-PST] 5.1. decode[e] = plain.
  var PERMUTE_DECODE = new Uint8Array([
    71, 241, 180, 230, 11, 106, 114, 72, 133, 78, 158, 235, 226, 248, 148, 83,
    224, 187, 160, 2, 232, 90, 9, 171, 219, 227, 186, 198, 124, 195, 16, 221,
    57, 5, 150, 48, 245, 55, 96, 130, 140, 201, 19, 74, 107, 29, 243, 251,
    143, 38, 151, 202, 145, 23, 1, 196, 50, 45, 110, 49, 149, 255, 217, 35,
    209, 0, 94, 121, 220, 68, 59, 26, 40, 197, 97, 87, 32, 144, 61, 131,
    185, 67, 190, 103, 210, 70, 66, 118, 192, 109, 91, 126, 178, 15, 22, 41,
    60, 169, 3, 84, 13, 218, 93, 223, 246, 183, 199, 98, 205, 141, 6, 211,
    105, 92, 134, 214, 20, 247, 165, 102, 117, 172, 177, 233, 69, 33, 112, 12,
    135, 159, 116, 164, 34, 76, 111, 191, 31, 86, 170, 46, 179, 120, 51, 80,
    176, 163, 146, 188, 207, 25, 28, 167, 99, 203, 30, 77, 62, 75, 27, 155,
    79, 231, 240, 238, 173, 58, 181, 89, 4, 234, 64, 85, 37, 81, 229, 122,
    137, 56, 104, 82, 123, 252, 39, 174, 215, 189, 250, 7, 244, 204, 142, 95,
    239, 53, 156, 132, 43, 21, 213, 119, 52, 73, 182, 18, 10, 127, 113, 136,
    253, 157, 24, 65, 125, 147, 216, 88, 44, 206, 254, 36, 175, 222, 184, 54,
    200, 161, 128, 166, 153, 152, 168, 47, 14, 129, 101, 115, 228, 194, 162, 138,
    212, 225, 17, 208, 8, 139, 42, 242, 237, 154, 100, 63, 193, 108, 249, 236
  ]);
  var PERMUTE_ENCODE = (function () {
    var enc = new Uint8Array(256);
    for (var e = 0; e < 256; e++) enc[PERMUTE_DECODE[e]] = e;
    return enc;
  })();

  // "High" (cyclic) encoding tables from [MS-PST] 5.2.
  var HIGH1 = new Uint8Array([
    65, 54, 19, 98, 168, 33, 110, 187, 244, 22, 204, 4, 127, 100, 232, 93, 30, 242, 203, 42, 116, 197, 94, 53, 210, 149, 71, 158, 150, 45, 154, 136,
    76, 125, 132, 63, 219, 172, 49, 182, 72, 95, 246, 196, 216, 57, 139, 231, 35, 59, 56, 142, 200, 193, 223, 37, 177, 32, 165, 70, 96, 78, 156, 251,
    170, 211, 86, 81, 69, 124, 85, 0, 7, 201, 43, 157, 133, 155, 9, 160, 143, 173, 179, 15, 99, 171, 137, 75, 215, 167, 21, 90, 113, 102, 66, 191,
    38, 74, 107, 152, 250, 234, 119, 83, 178, 112, 5, 44, 253, 89, 58, 134, 126, 206, 6, 235, 130, 120, 87, 199, 141, 67, 175, 180, 28, 212, 91, 205,
    226, 233, 39, 79, 195, 8, 114, 128, 207, 176, 239, 245, 40, 109, 190, 48, 77, 52, 146, 213, 14, 60, 34, 50, 229, 228, 249, 159, 194, 209, 10, 129,
    18, 225, 238, 145, 131, 118, 227, 151, 230, 97, 138, 23, 121, 164, 183, 220, 144, 122, 92, 140, 2, 166, 202, 105, 222, 80, 26, 17, 147, 185, 82, 135,
    88, 252, 237, 29, 55, 73, 27, 106, 224, 41, 51, 153, 189, 108, 217, 148, 243, 64, 84, 111, 240, 198, 115, 184, 214, 62, 101, 24, 68, 31, 221, 103,
    16, 241, 12, 25, 236, 174, 3, 161, 20, 123, 169, 11, 255, 248, 163, 192, 162, 1, 247, 46, 188, 36, 104, 117, 13, 254, 186, 47, 181, 208, 218, 61]);
  var HIGH2 = new Uint8Array([
    20, 83, 15, 86, 179, 200, 122, 156, 235, 101, 72, 23, 22, 21, 159, 2, 204, 84, 124, 131, 0, 13, 12, 11, 162, 98, 168, 118, 219, 217, 237, 199,
    197, 164, 220, 172, 133, 116, 214, 208, 167, 155, 174, 154, 150, 113, 102, 195, 99, 153, 184, 221, 115, 146, 142, 132, 125, 165, 94, 209, 93, 147, 177, 87,
    81, 80, 128, 137, 82, 148, 79, 78, 10, 107, 188, 141, 127, 110, 71, 70, 65, 64, 68, 1, 17, 203, 3, 63, 247, 244, 225, 169, 143, 60, 58, 249,
    251, 240, 25, 48, 130, 9, 46, 201, 157, 160, 134, 73, 238, 111, 77, 109, 196, 45, 129, 52, 37, 135, 27, 136, 170, 252, 6, 161, 18, 56, 253, 76,
    66, 114, 100, 19, 55, 36, 106, 117, 119, 67, 255, 230, 180, 75, 54, 92, 228, 216, 53, 61, 69, 185, 44, 236, 183, 49, 43, 41, 7, 104, 163, 14,
    105, 123, 24, 158, 33, 57, 190, 40, 26, 91, 120, 245, 35, 202, 42, 176, 175, 62, 254, 4, 140, 231, 229, 152, 50, 149, 211, 246, 74, 232, 166, 234,
    233, 243, 213, 47, 112, 32, 242, 31, 5, 103, 173, 85, 16, 206, 205, 227, 39, 59, 218, 186, 215, 194, 38, 212, 145, 29, 210, 28, 34, 51, 248, 250,
    241, 90, 239, 207, 144, 182, 139, 181, 189, 192, 191, 8, 151, 30, 108, 226, 97, 224, 198, 193, 89, 171, 187, 88, 222, 95, 223, 96, 121, 126, 178, 138]);
  var HIGH1_INV = invert(HIGH1), HIGH2_INV = invert(HIGH2);
  function invert(table) {
    var inv = new Uint8Array(256);
    for (var i = 0; i < 256; i++) inv[table[i]] = i;
    return inv;
  }

  // [MS-PST] 5.3 "weak" CRC-32: polynomial 0xEDB88320, initial value 0, no final XOR.
  var CRC_TABLE = (function () {
    var table = new Uint32Array(256);
    for (var i = 0; i < 256; i++) {
      var c = i;
      for (var k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      table[i] = c >>> 0;
    }
    return table;
  })();
  function computeCrc(bytes, start, len) {
    var crc = 0;
    for (var i = 0; i < len; i++) {
      crc = (CRC_TABLE[(crc ^ bytes[start + i]) & 0xff] ^ (crc >>> 8)) >>> 0;
    }
    return crc >>> 0;
  }

  // Decode/encode a data block in place according to the file's crypt method.
  // `key` is the lower 32 bits of the block's BID (used by the cyclic cipher).
  function decodeBlock(buf, start, len, crypt, key) {
    var i, v;
    if (crypt === CRYPT_PERMUTE) {
      for (i = 0; i < len; i++) buf[start + i] = PERMUTE_DECODE[buf[start + i]];
    } else if (crypt === CRYPT_CYCLIC) {
      var salt = (((key >>> 16) & 0xffff) ^ (key & 0xffff)) & 0xffff;
      for (i = 0; i < len; i++) {
        var lo = salt & 0xff, hi = (salt >> 8) & 0xff;
        v = buf[start + i];
        v = HIGH1[(v + lo) & 0xff];
        v = HIGH2[(v + hi) & 0xff];
        v = PERMUTE_DECODE[(v - hi) & 0xff];
        buf[start + i] = (v - lo) & 0xff;
        salt = (salt + 1) & 0xffff;
      }
    }
  }
  function encodeBlock(buf, start, len, crypt, key) {
    var i, v;
    if (crypt === CRYPT_PERMUTE) {
      for (i = 0; i < len; i++) buf[start + i] = PERMUTE_ENCODE[buf[start + i]];
    } else if (crypt === CRYPT_CYCLIC) {
      var salt = (((key >>> 16) & 0xffff) ^ (key & 0xffff)) & 0xffff;
      for (i = 0; i < len; i++) {
        var lo = salt & 0xff, hi = (salt >> 8) & 0xff;
        v = buf[start + i];
        v = PERMUTE_ENCODE[(v + lo) & 0xff];
        v = HIGH2_INV[(v + hi) & 0xff];
        v = HIGH1_INV[(v - hi) & 0xff];
        buf[start + i] = (v - lo) & 0xff;
        salt = (salt + 1) & 0xffff;
      }
    }
  }

  function fail(code, message) { var e = new Error(message); e.code = code; return e; }

  // ---- little-endian readers ------------------------------------------------

  function u16(b, o) { return b[o] | (b[o + 1] << 8); }
  function u32(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }
  function u64(b, o) { return u32(b, o) + u32(b, o + 4) * 0x100000000; } // as Number (offsets/sizes)
  function bid64(b, o) {
    var lo = BigInt(u32(b, o)), hi = BigInt(u32(b, o + 4));
    return (hi << 32n) | lo;
  }

  function isPst(bytes) {
    return bytes && bytes.length >= 4 &&
      bytes[0] === 0x21 && bytes[1] === 0x42 && bytes[2] === 0x44 && bytes[3] === 0x4e; // "!BDN"
  }

  // ---- format description (ANSI vs Unicode) ---------------------------------

  function describe(bytes) {
    if (!isPst(bytes)) throw fail('PST_INVALID', 'This file is not a valid PST (missing "!BDN" signature).');
    var ver = u16(bytes, 0x0a);
    var unicode = ver >= 0x17;
    if (unicode) {
      return {
        unicode: true,
        crypt: bytes[0x201],
        nbtRoot: { bid: bid64(bytes, 0xd8), ib: u64(bytes, 0xe0) },
        bbtRoot: { bid: bid64(bytes, 0xe8), ib: u64(bytes, 0xf0) },
        brefSize: 16, bidSize: 8,
        nbtEntrySize: 32, bbtEntrySize: 24, btEntrySize: 24,
        pageTrailer: 16, cEntOff: 488, cbEntOff: 490, cLevelOff: 491,
        blockTrailer: 16
      };
    }
    // ANSI
    return {
      unicode: false,
      crypt: bytes[0x1cd],
      nbtRoot: { bid: BigInt(u32(bytes, 0xb8)), ib: u32(bytes, 0xbc) },
      bbtRoot: { bid: BigInt(u32(bytes, 0xc0)), ib: u32(bytes, 0xc4) },
      brefSize: 8, bidSize: 4,
      nbtEntrySize: 16, bbtEntrySize: 12, btEntrySize: 12,
      pageTrailer: 12, cEntOff: 492, cbEntOff: 494, cLevelOff: 495,
      blockTrailer: 12
    };
  }

  // ---- B-tree walking --------------------------------------------------------

  function pageEntries(bytes, ib, fmt) {
    var cEnt = bytes[ib + fmt.cEntOff];
    var cbEnt = bytes[ib + fmt.cbEntOff];
    var cLevel = bytes[ib + fmt.cLevelOff];
    return { cEnt: cEnt, cbEnt: cbEnt, cLevel: cLevel, base: ib };
  }

  // Find the data BID for a given NID by walking the Node B-tree.
  function findNodeBid(bytes, root, nid, fmt) {
    var ib = root.ib;
    var guard = 0;
    while (guard++ < 64) {
      var pg = pageEntries(bytes, ib, fmt);
      if (pg.cLevel === 0) {
        // Leaf: NBTENTRYs.
        for (var i = 0; i < pg.cEnt; i++) {
          var off = ib + i * pg.cbEnt;
          var entryNid = fmt.unicode ? u32(bytes, off) : u32(bytes, off);
          if ((entryNid & 0xffffffff) === nid) {
            var bidOff = off + (fmt.unicode ? 8 : 4);
            return fmt.unicode ? bid64(bytes, bidOff) : BigInt(u32(bytes, bidOff));
          }
        }
        return null;
      }
      // Intermediate: BTENTRYs (btkey + BREF). Descend by key.
      var childIb = null, bestKey = -1n;
      for (var j = 0; j < pg.cEnt; j++) {
        var eoff = ib + j * pg.cbEnt;
        var key = fmt.unicode ? bid64(bytes, eoff) : BigInt(u32(bytes, eoff));
        var brefOff = eoff + (fmt.unicode ? 8 : 4);
        var keyTarget = BigInt(nid >>> 0);
        if (key <= keyTarget && key >= bestKey) {
          bestKey = key;
          childIb = fmt.unicode ? u64(bytes, brefOff + 8) : u32(bytes, brefOff + 4);
        }
      }
      if (childIb === null) return null;
      ib = childIb;
    }
    return null;
  }

  // Find the on-disk location (ib) and size (cb) of a block by its BID.
  function findBlock(bytes, root, bid, fmt) {
    var target = bid & ~1n; // ignore the reserved low bit when matching
    var ib = root.ib;
    var guard = 0;
    while (guard++ < 64) {
      var pg = pageEntries(bytes, ib, fmt);
      if (pg.cLevel === 0) {
        for (var i = 0; i < pg.cEnt; i++) {
          var off = ib + i * pg.cbEnt;
          var entryBid = (fmt.unicode ? bid64(bytes, off) : BigInt(u32(bytes, off))) & ~1n;
          if (entryBid === target) {
            var ibOff = off + (fmt.unicode ? 8 : 4);
            var cbOff = off + fmt.brefSize;
            return {
              ib: fmt.unicode ? u64(bytes, ibOff) : u32(bytes, ibOff),
              cb: u16(bytes, cbOff)
            };
          }
        }
        return null;
      }
      var childIb = null, bestKey = -1n;
      for (var j = 0; j < pg.cEnt; j++) {
        var eoff = ib + j * pg.cbEnt;
        var key = (fmt.unicode ? bid64(bytes, eoff) : BigInt(u32(bytes, eoff))) & ~1n;
        var brefOff = eoff + (fmt.unicode ? 8 : 4);
        if (key <= target && key >= bestKey) {
          bestKey = key;
          childIb = fmt.unicode ? u64(bytes, brefOff + 8) : u32(bytes, brefOff + 4);
        }
      }
      if (childIb === null) return null;
      ib = childIb;
    }
    return null;
  }

  // ---- Heap-on-Node / Property Context --------------------------------------

  function decodeDataBlock(bytes, loc, bid, fmt) {
    var decoded = bytes.subarray(loc.ib, loc.ib + loc.cb).slice();
    decodeBlock(decoded, 0, loc.cb, fmt.crypt, Number(bid & 0xffffffffn));
    return [{ ib: loc.ib, cb: loc.cb, bid: bid, decoded: decoded }];
  }

  function collectInternalBlocks(bytes, loc, fmt, depth) {
    var raw = bytes.subarray(loc.ib, loc.ib + loc.cb);
    if (raw[0] !== 0x01) return null;                  // btype must be 0x01
    var cEnt = u16(raw, 2);
    var leaves = [];
    for (var i = 0; i < cEnt; i++) {
      var off = 8 + i * fmt.bidSize;
      var childBid = fmt.unicode ? bid64(raw, off) : BigInt(u32(raw, off));
      var sub = collectDataBlocks(bytes, childBid, fmt, depth + 1);
      if (!sub) return null;
      leaves = leaves.concat(sub);
    }
    return leaves;
  }

  // Collect the leaf data blocks backing a node's data BID. A plain data block
  // yields one entry; an internal block (XBLOCK / XXBLOCK) is walked recursively
  // so multi-block message stores are reassembled. Each entry carries the
  // block's decoded payload (internal blocks themselves are never encoded).
  function collectDataBlocks(bytes, bid, fmt, depth) {
    if (depth > 8) return null;
    var loc = findBlock(bytes, fmt.bbtRoot, bid, fmt);
    if (!loc) return null;
    if ((bid & 2n) !== 2n) {
      return decodeDataBlock(bytes, loc, bid, fmt);
    }
    return collectInternalBlocks(bytes, loc, fmt, depth);
  }

  // Resolve a HID to its location within a (possibly multi-block) heap. Honours
  // the HID's block index so heaps spread over several blocks work.
  function resolveHid(blocks, hid) {
    if ((hid & 0x1f) !== 0) return null;               // not a HID
    var hidIndex = (hid >>> 5) & 0x7ff;
    if (hidIndex === 0) return null;
    var blockIdx = (hid >>> 16) & 0xffff;              // hidBlockIndex
    if (blockIdx >= blocks.length) return null;
    var buf = blocks[blockIdx].decoded;
    var ibHnpm = u16(buf, 0);                           // HNHDR / HNPAGEHDR
    var cAlloc = u16(buf, ibHnpm);
    if (hidIndex > cAlloc) return null;
    var rgibAlloc = ibHnpm + 4;
    return {
      blockIdx: blockIdx, buf: buf,
      start: u16(buf, rgibAlloc + (hidIndex - 1) * 2),
      end: u16(buf, rgibAlloc + hidIndex * 2)
    };
  }

  // Locate the PidTagPstPassword record in the message-store PC. Returns
  // { blockIdx, offset } pointing at its 4-byte value, or null.
  function findPasswordValueOffset(blocks) {
    var buf0 = blocks[0].decoded;
    if (buf0[2] !== 0xec) return null;                 // HNHDR.bSig must be 0xEC
    var hidUserRoot = u32(buf0, 4);                    // -> BTHHEADER
    var hdr = resolveHid(blocks, hidUserRoot);
    if (!hdr) return null;
    var hb = hdr.buf;
    var bType = hb[hdr.start];
    var cbKey = hb[hdr.start + 1];
    var cbEnt = hb[hdr.start + 2];
    var bIdxLevels = hb[hdr.start + 3];
    var hidRoot = u32(hb, hdr.start + 4);
    if (bType !== 0xb5 || bIdxLevels !== 0) return null; // only flat PC BTHs
    var recs = resolveHid(blocks, hidRoot);
    if (!recs) return null;
    var rb = recs.buf, recSize = cbKey + cbEnt;          // PC: 2 + 6 = 8
    if (recSize <= 0) return null;
    for (var p = recs.start; p + recSize <= recs.end; p += recSize) {
      if (u16(rb, p) === PROP_PST_PASSWORD) {
        return { blockIdx: recs.blockIdx, offset: p + cbKey + 2 };
      }
    }
    return null;
  }

  // ---- main ------------------------------------------------------------------

  /**
   * Removes the password from a PST file.
   * @param {Uint8Array|ArrayBuffer} input
   * @returns {{ bytes: Uint8Array, changed: boolean, hadPassword: boolean }}
   */
  function unlock(input) {
    var bytes = input instanceof Uint8Array ? input.slice() : new Uint8Array(input).slice();
    var fmt = describe(bytes);

    var storeBid = findNodeBid(bytes, fmt.nbtRoot, NID_MESSAGE_STORE, fmt);
    if (storeBid === null) throw fail('PST_INVALID', 'Could not locate the PST message store.');

    var blocks = collectDataBlocks(bytes, storeBid, fmt, 0);
    if (!blocks || !blocks.length) throw fail('PST_INVALID', 'Could not read the message store data block(s).');

    var loc = findPasswordValueOffset(blocks);
    if (!loc) {
      // No PC password property found — nothing to do.
      return { bytes: bytes, changed: false, hadPassword: false };
    }

    var blk = blocks[loc.blockIdx];
    var current = u32(blk.decoded, loc.offset);
    if (current === 0) {
      return { bytes: bytes, changed: false, hadPassword: false };
    }

    // Zero the password CRC in the owning block, re-encode and write it back.
    blk.decoded[loc.offset] = 0; blk.decoded[loc.offset + 1] = 0;
    blk.decoded[loc.offset + 2] = 0; blk.decoded[loc.offset + 3] = 0;
    encodeBlock(blk.decoded, 0, blk.cb, fmt.crypt, Number(blk.bid & 0xffffffffn));
    bytes.set(blk.decoded.subarray(0, blk.cb), blk.ib);

    // Recompute that block's trailer CRC (over its cb encoded data bytes).
    var aligned = Math.ceil((blk.cb + fmt.blockTrailer) / 64) * 64;
    var trailerOff = blk.ib + aligned - fmt.blockTrailer;
    var newCrc = computeCrc(bytes, blk.ib, blk.cb);
    bytes[trailerOff + 4] = newCrc & 0xff;
    bytes[trailerOff + 5] = (newCrc >>> 8) & 0xff;
    bytes[trailerOff + 6] = (newCrc >>> 16) & 0xff;
    bytes[trailerOff + 7] = (newCrc >>> 24) & 0xff;

    return { bytes: bytes, changed: true, hadPassword: true };
  }

  return {
    unlock: unlock,
    isPst: isPst,
    _describe: describe,
    _computeCrc: computeCrc,
    _encodeBlock: encodeBlock,
    _decodeBlock: decodeBlock
  };
});
