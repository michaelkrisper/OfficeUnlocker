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
  function decodeBlock(buf, start, len, crypt) {
    if (crypt === CRYPT_PERMUTE) {
      for (var i = 0; i < len; i++) buf[start + i] = PERMUTE_DECODE[buf[start + i]];
    } else if (crypt === CRYPT_CYCLIC) {
      throw fail('PST_UNSUPPORTED', 'This PST uses "high" (cyclic) encoding, which is not supported.');
    }
  }
  function encodeBlock(buf, start, len, crypt) {
    if (crypt === CRYPT_PERMUTE) {
      for (var i = 0; i < len; i++) buf[start + i] = PERMUTE_ENCODE[buf[start + i]];
    } else if (crypt === CRYPT_CYCLIC) {
      throw fail('PST_UNSUPPORTED', 'This PST uses "high" (cyclic) encoding, which is not supported.');
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

  // Resolve a HID to its byte offset within the (decoded) single-block heap.
  function resolveHid(data, hid) {
    var hidType = hid & 0x1f;
    if (hidType !== 0) return null;            // not a HID (could be an NID)
    var hidIndex = (hid >>> 5) & 0x7ff;
    if (hidIndex === 0) return null;
    var ibHnpm = u16(data, 0);                 // HNHDR.ibHnpm
    var cAlloc = u16(data, ibHnpm);
    if (hidIndex > cAlloc) return null;
    var rgibAlloc = ibHnpm + 4;
    var start = u16(data, rgibAlloc + (hidIndex - 1) * 2);
    var end = u16(data, rgibAlloc + hidIndex * 2);
    return { start: start, end: end };
  }

  // Locate the PidTagPstPassword record inside the message-store PC and return
  // the absolute offset of its 4-byte value within `data`, or null.
  function findPasswordValueOffset(data) {
    if (data[2] !== 0xec) return null;         // HNHDR.bSig must be 0xEC
    var hidUserRoot = u32(data, 4);            // HNHDR.hidUserRoot -> BTHHEADER
    var hdr = resolveHid(data, hidUserRoot);
    if (!hdr) return null;
    var bType = data[hdr.start];               // BTHHEADER.bType (0xB5)
    var cbKey = data[hdr.start + 1];
    var cbEnt = data[hdr.start + 2];
    var bIdxLevels = data[hdr.start + 3];
    var hidRoot = u32(data, hdr.start + 4);
    if (bType !== 0xb5 || bIdxLevels !== 0) return null; // only flat PC BTHs
    var recs = resolveHid(data, hidRoot);
    if (!recs) return null;
    var recSize = cbKey + cbEnt;               // PC: 2 + 6 = 8
    if (recSize <= 0) return null;
    for (var p = recs.start; p + recSize <= recs.end; p += recSize) {
      var propId = u16(data, p);
      if (propId === PROP_PST_PASSWORD) {
        // PCBTH: wPropId(2) wPropType(2) dwValueHnid(4) -> value at p + cbKey + 2.
        return p + cbKey + 2;
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

    if (fmt.crypt === CRYPT_CYCLIC) {
      throw fail('PST_UNSUPPORTED', 'This PST uses "high" (cyclic) encoding, which is not supported.');
    }

    var storeBid = findNodeBid(bytes, fmt.nbtRoot, NID_MESSAGE_STORE, fmt);
    if (storeBid === null) throw fail('PST_INVALID', 'Could not locate the PST message store.');

    if (fmt.unicode && (storeBid & 2n) === 2n) {
      throw fail('PST_UNSUPPORTED', 'The message store spans multiple blocks; this layout is not supported.');
    }

    var block = findBlock(bytes, fmt.bbtRoot, storeBid, fmt);
    if (!block) throw fail('PST_INVALID', 'Could not locate the message store data block.');

    // Decode the block payload (cb bytes at block.ib) into a working copy.
    var data = bytes.subarray(block.ib, block.ib + block.cb).slice();
    decodeBlock(data, 0, block.cb, fmt.crypt);

    var valueOff = findPasswordValueOffset(data);
    if (valueOff === null) {
      // No PC password property found — nothing to do.
      return { bytes: bytes, changed: false, hadPassword: false };
    }

    var current = u32(data, valueOff);
    if (current === 0) {
      return { bytes: bytes, changed: false, hadPassword: false };
    }

    // Zero the password CRC.
    data[valueOff] = 0; data[valueOff + 1] = 0; data[valueOff + 2] = 0; data[valueOff + 3] = 0;

    // Re-encode and write the block back.
    encodeBlock(data, 0, block.cb, fmt.crypt);
    bytes.set(data, block.ib);

    // Recompute the block trailer CRC (over the cb encoded data bytes).
    // The trailer sits at the end of the 64-byte aligned slot for this block.
    var aligned = Math.ceil((block.cb + fmt.blockTrailer) / 64) * 64;
    var trailerOff = block.ib + aligned - fmt.blockTrailer;
    var newCrc = computeCrc(bytes, block.ib, block.cb);
    // BLOCKTRAILER: cb(2), wSig(2), dwCRC(4), bid. dwCRC at +4.
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
    _computeCrc: computeCrc
  };
});
