/*
 * Minimal OLE2 / Compound File Binary (CFB) reader with in-place byte patching.
 *
 * Legacy binary Office files (.xls/.doc/.ppt) and embedded VBA projects
 * (vbaProject.bin) are CFB containers. We only need to (a) list directory
 * entries, (b) read a stream's bytes and (c) overwrite a few bytes of a stream
 * in place. Because every edit keeps the stream length identical, the container
 * structure (FAT, directory, sizes) stays valid and never has to be rebuilt.
 *
 * UMD: `require('./ole2.js')` in Node, `window.Ole2` in the browser.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.Ole2 = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var SIG = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
  var ENDOFCHAIN = 0xfffffffe;
  var FREESECT = 0xffffffff;

  function u16(b, o) { return b[o] | (b[o + 1] << 8); }
  function u32(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }

  function isOle2(bytes) {
    if (!bytes || bytes.length < 8) return false;
    for (var i = 0; i < 8; i++) if (bytes[i] !== SIG[i]) return false;
    return true;
  }

  function parse(bytes) {
    if (!isOle2(bytes)) throw err('OLE_INVALID', 'Not an OLE2 compound file.');

    var sectorSize = 1 << u16(bytes, 0x1e);
    var miniSectorSize = 1 << u16(bytes, 0x20);
    var miniCutoff = u32(bytes, 0x38);
    var firstDir = u32(bytes, 0x30);
    var firstMiniFat = u32(bytes, 0x3c);
    var firstDifat = u32(bytes, 0x44);
    var numDifat = u32(bytes, 0x48);

    function sectorOffset(sec) { return 512 + sec * sectorSize; }

    // Build the DIFAT (list of FAT sector numbers).
    var fatSectors = [];
    for (var i = 0; i < 109; i++) {
      var s = u32(bytes, 0x4c + i * 4);
      if (s === FREESECT || s === ENDOFCHAIN) break;
      fatSectors.push(s);
    }
    var difatSec = firstDifat, guard = 0;
    while (numDifat > 0 && difatSec !== ENDOFCHAIN && difatSec !== FREESECT && guard++ < 100000) {
      var base = sectorOffset(difatSec);
      var perSector = sectorSize / 4 - 1;
      for (var j = 0; j < perSector; j++) {
        var fs = u32(bytes, base + j * 4);
        if (fs === FREESECT || fs === ENDOFCHAIN) continue;
        fatSectors.push(fs);
      }
      difatSec = u32(bytes, base + perSector * 4);
    }

    // Assemble the FAT (next-sector table).
    var entriesPerSector = sectorSize / 4;
    var fat = new Uint32Array(fatSectors.length * entriesPerSector);
    for (i = 0; i < fatSectors.length; i++) {
      var off = sectorOffset(fatSectors[i]);
      for (j = 0; j < entriesPerSector; j++) fat[i * entriesPerSector + j] = u32(bytes, off + j * 4);
    }

    function fatChain(start) {
      var chain = [], sec = start, g = 0;
      while (sec !== ENDOFCHAIN && sec !== FREESECT && sec < fat.length && g++ < fat.length + 1) {
        chain.push(sec);
        sec = fat[sec];
      }
      return chain;
    }

    // Mini FAT.
    var miniFat = [];
    var mfChain = fatChain(firstMiniFat);
    for (i = 0; i < mfChain.length; i++) {
      var mo = sectorOffset(mfChain[i]);
      for (j = 0; j < entriesPerSector; j++) miniFat.push(u32(bytes, mo + j * 4));
    }

    // Directory entries.
    var dirChain = fatChain(firstDir);
    var entries = [];
    for (i = 0; i < dirChain.length; i++) {
      var dbase = sectorOffset(dirChain[i]);
      for (var e = 0; e < sectorSize / 128; e++) {
        var p = dbase + e * 128;
        var nameLen = u16(bytes, p + 0x40);
        var type = bytes[p + 0x42];
        if (type === 0) continue; // unused
        var nameChars = [];
        for (var c = 0; c < nameLen - 2 && c < 64; c += 2) {
          nameChars.push(u16(bytes, p + c));
        }
        var name = String.fromCharCode.apply(null, nameChars);
        entries.push({
          name: name,
          type: type,                 // 1 storage, 2 stream, 5 root
          start: u32(bytes, p + 0x74),
          size: u32(bytes, p + 0x78)  // low 32 bits (sufficient here)
        });
      }
    }

    var rootEntry = entries.filter(function (en) { return en.type === 5; })[0];
    var rootChain = rootEntry ? fatChain(rootEntry.start) : [];

    function physOffset(entry, logOff) {
      if (entry.size >= miniCutoff || entry.type === 5) {
        var idx = Math.floor(logOff / sectorSize), within = logOff % sectorSize;
        var chain = fatChain(entry.start);
        return sectorOffset(chain[idx]) + within;
      }
      // Mini stream.
      var midx = Math.floor(logOff / miniSectorSize), mw = logOff % miniSectorSize;
      var mc = miniFatChain(entry.start);
      var containerLog = mc[midx] * miniSectorSize + mw;
      var cidx = Math.floor(containerLog / sectorSize), cw = containerLog % sectorSize;
      return sectorOffset(rootChain[cidx]) + cw;
    }

    function miniFatChain(start) {
      var chain = [], sec = start, g = 0;
      while (sec !== ENDOFCHAIN && sec !== FREESECT && sec < miniFat.length && g++ < miniFat.length + 1) {
        chain.push(sec);
        sec = miniFat[sec];
      }
      return chain;
    }

    function find(name) {
      for (var k = 0; k < entries.length; k++) if (entries[k].name === name) return entries[k];
      return null;
    }

    function readStream(entry) {
      if (typeof entry === 'string') entry = find(entry);
      if (!entry) return null;
      var out = new Uint8Array(entry.size);
      for (var o = 0; o < entry.size; o++) out[o] = bytes[physOffset(entry, o)];
      return out;
    }

    // Overwrite `data` into a stream at a logical offset, in place in `bytes`.
    function patchStream(entry, logOff, data) {
      if (typeof entry === 'string') entry = find(entry);
      for (var o = 0; o < data.length; o++) bytes[physOffset(entry, logOff + o)] = data[o];
    }

    return {
      entries: entries,
      bytes: bytes,
      find: find,
      readStream: readStream,
      patchStream: patchStream
    };
  }

  function err(code, message) { var e = new Error(message); e.code = code; return e; }

  return { isOle2: isOle2, parse: parse };
});
