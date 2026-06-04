/*
 * Unlocker for OLE2 / Compound File Binary documents:
 *
 *   • Legacy Excel (.xls) — sheet/workbook/window/object protection records are
 *     plain BIFF records and are zeroed in place.
 *   • VBA projects — the "lock project for viewing" password lives in the
 *     PROJECT stream's DPB key. Renaming that key (DPB -> DPx, a same-length
 *     edit) makes the VBA editor treat the project as unprotected. This covers
 *     macro-enabled legacy files and the vbaProject.bin inside OOXML packages.
 *   • Encrypted documents — files with an open password (encrypted OOXML inside
 *     OLE2, or a BIFF FILEPASS / Word fEncrypted flag) are detected and reported
 *     rather than mangled.
 *
 * UMD: `require('./olelock.js')` in Node, `window.OleLock` in the browser.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('./ole2.js'), require('./utils.js'));
  } else {
    root.OleLock = factory(root.Ole2, root.Utils);
  }
})(typeof self !== 'undefined' ? self : this, function (Ole2, Utils) {
  'use strict';

  function err(code, message) { var e = new Error(message); e.code = code; return e; }
  var ENCRYPTED_MSG = 'This file is encrypted with an "open password" and cannot be unlocked without it.';

  // BIFF record ids that carry workbook/worksheet protection.
  var BIFF_PROTECT = 0x0012;
  var BIFF_PASSWORD = 0x0013;
  var BIFF_WINDOWPROTECT = 0x0019;
  var BIFF_OBJECTPROTECT = 0x0063;
  var BIFF_SCENPROTECT = 0x00dd;
  var BIFF_SHEETPROTECTION = 0x0867;
  var BIFF_FILEPASS = 0x002f;
  var BIFF_BOF = 0x0809;
  var PROTECT_RECORDS = [BIFF_PROTECT, BIFF_PASSWORD, BIFF_WINDOWPROTECT,
    BIFF_OBJECTPROTECT, BIFF_SCENPROTECT, BIFF_SHEETPROTECTION];

  var u16 = Utils.u16;
  var u32 = Utils.u32;

  // Remove the VBA project password by renaming the DPB key in the PROJECT
  // stream. Returns true if a change was made.
  function unlockVbaIn(cfb) {
    var project = cfb.find('PROJECT');
    if (!project || project.type !== 2) return false;
    var data = cfb.readStream(project);
    if (!data) return false;
    var changed = false;
    // Match "DPB=" (optionally preceded by a line break) and break the key name.
    for (var i = 0; i + 4 <= data.length; i++) {
      if (data[i] === 0x44 && data[i + 1] === 0x50 && data[i + 2] === 0x42 && data[i + 3] === 0x3d) { // "DPB="
        cfb.patchStream(project, i + 2, new Uint8Array([0x78])); // 'B' -> 'x'
        changed = true;
      }
    }
    return changed;
  }

  // Zero the protection records in an Excel BIFF stream. Throws if encrypted.
  function unlockExcelIn(cfb, removed) {
    var wb = cfb.find('Workbook') || cfb.find('Book');
    if (!wb) return;
    var data = cfb.readStream(wb);
    var pos = 0, guard = 0;
    var sawProtection = false;
    while (pos + 4 <= data.length && guard++ < 5000000) {
      var id = u16(data, pos);
      var len = u16(data, pos + 2);
      var dataOff = pos + 4;
      if (dataOff + len > data.length) break;
      if (id === BIFF_FILEPASS) throw err('ENCRYPTED', ENCRYPTED_MSG);
      if (PROTECT_RECORDS.indexOf(id) !== -1 && len > 0) {
        // Only act on a positive protect flag / non-empty record.
        cfb.patchStream(wb, dataOff, new Uint8Array(len));
        sawProtection = true;
      }
      pos = dataOff + len;
      if (id !== BIFF_BOF && pos > data.length) break;
    }
    if (sawProtection && removed.indexOf('worksheet/workbook protection') === -1) {
      removed.push('worksheet/workbook protection');
    }
  }

  // Legacy Word: reject if encrypted, otherwise clear the document-protection
  // ("Restrict Editing") master switch fProtEnabled in the Dop.
  //
  // The Dop lives in the table stream at FibRgFcLcb97.fcDop (FIB offset 0x192,
  // index 31 of the FC/LCB array). Dop byte 0x07 holds fProtEnabled (0x02);
  // clearing it disables protection regardless of the stored password hash.
  function unlockWordIn(cfb, removed) {
    var wd = cfb.find('WordDocument');
    if (!wd) return;
    var fib = cfb.readStream(wd);
    if (!fib || fib.length < 0x19a) return;
    if (u16(fib, 0) !== 0xa5ec) return;            // not a valid FIB
    var flags = u16(fib, 0x0a);
    if (flags & 0x0100) throw err('ENCRYPTED', ENCRYPTED_MSG); // fEncrypted

    var tableName = (flags & 0x0200) ? '1Table' : '0Table';
    var fcDop = u32(fib, 0x192);
    var lcbDop = u32(fib, 0x196);
    if (lcbDop < 8) return;                          // no Dop present

    var table = cfb.find(tableName);
    if (!table) return;
    var tbl = cfb.readStream(table);
    var off = fcDop + 0x07;
    if (!tbl || off >= tbl.length) return;
    if (tbl[off] & 0x02) {
      cfb.patchStream(table, off, new Uint8Array([tbl[off] & ~0x02]));
      if (removed.indexOf('document protection') === -1) removed.push('document protection');
    }
  }

  /**
   * Unlocks an OLE2 document supplied as bytes (modified in place).
   * @returns {{ bytes: Uint8Array, removed: string[], kind: string }}
   */
  function unlock(input) {
    var bytes = input instanceof Uint8Array ? input.slice() : new Uint8Array(input).slice();
    if (bytes.length < 512) throw err('ENCRYPTED', ENCRYPTED_MSG);

    var cfb;
    try {
      cfb = Ole2.parse(bytes);
    } catch {
      // Not a readable CFB — most likely an encrypted package we can't open.
      throw err('ENCRYPTED', ENCRYPTED_MSG);
    }

    // Encrypted OOXML stored inside an OLE2 wrapper.
    if (cfb.find('EncryptedPackage') || cfb.find('EncryptionInfo')) {
      throw err('ENCRYPTED', ENCRYPTED_MSG);
    }

    var removed = [];
    unlockWordIn(cfb, removed);
    unlockExcelIn(cfb, removed);
    if (unlockVbaIn(cfb)) removed.push('VBA project password');

    return { bytes: cfb.bytes, removed: removed, kind: 'ole2' };
  }

  // Unlock a standalone vbaProject.bin (CFB). Returns { bytes, changed }.
  function unlockVbaProjectBin(input) {
    var bytes = input instanceof Uint8Array ? input.slice() : new Uint8Array(input).slice();
    if (!Ole2.isOle2(bytes)) return { bytes: bytes, changed: false };
    var cfb;
    try { cfb = Ole2.parse(bytes); } catch { return { bytes: bytes, changed: false }; }
    var changed = unlockVbaIn(cfb);
    return { bytes: cfb.bytes, changed: changed };
  }

  return { unlock: unlock, unlockVbaProjectBin: unlockVbaProjectBin };
});
