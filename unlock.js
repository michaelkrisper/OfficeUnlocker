/*
 * OfficeUnlocker core logic.
 *
 * Removes editing restrictions that are stored as flags/properties, entirely in
 * the browser — it does NOT break real encryption:
 *
 *   • Office Open XML (.xlsx, .docx, .pptx) and OpenDocument (.ods, .odt, .odp)
 *     – sheet / workbook / document protection, stored as plain XML flags.
 *   • Legacy binary Office (.xls, .doc) – BIFF protection records / the Word
 *     document-protection flag, plus VBA project passwords.
 *   • Outlook PST (.pst) – the message-store password, which is only a CRC and
 *     does not encrypt the mail, so it can be cleared outright.
 *
 * NOTE: This does NOT decrypt files protected with an "open password"
 * (full-file encryption). Those are detected and reported, never decrypted.
 *
 * Written in a UMD style so it runs both in the browser (as a global,
 * `window.OfficeUnlocker`) and in Node.js (via `require`) for automated tests.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    // Node.js – pull in dependencies from node_modules / sibling files.
    module.exports = factory(require('jszip'), require('./pstunlock.js'), require('./olelock.js'));
  } else {
    // Browser – dependencies are expected to be loaded globally beforehand.
    root.OfficeUnlocker = factory(root.JSZip, root.PstUnlock, root.OleLock);
  }
})(typeof self !== 'undefined' ? self : this, function (JSZip, PstUnlock, OleLock) {
  'use strict';

  var OOXML_EXTENSIONS = ['xlsx', 'docx', 'pptx', 'xlsm', 'docm', 'pptm', 'xlsb'];
  var ODF_EXTENSIONS = ['odt', 'ods', 'odp', 'odg'];
  var LEGACY_EXTENSIONS = ['xls', 'doc', 'ppt'];
  var SUPPORTED_EXTENSIONS = OOXML_EXTENSIONS
    .concat(ODF_EXTENSIONS, LEGACY_EXTENSIONS, ['pst']);

  // OLE2 / Compound File Binary magic number. Files starting with these bytes
  // are encrypted Office documents (open-password protected) and are NOT ZIPs.
  var OLE2_MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

  /**
   * Returns true if the given bytes look like an encrypted (OLE2) Office file.
   * @param {Uint8Array} bytes
   */
  function looksEncrypted(bytes) {
    if (!bytes || bytes.length < OLE2_MAGIC.length) return false;
    for (var i = 0; i < OLE2_MAGIC.length; i++) {
      if (bytes[i] !== OLE2_MAGIC[i]) return false;
    }
    return true;
  }

  // Magic number used to route by content rather than trusting the extension.
  var PST_MAGIC = [0x21, 0x42, 0x44, 0x4e];             // "!BDN"

  function startsWith(bytes, magic) {
    if (!bytes || bytes.length < magic.length) return false;
    for (var i = 0; i < magic.length; i++) if (bytes[i] !== magic[i]) return false;
    return true;
  }

  function getExtension(filename) {
    var parts = filename.split('.');
    return parts.length > 1 ? parts.pop().toLowerCase() : '';
  }

  function isSupported(filename) {
    return SUPPORTED_EXTENSIONS.indexOf(getExtension(filename)) !== -1;
  }

  /**
   * Strips a single OOXML protection element (self-closing OR paired) from an
   * XML string. Returns { content, removed }.
   *
   * @param {string} xml
   * @param {string} tag e.g. "sheetProtection" or "w:documentProtection"
   */
  var elementRegexCache = {};
  function stripElement(xml, tag) {
    var patterns = elementRegexCache[tag];
    if (!patterns) {
      // Escape ":" is fine inside a regex character context; build patterns.
      var escaped = tag.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      patterns = elementRegexCache[tag] = {
        // Paired form: <tag ...> ... </tag>
        paired: new RegExp('<' + escaped + '\\b[^>]*>[\\s\\S]*?<\\/' + escaped + '>', 'g'),
        // Self-closing or empty form: <tag .../> or <tag ...>
        single: new RegExp('<' + escaped + '\\b[^>]*\\/?>', 'g')
      };
    }

    var before = xml;
    var out = xml.replace(patterns.paired, '').replace(patterns.single, '');
    return { content: out, removed: out !== before };
  }

  /**
   * Map of file path (or matcher) -> list of protection tags to remove.
   * Worksheets / chartsheets are matched dynamically by prefix.
   */
  var STATIC_TARGETS = {
    'xl/workbook.xml': ['workbookProtection', 'fileSharing'],
    'word/settings.xml': ['w:documentProtection', 'w:writeProtection'],
    'ppt/presentation.xml': ['p:modifyVerifier']
  };

  function tagsForPath(path) {
    if (STATIC_TARGETS[path]) return STATIC_TARGETS[path];
    if (/^xl\/worksheets\/.*\.xml$/.test(path)) return ['sheetProtection'];
    if (/^xl\/chartsheets\/.*\.xml$/.test(path)) return ['sheetProtection'];
    return null;
  }

  // Read the full bytes as a Uint8Array (handles Blob / ArrayBuffer / views).
  async function toBytes(data) {
    if (typeof Blob !== 'undefined' && data instanceof Blob) {
      return new Uint8Array(await data.arrayBuffer());
    }
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    return new Uint8Array(0);
  }

  function isNodeEnv() {
    return typeof process !== 'undefined' && process.versions && process.versions.node;
  }

  // Wrap raw output bytes as a Node Buffer (tests) or a browser Blob (download).
  function toOutput(bytes) {
    if (isNodeEnv()) return Buffer.from(bytes);
    return new Blob([bytes], { type: 'application/octet-stream' });
  }

  /**
   * Unlocks a supported file. Routes by content (magic bytes) so a mislabelled
   * extension still works.
   *
   * @param {ArrayBuffer|Uint8Array|Buffer|Blob} data Raw file bytes.
   * @returns {Promise<{blob: (Blob|Buffer), removed: string[], kind: string}>}
   *   `blob` is the unlocked file, `removed` lists which protections were
   *   stripped, `kind` is one of 'ooxml' | 'odf' | 'ole2' | 'pst'.
   */
  async function unlock(data) {
    var bytes = await toBytes(data);

    if (startsWith(bytes, PST_MAGIC)) {
      if (!PstUnlock) throw makeError('INVALID', 'PST support is not available.');
      var pstRes = PstUnlock.unlock(bytes);
      return { blob: toOutput(pstRes.bytes), removed: pstRes.changed ? ['PST password'] : [], kind: 'pst' };
    }

    return unlockOoxml(data, bytes);
  }

  function makeError(code, message) { var e = new Error(message); e.code = code; return e; }

  // OLE2 container: a legacy binary Office / VBA file. Encrypted documents
  // (open password) are detected and reported, never decrypted.
  function unlockOle2(bytes) {
    if (!OleLock) throw makeError('ENCRYPTED', 'This file is encrypted with an "open password" and cannot be unlocked without it.');
    var res = OleLock.unlock(bytes);
    return { blob: toOutput(res.bytes), removed: res.removed, kind: res.kind };
  }

  // Macro-enabled OOXML packages embed the VBA project as vbaProject.bin (a CFB).
  async function stripVbaProject(zip) {
    if (!OleLock) return [];
    var paths = Object.keys(zip.files);
    for (var i = 0; i < paths.length; i++) {
      var path = paths[i];
      if (!/(^|\/)vbaProject\.bin$/i.test(path) || zip.files[path].dir) continue;
      var bin = await zip.files[path].async('uint8array');
      var res = OleLock.unlockVbaProjectBin(bin);
      if (res.changed) {
        zip.file(path, res.bytes);
        return ['VBA project password'];
      }
    }
    return [];
  }

  // --- ZIP-based documents: OOXML (.xlsx/.docx/.pptx) and ODF (.odt/.ods/.odp)

  async function unlockOoxml(data, bytes) {
    var head = bytes.subarray(0, 8);

    if (looksEncrypted(head)) {
      // OLE2 container: encrypted OOXML or a legacy binary Office file.
      return unlockOle2(bytes);
    }

    var zip;
    try {
      zip = await JSZip.loadAsync(data);
    } catch {
      var ze = new Error('The file is not a valid Office document (could not read the ZIP archive).');
      ze.code = 'INVALID';
      throw ze;
    }

    var isOdf = false;
    if (zip.files['mimetype']) {
      var mt = await zip.files['mimetype'].async('string');
      isOdf = /application\/vnd\.oasis\.opendocument/.test(mt);
    }

    var removed = isOdf ? await stripOdf(zip) : await stripOoxml(zip);
    removed = removed.concat(await stripVbaProject(zip));

    var outputType = isNodeEnv() ? 'nodebuffer' : 'blob';
    var blob = await zip.generateAsync({
      type: outputType,
      compression: 'DEFLATE',
      compressionOptions: { level: 6 },
      mimeType: 'application/octet-stream'
    });

    return { blob: blob, removed: removed, kind: isOdf ? 'odf' : 'ooxml' };
  }

  async function stripOoxml(zip) {
    var removed = [];
    var paths = Object.keys(zip.files);
    for (var i = 0; i < paths.length; i++) {
      var path = paths[i];
      var entry = zip.files[path];
      if (entry.dir) continue;

      var tags = tagsForPath(path);
      if (!tags) continue;

      var content = await entry.async('string');
      var changed = false;
      for (var t = 0; t < tags.length; t++) {
        var result = stripElement(content, tags[t]);
        if (result.removed) {
          content = result.content;
          changed = true;
          if (removed.indexOf(tags[t]) === -1) removed.push(tags[t]);
        }
      }
      if (changed) zip.file(path, content);
    }
    return removed;
  }

  // OpenDocument stores protection as XML *attributes* (e.g. table:protected),
  // optionally guarded by a hashed protection-key — neither of which encrypts
  // the content, so both can simply be cleared.
  async function stripOdf(zip) {
    // Refuse genuinely encrypted ODF (open password).
    if (zip.files['META-INF/manifest.xml']) {
      var manifest = await zip.files['META-INF/manifest.xml'].async('string');
      if (/encryption-data/.test(manifest)) {
        var err = new Error('This OpenDocument file is encrypted with a password and cannot be unlocked without it.');
        err.code = 'ENCRYPTED';
        throw err;
      }
    }

    var removed = [];
    var targets = ['content.xml', 'styles.xml'];
    for (var i = 0; i < targets.length; i++) {
      var path = targets[i];
      if (!zip.files[path]) continue;
      var xml = await zip.files[path].async('string');
      var before = xml;
      // Flip protection flags off (sheets, sections, drawings, forms).
      xml = xml.replace(/((?:\w+:)?(?:protected|protection))="true"/g, '$1="false"');
      // Remove the stored protection-key hashes entirely.
      xml = xml.replace(/\s+(?:\w+:)?protection-key(?:-digest-algorithm(?:-gpg)?)?="[^"]*"/g, '');
      if (xml !== before) {
        zip.file(path, xml);
        if (removed.indexOf('document protection') === -1) removed.push('document protection');
      }
    }
    return removed;
  }

  return {
    unlock: unlock,
    isSupported: isSupported,
    getExtension: getExtension,
    looksEncrypted: looksEncrypted,
    stripElement: stripElement,
    SUPPORTED_EXTENSIONS: SUPPORTED_EXTENSIONS
  };
});
