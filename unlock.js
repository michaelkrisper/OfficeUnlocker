/*
 * OfficeUnlocker core logic.
 *
 * Removes editing / sheet / workbook / document protection from Office Open XML
 * documents (.xlsx, .docx, .pptx). These protections are stored as plain XML
 * flags inside the ZIP container, so they can be stripped without knowing the
 * password.
 *
 * NOTE: This does NOT decrypt files that are protected with an "open password"
 * (full-file AES encryption). Those files are not ZIP archives at all – they are
 * encrypted OLE2 containers – and cannot be opened without the password.
 *
 * Written in a UMD style so it runs both in the browser (as a global,
 * `window.OfficeUnlocker`) and in Node.js (via `require`) for automated tests.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    // Node.js – pull in JSZip from node_modules for testing.
    module.exports = factory(require('jszip'));
  } else {
    // Browser – JSZip is expected to be loaded globally beforehand.
    root.OfficeUnlocker = factory(root.JSZip);
  }
})(typeof self !== 'undefined' ? self : this, function (JSZip) {
  'use strict';

  var SUPPORTED_EXTENSIONS = ['xlsx', 'docx', 'pptx'];

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
   * Matching is namespace-prefix agnostic: an element belongs to a namespace,
   * not to a particular prefix, so `<sheetProtection/>`, `<x:sheetProtection/>`
   * and `<ns0:sheetProtection/>` are all equivalent. We therefore match the
   * element's *local name* and allow any (or no) prefix. The prefix in a tag
   * such as "w:documentProtection" is only used to derive that local name.
   *
   * @param {string} xml
   * @param {string} tag e.g. "sheetProtection" or "w:documentProtection"
   */
  function stripElement(xml, tag) {
    var colon = tag.lastIndexOf(':');
    var localName = colon === -1 ? tag : tag.slice(colon + 1);
    var escaped = localName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    // Optional XML namespace prefix, e.g. "w:", "x:", "ns0:".
    var prefix = '(?:[A-Za-z_][\\w.-]*:)?';
    // Paired form: <tag ...> ... </tag>
    var paired = new RegExp('<' + prefix + escaped + '\\b[^>]*>[\\s\\S]*?<\\/' + prefix + escaped + '>', 'g');
    // Self-closing or empty form: <tag .../> or <tag ...>
    var single = new RegExp('<' + prefix + escaped + '\\b[^>]*\\/?>', 'g');

    var before = xml;
    var out = xml.replace(paired, '').replace(single, '');
    return { content: out, removed: out !== before };
  }

  /**
   * Map of file path (or matcher) -> list of protection tags to remove.
   * Worksheets / chartsheets are matched dynamically by prefix.
   */
  var STATIC_TARGETS = {
    'xl/workbook.xml': ['workbookProtection', 'fileSharing'],
    // word/document.xml also carries the editable-region markers that pair with
    // documentProtection ("allow editing only in these regions").
    'word/document.xml': ['w:permStart', 'w:permEnd'],
    'word/settings.xml': ['w:documentProtection', 'w:writeProtection'],
    'ppt/presentation.xml': ['p:modifyVerifier']
  };

  function tagsForPath(path) {
    if (STATIC_TARGETS[path]) return STATIC_TARGETS[path];
    // Worksheets carry the sheet protection flag plus any password-protected
    // "allow users to edit ranges" definitions (protectedRanges).
    if (/^xl\/worksheets\/.*\.xml$/.test(path)) return ['sheetProtection', 'protectedRanges'];
    if (/^xl\/chartsheets\/.*\.xml$/.test(path)) return ['sheetProtection'];
    return null;
  }

  /**
   * Unlocks an Office file.
   *
   * @param {ArrayBuffer|Uint8Array|Buffer|Blob} data Raw file bytes.
   * @returns {Promise<{blob: (Blob|Buffer), removed: string[]}>}
   *   `blob` is the unlocked file, `removed` lists which protections were stripped.
   */
  async function unlock(data) {
    // Peek at the first bytes to detect encrypted (OLE2) files up front.
    var head;
    if (typeof Blob !== 'undefined' && data instanceof Blob) {
      head = new Uint8Array(await data.slice(0, 8).arrayBuffer());
    } else if (data instanceof ArrayBuffer) {
      head = new Uint8Array(data, 0, Math.min(8, data.byteLength));
    } else if (ArrayBuffer.isView(data)) {
      // Covers Node Buffer, Uint8Array, etc. Honour the view's byteOffset.
      head = data.subarray(0, 8);
    } else {
      head = new Uint8Array(0);
    }

    if (looksEncrypted(head)) {
      var err = new Error(
        'This file is encrypted with an "open password". It cannot be unlocked ' +
        'in the browser without the password.'
      );
      err.code = 'ENCRYPTED';
      throw err;
    }

    var zip;
    try {
      zip = await JSZip.loadAsync(data);
    } catch {
      var ze = new Error('The file is not a valid Office document (could not read the ZIP archive).');
      ze.code = 'INVALID';
      throw ze;
    }

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
      if (changed) {
        zip.file(path, content);
      }
    }

    var isNode = typeof process !== 'undefined' && process.versions && process.versions.node;
    var outputType = isNode ? 'nodebuffer' : 'blob';
    var blob = await zip.generateAsync({
      type: outputType,
      compression: 'DEFLATE',
      compressionOptions: { level: 6 },
      mimeType: 'application/octet-stream'
    });

    return { blob: blob, removed: removed };
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
