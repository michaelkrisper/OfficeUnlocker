/*
 * OfficeUnlocker core logic.
 *
 * Office files (.xlsx, .docx, .pptx) are ZIP archives containing XML parts.
 * "Protection" (read-only restrictions, sheet/workbook/document protection)
 * is stored as XML elements inside those parts. This module removes those
 * elements so the file can be edited again.
 *
 * NOTE: This does NOT decrypt files that were encrypted with an *open*
 * password. Those files are not ZIP archives at all (they use the OLE/CFB
 * compound format with AES encryption) and require the password to open.
 *
 * The module is written in UMD style so it can be used both from the browser
 * (attaches `unlockOfficeZip` to `window`) and from Node (module.exports) for
 * automated tests.
 */
(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.OfficeUnlocker = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // Removes both self-closing (<tag .../>) and paired (<tag ...>...</tag>)
    // forms of the given element name from an XML string.
    function stripElement(xml, tagName) {
        const selfClosing = new RegExp('<' + tagName + '\\b[^>]*?/>', 'g');
        const paired = new RegExp('<' + tagName + '\\b[^>]*?>[\\s\\S]*?</' + tagName + '>', 'g');
        return xml.replace(paired, '').replace(selfClosing, '');
    }

    async function editPart(zip, path, tags) {
        const file = zip.file(path);
        if (!file) return false;
        let content = await file.async('string');
        const before = content;
        for (const tag of tags) {
            content = stripElement(content, tag);
        }
        if (content !== before) {
            zip.file(path, content);
            return true;
        }
        return false;
    }

    // Returns an array of all worksheet part paths (xl/worksheets/sheetN.xml).
    function worksheetPaths(zip) {
        const paths = [];
        zip.forEach(function (relativePath, entry) {
            if (/^xl\/worksheets\/[^/]+\.xml$/.test(entry.name) && !entry.dir) {
                paths.push(entry.name);
            }
        });
        return paths;
    }

    /**
     * Removes protection from an opened JSZip archive, in place.
     * @param {JSZip} zip - the loaded archive
     * @param {string} extension - "xlsx" | "docx" | "pptx"
     * @returns {Promise<{changed: boolean, parts: string[]}>}
     */
    async function unlockOfficeZip(zip, extension) {
        const changedParts = [];
        const note = async (path, tags) => {
            if (await editPart(zip, path, tags)) changedParts.push(path);
        };

        if (extension === 'xlsx') {
            // Workbook-level protection + structure/window locking + file sharing.
            await note('xl/workbook.xml', ['workbookProtection', 'fileSharing']);
            // Per-sheet protection.
            for (const sheet of worksheetPaths(zip)) {
                await note(sheet, ['sheetProtection']);
            }
        } else if (extension === 'docx') {
            // Editing restrictions + write protection.
            await note('word/settings.xml', ['w:documentProtection', 'w:writeProtection']);
        } else if (extension === 'pptx') {
            // Modify password / read-only recommendation.
            await note('ppt/presentation.xml', ['p:modifyVerifier']);
        } else {
            throw new Error('Unsupported file type: ' + extension);
        }

        return { changed: changedParts.length > 0, parts: changedParts };
    }

    return { unlockOfficeZip: unlockOfficeZip, stripElement: stripElement };
}));
