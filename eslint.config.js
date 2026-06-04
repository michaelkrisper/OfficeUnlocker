'use strict';

const js = require('@eslint/js');

module.exports = [
  js.configs.recommended,
  {
    // Shared core logic – runs in both the browser and Node.js (UMD).
    files: ['unlock.js', 'bincrypto.js', 'pdfunlock.js', 'pstunlock.js', 'ole2.js', 'olelock.js', 'ooxmlcrypt.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'script',
      globals: {
        module: 'readonly',
        require: 'readonly',
        self: 'readonly',
        window: 'readonly',
        Blob: 'readonly',
        process: 'readonly',
        Buffer: 'readonly',
        ArrayBuffer: 'readonly',
        Uint8Array: 'readonly',
        Uint32Array: 'readonly',
        BigInt: 'readonly'
      }
    },
    rules: {
      'no-var': 'off',
      'prefer-const': 'off'
    }
  },
  {
    // Node.js test + config files.
    files: ['test/**/*.js', 'eslint.config.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: {
        module: 'readonly',
        require: 'readonly',
        process: 'readonly',
        console: 'readonly',
        Buffer: 'readonly',
        __dirname: 'readonly'
      }
    }
  },
  {
    // Browser-only inline app script lives in index.html and is not linted here;
    // its logic is delegated to unlock.js which IS linted.
    ignores: ['node_modules/**']
  }
];
