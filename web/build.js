#!/usr/bin/env node
'use strict';
// Run this script after modifying web/web-client.html or .env.local:
//   node web/build.js
// Generates _bundle.js with the HTML page and non-sensitive config for web-server.js to require().
// NIST_API_KEY is intentionally excluded — it never flows to HTML output.
const fs   = require('fs');
const path = require('path');

function loadEnv(filePath) {
    const env = {};
    try {
        for (const line of fs.readFileSync(filePath, 'utf8').split(/\r?\n/)) {
            const t = line.trim();
            if (!t || t.startsWith('#')) continue;
            const eq = t.indexOf('=');
            if (eq < 0) continue;
            env[t.slice(0, eq).trim()] = t.slice(eq + 1).trim();
        }
    } catch { /* .env.local not found */ }
    return env;
}

const env = loadEnv(path.join(__dirname, '..', '.env.local'));

const portableEnable = (env.PORTABLE_ENABLE || 'true').toLowerCase() !== 'false';
const whitelist      = env.WHITELIST || '';

const portables = [];
if (portableEnable) {
    for (let i = 0; ; i++) {
        const val = env[`PORTABLE_${i}`];
        if (!val) break;
        const [name = '', version = ''] = val.split('|');
        if (name.trim()) portables.push({ name: name.trim(), version: version.trim() });
    }
}

const hasApiKey    = !!(env.NIST_API_KEY || '').trim();
const requestDelay = hasApiKey ? 700 : 6500;
const config       = { portableEnable, whitelist, portables, requestDelay };

const html = fs.readFileSync(path.join(__dirname, 'web-client.html'), 'utf8');

const out = '// Auto-generated — do not edit manually. Run: node build.js\n'
          + `module.exports = ${JSON.stringify({ html, config }, null, 2)};\n`;

fs.writeFileSync(path.join(__dirname, '_bundle.js'), out, 'utf8');
console.log(`bundled: web-client.html (${html.length} chars), whitelist="${whitelist}", portables=${portables.length}, delay=${requestDelay}ms → _bundle.js`);
