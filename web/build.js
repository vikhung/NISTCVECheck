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

// Inject shared modules from lib/ into the template to produce web-client.html
const cveLogic    = fs.readFileSync(path.join(__dirname, '..', 'lib', 'cve-logic.js'), 'utf8');
const reportHTML  = fs.readFileSync(path.join(__dirname, '..', 'lib', 'report-html.js'), 'utf8');
const template    = fs.readFileSync(path.join(__dirname, 'web-client.src.html'), 'utf8');
const MARKER_LOGIC  = '// @@CVE_LOGIC@@';
const MARKER_REPORT = '// @@REPORT_HTML@@';
if (!template.includes(MARKER_LOGIC))  throw new Error(`Marker "${MARKER_LOGIC}" not found in web-client.src.html`);
if (!template.includes(MARKER_REPORT)) throw new Error(`Marker "${MARKER_REPORT}" not found in web-client.src.html`);
const html = template.replace(MARKER_LOGIC, cveLogic).replace(MARKER_REPORT, reportHTML);
fs.writeFileSync(path.join(__dirname, 'web-client.html'), html, 'utf8');
console.log(`injected: lib/cve-logic.js (${cveLogic.length} chars) + lib/report-html.js (${reportHTML.length} chars) → web-client.html`);

const out = '// Auto-generated — do not edit manually. Run: node build.js\n'
          + `module.exports = ${JSON.stringify({ html, config }, null, 2)};\n`;

fs.writeFileSync(path.join(__dirname, '_bundle.js'), out, 'utf8');
console.log(`bundled: web-client.html (${html.length} chars), whitelist="${whitelist}", portables=${portables.length}, delay=${requestDelay}ms → _bundle.js`);
