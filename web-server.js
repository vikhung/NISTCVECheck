#!/usr/bin/env node
'use strict';

const http  = require('http');
const https = require('https');
const fs    = require('fs');
const path  = require('path');
const os    = require('os');

// ─── Port resolution ─────────────────────────────────────────────────────────
// Priority: CLI arg → PORT env var → default 8093
// Usage: node web-server.js [PORT]
const cliPort = parseInt(process.argv[2] || '', 10);
const PORT    = (!isNaN(cliPort) && cliPort > 0 && cliPort < 65536)
                ? cliPort
                : parseInt(process.env.PORT || '8093', 10);

const HTML    = path.join(__dirname, 'web-client.html');
const NVD_HOST = 'services.nvd.nist.gov';
const NVD_PATH = '/rest/json/cves/2.0';

// ─── Load .env.local ─────────────────────────────────────────────────────────
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
    } catch { /* .env.local not found — skip */ }
    return env;
}

const env              = loadEnv(path.join(__dirname, '.env.local'));
const defaultApiKey    = env.NIST_API_KEY || '';
const defaultWhitelist = env.WHITELIST    || '';

// Parse PORTABLE_N=name|version entries
const defaultPortables = [];
for (let i = 0; ; i++) {
    const val = env[`PORTABLE_${i}`];
    if (!val) break;
    const [name = '', version = ''] = val.split('|');
    if (name.trim()) defaultPortables.push({ name: name.trim(), version: version.trim() });
}

// Injected before </body>:
// - Tells browser to use local /api/nvd proxy (avoids CORS, API key stays server-side)
// - Pre-fills whitelist if localStorage is empty
const injectLines = [
    `window.__NVD_PROXY__   = '/api/nvd';`,
    `window.__NVD_DELAY__   = ${defaultApiKey ? 700 : 6500};`,
];
// Call addPortableRow() directly — the injected script runs after the main <script> block,
// so the function is already defined and the portable list is populated immediately.
for (const p of defaultPortables) {
    injectLines.push(`if(typeof addPortableRow==='function')addPortableRow(${JSON.stringify(p.name)},${JSON.stringify(p.version)});`);
}
if (defaultWhitelist) {
    injectLines.push(
        `var w=document.getElementById('whitelist'); if(w&&!w.value)w.value=${JSON.stringify(defaultWhitelist)};`
    );
}
if (defaultApiKey) {
    // Hide the API key field and insert a status label beside it (keep #api-key in DOM so scan code can still read .value)
    injectLines.push(
        `var fg=document.getElementById('api-key')?.closest('.form-group');`,
        `if(fg){fg.style.display='none';var el=document.createElement('div');el.className='form-group';el.innerHTML='<label>NIST API Key</label><span class="hint" style="color:#4ade80">&#10003; 由伺服器代理處理（.env.local）</span>';fg.parentNode.insertBefore(el,fg);}`
    );
}
const injectScript = `<script>(function(){\n  ${injectLines.join('\n  ')}\n})();</script>`;

// Keep-alive agent: reuses the TLS connection across requests (same as CLI behaviour).
// maxSockets:1 ensures sequential requests; keepAliveMsecs keeps the socket warm between the
// ~700 ms inter-request delays.  If NVD closes a stale socket the client retry logic recovers.
const nvdAgent = new https.Agent({ keepAlive: true, keepAliveMsecs: 10000, maxSockets: 1 });

// ─── NVD proxy ────────────────────────────────────────────────────────────────
function proxyNVD(req, res) {
    const qs = req.url.slice('/api/nvd'.length); // preserve '?...' query string
    const reqHeaders = { 'User-Agent': 'CVE-Web-Scanner/1.0' };
    if (defaultApiKey) reqHeaders['apiKey'] = defaultApiKey;

    // Without this, an abrupt browser disconnect (TCP RST) while pipe() is active
    // emits an unhandled 'error' on res and crashes the process.
    res.on('error', () => {});

    // Guard against double-write (e.g. error fires after response already started)
    let settled = false;
    const fail = (code, msg) => {
        if (settled) {
            // Headers already sent; just close the stream so the browser doesn't hang
            try { if (!res.writableEnded) res.end(); } catch (_) {}
            return;
        }
        settled = true;
        try {
            if (!res.headersSent) res.writeHead(code, { 'Content-Type': 'application/json' });
            if (!res.writableEnded)  res.end(JSON.stringify({ error: msg }));
        } catch (_) {}
    };

    const proxyReq = https.request(
        { hostname: NVD_HOST, path: NVD_PATH + qs, method: 'GET', headers: reqHeaders, timeout: 30000, agent: nvdAgent },
        proxyRes => {
            settled = true;
            res.writeHead(proxyRes.statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
            proxyRes.pipe(res);
            // Handle mid-stream connection drop from NVD
            proxyRes.on('error', () => { try { if (!res.writableEnded) res.end(); } catch (_) {} });
        }
    );
    proxyReq.on('timeout', () => { proxyReq.destroy(); fail(504, 'NVD API timeout (30 s)'); });
    proxyReq.on('error',   err => { console.error(`[NVD proxy] ${err.message}`); fail(502, err.message); });
    proxyReq.end();
}

// ─── Request handler ──────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
    if (req.method !== 'GET') {
        res.writeHead(405); res.end(); return;
    }

    // NVD proxy endpoint
    if (req.url === '/api/nvd' || req.url.startsWith('/api/nvd?')) {
        proxyNVD(req, res); return;
    }

    // Serve the web client
    if (req.url !== '/' && req.url !== '/index.html') {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('404 Not Found');
        return;
    }

    fs.readFile(HTML, 'utf8', (err, data) => {
        if (err) {
            res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('無法讀取 web-client.html：' + err.message);
            return;
        }
        const idx  = data.lastIndexOf('</body>');
        const html = data.slice(0, idx) + injectScript + '\n' + data.slice(idx);
        const buf  = Buffer.from(html, 'utf8');
        res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-store',
            'Content-Length': buf.length,
            'X-Content-Type-Options': 'nosniff',
        });
        res.end(buf);
    });
});

// Extend keep-alive timeout so the browser→proxy connection isn't closed
// between scan items when NVD responses are slow (default 5 s is too short).
server.keepAliveTimeout = 65000;
server.headersTimeout   = 66000;

// ─── Start ────────────────────────────────────────────────────────────────────
server.listen(PORT, '0.0.0.0', () => {
    const c = { bold: '\x1b[1m', reset: '\x1b[0m', cyan: '\x1b[36m', green: '\x1b[32m', gray: '\x1b[90m' };

    console.log(`\n${c.bold}CVE Web Scanner${c.reset}`);
    console.log(`${c.gray}${'─'.repeat(40)}${c.reset}`);
    console.log(`${c.gray}本機：${c.reset}    ${c.cyan}http://localhost:${PORT}${c.reset}`);

    for (const addrs of Object.values(os.networkInterfaces())) {
        for (const addr of addrs) {
            if (addr.family === 'IPv4' && !addr.internal) {
                console.log(`${c.gray}區域網路：${c.reset} ${c.bold}${c.green}http://${addr.address}:${PORT}${c.reset}`);
            }
        }
    }

    console.log(`${c.gray}${'─'.repeat(40)}${c.reset}`);
    console.log(`${c.gray}NVD 代理：${c.reset} /api/nvd → ${NVD_HOST}`);
    if (defaultApiKey)    console.log(`${c.gray}API Key：${c.reset}  已載入（0.7 秒/次）`);
    else                  console.log(`${c.gray}API Key：${c.reset}  未設定（6.5 秒/次）`);
    if (defaultWhitelist) console.log(`${c.gray}白名單：${c.reset}   ${defaultWhitelist}`);
    console.log(`${c.gray}${'─'.repeat(40)}${c.reset}`);
    console.log(`${c.gray}Ctrl+C 停止伺服器${c.reset}\n`);
});

server.on('error', err => {
    if (err.code === 'EADDRINUSE') {
        console.error(`\n錯誤：Port ${PORT} 已被佔用。請改用其他 Port：`);
        console.error(`  node web-server.js ${PORT + 1}\n`);
    } else {
        console.error('\n伺服器錯誤：', err.message);
    }
    process.exit(1);
});
