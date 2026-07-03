#!/usr/bin/env node
'use strict';

// ─── 部署打包工具 ───────────────────────────────────────────────────────────────
// 把「執行本程式所需的必要檔案」壓成一個 zip，供部署到公司環境。
// 使用專案既有的 adm-zip（唯一核准的外部套件）。
//
// 預設納入：程式碼（lib/、scripts/）、findSW.ps1、文件、以及本機 CVE 查詢快取
//   （data/cve_cache、data/cpe_cache）→ 公司端首次掃描可暖啟動、少打 NVD。
// 預設排除（大型 / 機密 / 本機專屬 / 建置產物）：
//   .env.local（含 NIST_API_KEY！）、logs/、data/mitre_mirror/、report/、team/、
//   node_modules/、.git/、scan.json、docs/*.pptx、
//   scripts/_bundle.js 與 scripts/web-client.html（建置產物，會內嵌本機 PORTABLE_N/whitelist，
//   公司端 `npm run web` 會用他們自己的 .env.local 重新產生）。
//
// 用法：
//   node scripts/package-deploy.js                 # 預設（含快取、不含 node_modules）
//   node scripts/package-deploy.js --no-cache      # 不含 CVE 快取（乾淨部署）
//   node scripts/package-deploy.js --with-node-modules   # 連 node_modules 一起打包（離線環境）
//   node scripts/package-deploy.js --out=D:/x.zip  # 指定輸出路徑

const fs   = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');

const ROOT = path.join(__dirname, '..');
const TOP  = 'NISTCVECheck'; // zip 內最上層資料夾，解壓後乾淨落在此目錄

// ── 解析參數 ──
const args = process.argv.slice(2);
const noCache        = args.includes('--no-cache');
const withNodeMods   = args.includes('--with-node-modules');
const outArg         = (args.find(a => a.startsWith('--out=')) || '').slice('--out='.length);

// ── 納入清單（明確列舉，避免誤打包機密）──
const INCLUDE = [
    'package.json', 'package-lock.json',
    'README.md', 'CLAUDE.md', 'LICENSE',
    '.env.local.example',
    'findSW.ps1',
    'lib', 'scripts', 'docs',
];
if (!noCache)      INCLUDE.push('data/cve_cache', 'data/cpe_cache');
if (withNodeMods)  INCLUDE.push('node_modules');

// ── 排除規則（作用於納入目錄底下的個別檔案，rel 為相對 ROOT 的 POSIX 路徑）──
function isExcluded(rel) {
    const base = path.posix.basename(rel);
    // 機密：任何 .env.local（保險，避免未來新增納入路徑時誤帶）
    if (base === '.env.local') return true;
    // 建置產物（會內嵌本機設定，公司端自行重建）
    if (rel === 'scripts/_bundle.js' || rel === 'scripts/web-client.html') return true;
    // 大型二進位簡報（部署執行不需要）
    if (rel.startsWith('docs/') && base.toLowerCase().endsWith('.pptx')) return true;
    // 系統雜檔
    if (base === '.DS_Store' || base === 'Thumbs.db') return true;
    // 防禦性：即使被誤列入納入清單也擋掉這些大型/本機專屬目錄
    const banned = ['logs/', 'data/mitre_mirror/', 'report/', 'team/', '.git/'];
    if (!withNodeMods) banned.push('node_modules/');
    if (banned.some(b => rel === b.slice(0, -1) || rel.startsWith(b))) return true;
    return false;
}

// ── 遞迴收集檔案 ──
const files = []; // { full, rel }
function collect(rel) {
    if (isExcluded(rel)) return;
    const full = path.join(ROOT, rel);
    let st;
    try { st = fs.statSync(full); } catch { return; } // 不存在就略過（如尚未建立快取）
    if (st.isDirectory()) {
        for (const name of fs.readdirSync(full)) {
            collect(path.posix.join(rel, name));
        }
    } else if (st.isFile()) {
        files.push({ full, rel, size: st.size });
    }
}
for (const entry of INCLUDE) collect(entry);

if (files.length === 0) {
    console.error('沒有任何檔案可打包（請確認在專案根目錄執行）。');
    process.exit(1);
}

// ── 安全檢查：確保沒有機密外洩 ──
const leaked = files.filter(f => path.posix.basename(f.rel) === '.env.local');
if (leaked.length) {
    console.error(`安全中止：偵測到機密檔案被納入 → ${leaked.map(f => f.rel).join(', ')}`);
    process.exit(1);
}

// ── 建立 zip ──
const zip = new AdmZip();
for (const f of files) {
    const entry = path.posix.join(TOP, f.rel);
    zip.addLocalFile(f.full, path.posix.dirname(entry), path.posix.basename(entry));
}

// ── 輸出路徑（預設 dist/，已在 .gitignore）──
const pad2 = n => String(n).padStart(2, '0');
const d = new Date();
const stamp = `${d.getFullYear()}${pad2(d.getMonth() + 1)}${pad2(d.getDate())}`;
const outPath = outArg
    ? path.resolve(outArg)
    : path.join(ROOT, 'dist', `NISTCVECheck_deploy_${stamp}.zip`);
fs.mkdirSync(path.dirname(outPath), { recursive: true });
zip.writeZip(outPath);

// ── 摘要 ──
const totalBytes = files.reduce((s, f) => s + f.size, 0);
const zipBytes   = fs.statSync(outPath).size;
const mb = b => (b / 1024 / 1024).toFixed(2) + ' MB';

// 依最上層路徑分組統計
const groups = {};
for (const f of files) {
    const top = f.rel.includes('/') ? f.rel.split('/').slice(0, 2).join('/') : f.rel;
    const key = top.startsWith('data/') ? top : (f.rel.split('/')[0]);
    (groups[key] ??= { count: 0, size: 0 });
    groups[key].count++; groups[key].size += f.size;
}

console.log('═'.repeat(60));
console.log('部署封裝完成');
console.log('═'.repeat(60));
console.log(`輸出：${outPath}`);
console.log(`檔案數：${files.length}｜原始大小：${mb(totalBytes)}｜壓縮後：${mb(zipBytes)}`);
console.log(`CVE 快取：${noCache ? '未納入（--no-cache）' : '已納入'}｜node_modules：${withNodeMods ? '已納入' : '未納入（公司端 npm install）'}`);
console.log('─'.repeat(60));
console.log('內容組成：');
for (const [k, v] of Object.entries(groups).sort()) {
    console.log(`  ${k.padEnd(20)} ${String(v.count).padStart(4)} 檔  ${mb(v.size).padStart(10)}`);
}
console.log('─'.repeat(60));
console.log('公司端部署步驟：');
console.log('  1. 解壓縮 → 進入 NISTCVECheck/ 目錄');
console.log('  2. 複製 .env.local.example 為 .env.local，填入 NIST_API_KEY 與 PORTABLE_N');
console.log('  3. npm install            （取得 adm-zip）');
console.log('  4. npm start              （CLI 掃描）  或  npm run web （Web 介面）');
console.log('═'.repeat(60));
