#!/usr/bin/env node
'use strict';

// ─── 部署打包工具 ───────────────────────────────────────────────────────────────
// 把「執行本程式所需的必要檔案」壓成一個 rar，供部署到公司環境。
// RAR 是專屬格式，只有 WinRAR 的命令列工具 Rar.exe 能產生（沒有任何函式庫可寫 RAR），
// 因此本工具呼叫本機已安裝的 WinRAR；不需要任何 npm 套件。
// Rar.exe 尋找順序：環境變數 RAR_PATH → 「Program Files\WinRAR\Rar.exe」→ PATH 中的 rar。
//
// 預設納入：程式碼（lib/、scripts/）、findSW.ps1、文件。
// 預設排除（大型 / 機密 / 本機專屬 / 建置產物）：
//   data/（CVE／CPE 快取，上百 MB；公司端首次掃描會自行向 NVD 下載並建立）、
//   .env.local（含 NIST_API_KEY！）、logs/、report/、team/、
//   node_modules/、.git/、scan.json、docs/*.pptx、
//   scripts/_bundle.js 與 scripts/web-client.html（建置產物，會內嵌本機 PORTABLE_N/whitelist，
//   公司端 `npm run web` 會用他們自己的 .env.local 重新產生）。
//
// 用法：
//   node scripts/package-deploy.js                 # 預設（不含 data/ 快取）
//   node scripts/package-deploy.js --with-cache    # 連 data/ 快取一起打包（檔案很大，公司端可免首次下載）
//   node scripts/package-deploy.js --out=D:/x.rar  # 指定輸出路徑

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const TOP  = 'NISTCVECheck'; // rar 內最上層資料夾，解壓後乾淨落在此目錄

// ── 解析參數 ──
const args = process.argv.slice(2);
const withCache      = args.includes('--with-cache');
const outArg         = (args.find(a => a.startsWith('--out=')) || '').slice('--out='.length);

// ── 納入清單（明確列舉，避免誤打包機密）──
const INCLUDE = [
    'package.json', 'package-lock.json',
    'README.md', 'CLAUDE.md', 'LICENSE',
    '.env.local.example',
    'findSW.ps1',
    'lib', 'scripts', 'docs',
];
// data/ 快取預設不打包（太大）；需要時以 --with-cache 明確指定
if (withCache)     INCLUDE.push('data/cve_cache', 'data/cpe_cache');

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
    const banned = ['logs/', 'report/', 'team/', '.git/', 'node_modules/'];
    if (!withCache) banned.push('data/');
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

// ── 尋找 WinRAR 命令列工具 Rar.exe ──
function findRar() {
    const candidates = [
        process.env.RAR_PATH,
        process.env.ProgramFiles         && path.join(process.env.ProgramFiles, 'WinRAR', 'Rar.exe'),
        process.env['ProgramFiles(x86)'] && path.join(process.env['ProgramFiles(x86)'], 'WinRAR', 'Rar.exe'),
    ].filter(Boolean);
    for (const c of candidates) {
        if (fs.existsSync(c)) return c;
    }
    // 最後嘗試 PATH 中的 rar（執行得起來才算數）
    try { execFileSync('rar', ['-?'], { stdio: 'ignore' }); return 'rar'; } catch { return null; }
}
const rarExe = findRar();
if (!rarExe) {
    console.error('找不到 WinRAR 的命令列工具 Rar.exe，無法產生 rar。');
    console.error('請安裝 WinRAR，或以環境變數 RAR_PATH 指定 Rar.exe 的完整路徑。');
    process.exit(1);
}

// ── 輸出路徑（預設 dist/，已在 .gitignore）──
const pad2 = n => String(n).padStart(2, '0');
const d = new Date();
const stamp = `${d.getFullYear()}${pad2(d.getMonth() + 1)}${pad2(d.getDate())}`;
const outPath = outArg
    ? path.resolve(outArg)
    : path.join(ROOT, 'dist', `NISTCVECheck_deploy_${stamp}.rar`);
fs.mkdirSync(path.dirname(outPath), { recursive: true });
// rar 的 a 指令遇到既有壓縮檔是「更新」而非重建，會殘留上次的舊檔，故先刪除
fs.rmSync(outPath, { force: true });

// ── 建立 rar ──
// 以清單檔（@listfile）明確列出要壓的檔案，只有通過納入/排除規則的檔案會進壓縮檔。
//   a         新增到壓縮檔      -m5   最高壓縮率
//   -ap<dir>  壓縮檔內的最上層資料夾（解壓後乾淨落在 NISTCVECheck/）
//   -scFL     清單檔為 UTF-8    -idq  安靜模式    -y  一律回答 yes
const listFile = path.join(os.tmpdir(), `nistcve_deploy_${process.pid}.lst`);
fs.writeFileSync(listFile, files.map(f => f.rel.split('/').join(path.sep)).join('\r\n'), 'utf-8');
try {
    execFileSync(rarExe, ['a', '-m5', `-ap${TOP}`, '-scFL', '-idq', '-y', outPath, `@${listFile}`],
                 { cwd: ROOT, stdio: ['ignore', 'ignore', 'inherit'] });
} catch (e) {
    console.error(`rar 壓縮失敗：${e.message}`);
    process.exit(1);
} finally {
    fs.rmSync(listFile, { force: true });
}

// ── 摘要 ──
const totalBytes = files.reduce((s, f) => s + f.size, 0);
const rarBytes   = fs.statSync(outPath).size;
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
console.log(`檔案數：${files.length}｜原始大小：${mb(totalBytes)}｜壓縮後：${mb(rarBytes)}`);
console.log(`data/ 快取：${withCache ? '已納入（--with-cache）' : '未納入（公司端首次掃描會自行向 NVD 下載）'}`);
console.log('─'.repeat(60));
console.log('內容組成：');
for (const [k, v] of Object.entries(groups).sort()) {
    console.log(`  ${k.padEnd(20)} ${String(v.count).padStart(4)} 檔  ${mb(v.size).padStart(10)}`);
}
console.log('─'.repeat(60));
console.log('公司端部署步驟：');
console.log('  1. 解壓縮 → 進入 NISTCVECheck/ 目錄');
console.log('  2. 複製 .env.local.example 為 .env.local，填入 NIST_API_KEY 與 PORTABLE_N');
console.log('  3. npm start              （CLI 掃描）  或  npm run web （Web 介面）');
console.log('═'.repeat(60));
