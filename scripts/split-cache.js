'use strict';

// 快取分檔工具：把 data/cve_cache、data/cpe_cache 內超過 10MB 的快取檔切成多個分檔。
//
// 平常「不需要」手動執行——程式讀寫快取時會自動分檔（lib/cache-file.js）。
// 本工具用於想「事先」整理的情境：例如把舊版的大檔搬到新環境後、或提交版控/打包之前，
// 先一次把所有超大檔切好。完全離線，不會連 NVD，只用 Node.js 內建模組。
//
// 用法：
//   npm run split-cache                    實際切割（切完逐檔讀回比對，確認內容一致）
//   npm run split-cache -- --dry-run       只列出哪些檔案會被切割，不寫入
//   npm run split-cache -- --dir=<路徑>    指定快取根目錄（預設為專案的 data/）
// 可重複執行：已經切好的檔案會被略過。

const fs     = require('fs');
const path   = require('path');
const assert = require('assert');
const { MAX_CACHE_FILE_BYTES, readCacheFile, writeCacheFile, isPartFile } = require('../lib/cache-file');

const args    = process.argv.slice(2);
const dryRun  = args.includes('--dry-run');
const dirArg  = args.find(a => a.startsWith('--dir='));
const rootDir = dirArg ? path.resolve(dirArg.slice('--dir='.length)) : path.join(__dirname, '..', 'data');

const mb = (bytes) => (bytes / 1024 / 1024).toFixed(1) + ' MB';

if (!fs.existsSync(rootDir)) {
    console.log(`找不到快取目錄：${rootDir}（尚未掃描過任何軟體，無須處理）`);
    process.exit(0);
}

console.log(`快取目錄：${rootDir}`);
console.log(`單檔上限：${mb(MAX_CACHE_FILE_BYTES)}${dryRun ? '（--dry-run：只檢查，不寫入）' : ''}\n`);

let splitCount = 0, failCount = 0, checked = 0;
for (const sub of ['cve_cache', 'cpe_cache']) {
    const dir = path.join(rootDir, sub);
    if (!fs.existsSync(dir)) continue;
    for (const f of fs.readdirSync(dir).sort()) {
        // 分檔本身（<key>.partNNN.json）不是切割對象
        if (!f.endsWith('.json') || isPartFile(f)) continue;
        checked++;
        const size = fs.statSync(path.join(dir, f)).size;
        if (size <= MAX_CACHE_FILE_BYTES) continue;

        const key = f.slice(0, -'.json'.length);
        if (dryRun) {
            console.log(`  [需切割] ${sub}/${f}（${mb(size)}）`);
            splitCount++;
            continue;
        }
        try {
            const before = readCacheFile(dir, key);
            const parts  = writeCacheFile(dir, key, before);
            // 切完立即讀回比對，確認沒有任何一筆資料遺失或變動
            assert.deepStrictEqual(readCacheFile(dir, key), before);
            console.log(`  [已切割] ${sub}/${f}（${mb(size)}）→ ${parts} 個分檔，內容比對一致`);
            splitCount++;
        } catch (e) {
            console.log(`  [失敗]   ${sub}/${f}：${e.message}`);
            failCount++;
        }
    }
}

console.log(`\n共檢查 ${checked} 個快取，${dryRun ? '需切割' : '已切割'} ${splitCount} 個${failCount ? `，失敗 ${failCount} 個` : ''}。`);
if (!splitCount && !failCount) console.log('所有快取檔皆未超過上限，無須處理。');
process.exit(failCount ? 1 : 0);
