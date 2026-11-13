'use strict';

// 快取檔讀寫（含「超過 10MB 自動分檔」），純 server-side。
// lib/nvd-client.js（讀寫快取）與 scripts/web-server.js（CVE 查詢頁籤讀快取）共用，
// 分檔格式只有這一份實作，呼叫端拿到的永遠是「合併後的完整物件」，不需關心是否分檔。
//
// 檔案配置：
//   未超過上限 → 單一檔 <key>.json（與過去格式完全相同）
//   超過上限   → 主檔   <key>.json          ：原本的描述欄位 + parts（分檔數）/ partField（被拆出的陣列欄位名）/ itemCount（總筆數）
//                分檔   <key>.part001.json… ：{ cacheKey, part, of, <partField>: [ ... ] }，每檔不超過上限
// 以「陣列元素」為單位切分（不會把單一筆 CVE 切成兩半）；單一元素本身就超過上限時獨佔一檔。

const fs   = require('fs');
const path = require('path');

// 單一快取檔的大小上限（位元組）
const MAX_CACHE_FILE_BYTES = 10 * 1024 * 1024;

// 可被拆分的陣列欄位：CVE 快取為 cves，CPE 字典快取為 products
const SPLIT_FIELDS = ['cves', 'products'];

// 分檔檔名：<key>.part001.json（快取鍵只含 a-z0-9_，不會與 .partNNN 混淆）
const PART_RE = /\.part\d+\.json$/;
function partFileName(cacheKey, n) {
    return `${cacheKey}.part${String(n).padStart(3, '0')}.json`;
}
function isPartFile(fileName) {
    return PART_RE.test(fileName);
}

// 刪除編號 >= from 的殘留分檔（分檔數變少、或縮回單一檔時清掉舊檔）
function _removePartsFrom(dir, cacheKey, from) {
    for (let n = from; ; n++) {
        const p = path.join(dir, partFileName(cacheKey, n));
        if (!fs.existsSync(p)) break;
        fs.unlinkSync(p);
    }
}

// 讀取快取，回傳完整物件（已分檔者自動合併）。檔案不存在/損毀/分檔不齊全時拋出例外，由呼叫端視為未命中。
function readCacheFile(dir, cacheKey) {
    const main = JSON.parse(fs.readFileSync(path.join(dir, `${cacheKey}.json`), 'utf-8'));
    if (!Number.isInteger(main.parts)) return main;   // 單一檔（含舊格式）

    const { parts, partField, itemCount, ...meta } = main;
    const items = [];
    for (let n = 1; n <= parts; n++) {
        const part = JSON.parse(fs.readFileSync(path.join(dir, partFileName(cacheKey, n)), 'utf-8'));
        if (part.part !== n || !Array.isArray(part[partField])) throw new Error(`快取分檔格式不符：${partFileName(cacheKey, n)}`);
        for (const item of part[partField]) items.push(item);
    }
    // 寫入中途中斷會造成主檔與分檔不一致，筆數對不上就視為損毀（呼叫端會重新下載）
    if (items.length !== itemCount) throw new Error(`快取分檔筆數不符：${cacheKey}`);
    return { ...meta, [partField]: items };
}

// 寫入快取；序列化後超過 maxBytes 就把陣列欄位拆到多個分檔。回傳實際分檔數（0 = 單一檔）。
function writeCacheFile(dir, cacheKey, data, maxBytes = MAX_CACHE_FILE_BYTES) {
    fs.mkdirSync(dir, { recursive: true });
    const mainPath = path.join(dir, `${cacheKey}.json`);
    const field = SPLIT_FIELDS.find(f => Array.isArray(data[f]));

    // 逐筆序列化（縮排與整檔 JSON.stringify(data, null, 2) 時該元素所在層級一致），同時算出各筆位元組數
    const INDENT = '    ';
    const texts = field ? data[field].map(v => INDENT + JSON.stringify(v, null, 2).replace(/\n/g, '\n' + INDENT)) : [];
    const sizes = texts.map(t => Buffer.byteLength(t) + 2);   // +2：元素之間的「,\n」
    const OVERHEAD = 1024;                                    // 描述欄位與括號的保守估計
    const total = sizes.reduce((a, b) => a + b, 0) + OVERHEAD;

    if (!field || total <= maxBytes) {
        fs.writeFileSync(mainPath, JSON.stringify(data, null, 2), 'utf-8');
        _removePartsFrom(dir, cacheKey, 1);
        return 0;
    }

    // 依序裝箱：累計超過上限就開新檔
    const groups = [];
    let cur = [], curSize = OVERHEAD;
    for (let i = 0; i < texts.length; i++) {
        if (cur.length && curSize + sizes[i] > maxBytes) { groups.push(cur); cur = []; curSize = OVERHEAD; }
        cur.push(texts[i]);
        curSize += sizes[i];
    }
    if (cur.length) groups.push(cur);

    // 先寫分檔、再寫主檔、最後清掉多餘的舊分檔
    groups.forEach((g, idx) => {
        const head = `{\n  "cacheKey": ${JSON.stringify(cacheKey)},\n  "part": ${idx + 1},\n  "of": ${groups.length},\n  ${JSON.stringify(field)}: [\n`;
        fs.writeFileSync(path.join(dir, partFileName(cacheKey, idx + 1)), head + g.join(',\n') + '\n  ]\n}', 'utf-8');
    });
    const { [field]: _omit, ...meta } = data;
    fs.writeFileSync(mainPath, JSON.stringify({ ...meta, parts: groups.length, partField: field, itemCount: texts.length }, null, 2), 'utf-8');
    _removePartsFrom(dir, cacheKey, groups.length + 1);
    return groups.length;
}

module.exports = { MAX_CACHE_FILE_BYTES, readCacheFile, writeCacheFile, isPartFile, partFileName };
