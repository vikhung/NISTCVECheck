// MITRE 本機鏡像客戶端：讀取 scripts/mitre-sync.js 建立的 data/mitre_mirror/index/ NDJSON 索引，
// 對外介面與 lib/nvd-client.js 的 createNvdClient() 完全相容（{ fetchCVEs, fetchCPEs }），
// 讓 scripts/cve-checker.js、scripts/web-server.js 只需切換要呼叫哪個 factory，無需改呼叫端邏輯。
'use strict';

const fs   = require('fs');
const path = require('path');
const { toNvdShape } = require('./mitre-adapter');

function createMitreClient({ mirrorDir, logger = null }) {
    const indexDir = path.join(mirrorDir, 'index');
    const metaPath = path.join(indexDir, 'meta.json');

    // 建構時立即檢查索引是否存在（fail-fast），不要等第一次查詢才發現沒同步過
    if (!fs.existsSync(metaPath)) {
        throw new Error(`MITRE 本機索引不存在，請先執行：npm run sync-mitre`);
    }
    const meta = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));
    if (!meta.yearsIndexed || meta.yearsIndexed.length === 0) {
        throw new Error(`MITRE 本機索引是空的（0 個年份），請先執行：npm run sync-mitre`);
    }

    const _shardCache = new Map(); // year(string) -> record[]
    function _loadYearShard(year) {
        const key = String(year);
        if (_shardCache.has(key)) return _shardCache.get(key);
        const filePath = path.join(indexDir, `${key}.ndjson`);
        let records = [];
        if (fs.existsSync(filePath)) {
            records = fs.readFileSync(filePath, 'utf-8')
                .split('\n')
                .filter(Boolean)
                .map(line => { try { return JSON.parse(line); } catch { return null; } })
                .filter(Boolean);
        }
        _shardCache.set(key, records);
        return records;
    }

    function _yearsInRange(start, end) {
        const years = [];
        for (let y = start.getUTCFullYear(); y <= end.getUTCFullYear(); y++) years.push(y);
        // 只考慮實際有索引的年份，避免白白嘗試讀取不存在的 shard 檔
        return years.filter(y => meta.yearsIndexed.includes(String(y)));
    }

    function _matchesKeyword(record, kw) {
        return record.descLower.includes(kw)
            || record.vendors.some(v => v.includes(kw))
            || record.products.some(p => p.includes(kw));
    }

    function _matchesCpe(record, vendor, product) {
        return record.vendors.includes(vendor) && record.products.includes(product);
    }

    async function fetchCVEs({ queryType, queryValue, coverageStart, endDate, log: itemLog }) {
        const emit  = itemLog || (() => {});
        const start = coverageStart || new Date(new Date().getFullYear() - 5, 0, 1);
        const end   = endDate || new Date();
        const years = _yearsInRange(start, end);

        const matched = [];
        for (const year of years) {
            for (const rec of _loadYearShard(year)) {
                if (rec.state !== 'PUBLISHED') continue;
                const published = new Date(rec.published);
                if (published < start || published > end) continue;

                const isMatch = queryType === 'cpe'
                    ? _matchesCpe(rec, queryValue.vendor.toLowerCase(), queryValue.product.toLowerCase())
                    : _matchesKeyword(rec, String(queryValue).toLowerCase());
                if (!isMatch) continue;

                matched.push(toNvdShape(rec));
            }
        }
        emit('cache', `[MITRE 本機索引] ${matched.length} 筆（${years.join(',')} 年）`);
        // 本機鏡像沒有「即時查詢 vs 快取」的區分，一律視為 fromCache（語意上忠實：永遠讀本機資料）
        return { cves: matched, fromCache: true, newCount: 0 };
    }

    // MITRE 沒有真正的 CPE 字典，掃描索引中符合關鍵字的 vendor/product 組合，
    // 合成與 NVD CPE API 回應相容的 shape，讓既有 findAllCPEBases() 不需修改即可運作。
    async function fetchCPEs(keyword) {
        const kw = keyword.toLowerCase();
        const seen = new Set();
        const products = [];
        for (const year of meta.yearsIndexed) {
            for (const rec of _loadYearShard(year)) {
                for (const vendor of rec.vendors) {
                    for (const product of rec.products) {
                        if (!`${vendor} ${product}`.includes(kw)) continue;
                        const key = `${vendor}:${product}`;
                        if (seen.has(key)) continue;
                        seen.add(key);
                        products.push({ cpe: { cpeName: `cpe:2.3:a:${vendor}:${product}:*:*:*:*:*:*:*:*` } });
                    }
                }
            }
        }
        return { products, fromCache: true };
    }

    logger?.('info', '', `MITRE 本機索引已載入：${meta.yearsIndexed.join(', ')} 年，共 ${meta.cveCount} 筆 CVE（同步時間：${meta.lastSyncedAt}）`);

    return { fetchCVEs, fetchCPEs };
}

module.exports = { createMitreClient };
