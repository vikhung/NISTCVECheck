'use strict';

// lib/cache-file.js 回歸測試：快取檔超過上限時分檔儲存，讀回時自動合併。
// 用暫存目錄與調小的上限（不需真的產生 10MB 檔案），不需網路。

const test   = require('node:test');
const assert = require('node:assert');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const { readCacheFile, writeCacheFile, isPartFile, partFileName } = require('../../lib/cache-file');
const { createNvdClient } = require('../../lib/nvd-client');

// 建立暫存目錄，測試結束自動刪除
function tmpDir(t) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cachefile-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    return dir;
}

// 產生 n 筆假 CVE（每筆約 500 位元組，含中文確認以「位元組」而非字元數計算）
function fakeCves(n) {
    return Array.from({ length: n }, (_, i) => ({
        cve: { id: `CVE-2025-${String(i).padStart(5, '0')}`, published: '2025-06-01T00:00:00.000', descriptions: [{ lang: 'en', value: '說明'.repeat(60) + 'x'.repeat(100) }] },
    }));
}
const makeData = (n) => ({ cveCount: n, cacheKey: 'kw_demo', coverageStart: '2025-01-01T00:00:00.000Z', lastFetchedAt: '2026-01-01T00:00:00.000Z', cves: fakeCves(n) });

test('未超過上限：維持單一檔，格式與過去相同', (t) => {
    const dir = tmpDir(t);
    const data = makeData(5);
    assert.strictEqual(writeCacheFile(dir, 'kw_demo', data, 1024 * 1024), 0);
    assert.deepStrictEqual(fs.readdirSync(dir), ['kw_demo.json']);
    assert.deepStrictEqual(JSON.parse(fs.readFileSync(path.join(dir, 'kw_demo.json'), 'utf-8')), data);
    assert.deepStrictEqual(readCacheFile(dir, 'kw_demo'), data);
});

test('超過上限：分檔儲存，每檔不超過上限，讀回內容與順序完全相同', (t) => {
    const dir = tmpDir(t);
    const MAX = 8 * 1024;
    const data = makeData(100);
    const parts = writeCacheFile(dir, 'kw_demo', data, MAX);
    assert.ok(parts > 1, '應拆成多個分檔');

    const files = fs.readdirSync(dir).sort();
    assert.strictEqual(files.length, parts + 1);
    for (const f of files) {
        assert.ok(fs.statSync(path.join(dir, f)).size <= MAX, `${f} 超過上限`);
    }
    // 主檔只留描述欄位，不含 cves
    const main = JSON.parse(fs.readFileSync(path.join(dir, 'kw_demo.json'), 'utf-8'));
    assert.strictEqual(main.cves, undefined);
    assert.strictEqual(main.parts, parts);
    assert.strictEqual(main.itemCount, 100);
    assert.strictEqual(main.coverageStart, data.coverageStart);
    assert.ok(isPartFile(partFileName('kw_demo', 1)) && !isPartFile('kw_demo.json'));

    assert.deepStrictEqual(readCacheFile(dir, 'kw_demo'), data);
});

test('資料變少：多餘的舊分檔會被清除；縮回上限內則恢復單一檔', (t) => {
    const dir = tmpDir(t);
    const MAX = 8 * 1024;
    const many = writeCacheFile(dir, 'kw_demo', makeData(100), MAX);
    const fewer = writeCacheFile(dir, 'kw_demo', makeData(40), MAX);
    assert.ok(fewer < many);
    assert.strictEqual(fs.readdirSync(dir).length, fewer + 1);
    assert.strictEqual(readCacheFile(dir, 'kw_demo').cves.length, 40);

    writeCacheFile(dir, 'kw_demo', makeData(3), MAX);
    assert.deepStrictEqual(fs.readdirSync(dir), ['kw_demo.json']);
    assert.strictEqual(readCacheFile(dir, 'kw_demo').cves.length, 3);
});

test('分檔缺漏或筆數不符：讀取拋出例外（呼叫端視為未命中）', (t) => {
    const dir = tmpDir(t);
    const parts = writeCacheFile(dir, 'kw_demo', makeData(100), 8 * 1024);
    fs.unlinkSync(path.join(dir, partFileName('kw_demo', parts)));
    assert.throws(() => readCacheFile(dir, 'kw_demo'));
});

test('單一元素本身超過上限：獨佔一檔，資料不遺失', (t) => {
    const dir = tmpDir(t);
    const data = makeData(4);
    data.cves[1].cve.descriptions[0].value = 'y'.repeat(20 * 1024);
    writeCacheFile(dir, 'kw_demo', data, 8 * 1024);
    assert.deepStrictEqual(readCacheFile(dir, 'kw_demo'), data);
});

test('nvd-client：舊版超大單一檔在讀取時自動改存為分檔，查詢結果不變', (t) => {
    const root = tmpDir(t);
    const dir  = path.join(root, 'cve_cache');
    fs.mkdirSync(dir);
    const data = makeData(100);
    fs.writeFileSync(path.join(dir, 'kw_demo.json'), JSON.stringify(data, null, 2), 'utf-8');   // 舊格式

    const client = createNvdClient({ fetchFn: () => { throw new Error('不應連網'); }, cacheDir: root, maxFileBytes: 8 * 1024 });
    const { cves } = client.queryCVECache({ queryType: 'keyword', queryValue: 'demo', coverageStart: new Date('2025-01-01') });
    assert.strictEqual(cves.length, 100);
    assert.ok(fs.readdirSync(dir).some(isPartFile), '應已轉成分檔');
    assert.ok(fs.statSync(path.join(dir, 'kw_demo.json')).size <= 8 * 1024);
    // 再讀一次（此時走分檔路徑）結果相同
    assert.deepStrictEqual(client.queryCVECache({ queryType: 'keyword', queryValue: 'demo', coverageStart: new Date('2025-01-01') }).cves, cves);
});
