// lib/scan-software.js 回歸測試（Node 原生 node:test，無外部套件；以假的 nvdClient，不需網路）。
// 執行：npm test  或  node --test "scripts/test/scan-software.test.js"
//
// 這支流程過去在 cve-checker.js 與 web-server.js 各複製一份；這裡固定共用版的關鍵行為：
//   CPE_BASE_N 指定跳過字典、字典收斂（精確/通用）、多 base 合併去重、keyword 補撈守門。
const { test } = require('node:test');
const assert = require('node:assert');
const S = require('../../lib/scan-software.js');

const mkCpe = vp => ({ cpe: { cpeName: `cpe:2.3:a:${vp}:*:*:*:*:*:*:*:*` } });
const mkCve = (id, { criteria, refs = [] } = {}) => ({
    cve: {
        id,
        configurations: criteria ? [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria }] }] }] : [],
        references: refs.map(url => ({ url })),
    },
});

// 假的 nvdClient：記錄呼叫（update＝下載增量、query＝查快取）並依 queryType/queryValue 回傳預設資料。
// incremental=true 模擬「每天首次執行，有實際下載增量」；預設為「今天已查過，略過下載」。
function fakeClient({ cpe = { products: [], fromCache: true }, cves = {}, incremental = false } = {}) {
    const calls = [];
    const keyOf = (queryType, queryValue) => (queryType === 'cpe' ? `${queryValue.vendor}:${queryValue.product}` : `kw:${queryValue}`);
    return {
        calls,
        async fetchCPEs(keyword) { calls.push(['cpe', keyword]); return cpe; },
        async updateCVECache({ queryType, queryValue }) {
            calls.push(['update', keyOf(queryType, queryValue)]);
            return incremental
                ? { updated: true, newCount: 0, cacheNote: '已補查 2026-10-13 至今增量，新增 0 筆' }
                : { updated: false, newCount: 0, cacheNote: '今天已查詢' };
        },
        queryCVECache({ queryType, queryValue }) {
            const key = keyOf(queryType, queryValue);
            calls.push(['query', key]);
            return { cves: cves[key] || [] };
        },
    };
}
const collect = () => { const lines = []; const log = (level, msg) => lines.push([level, msg]); log.lines = lines; return log; };

// ── 環境變數解析 ───────────────────────────────────────────────────────────────
test('parseCpeBases: 名稱小寫、多 vendor:product、略過格式不全者', () => {
    const map = S.parseCpeBases({
        CPE_BASE_0: 'Python|python:python',
        CPE_BASE_1: 'git|git-scm:git|git:git',
        CPE_BASE_2: 'broken',
    });
    assert.deepStrictEqual(map, {
        python: [{ vendor: 'python', product: 'python' }],
        git: [{ vendor: 'git-scm', product: 'git' }, { vendor: 'git', product: 'git' }],
    });
});

test('parseCacheAliases: 第一個為正式名稱，其餘為別名（皆小寫）', () => {
    assert.deepStrictEqual(
        S.parseCacheAliases({ CACHE_ALIAS_0: 'Node.js|nodejs|node' }),
        { 'node.js': ['nodejs', 'node'] },
    );
});

// ── resolveCpeBases ───────────────────────────────────────────────────────────
test('resolveCpeBases: CPE_BASE_N 命中 → 完全略過 CPE 字典查詢', async () => {
    const client = fakeClient();
    const log = collect();
    const r = await S.resolveCpeBases({
        nvdClient: client, searchName: 'Python', isPortable: false,
        cpeBaseMap: { python: [{ vendor: 'python', product: 'python' }] }, log,
    });
    assert.deepStrictEqual(r.cpeBases, [{ vendor: 'python', product: 'python' }]);
    assert.strictEqual(client.calls.length, 0, '不應呼叫 fetchCPEs');
    assert.match(log.lines[0][1], /\[CPE 指定\]/);
});

test('resolveCpeBases: 非 Portable 走精確模式（Webex 只命中 cisco:webex）', async () => {
    const products = [mkCpe('cisco:webex'), mkCpe('cisco:webex_meetings'), mkCpe('cisco:webex_teams')];
    const client = fakeClient({ cpe: { products, fromCache: false } });
    const r = await S.resolveCpeBases({ nvdClient: client, searchName: 'Webex', isPortable: false, log: collect() });
    assert.deepStrictEqual(r.cpeBases, [{ vendor: 'cisco', product: 'webex' }]);
});

test('resolveCpeBases: 字典過於通用 → 空 cpeBases 並提示改用關鍵字', async () => {
    const client = fakeClient({ cpe: { products: [], fromCache: false, tooGeneric: true, totalResults: 12546 } });
    const log = collect();
    const r = await S.resolveCpeBases({ nvdClient: client, searchName: 'Git', isPortable: false, log });
    assert.deepStrictEqual(r.cpeBases, []);
    assert.strictEqual(r.tooGeneric, true);
    assert.strictEqual(log.lines.at(-1)[1], '關鍵字過於通用(命中 12546 筆 CPE)，改用關鍵字搜尋');
});

test('resolveCpeBases: Portable 找不到 CPE → warn 等級', async () => {
    const log = collect();
    await S.resolveCpeBases({ nvdClient: fakeClient(), searchName: 'MyTool', isPortable: true, log });
    assert.deepStrictEqual(log.lines.at(-1), ['warn', '⚠ 未找到對應 CPE，改用關鍵字比對']);
});

test('resolveCpeBases: fetchCPEs 拋錯時不中斷（視為查無 CPE）', async () => {
    const client = { async fetchCPEs() { throw new Error('boom'); } };
    const r = await S.resolveCpeBases({ nvdClient: client, searchName: 'X', isPortable: false, log: collect() });
    assert.deepStrictEqual(r.cpeBases, []);
});

// ── fetchSoftwareCVEs ─────────────────────────────────────────────────────────
const bases = [{ vendor: 'yaxim', product: 'bruno' }, { vendor: 'usebruno', product: 'bruno' }];
const range = { coverageStart: new Date('2025-01-01'), endDate: new Date('2026-01-01') };

test('fetchSoftwareCVEs: 逐一查詢每個 base 並依 CVE id 合併去重', async () => {
    const shared = mkCve('CVE-1', { criteria: 'cpe:2.3:a:usebruno:bruno:*:*:*:*:*:*:*:*' });
    const client = fakeClient({ cves: {
        'yaxim:bruno': [shared],
        'usebruno:bruno': [shared, mkCve('CVE-2', { criteria: 'cpe:2.3:a:usebruno:bruno:*:*:*:*:*:*:*:*' })],
    } });
    const r = await S.fetchSoftwareCVEs({ nvdClient: client, searchName: 'Bruno', cpeBases: bases, log: collect(), ...range });
    assert.deepStrictEqual(r.cves.map(v => v.cve.id).sort(), ['CVE-1', 'CVE-2']);
    // 先全部下載增量，再全部查快取（兩階段），最後才處理 keyword 補撈的下載與查詢
    assert.deepStrictEqual(client.calls, [
        ['update', 'yaxim:bruno'], ['update', 'usebruno:bruno'],
        ['query', 'yaxim:bruno'], ['query', 'usebruno:bruno'],
        ['update', 'kw:Bruno'], ['query', 'kw:Bruno'],
    ]);
});

test('fetchSoftwareCVEs: 補撈只併入「無 CPE 且參考連結指向本軟體」者', async () => {
    const pending = mkCve('CVE-PENDING', { refs: ['https://github.com/usebruno/bruno/issues/1'] });
    const unrelatedNoCpe = mkCve('CVE-NOISE', { refs: ['https://example.com/advisory/other'] });
    const otherVendor = mkCve('CVE-OTHER', { criteria: 'cpe:2.3:a:someone:bruno-clone:*:*:*:*:*:*:*:*',
        refs: ['https://github.com/usebruno/bruno/issues/2'] });
    const client = fakeClient({ cves: { 'kw:Bruno': [pending, unrelatedNoCpe, otherVendor] } });
    const log = collect();
    const r = await S.fetchSoftwareCVEs({ nvdClient: client, searchName: 'Bruno', cpeBases: bases, log, ...range });
    assert.deepStrictEqual(r.cves.map(v => v.cve.id), ['CVE-PENDING']);
    // keyword 命中 3 筆：1 筆確屬本軟體併入、2 筆無相關（無 CPE 但連結不符／屬別 vendor），無上述已重複者
    assert.ok(log.lines.some(([, m]) => m === '[CVE 快取] 命中 1 筆(共命中 3 筆，0筆上述已重複，2筆無相關，今天已查詢)'));
});

test('fetchSoftwareCVEs: 補撈 0 筆也印一行說明（含 0 筆）', async () => {
    const log = collect();
    await S.fetchSoftwareCVEs({ nvdClient: fakeClient(), searchName: 'Bruno', cpeBases: bases, log, ...range });
    assert.ok(log.lines.some(([, m]) => m === '[CVE 快取] 命中 0 筆(共命中 0 筆，0筆上述已重複，0筆無相關，今天已查詢)'));
});

test('fetchSoftwareCVEs: 無 cpeBases → 只做 keyword 查詢（不補撈）', async () => {
    const client = fakeClient({ cves: { 'kw:Git': [mkCve('CVE-G')] } });
    const r = await S.fetchSoftwareCVEs({ nvdClient: client, searchName: 'Git', cpeBases: [], log: collect(), ...range });
    assert.deepStrictEqual(r.cves.map(v => v.cve.id), ['CVE-G']);
    assert.deepStrictEqual(client.calls, [['update', 'kw:Git'], ['query', 'kw:Git']]);
});

test('lookupSoftwareCVEs: CPE 偵測 + 查詢整合，並回傳 cpeBases', async () => {
    const client = fakeClient({
        cpe: { products: [mkCpe('usebruno:bruno'), mkCpe('yaxim:bruno')], fromCache: true },
        cves: { 'usebruno:bruno': [mkCve('CVE-A', { criteria: 'cpe:2.3:a:usebruno:bruno:*:*:*:*:*:*:*:*' })] },
    });
    const r = await S.lookupSoftwareCVEs({ nvdClient: client, searchName: 'Bruno', isPortable: false, ...range, log: collect() });
    assert.strictEqual(r.cpeBases.length, 2);
    assert.deepStrictEqual(r.cves.map(v => v.cve.id), ['CVE-A']);
});

test('fetchSoftwareCVEs: keyword 命中筆數＝上步驟已查出＋無相關＋併入（log 數字可對帳）', async () => {
    const found = mkCve('CVE-FOUND', { criteria: 'cpe:2.3:a:usebruno:bruno:*:*:*:*:*:*:*:*' });
    const pending = mkCve('CVE-PENDING', { refs: ['https://github.com/usebruno/bruno/issues/1'] });
    const noiseA = mkCve('CVE-NOISE-A', { refs: ['https://patchstack.com/database/x'] });
    const noiseB = mkCve('CVE-NOISE-B', { criteria: 'cpe:2.3:a:skyphe:file_gallery:*:*:*:*:*:*:*:*' });
    const client = fakeClient({ cves: {
        'usebruno:bruno': [found],
        'kw:Bruno': [found, pending, noiseA, noiseB],
    } });
    const log = collect();
    const r = await S.fetchSoftwareCVEs({ nvdClient: client, searchName: 'Bruno', cpeBases: bases, log, ...range });
    assert.deepStrictEqual(r.cves.map(v => v.cve.id).sort(), ['CVE-FOUND', 'CVE-PENDING']);
    assert.ok(log.lines.some(([, m]) => m === '[CVE 快取] 命中 1 筆(共命中 4 筆，1筆上述已重複，2筆無相關，今天已查詢)'));
});

test('fetchSoftwareCVEs: 輸出格式——四階段（下載增量→查快取→下載補撈增量→查補撈快取），今天已查過', async () => {
    const client = fakeClient({ cves: { 'usebruno:bruno': [mkCve('CVE-A', { criteria: 'cpe:2.3:a:usebruno:bruno:*:*:*:*:*:*:*:*' })] } });
    const log = collect();
    await S.fetchSoftwareCVEs({ nvdClient: client, searchName: 'Bruno', cpeBases: bases, log, ...range });
    assert.deepStrictEqual(log.lines.map(l => l[1]), [
        '-----下載增量CVE-----',
        '(1/2) cpe:2.3:a:yaxim:bruno:*',
        '[CVE 快取] 今天已查詢，略過下載',
        '(2/2) cpe:2.3:a:usebruno:bruno:*',
        '[CVE 快取] 今天已查詢，略過下載',
        '-----查詢CVE快取-----',
        '(1/2) cpe:2.3:a:yaxim:bruno:*',
        '[CVE 快取] 命中 0 筆',
        '(2/2) cpe:2.3:a:usebruno:bruno:*',
        '[CVE 快取] 命中 1 筆',
        '-----下載NVD尚未立案增量CVE-----',
        '[CVE 快取] 今天已查詢，略過下載',
        '-----查詢NVD尚未立案CVE快取-----',
        '[CVE 快取] 命中 0 筆(共命中 0 筆，0筆上述已重複，0筆無相關，今天已查詢)',
    ]);
});

test('fetchSoftwareCVEs: 每天首次執行（有下載增量）——不印「略過下載」，補撈對帳行帶增量說明', async () => {
    const client = fakeClient({ incremental: true });
    const log = collect();
    const r = await S.fetchSoftwareCVEs({ nvdClient: client, searchName: 'Bruno', cpeBases: bases, log, ...range });
    const msgs = log.lines.map(l => l[1]);
    assert.ok(!msgs.some(m => /略過下載/.test(m)));
    assert.strictEqual(r.fromCache, false);
    assert.strictEqual(msgs.at(-1),
        '[CVE 快取] 命中 0 筆(共命中 0 筆，0筆上述已重複，0筆無相關，已補查 2026-10-13 至今增量，新增 0 筆)');
    // 階段順序仍固定：下載 → 查快取 → 下載補撈 → 查補撈快取
    assert.deepStrictEqual(
        msgs.filter(m => m.startsWith('-----')),
        ['-----下載增量CVE-----', '-----查詢CVE快取-----', '-----下載NVD尚未立案增量CVE-----', '-----查詢NVD尚未立案CVE快取-----']);
});

test('fetchSoftwareCVEs: 嚴重度門檻在取回當下套用——低於門檻不算命中（HIGH 不計 MEDIUM，MEDIUM 才計入）', async () => {
    const withSev = (id, severity, score) => ({
        cve: {
            id,
            configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:usebruno:bruno:*:*:*:*:*:*:*:*' }] }] }],
            metrics: { cvssMetricV31: [{ type: 'Primary', cvssData: { baseScore: score, baseSeverity: severity } }] },
        },
    });
    const cves = { 'usebruno:bruno': [withSev('CVE-CRIT', 'CRITICAL', 9.8), withSev('CVE-MED', 'MEDIUM', 6.1)] };

    const logHigh = collect();
    const high = await S.fetchSoftwareCVEs({ nvdClient: fakeClient({ cves }), searchName: 'Bruno', cpeBases: bases, minSeverity: 'HIGH', log: logHigh, ...range });
    assert.deepStrictEqual(high.cves.map(v => v.cve.id), ['CVE-CRIT']);
    assert.ok(logHigh.lines.some(([, m]) => m === '[CVE 快取] 命中 1 筆'));

    const med = await S.fetchSoftwareCVEs({ nvdClient: fakeClient({ cves }), searchName: 'Bruno', cpeBases: bases, minSeverity: 'MEDIUM', log: collect(), ...range });
    assert.deepStrictEqual(med.cves.map(v => v.cve.id).sort(), ['CVE-CRIT', 'CVE-MED']);
});
