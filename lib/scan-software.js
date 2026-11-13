// 單一軟體的「CPE 偵測 → CVE 查詢 → NVD 尚未分析 CVE 補撈」流程（CLI 與 Web Server 共用）。
// 純 server-side（與 nvd-client.js 同類），不會被 build.js 注入網頁。
//
// 為何獨立成模組：過去 scripts/cve-checker.js 與 scripts/web-server.js 各複製一份約 80 行的相同流程，
// 兩邊改一邊漏另一邊就會行為不一致。現統一在此，呼叫端只負責「傳入 log 回調」與「套用顯示」。
// 業務判斷（精確/模糊 CPE 比對、補撈守門）仍在 lib/cve-logic.js，這裡只做流程編排。
'use strict';

const { findAllCPEBases, isPendingSupplementCVE, getCvss, SEVERITY_ORDER } = require('./cve-logic');

// 解析 CACHE_ALIAS_N 環境變數（格式：canonical|alias1|alias2，第一個為正式名稱）。
// 回傳 { canonical(小寫): [alias(小寫), ...] }，交給 nvd-client 的 aliases 參數。
function parseCacheAliases(env) {
    const aliases = {};
    for (let i = 0; ; i++) {
        const entry = env[`CACHE_ALIAS_${i}`];
        if (!entry) break;
        const parts = entry.split('|').map(s => s.trim().toLowerCase()).filter(Boolean);
        if (parts.length >= 2) aliases[parts[0]] = parts.slice(1);
    }
    return aliases;
}

// 解析 CPE_BASE_N 環境變數（格式：名稱|vendor:product[|vendor:product...]）。
//   例：CPE_BASE_0=python|python:python
//       CPE_BASE_1=git|git-scm:git|git:git
// 用途：Python/Git 等「過於通用」的軟體，CPE 字典查詢會命中上萬筆而被判 tooGeneric → 退化成
// 關鍵字搜尋（只比對描述全文，描述沒提到產品名就漏，且易誤報）。預先指定其標準 CPE base，即可
// 跳過字典查詢、直接以 virtualMatchString 精準查 CVE。回傳 { 名稱(小寫): [{vendor,product}, ...] }。
function parseCpeBases(env) {
    const map = {};
    for (let i = 0; ; i++) {
        const entry = env[`CPE_BASE_${i}`];
        if (!entry) break;
        const parts = entry.split('|').map(s => s.trim()).filter(Boolean);
        if (parts.length < 2) continue;
        const bases = [];
        for (const vp of parts.slice(1)) {
            const [vendor, product] = vp.split(':').map(s => s.trim().toLowerCase());
            if (vendor && product) bases.push({ vendor, product });
        }
        if (bases.length) map[parts[0].toLowerCase()] = bases;
    }
    return map;
}

const _cpeUrn = b => `cpe:2.3:a:${b.vendor}:${b.product}:*`;

// 決定此軟體要用哪些 CPE base（OR 邏輯）。
//   1) .env.local 的 CPE_BASE_N 命中 → 直接使用，完全略過 CPE 字典查詢
//   2) 否則 nvdClient.fetchCPEs() 查字典，再以 findAllCPEBases 收斂
//      （非 Portable → 精確模式避免多產品 vendor 爆量；Portable → 模糊模式）
// 回傳 { cpeBases, tooGeneric }；cpeBases 為空代表須改用關鍵字搜尋。
// log(level, msg)：level 為 'cache' | 'info' | 'warn'。
async function resolveCpeBases({ nvdClient, searchName, isPortable, cpeBaseMap = {}, log }) {
    const known = cpeBaseMap[searchName.toLowerCase()];
    if (known) {
        log('cache', `[CPE 指定] 使用 .env.local 設定的標準 CPE(${known.length} 筆，略過字典查詢)`);
        log('info', known.map(_cpeUrn).join(' | '));
        return { cpeBases: known, tooGeneric: false };
    }

    const cpeData = await nvdClient.fetchCPEs(searchName).catch(() => ({ products: [], fromCache: false }));
    const nameWords = searchName.toLowerCase().replace(/[^a-z0-9]/g, ' ').split(/\s+/).filter(w => w.length >= 2);
    const cpeBases = findAllCPEBases(cpeData.products || [], nameWords, !isPortable);

    // fetchCPEs 不在內部印 log（它只知道 NVD 原始條目數），這裡以去重後的 base 數量合併成一行
    if (cpeBases.length > 0) {
        log('cache', cpeData.fromCache
            ? `[CPE 快取] 命中(${cpeBases.length} 筆，今天已查詢)`
            : `[CPE] 查詢完成(${cpeBases.length} 筆)`);
        log('info', cpeBases.map(_cpeUrn).join(' | '));
    } else if (cpeData.tooGeneric) {
        log('info', `關鍵字過於通用(命中 ${cpeData.totalResults} 筆 CPE)，改用關鍵字搜尋`);
    } else if (isPortable) {
        log('warn', '⚠ 未找到對應 CPE，改用關鍵字比對');
    } else {
        log('info', '未找到對應 CPE，使用關鍵字搜尋');
    }
    return { cpeBases, tooGeneric: !!cpeData.tooGeneric };
}

// 依 cpeBases 取得此軟體的 CVE：
//   - 有 cpeBases：逐一查詢每個 base 並依 CVE id 合併去重（不可只查第一個，否則其他 vendor 名稱下的
//     CVE 永遠查不到，例如 Bruno 的 usebruno:bruno / yaxim:bruno），再以 keyword 補撈 NVD 尚未分析者。
//   - 無 cpeBases：直接 keyword 查詢。
// 補撈原因：CPE 查詢（virtualMatchString）只回傳「已有 CPE 適用性」的 CVE，會漏掉 NVD
// Awaiting Analysis（configurations 為空）的新 CVE（例：FFmpeg CVE-2026-8461）。同範圍 keyword
// 查詢中「CPE 結果沒有、且無 CPE 適用性、且參考連結指向本軟體」者併入（isPendingSupplementCVE），
// 後續 classifyCVE 會標 pendingNvd（⚠ NVD 分析中）供人工確認。
// 回傳 { cves, fromCache, newCount }；年份已由 nvd-client 依 coverageStart 裁切。
async function fetchSoftwareCVEs({ nvdClient, searchName, cpeBases, coverageStart, endDate = new Date(), minSeverity = '', log }) {
    const common = { coverageStart, endDate };
    // 嚴重度門檻在「取回結果的當下」套用：低於門檻的 CVE 不算命中，後續的筆數、重複/無相關對帳與小結都以
    // 門檻以上計算。快取檔仍保留全部嚴重度（讓未來更低門檻的查詢可直接複用，不漏資料），只在這裡過濾回傳值。
    const minIdx = SEVERITY_ORDER.indexOf(String(minSeverity).toUpperCase());
    const keep   = v => minIdx < 0 || SEVERITY_ORDER.indexOf(getCvss(v.cve).severity) >= minIdx;

    // 「下載增量」與「查詢快取」分成兩個階段：每天首次執行會在第一階段補下載，之後的查詢階段與平常每次
    // 執行完全相同，畫面一致、也一眼看出「有沒有下載」。
    const isKw    = !cpeBases || cpeBases.length === 0;
    const queries = isKw
        ? [{ queryType: 'keyword', queryValue: searchName, label: `關鍵字 "${searchName}"` }]
        : cpeBases.map(base => ({ queryType: 'cpe', queryValue: base, label: _cpeUrn(base) }));
    const labelOf = (q, i) => (isKw ? q.label : `(${i + 1}/${queries.length}) ${q.label}`);

    // 一個查詢的「下載增量」步驟；今天已更新過則明說略過，避免只看到查詢列卻不知道有沒有動作
    let fromCache = true;
    let newCount  = 0;
    const update = async q => {
        const u = await nvdClient.updateCVECache({ queryType: q.queryType, queryValue: q.queryValue, ...common, log });
        if (!u.updated) log('cache', '[CVE 快取] 今天已查詢，略過下載');
        fromCache = fromCache && !u.updated;
        newCount += u.newCount;
        return u;
    };

    // ── 階段 1：下載增量 ──
    log('info', '-----下載增量CVE-----');
    for (let i = 0; i < queries.length; i++) {
        log('info', labelOf(queries[i], i));
        await update(queries[i]);
    }

    // ── 階段 2：查詢 CVE 快取（逐 base 查詢並依 CVE id 合併去重）──
    log('info', '-----查詢CVE快取-----');
    const cveMap = new Map();
    for (let i = 0; i < queries.length; i++) {
        log('info', labelOf(queries[i], i));
        const r = nvdClient.queryCVECache({ queryType: queries[i].queryType, queryValue: queries[i].queryValue, ...common });
        const kept = r.cves.filter(keep);
        log('cache', `[CVE 快取] 命中 ${kept.length} 筆`);
        for (const v of kept) cveMap.set(v.cve.id, v);
    }
    if (isKw) return { cves: [...cveMap.values()], fromCache, newCount };

    // ── 階段 3、4：補撈 NVD 尚未立案的 CVE ──
    // CPE 查詢只回傳「已有 CPE 適用性」的 CVE，會漏掉 NVD Awaiting Analysis（configurations 為空）的新 CVE
    // （例：FFmpeg CVE-2026-8461）。同範圍 keyword 查詢中，扣掉「上一步 CPE 已查出者」與「無相關者」
    // （名字撞到、屬別產品），僅餘「無 CPE 適用性且參考連結指向本軟體」者併入（isPendingSupplementCVE），
    // 後續 classifyCVE 會標 pendingNvd（⚠ NVD 分析中）供人工確認。
    const kwQuery = { queryType: 'keyword', queryValue: searchName };
    log('info', '-----下載NVD尚未立案增量CVE-----');
    const ku = await update(kwQuery);

    log('info', '-----查詢NVD尚未立案CVE快取-----');
    const kw = nvdClient.queryCVECache({ ...kwQuery, ...common }).cves.filter(keep);
    let dupCount = 0, noiseCount = 0, suppCount = 0;
    for (const v of kw) {
        if (cveMap.has(v.cve.id)) { dupCount++; continue; }
        if (isPendingSupplementCVE(v.cve, cpeBases)) { cveMap.set(v.cve.id, v); suppCount++; }
        else noiseCount++;
    }
    // 一律印一行（含 0 筆），避免誤會「沒補查」；括號內讓使用者對帳 keyword 命中筆數的去向
    log('cache', `[CVE 快取] 命中 ${suppCount} 筆(共命中 ${kw.length} 筆，${dupCount}筆上述已重複，${noiseCount}筆無相關，${ku.cacheNote})`);
    return { cves: [...cveMap.values()], fromCache, newCount };
}

// 單一軟體完整流程：CPE 偵測 → CVE 查詢（含補撈）。
// 回傳 { cpeBases, cves, fromCache, newCount }。
async function lookupSoftwareCVEs({ nvdClient, searchName, isPortable = false, cpeBaseMap = {}, coverageStart, endDate, minSeverity = '', log = () => {} }) {
    const { cpeBases } = await resolveCpeBases({ nvdClient, searchName, isPortable, cpeBaseMap, log });
    const r = await fetchSoftwareCVEs({ nvdClient, searchName, cpeBases, coverageStart, endDate, minSeverity, log });
    return { cpeBases, ...r };
}

module.exports = { parseCacheAliases, parseCpeBases, resolveCpeBases, fetchSoftwareCVEs, lookupSoftwareCVEs };
