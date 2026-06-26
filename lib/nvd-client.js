'use strict';

const fs   = require('fs');
const path = require('path');

// 將 Date 轉為 NVD API 接受的格式：2024-01-01T00:00:00.000
function _toNvdDate(d) {
    return d.toISOString().replace('Z', '');
}

// 將日期範圍切成每段最多 maxDays 天的陣列（由新到舊）
function splitDateRange(startDate, endDate, maxDays = 120) {
    const chunks = [];
    let end = new Date(endDate);
    const start = new Date(startDate);
    const msPerDay = 24 * 60 * 60 * 1000;
    while (end > start) {
        const cs = new Date(Math.max(start.getTime(), end.getTime() - maxDays * msPerDay));
        chunks.push({ start: cs, end: new Date(end) });
        end = new Date(cs.getTime() - 1); // 下一段結束在本段開始的前 1ms
    }
    return chunks;
}

// 將任意名稱轉為安全的快取檔名組成部分
function sanitizeCacheKey(name) {
    return name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
}

// 建立 NVD API 客戶端（含快取 + 120 天分段查詢）
//
// opts:
//   fetchFn    : fetch-like function（支援 proxy）
//   apiKey     : NIST_API_KEY，設定後走 apiKey header
//   delay      : ms，無 slotFn 時兩次請求之間的最小間距（預設 6500）
//   cacheDir   : 快取根目錄路徑，null 表示停用快取（內部依快取種類分存於 cacheDir/cpe_cache 與 cacheDir/cve_cache）
//   aliases    : { 'canonical': ['alias1', 'alias2'] }，別名映射
//   slotFn     : async () => void，外部速率控制（web-server 的 nvdSlot）
//   logger     : (level, keyword, msg) => void，進度回調
function createNvdClient({ fetchFn, apiKey = '', delay = 6500, cacheDir = null, aliases = {}, slotFn = null, logger = null }) {
    const NVD_CVE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
    const NVD_CPE = 'https://services.nvd.nist.gov/rest/json/cpes/2.0';

    // 建立反向別名映射：alias_lower -> canonical
    const reverseAlias = {};
    for (const [canonical, aliasList] of Object.entries(aliases)) {
        for (const alias of aliasList) {
            reverseAlias[alias.toLowerCase()] = canonical;
        }
    }

    // 速率控制（無 slotFn 時使用本地計時器）
    let _lastCall = 0;
    async function _rateLimit() {
        if (slotFn) {
            await slotFn();
        } else {
            const wait = Math.max(0, _lastCall + delay - Date.now());
            if (wait > 0) await new Promise(r => setTimeout(r, wait));
            _lastCall = Date.now();
        }
    }

    // 帶速率限制與重試的 HTTP GET（指數退避：第1次30s、第2次60s、第3次120s）
    const MAX_RETRIES = 3;
    async function _httpGet(url, retries = MAX_RETRIES) {
        const headers = { 'User-Agent': 'NISTCVECheck/1.0' };
        if (apiKey) headers['apiKey'] = apiKey;
        await _rateLimit();
        let res;
        try {
            res = await fetchFn(url, { headers, signal: AbortSignal.timeout(60000) });
        } catch (err) {
            // AbortError = 60 秒逾時，NVD 伺服器偶發性慢回應
            if (err.name === 'AbortError' || err.name === 'TimeoutError') {
                if (retries > 0) {
                    const wait = (MAX_RETRIES - retries + 1) * 30;
                    logger?.('warn', '', `NVD 請求逾時，${wait} 秒後重試（剩餘 ${retries} 次）...`);
                    await new Promise(r => setTimeout(r, wait * 1000));
                    return _httpGet(url, retries - 1);
                }
                throw new Error(`NVD API 請求逾時（已重試 ${MAX_RETRIES} 次）`);
            }
            // 其餘連線層級錯誤（ECONNRESET、ECONNREFUSED、ENOTFOUND、socket hang up、TLS 失敗等）：
            // Node fetch() 統一包成 TypeError: fetch failed，沒有 HTTP status 可判斷，視為暫時性問題一律重試
            if (retries > 0) {
                const wait = (MAX_RETRIES - retries + 1) * 30;
                const reason = err.cause?.code || err.cause?.message || err.message;
                logger?.('warn', '', `NVD 連線失敗（${reason}），${wait} 秒後重試（剩餘 ${retries} 次）...`);
                await new Promise(r => setTimeout(r, wait * 1000));
                return _httpGet(url, retries - 1);
            }
            throw err;
        }
        if (res.ok) return res.json();
        if (res.status === 429 && retries > 0) {
            logger?.('warn', '', 'HTTP 429 Rate Limit，等待 15 秒...');
            await new Promise(r => setTimeout(r, 15000));
            return _httpGet(url, retries - 1);
        }
        if (res.status === 503 && retries > 0) {
            const wait = (MAX_RETRIES - retries + 1) * 30;
            logger?.('warn', '', `HTTP 503 NVD 伺服器暫時過載，${wait} 秒後重試（剩餘 ${retries} 次）...`);
            await new Promise(r => setTimeout(r, wait * 1000));
            return _httpGet(url, retries - 1);
        }
        throw new Error(`HTTP ${res.status}`);
    }

    // 計算快取鍵
    function _resolveCacheKey(queryType, queryValue) {
        if (queryType === 'cpe') {
            return `cpe_${sanitizeCacheKey(queryValue.vendor)}_${sanitizeCacheKey(queryValue.product)}`;
        }
        const kw = (typeof queryValue === 'string' ? queryValue : '').toLowerCase();
        const canonical = reverseAlias[kw] || kw;
        return `kw_${sanitizeCacheKey(canonical)}`;
    }

    // 快取分兩個子目錄存放，避免 data/ 目錄混雜兩種性質不同的檔案：
    //   cpe_cache/ — cpekw_ 開頭，CPE 字典查找快取（{products}）
    //   cve_cache/ — cpe_ / kw_ 開頭，CVE 查詢快取（{cves}）
    function _dirFor(cacheKey) {
        return path.join(cacheDir, cacheKey.startsWith('cpekw_') ? 'cpe_cache' : 'cve_cache');
    }

    // 快取讀寫
    function _loadCache(cacheKey) {
        if (!cacheDir) return null;
        try {
            return JSON.parse(fs.readFileSync(path.join(_dirFor(cacheKey), `${cacheKey}.json`), 'utf-8'));
        } catch { return null; }
    }

    function _saveCache(cacheKey, data) {
        if (!cacheDir) return;
        try {
            const dir = _dirFor(cacheKey);
            fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(path.join(dir, `${cacheKey}.json`), JSON.stringify(data, null, 2), 'utf-8');
        } catch (e) {
            logger?.('warn', '', `快取儲存失敗：${e.message}`);
        }
    }

    // 快取可能比本次要求的範圍更廣（曾被更早的 minYear 查詢過），回傳前過濾掉早於 start 的 CVE，
    // 避免「已經依日期分段抓回本機」卻又把全部資料原封不動丟給呼叫端，讓呼叫端各自重複過濾一次
    function _filterFromStart(cves, start) {
        return cves.filter(v => new Date(v.cve.published) >= start);
    }

    // 產生 curl 指令字串（供 log 顯示，URL 解碼方便閱讀，API key 遮罩為 ****）
    function _toCurl(url) {
        const keyPart = apiKey ? ` -H "apiKey: ****"` : '';
        return `curl "${decodeURIComponent(url)}"${keyPart}`;
    }

    // 以 pubStartDate/pubEndDate 查詢單段 CVE
    async function _fetchPubRange(queryType, queryValue, cs, ce, emit) {
        const params = new URLSearchParams({
            pubStartDate:   _toNvdDate(cs),
            pubEndDate:     _toNvdDate(ce),
            resultsPerPage: '2000',
            noRejected:     '',
        });
        if (queryType === 'cpe') {
            params.set('virtualMatchString', `cpe:2.3:a:${queryValue.vendor}:${queryValue.product}:*`);
        } else {
            params.set('keywordSearch', queryValue);
        }
        const url = `${NVD_CVE}?${params}`;
        emit?.('debug', `  ${_toCurl(url)}`);
        const data = await _httpGet(url);
        return data.vulnerabilities || [];
    }

    // 以 lastModStartDate/lastModEndDate 查詢單段增量 CVE
    async function _fetchModRange(queryType, queryValue, cs, ce, emit) {
        const params = new URLSearchParams({
            lastModStartDate: _toNvdDate(cs),
            lastModEndDate:   _toNvdDate(ce),
            resultsPerPage:   '2000',
            noRejected:       '',
        });
        if (queryType === 'cpe') {
            params.set('virtualMatchString', `cpe:2.3:a:${queryValue.vendor}:${queryValue.product}:*`);
        } else {
            params.set('keywordSearch', queryValue);
        }
        const url = `${NVD_CVE}?${params}`;
        emit?.('debug', `  ${_toCurl(url)}`);
        const data = await _httpGet(url);
        return data.vulnerabilities || [];
    }

    // 主查詢方法
    // queryType    : 'keyword' | 'cpe'
    // queryValue   : string（keyword）| { vendor, product }（cpe）
    // coverageStart: Date，查詢起始日期（對應 minYear）
    // endDate      : Date，查詢結束日期（預設 now）
    // log          : (level, msg) => void，此筆 keyword 的進度輸出
    //
    // 回傳：{ cves: Array<{cve:{...}}>, fromCache: bool, newCount: number }
    // 回傳本地時間戳：mm/dd HH:mm:ss
    function _ts() {
        const d = new Date();
        const mm = String(d.getMonth() + 1).padStart(2, '0');
        const dd = String(d.getDate()).padStart(2, '0');
        const HH = String(d.getHours()).padStart(2, '0');
        const mi = String(d.getMinutes()).padStart(2, '0');
        const ss = String(d.getSeconds()).padStart(2, '0');
        return `${mm}/${dd} ${HH}:${mi}:${ss}`;
    }

    async function fetchCVEs({ queryType, queryValue, coverageStart, endDate, log: itemLog }) {
        const emit     = itemLog || ((lvl, msg) => logger?.(lvl, queryValue, msg));
        const cacheKey = _resolveCacheKey(queryType, queryValue);
        const now      = endDate  || new Date();
        const start    = coverageStart || new Date(new Date().getFullYear() - 1, 0, 1);
        const cache    = _loadCache(cacheKey);

        if (cache && new Date(cache.coverageStart) <= start) {
            // 快取覆蓋範圍足夠
            const lastFetched = new Date(cache.lastFetchedAt);
            if (lastFetched.toDateString() === now.toDateString()) {
                // 同一天內已查詢過，直接使用，不重複打 API（NVD CVE 以「天」為單位才有新資料，同一天內補查沒有意義）
                emit('cache', `[CVE 快取] 命中（${cache.cves.length} 筆，今天已查詢過）`);
                return { cves: _filterFromStart(cache.cves, start), fromCache: true, newCount: 0 };
            }

            // 增量查詢：lastModifiedDate in [lastFetched, now]
            const incrChunks = splitDateRange(lastFetched, now);
            emit('cache', `[CVE 快取] 命中（${cache.cves.length} 筆），補查 ${lastFetched.toISOString().substring(0, 10)} 至今的增量（${incrChunks.length} 段）`);

            const newVulns = [];
            for (let i = 0; i < incrChunks.length; i++) {
                const { start: cs, end: ce } = incrChunks[i];
                emit('info', `  [${_ts()} 增量 ${i + 1}/${incrChunks.length}] lastMod: ${cs.toISOString().substring(0, 10)} ~ ${ce.toISOString().substring(0, 10)} 查詢中...`);
                const vulns = await _fetchModRange(queryType, queryValue, cs, ce, emit);
                emit('info', `    → 取得 ${vulns.length} 筆`);
                newVulns.push(...vulns);
            }

            // 合併（新資料覆蓋舊資料，以 CVE id 去重）
            const cveMap = new Map(cache.cves.map(v => [v.cve.id, v]));
            let addedCount = 0;
            for (const v of newVulns) {
                if (!cveMap.has(v.cve.id)) addedCount++;
                cveMap.set(v.cve.id, v);
            }
            const merged = [...cveMap.values()];
            _saveCache(cacheKey, { cveCount: merged.length, cacheKey, coverageStart: cache.coverageStart, lastFetchedAt: now.toISOString(), cves: merged });
            emit('cache', `[CVE 快取] 增量更新完成（新增 ${addedCount} 筆，合計 ${merged.length} 筆）`);
            return { cves: _filterFromStart(merged, start), fromCache: false, newCount: addedCount };
        }

        // 全量查詢，或接續部分快取補查缺少的舊資料
        const isPartialCache = !!cache;  // 走到這裡的 cache 必為覆蓋不足（部分快取）
        if (isPartialCache) {
            const cachedFrom = new Date(cache.coverageStart).toISOString().substring(0, 10);
            emit('cache', `[CVE 快取] 部分命中（已覆蓋至 ${cachedFrom}），接續補查 ${start.toISOString().substring(0, 10)} ~ ${cachedFrom} 的舊資料`);
        } else {
            emit('cache', `[CVE 快取] 未命中，首次全量查詢`);
        }

        // 部分快取：只查缺少的舊範圍（start ~ cache.coverageStart）
        // 無快取：全量查詢（start ~ now）
        const queryEnd  = isPartialCache ? new Date(cache.coverageStart) : now;
        const chunks    = splitDateRange(start, queryEnd);
        const rangeDesc = `${start.toISOString().substring(0, 10)} ~ ${queryEnd.toISOString().substring(0, 10)}`;
        emit('info', `[全量查詢] 分 ${chunks.length} 段（各最多 120 天），${rangeDesc}`);

        // 以現有快取為基礎，部分快取時保留已有資料
        const cveMap = new Map(isPartialCache ? cache.cves.map(v => [v.cve.id, v]) : []);
        const baseCount = cveMap.size;

        for (let i = 0; i < chunks.length; i++) {
            const { start: cs, end: ce } = chunks[i];
            const vulns = await _fetchPubRange(queryType, queryValue, cs, ce, emit);
            for (const v of vulns) cveMap.set(v.cve.id, v);
            // 逐段寫入快取：coverageStart 設為本段起始，下次可從此接續
            const partial = [...cveMap.values()];
            _saveCache(cacheKey, { cveCount: partial.length, cacheKey, coverageStart: cs.toISOString(), lastFetchedAt: now.toISOString(), cves: partial });
            // 「查詢中…」與「取得 N 筆」濃縮為一行（查詢結束後一次輸出，含本段筆數與累計）
            emit('info', `  [${_ts()} 分段 ${i + 1}/${chunks.length}] pubDate: ${cs.toISOString().substring(0, 10)} ~ ${ce.toISOString().substring(0, 10)} 查詢中...      → 取得 ${vulns.length} 筆（累計 ${partial.length} 筆，已暫存）`);
        }

        const deduped = [...cveMap.values()];
        // 最終儲存：coverageStart 確定為 start，標記完整覆蓋
        _saveCache(cacheKey, { cveCount: deduped.length, cacheKey, coverageStart: start.toISOString(), lastFetchedAt: now.toISOString(), cves: deduped });
        emit('cache', `[CVE 快取] 儲存完成（${deduped.length} 筆 → data/cve_cache/${cacheKey}.json）`);
        return { cves: _filterFromStart(deduped, start), fromCache: false, newCount: deduped.length - baseCount };
    }

    // CPE 資料庫查詢：依關鍵字快取，與 CVE 快取邏輯一致 — 同一天內查過直接用快取，跨天才重新查詢。
    // fromCache 回傳給呼叫端，待呼叫端跑完 findAllCPEBases() 算出去重後的筆數，再合併印成一行 log
    // （fetchCPEs 此時只知道 NVD 原始條目數，不知道去重後剩幾個 vendor:product，不適合在這裡印 log）
    // CPE 字典分頁大小與「過於通用」門檻：
    // 一般軟體命中的 CPE 條目很少（實測 Apache Maven 31、PuTTY 70、Bruno 200、7-Zip 295），
    // 但單字通用名稱會命中上萬筆（Git 12546、Python 20067、Node.js 116997）。過往一次要求
    // resultsPerPage=10000，NVD 光是組裝 Git 的 1 萬筆 CPE 回應就要約 113 秒，遠超 60 秒逾時 →
    // 每次查 Git 都白等 60 秒逾時才 fallback。改為「先抓一頁取得 totalResults」：
    //   - total <= CPE_PAGE：一頁就拿到全部（一般軟體 1 次請求，與過往一樣快）
    //   - CPE_PAGE < total <= MAX_CPE_DICT：分頁補齊其餘（中量級，少數情況）
    //   - total > MAX_CPE_DICT：關鍵字過於通用，逐一列舉 vendor:product 既慢又不精準（同名 vendor
    //     太多），直接回空陣列讓呼叫端 fallback 到關鍵字 CVE 搜尋，省去 60 秒逾時等待。
    const CPE_PAGE = 500;
    const MAX_CPE_DICT = 2000;
    async function fetchCPEs(keyword) {
        const cacheKey = `cpekw_${sanitizeCacheKey(keyword)}`;
        const cache = _loadCache(cacheKey);
        if (cache && new Date(cache.fetchedAt).toDateString() === new Date().toDateString()) {
            return { products: cache.products, fromCache: true, totalResults: cache.totalResults, tooGeneric: cache.tooGeneric };
        }
        const _page = (start) => _httpGet(`${NVD_CPE}?${new URLSearchParams({
            keywordSearch: keyword, resultsPerPage: String(CPE_PAGE), startIndex: String(start),
        })}`);

        const first = await _page(0);
        const total = first.totalResults || 0;
        let products = [];
        let tooGeneric = false;
        if (total > MAX_CPE_DICT) {
            tooGeneric = true;                          // 過於通用 → 不列舉，交給關鍵字搜尋
        } else if (total <= CPE_PAGE) {
            products = first.products || [];            // 一頁即全部
        } else {
            products = [...(first.products || [])];     // 中量級：分頁補齊
            for (let start = CPE_PAGE; start < total; start += CPE_PAGE) {
                const more = await _page(start);
                products.push(...(more.products || []));
            }
        }
        _saveCache(cacheKey, { productCount: products.length, totalResults: total, tooGeneric, cacheKey, fetchedAt: new Date().toISOString(), products });
        return { products, fromCache: false, totalResults: total, tooGeneric };
    }

    return { fetchCVEs, fetchCPEs };
}

module.exports = { createNvdClient, splitDateRange, sanitizeCacheKey };
