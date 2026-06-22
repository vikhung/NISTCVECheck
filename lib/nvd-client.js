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
//   cacheDir   : 快取目錄路徑，null 表示停用快取
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

    // 快取讀寫
    function _loadCache(cacheKey) {
        if (!cacheDir) return null;
        try {
            return JSON.parse(fs.readFileSync(path.join(cacheDir, `${cacheKey}.json`), 'utf-8'));
        } catch { return null; }
    }

    function _saveCache(cacheKey, data) {
        if (!cacheDir) return;
        try {
            fs.mkdirSync(cacheDir, { recursive: true });
            fs.writeFileSync(path.join(cacheDir, `${cacheKey}.json`), JSON.stringify(data, null, 2), 'utf-8');
        } catch (e) {
            logger?.('warn', '', `快取儲存失敗：${e.message}`);
        }
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
        emit?.('info', `  ${_toCurl(url)}`);
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
        emit?.('info', `  ${_toCurl(url)}`);
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
        const start    = coverageStart || new Date(new Date().getFullYear() - 5, 0, 1);
        const cache    = _loadCache(cacheKey);

        if (cache && new Date(cache.coverageStart) <= start) {
            // 快取覆蓋範圍足夠
            const lastFetched = new Date(cache.lastFetchedAt);
            if ((now - lastFetched) < 3600 * 1000) {
                // 1 小時內已查詢過，直接使用
                emit('cache', `[快取] 命中（${cache.cves.length} 筆，上次查詢不足 1 小時前）`);
                return { cves: cache.cves, fromCache: true, newCount: 0 };
            }

            // 增量查詢：lastModifiedDate in [lastFetched, now]
            const incrChunks = splitDateRange(lastFetched, now);
            emit('cache', `[快取] 命中（${cache.cves.length} 筆），補查 ${lastFetched.toISOString().substring(0, 10)} 至今的增量（${incrChunks.length} 段）`);

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
            emit('cache', `[快取] 增量更新完成（新增 ${addedCount} 筆，合計 ${merged.length} 筆）`);
            return { cves: merged, fromCache: false, newCount: addedCount };
        }

        // 全量查詢，或接續部分快取補查缺少的舊資料
        const isPartialCache = !!cache;  // 走到這裡的 cache 必為覆蓋不足（部分快取）
        if (isPartialCache) {
            const cachedFrom = new Date(cache.coverageStart).toISOString().substring(0, 10);
            emit('cache', `[快取] 部分命中（已覆蓋至 ${cachedFrom}），接續補查 ${start.toISOString().substring(0, 10)} ~ ${cachedFrom} 的舊資料`);
        } else {
            emit('cache', `[快取] 未命中，首次全量查詢`);
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
            emit('info', `  [${_ts()} 分段 ${i + 1}/${chunks.length}] pubDate: ${cs.toISOString().substring(0, 10)} ~ ${ce.toISOString().substring(0, 10)} 查詢中...`);
            const vulns = await _fetchPubRange(queryType, queryValue, cs, ce, emit);
            for (const v of vulns) cveMap.set(v.cve.id, v);
            // 逐段寫入快取：coverageStart 設為本段起始，下次可從此接續
            const partial = [...cveMap.values()];
            _saveCache(cacheKey, { cveCount: partial.length, cacheKey, coverageStart: cs.toISOString(), lastFetchedAt: now.toISOString(), cves: partial });
            emit('info', `    → 取得 ${vulns.length} 筆（累計 ${partial.length} 筆，已暫存）`);
        }

        const deduped = [...cveMap.values()];
        // 最終儲存：coverageStart 確定為 start，標記完整覆蓋
        _saveCache(cacheKey, { cveCount: deduped.length, cacheKey, coverageStart: start.toISOString(), lastFetchedAt: now.toISOString(), cves: deduped });
        emit('cache', `[快取] 儲存完成（${deduped.length} 筆 → data/${cacheKey}.json）`);
        return { cves: deduped, fromCache: false, newCount: deduped.length - baseCount };
    }

    // CPE 資料庫查詢（不快取）
    async function fetchCPEs(keyword) {
        const params = new URLSearchParams({ keywordSearch: keyword, resultsPerPage: '10000' });
        return _httpGet(`${NVD_CPE}?${params}`);
    }

    return { fetchCVEs, fetchCPEs };
}

module.exports = { createNvdClient, splitDateRange, sanitizeCacheKey };
