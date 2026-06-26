#!/usr/bin/env node
// MITRE cvelistV5 本機鏡像同步腳本（npm run sync-mitre）。
// 因為 MITRE 的 CVE Services API 只能「已知 CVE ID 查單筆」，關鍵字/日期區段查詢端點
// 鎖在僅有 CVE Program 內部 Secretariat 角色才能用，外部使用者完全拿不到——
// 唯一可行的替代搜尋來源做法是：定期下載 cvelistV5 的每日 baseline + 當次 delta 壓縮檔
// （兩者打包在同一個 GitHub Release 裡，互相一致，不需要自己串接多個小時的 delta），
// 解壓後只保留近 minYear 年份，建立本機可查詢的 NDJSON 索引。
//
// 同步流程具備 checkpoint／resume 機制：下載/解壓/攤平 baseline、下載/解壓/攤平 delta、
// 重建索引+寫入 meta 共 7 個階段，每完成一個就把進度寫入 data/mitre_mirror/_tmp/progress.json。
// 任一階段失敗（例如 delta zip 結構問題）中斷後重跑，會自動略過已完成的階段（含檔案大小比對，
// 避免重新下載已下載好的 zip），不會把已經辛苦下載好的 baseline 整個丟掉重來。全部階段成功後才
// 清除 progress.json 與暫存檔。可用 --step=<phase> 手動執行單一階段（除錯用）。
//
// 詳見 CLAUDE.md「第二資料來源：MITRE cvelistV5」章節。
'use strict';

const fs   = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');

const GITHUB_API   = 'https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=5';
const DEFAULT_MIRROR_DIR = path.join(__dirname, '..', 'data', 'mitre_mirror');

// ─── 索引記錄建構（純函式，無 I/O，可獨立測試）──────────────────────────────

// cna 容器優先；affected[]/metrics[] 任一缺空時，逐欄 fallback 到第一個有資料的 adp[] 項目
// （adp 通常是 CISA Vulnrichment，補完 CNA 沒填的 CVSS/CPE）
function resolveAffectedAndMetrics(containers) {
    const cna = containers.cna || {};
    let affected = cna.affected;
    let metrics  = cna.metrics;
    const needAffected = !affected || !affected.length;
    const needMetrics  = !metrics || !metrics.length;
    if (needAffected || needMetrics) {
        for (const adp of (containers.adp || [])) {
            if (needAffected && !affected?.length && adp.affected?.length) affected = adp.affected;
            if (needMetrics  && !metrics?.length  && adp.metrics?.length)  metrics  = adp.metrics;
        }
    }
    return { affected: affected || [], metrics: metrics || [] };
}

// metrics[] 原始格式 [{cvssV3_1:{...}}, {cvssV4_0:{...}}, ...] → 精簡格式 [{version,vectorString,baseScore,baseSeverity}]
const CVSS_RAW_KEYS = [['cvssV4_0', '4.0'], ['cvssV3_1', '3.1'], ['cvssV3_0', '3.0'], ['cvssV2_0', '2.0']];
function flattenMetrics(rawMetrics) {
    const out = [];
    for (const entry of (rawMetrics || [])) {
        for (const [key, ver] of CVSS_RAW_KEYS) {
            const d = entry[key];
            if (d) out.push({ version: ver, vectorString: d.vectorString, baseScore: d.baseScore, baseSeverity: d.baseSeverity });
        }
    }
    return out;
}

// affected[] 原始格式 → 索引用精簡格式
function flattenAffected(rawAffected) {
    return (rawAffected || []).map(a => ({
        vendor:  a.vendor  || '',
        product: a.product || '',
        versions: (a.versions || []).map(v => ({
            version: v.version, status: v.status, versionType: v.versionType,
            lessThan: v.lessThan, lessThanOrEqual: v.lessThanOrEqual,
        })),
        cpes: a.cpes || [],
    }));
}

// 將一筆原始 MITRE CVE JSON 5.x 記錄轉成索引記錄；非 PUBLISHED 狀態回傳 null（不寫入索引）
function buildIndexRecord(raw) {
    const meta = raw.cveMetadata || {};
    if (meta.state !== 'PUBLISHED') return null;

    const containers = raw.containers || {};
    const { affected: rawAffected, metrics: rawMetrics } = resolveAffectedAndMetrics(containers);
    const affected = flattenAffected(rawAffected);
    const metrics  = flattenMetrics(rawMetrics);

    const vendors  = [...new Set(affected.map(a => a.vendor.toLowerCase()).filter(Boolean))];
    const products = [...new Set(affected.map(a => a.product.toLowerCase()).filter(Boolean))];
    const cpes      = [...new Set(affected.flatMap(a => a.cpes))];

    const descEntries = (containers.cna && containers.cna.descriptions) || [];
    const descLower = descEntries
        .filter(d => (d.lang || '').toLowerCase().startsWith('en'))
        .map(d => d.value || '')
        .join(' ')
        .toLowerCase();

    return {
        id: meta.cveId,
        state: meta.state,
        published: meta.datePublished || meta.dateReserved || null,
        lastModified: meta.dateUpdated || meta.datePublished || null,
        vendors, products, descLower, cpes, affected, metrics,
    };
}

// ─── 進度檔（checkpoint／resume 用）───────────────────────────────────────────

function _loadJsonSafe(filePath, fallback) {
    if (!fs.existsSync(filePath)) return fallback;
    try { return JSON.parse(fs.readFileSync(filePath, 'utf-8')); } catch { return fallback; }
}

function _saveProgress(progressPath, progress) {
    fs.mkdirSync(path.dirname(progressPath), { recursive: true });
    fs.writeFileSync(progressPath, JSON.stringify(progress, null, 2));
}

// 比對本機暫存檔案是否已存在且大小與 GitHub 資產一致；一致代表先前已下載完整，不需重新下載
function _fileMatchesSize(filePath, expectedSize) {
    if (!fs.existsSync(filePath)) return false;
    try { return fs.statSync(filePath).size === expectedSize; } catch { return false; }
}

// ─── 同步作業 ────────────────────────────────────────────────────────────────

async function _fetchJson(fetchFn, url) {
    const res = await fetchFn(url, { headers: { 'User-Agent': 'NISTCVECheck/1.0', Accept: 'application/vnd.github+json' } });
    if (!res.ok) throw new Error(`GitHub API 請求失敗：HTTP ${res.status} ${url}`);
    return res.json();
}

// 找最新一筆 release，回傳其 baseline（*_all_CVEs_at_midnight.zip*）與 delta（*_delta_CVEs_at_*Z.zip）資產
// 兩者來自同一個 release，內容互相一致，不需要自己串接多個小時的 delta。
function _pickAssets(release) {
    const baseline = release.assets.find(a => /_all_CVEs_at_midnight\.zip/.test(a.name));
    const delta    = release.assets.find(a => /_delta_CVEs_at_.*Z\.zip$/.test(a.name));
    return { baseline, delta };
}

async function _downloadAsset(fetchFn, asset, destPath) {
    const res = await fetchFn(asset.url, {
        headers: { 'User-Agent': 'NISTCVECheck/1.0', Accept: 'application/octet-stream' },
        redirect: 'follow',
    });
    if (!res.ok) throw new Error(`下載資產失敗：HTTP ${res.status} ${asset.name}`);
    const buf = Buffer.from(await res.arrayBuffer());
    fs.mkdirSync(path.dirname(destPath), { recursive: true });
    fs.writeFileSync(destPath, buf);
}

// 解壓 zip 到 destDir；expectedDir 是解壓後預期看到的頂層目錄名稱
// （baseline 是 'cves'，delta 是 'deltaCves'——兩者結構不同，不能共用同一個假設）。
// 防禦處理已知的「雙重 .zip.zip」bug（CVEProject/cvelistV5 issue #67/#68，至今仍未修復）：
// 解壓後若找不到 expectedDir，但頂層恰好只有一個 .zip 檔，視為內層還包了一層，再解一次。
function _extractZipDefensive(zipPath, destDir, expectedDir, depth = 0) {
    fs.mkdirSync(destDir, { recursive: true });
    const zip = new AdmZip(zipPath);
    zip.extractAllTo(destDir, true);

    const entries = fs.readdirSync(destDir);
    if (entries.includes(expectedDir)) return; // 正常情況，到此結束
    if (depth >= 2) throw new Error(`解壓 ${zipPath} 後仍找不到 ${expectedDir}/ 目錄（已嘗試 ${depth} 層內層 zip）`);

    const innerZip = entries.find(e => e.toLowerCase().endsWith('.zip'));
    if (!innerZip) throw new Error(`解壓 ${zipPath} 後找不到 ${expectedDir}/ 目錄，也沒有內層 zip 可繼續解`);
    _extractZipDefensive(path.join(destDir, innerZip), destDir, expectedDir, depth + 1);
}

// 將解壓出的 cves/<year>/<bucket>/CVE-*.json 攤平搬進 raw/<year>/CVE-*.json（去掉 bucket 子目錄層）
// 只保留 year >= minYear，其餘立即略過（不搬移），控制磁碟用量
function _flattenYearsInto(extractedCvesDir, rawDir, minYear, logger) {
    const years = fs.readdirSync(extractedCvesDir).filter(y => /^\d{4}$/.test(y) && Number(y) >= minYear);
    const touchedYears = [];
    for (const year of years) {
        const yearSrcDir = path.join(extractedCvesDir, year);
        const yearDestDir = path.join(rawDir, year);
        fs.mkdirSync(yearDestDir, { recursive: true });
        let count = 0;
        for (const bucket of fs.readdirSync(yearSrcDir)) {
            const bucketDir = path.join(yearSrcDir, bucket);
            if (!fs.statSync(bucketDir).isDirectory()) continue;
            for (const file of fs.readdirSync(bucketDir)) {
                if (!file.endsWith('.json')) continue;
                fs.copyFileSync(path.join(bucketDir, file), path.join(yearDestDir, file));
                count++;
            }
        }
        touchedYears.push(year);
        logger?.('info', `  ${year}：${count} 筆檔案`);
    }
    return touchedYears;
}

// 將解壓出的 deltaCves/CVE-<year>-<seq>.json 攤平搬進 raw/<year>/CVE-*.json。
// 與 baseline 的 cves/ 不同，delta 是「扁平」結構（沒有年份/bucket 子目錄），
// 年份必須從檔名解析。只保留 year >= minYear。
function _flattenDeltaInto(extractedDeltaCvesDir, rawDir, minYear, logger) {
    const touchedYears = new Set();
    let skipped = 0;
    for (const file of fs.readdirSync(extractedDeltaCvesDir)) {
        if (!file.endsWith('.json')) continue;
        const m = /^CVE-(\d{4})-/.exec(file);
        if (!m) continue;
        const year = m[1];
        if (Number(year) < minYear) { skipped++; continue; }
        const yearDestDir = path.join(rawDir, year);
        fs.mkdirSync(yearDestDir, { recursive: true });
        fs.copyFileSync(path.join(extractedDeltaCvesDir, file), path.join(yearDestDir, file));
        touchedYears.add(year);
    }
    const years = [...touchedYears].sort();
    logger?.('info', `  delta：${years.join(', ') || '（無符合年份的變動）'}（略過 ${skipped} 筆早於 ${minYear} 年的項目）`);
    return years;
}

// 重建/更新指定年份的 NDJSON 索引：讀 raw/<year>/ 下全部 json，逐筆轉換，以 Map 去重後整檔寫回
function _rebuildYearIndex(year, rawDir, indexDir, logger) {
    const yearRawDir = path.join(rawDir, year);
    if (!fs.existsSync(yearRawDir)) return 0;

    const indexPath = path.join(indexDir, `${year}.ndjson`);
    const map = new Map();
    // 保留既有索引中、這次沒有被觸碰到的舊記錄（例如只跑 delta 時，其餘檔案維持原狀）
    if (fs.existsSync(indexPath)) {
        for (const line of fs.readFileSync(indexPath, 'utf-8').split('\n')) {
            if (!line.trim()) continue;
            try { const rec = JSON.parse(line); map.set(rec.id, rec); } catch { /* 損壞行，略過 */ }
        }
    }

    let written = 0, skippedRejected = 0;
    for (const file of fs.readdirSync(yearRawDir)) {
        if (!file.endsWith('.json')) continue;
        let raw;
        try { raw = JSON.parse(fs.readFileSync(path.join(yearRawDir, file), 'utf-8')); } catch { continue; }
        const rec = buildIndexRecord(raw);
        if (!rec) { skippedRejected++; map.delete(raw?.cveMetadata?.cveId); continue; } // 非 PUBLISHED（如 REJECTED）：確保不留在索引中
        map.set(rec.id, rec);
        written++;
    }

    fs.mkdirSync(indexDir, { recursive: true });
    const lines = [...map.values()].map(r => JSON.stringify(r));
    fs.writeFileSync(indexPath, lines.length ? lines.join('\n') + '\n' : '');
    logger?.('info', `  ${year} 索引：新增/更新 ${written} 筆，略過非 PUBLISHED ${skippedRejected} 筆，合計 ${map.size} 筆`);
    return map.size;
}

// 計算既有索引檔的筆數（年份未變動，不需重建，只需算筆數彙總進 meta.cveCount）
function _countYearIndexLines(year, indexDir) {
    const p = path.join(indexDir, `${year}.ndjson`);
    if (!fs.existsSync(p)) return 0;
    return fs.readFileSync(p, 'utf-8').split('\n').filter(Boolean).length;
}

const STEP_NAMES = ['download-baseline', 'extract-baseline', 'flatten-baseline', 'download-delta', 'extract-delta', 'flatten-delta', 'finalize'];

async function syncMitre({ fetchFn = fetch, mirrorDir = DEFAULT_MIRROR_DIR, minYear, logger = () => {}, full = false, step = null } = {}) {
    minYear = minYear || (new Date().getUTCFullYear() - 5);
    const rawDir   = path.join(mirrorDir, 'raw');
    const indexDir = path.join(mirrorDir, 'index');
    const metaPath = path.join(indexDir, 'meta.json');
    const tmpDir   = path.join(mirrorDir, '_tmp');
    const progressPath = path.join(tmpDir, 'progress.json');

    if (step && !STEP_NAMES.includes(step)) {
        throw new Error(`未知的 --step=${step}，可用值：${STEP_NAMES.join(', ')}`);
    }

    logger('info', `▶ 開始同步 MITRE cvelistV5（保留 ${minYear} 年至今）`);

    let meta = _loadJsonSafe(metaPath, { lastSyncedAt: null, lastReleaseTag: null, lastBaselineDate: null, yearsIndexed: [], cveCount: 0 });
    const todayUtc = new Date().toISOString().substring(0, 10);

    // ─── 決定要處理哪個 release：若有未完成的進度（且非 --full）就沿用同一個 release 繼續，
    // 避免已下載/已攤平的內容被丟掉重來；否則才查詢最新 release 並建立新的進度檔。
    let progress = full ? null : _loadJsonSafe(progressPath, null);

    if (progress) {
        logger('info', `偵測到未完成的同步進度（release ${progress.releaseTag}），將從中斷處繼續...`);
    } else {
        logger('info', '查詢最新 release...');
        const releases = await _fetchJson(fetchFn, GITHUB_API);
        if (!releases.length) throw new Error('GitHub releases 列表是空的，無法同步');
        const latest = releases[0];
        const { baseline, delta } = _pickAssets(latest);
        if (!baseline) throw new Error(`最新 release（${latest.tag_name}）找不到 baseline 資產（檔名應符合 *_all_CVEs_at_midnight.zip*），可能是 MITRE 改了命名規則，請檢查`);
        logger('info', `最新 release：${latest.tag_name}（published_at: ${latest.published_at}）`);

        const needBaseline = full || !meta.lastBaselineDate || meta.lastBaselineDate !== todayUtc || meta.yearsIndexed.length === 0;
        if (!needBaseline) logger('info', '今日 baseline 已同步過，僅套用最新 delta');

        progress = {
            releaseTag: latest.tag_name,
            baseline, delta: delta || null,
            // 不需要處理 baseline 時，直接把對應步驟標記為「已完成」（略過），沿用同一套 skip 機制
            steps: {
                downloadBaseline: !needBaseline, extractBaseline: !needBaseline, flattenBaseline: !needBaseline,
                downloadDelta: false, extractDelta: false, flattenDelta: false,
            },
            touchedYears: [],
        };
        _saveProgress(progressPath, progress);
    }

    const tmpBaselineZip     = path.join(tmpDir, 'baseline.zip');
    const tmpBaselineExtract = path.join(tmpDir, 'baseline_extracted');
    const tmpDeltaZip        = path.join(tmpDir, 'delta.zip');
    const tmpDeltaExtract    = path.join(tmpDir, 'delta_extracted');

    async function stepDownloadBaseline() {
        if (progress.steps.downloadBaseline) { logger('info', '（略過）baseline 已下載過'); return; }
        if (_fileMatchesSize(tmpBaselineZip, progress.baseline.size)) {
            logger('info', '偵測到先前已下載的 baseline 檔案（大小相符），略過重新下載');
        } else {
            logger('info', `下載 baseline：${progress.baseline.name}（${(progress.baseline.size / 1024 / 1024).toFixed(0)} MB）...`);
            await _downloadAsset(fetchFn, progress.baseline, tmpBaselineZip);
        }
        progress.steps.downloadBaseline = true;
        _saveProgress(progressPath, progress);
    }

    function stepExtractBaseline() {
        if (progress.steps.extractBaseline) { logger('info', '（略過）baseline 已解壓過'); return; }
        logger('info', '解壓 baseline...');
        _extractZipDefensive(tmpBaselineZip, tmpBaselineExtract, 'cves', 0);
        progress.steps.extractBaseline = true;
        _saveProgress(progressPath, progress);
    }

    function stepFlattenBaseline() {
        if (progress.steps.flattenBaseline) { logger('info', '（略過）baseline 已攤平過'); return; }
        logger('info', `攤平搬移 ${minYear} 年至今的資料...`);
        const touched = _flattenYearsInto(path.join(tmpBaselineExtract, 'cves'), rawDir, minYear, logger);
        progress.touchedYears = [...new Set([...progress.touchedYears, ...touched])];
        progress.steps.flattenBaseline = true;
        meta.lastBaselineDate = todayUtc;
        _saveProgress(progressPath, progress);
    }

    async function stepDownloadDelta() {
        if (!progress.delta || progress.steps.downloadDelta) { if (progress.delta) logger('info', '（略過）delta 已下載過'); return; }
        if (_fileMatchesSize(tmpDeltaZip, progress.delta.size)) {
            logger('info', '偵測到先前已下載的 delta 檔案（大小相符），略過重新下載');
        } else {
            logger('info', `下載 delta：${progress.delta.name}（${progress.delta.size} bytes）...`);
            await _downloadAsset(fetchFn, progress.delta, tmpDeltaZip);
        }
        progress.steps.downloadDelta = true;
        _saveProgress(progressPath, progress);
    }

    function stepExtractDelta() {
        if (!progress.delta || progress.steps.extractDelta) { if (progress.delta) logger('info', '（略過）delta 已解壓過'); return; }
        logger('info', '解壓 delta...');
        _extractZipDefensive(tmpDeltaZip, tmpDeltaExtract, 'deltaCves', 0);
        progress.steps.extractDelta = true;
        _saveProgress(progressPath, progress);
    }

    function stepFlattenDelta() {
        if (!progress.delta || progress.steps.flattenDelta) { if (progress.delta) logger('info', '（略過）delta 已攤平過'); return; }
        logger('info', '攤平搬移 delta 資料...');
        const touched = _flattenDeltaInto(path.join(tmpDeltaExtract, 'deltaCves'), rawDir, minYear, logger);
        progress.touchedYears = [...new Set([...progress.touchedYears, ...touched])];
        progress.steps.flattenDelta = true;
        _saveProgress(progressPath, progress);
    }

    function stepFinalize() {
        if (progress.touchedYears.length === 0) logger('warn', '本次沒有任何年份有資料變動（可能已是最新狀態）');
        logger('info', '重建索引...');
        let cveCount = 0;
        const allYears = [...new Set([...meta.yearsIndexed, ...progress.touchedYears])];
        for (const year of allYears) {
            const needsRebuild = progress.touchedYears.includes(year) || !meta.yearsIndexed.includes(year);
            cveCount += needsRebuild ? _rebuildYearIndex(year, rawDir, indexDir, logger) : _countYearIndexLines(year, indexDir);
        }

        meta.lastSyncedAt = new Date().toISOString();
        meta.lastReleaseTag = progress.releaseTag;
        meta.yearsIndexed = allYears.sort();
        meta.cveCount = cveCount;
        fs.mkdirSync(indexDir, { recursive: true });
        fs.writeFileSync(metaPath, JSON.stringify(meta, null, 2));

        // 全部完成才清除暫存檔與進度檔；中途失敗則保留，供下次重跑時略過已完成的階段
        fs.rmSync(tmpDir, { recursive: true, force: true });

        logger('info', `✓ 同步完成：${meta.yearsIndexed.join(', ')} 年，共 ${cveCount} 筆 CVE`);
    }

    const stepFns = {
        'download-baseline': stepDownloadBaseline, 'extract-baseline': stepExtractBaseline, 'flatten-baseline': stepFlattenBaseline,
        'download-delta': stepDownloadDelta, 'extract-delta': stepExtractDelta, 'flatten-delta': stepFlattenDelta,
        finalize: stepFinalize,
    };

    if (step) {
        await stepFns[step]();
        logger('info', `✓ 單一步驟「${step}」執行完成`);
        return meta;
    }

    await stepDownloadBaseline();
    stepExtractBaseline();
    stepFlattenBaseline();
    await stepDownloadDelta();
    stepExtractDelta();
    stepFlattenDelta();
    stepFinalize();
    return meta;
}

module.exports = { syncMitre, buildIndexRecord, resolveAffectedAndMetrics, flattenMetrics, flattenAffected };

if (require.main === module) {
    const full = process.argv.includes('--full');
    const stepArg = process.argv.find(a => a.startsWith('--step='));
    const step = stepArg ? stepArg.slice('--step='.length) : null;
    const logger = (level, msg) => {
        const prefix = level === 'warn' ? '⚠ ' : '';
        console.log(`${prefix}${msg}`);
    };
    syncMitre({ full, step, logger }).catch(err => {
        console.error(`\n✗ 同步失敗：${err.message}`);
        process.exit(1);
    });
}
