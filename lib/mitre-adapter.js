// MITRE cvelistV5 索引記錄 → NVD API 2.0 相容的 synthetic CVE 物件。
// 目的：讓 lib/cve-logic.js（唯一來源的關聯性/版本比對邏輯）完全不需修改，
// 即可同時運作於 NVD 與 MITRE 兩種資料來源。純函式，無 I/O。
// 索引記錄格式（由 scripts/mitre-sync.js 產生）：
//   { id, state, published, lastModified, vendors[], products[], descLower,
//     cpes[], affected[]:[{vendor,product,versions[],cpes[]}], metrics[]:[{version,vectorString,baseScore,baseSeverity}] }
'use strict';

// MITRE 的 metrics[].version（"4.0"/"3.1"/"3.0"/"2.0"）→ NVD 的 cve.metrics.cvssMetricVxx 鍵名。
// 同一筆記錄可能同時有多個版本（CNA 與 ADP 各自評分），全部保留，
// 既有 getCvss() 的優先序（V40 > V31 > V30 > V2）會自動挑最佳。
const CVSS_KEY_MAP = { '4.0': 'cvssMetricV40', '3.1': 'cvssMetricV31', '3.0': 'cvssMetricV30', '2.0': 'cvssMetricV2' };

function _buildMetrics(metricsList) {
    const out = {};
    for (const m of (metricsList || [])) {
        const key = CVSS_KEY_MAP[m.version];
        if (!key) continue;
        if (!out[key]) out[key] = [];
        out[key].push({ cvssData: { baseScore: m.baseScore, baseSeverity: m.baseSeverity, vectorString: m.vectorString } });
    }
    return out;
}

// affected[].versions[] → cpeMatch[]。
// MITRE 的 versions[] 每筆條目語意：
//   - 有 lessThan/lessThanOrEqual → 版本範圍（version 為起點，lessThan 不含/lessThanOrEqual 含上界）
//   - 兩者都沒有 → 單一精確版本受影響/不受影響（不是「此版本之後全部」），
//     對應 NVD 慣例的「精確版本 CPE」（無 versionStart/End，版本寫在 criteria 第 5 欄）
// changes[]（同一版本線內多次受影響狀態反轉）目前不展開為多個子範圍，僅用條目本身的 status —
// 已知簡化，極少數情況才會用到 changes[]。
function _buildCpeMatchesForAffected(aff) {
    const vendor  = (aff.vendor  || 'unknown').toLowerCase().replace(/\s+/g, '_');
    const product = (aff.product || 'unknown').toLowerCase().replace(/\s+/g, '_');
    // 優先使用真實 cpes[]（若有）；只取第一個當 criteria 基底（多 CPE 情境少見）
    const realCpe = (aff.cpes && aff.cpes.length) ? aff.cpes[0] : null;
    const matches = [];

    const versions = (aff.versions && aff.versions.length) ? aff.versions : [{ status: 'affected' }];
    for (const v of versions) {
        const vulnerable = v.status === 'affected';
        const hasRange = !!(v.lessThan || v.lessThanOrEqual);

        if (hasRange) {
            const base = realCpe || `cpe:2.3:a:${vendor}:${product}:*:*:*:*:*:*:*:*`;
            matches.push({
                criteria: base,
                vulnerable,
                versionStartIncluding: v.version || undefined,
                versionEndExcluding:   v.lessThan || undefined,
                versionEndIncluding:   v.lessThanOrEqual || undefined,
            });
        } else if (v.version) {
            // 精確版本：版本號寫進 criteria 第 5 欄，不設範圍欄位，
            // 讓 cveExactVersionCheck() 走精確比對路徑而非誤判為「無上界範圍」
            const exactCriteria = realCpe || `cpe:2.3:a:${vendor}:${product}:${v.version}:*:*:*:*:*:*:*`;
            matches.push({ criteria: exactCriteria, vulnerable });
        } else {
            // 完全沒有版本資訊（罕見）：只保留 vendor/product 供關聯性比對用
            const base = realCpe || `cpe:2.3:a:${vendor}:${product}:*:*:*:*:*:*:*:*`;
            matches.push({ criteria: base, vulnerable });
        }
    }
    return matches;
}

// 將整筆 affected[] 轉成 configurations 結構。
// 缺口處理：
//   - 有 affected[] 條目（不論是否有 cpes[]）→ 正常轉換
//   - 完全沒有 affected[]（連 vendor/product 文字都沒有）→ configurations: []，
//     讓 cveRelevanceCheck/cveMatchesCPEBase 自然回傳 null（「無 CPE 資料」），
//     套用既有「無法驗證關聯性 → 過濾」政策，不要硬湊出比對結果。
function _buildConfigurations(affectedList) {
    if (!affectedList || !affectedList.length) return [];
    const cpeMatch = affectedList.flatMap(_buildCpeMatchesForAffected);
    if (!cpeMatch.length) return [];
    return [{ nodes: [{ cpeMatch }] }];
}

// 索引記錄 → synthetic NVD 格式 { cve: {...} }（與 nvd-client.js 回傳的 v.cve 結構相容）
function toNvdShape(record) {
    return {
        cve: {
            id: record.id,
            published: record.published,
            lastModified: record.lastModified || record.published,
            descriptions: [{ lang: 'en', value: record.descLower || '' }],
            metrics: _buildMetrics(record.metrics),
            configurations: _buildConfigurations(record.affected),
        },
    };
}

module.exports = { toNvdShape, _buildMetrics, _buildConfigurations, _buildCpeMatchesForAffected };
