// Shared HTML report generator — single source of truth.
// Used by: cve-checker.js (via require), web/web-client.html (via build.js injection).
// Pure function: takes a report object, returns an HTML string. No I/O.
'use strict';

// In Node.js: isSafeVersion comes from cve-logic. In browser: already in scope from @@CVE_LOGIC@@ injection.
const _isSafeVersion =
    typeof isSafeVersion !== 'undefined'
        ? isSafeVersion
        : require('./cve-logic').isSafeVersion;

function _formatDateTime(iso) {
    const d = new Date(iso);
    const pad = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function buildHTMLReport(report) {
    const esc = s => (s == null ? '' : String(s))
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');

    const SEV_COLOR = { CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#d97706', LOW: '#2563eb' };
    const badge = (sev, score) =>
        `<span class="badge" style="background:${SEV_COLOR[sev]||'#6b7280'}">${esc(sev)}${score !== '' ? ' '+score : ''}</span>`;

    const hasUnfixedCVE = r => (r.cves || []).some(v => !v.fixedVersion);

    // 已修正：有明確修復版、目前版本已達要求、所有 CVE 均有 fix 資訊 → 列入獨立稽核區塊
    const fixedResults  = report.results.filter(r =>
        r.recommendedVersion && _isSafeVersion(r.software.version, r.recommendedVersion) && !hasUnfixedCVE(r)
    );
    // 需行動：需升級 ✗ 或無法確定 ? → 列入主摘要與 CVE 詳細資訊
    const actionResults = report.results.filter(r =>
        !r.recommendedVersion || !_isSafeVersion(r.software.version, r.recommendedVersion) || hasUnfixedCVE(r)
    );

    const needUpgrade  = actionResults.filter(r => r.recommendedVersion && !_isSafeVersion(r.software.version, r.recommendedVersion)).length;
    const noRecCount   = actionResults.filter(r => !r.recommendedVersion || hasUnfixedCVE(r)).length;
    const alreadySafe  = fixedResults.length;
    const cleanCount   = (report.cleanResults || []).length;
    const scanDateStr  = (report.generatedAt || '').substring(0, 10).replace(/-/g, '/');
    const minYearLabel = report.minYear ? `${report.minYear}/01/01~${scanDateStr}` : '不限';

    // Whitelisted section
    const wlGroups = {};
    for (const sw of (report.whitelisted || [])) (wlGroups[sw.matchedRule] ??= []).push(sw);
    const wlHTML = (report.whitelisted || []).length === 0 ? '' : `
  <section id="whitelisted">
    <h2>白名單跳過的軟體（${report.whitelisted.length} 筆，未進行掃描）</h2>
    <p class="sec-note">以下軟體因 Publisher 符合白名單設定而略過，未查詢 NIST NVD。</p>
    ${Object.entries(wlGroups).map(([rule, list]) => `
    <div class="wl-group"><div class="wl-rule">規則：${esc(rule)}</div>
    <table><thead><tr><th>Software</th><th>Version</th><th>Publisher</th></tr></thead>
    <tbody>${list.map(sw => `<tr><td>${esc(sw.name)}</td><td>${esc(sw.version)}</td><td>${esc(sw.publisher)}</td></tr>`).join('')}</tbody></table></div>`).join('')}
  </section>`;

    const patternHTML = (report.skippedByPattern || []).length === 0 ? '' : `
  <section id="skipped-pattern">
    <h2>子元件跳過的軟體（${report.skippedByPattern.length} 筆，未進行掃描）</h2>
    <p class="sec-note">以下軟體符合內建 SKIP_PATTERNS 規則（VC++ Runtime 子元件、Office Click-to-Run 元件、Python 子安裝項），其弱點已由對應的主程式條目代表，故略過。</p>
    <table><thead><tr><th>Software</th><th>Version</th><th>Publisher</th></tr></thead>
    <tbody>${report.skippedByPattern.map(sw => `<tr><td>${esc(sw.name)}</td><td>${esc(sw.version)}</td><td>${esc(sw.publisher)}</td></tr>`).join('')}</tbody></table>
  </section>`;

    const dedupHTML = (report.skippedByDedup || []).length === 0 ? '' : `
  <section id="skipped-dedup">
    <h2>重複去除的軟體（${report.skippedByDedup.length} 筆，未進行掃描）</h2>
    <p class="sec-note">以下軟體在去除版號後與另一條目名稱相同，已由較早出現的條目代表，故略過重複查詢。</p>
    <table><thead><tr><th>Software</th><th>Version</th><th>Publisher</th><th>合併為</th></tr></thead>
    <tbody>${report.skippedByDedup.map(sw => `<tr><td>${esc(sw.name)}</td><td>${esc(sw.version)}</td><td>${esc(sw.publisher)}</td><td style="font-size:.78rem;color:#6b7280">${esc(sw.mergedAs)}</td></tr>`).join('')}</tbody></table>
  </section>`;

    // 主摘要表：只顯示「需行動」項目（✗ 升級 / ? 確認），已修正者移至獨立稽核區
    const affectedRows = actionResults.map(r => {
        const { software, recommendedVersion, cves } = r;
        const unfixedCVE = (cves || []).some(v => !v.fixedVersion);
        let recTd, statusTd;
        if (recommendedVersion) {
            recTd = `${recommendedVersion.op === '>=' ? '≥' : '>'} ${esc(recommendedVersion.version)}`;
            statusTd = !_isSafeVersion(software.version, recommendedVersion)
                ? `<td class="st danger">✗ 需要升級</td>`
                : `<td class="st warn">? 請手動確認</td>`;
        } else {
            recTd = '—';
            statusTd = `<td class="st warn">? 請手動確認</td>`;
        }
        return `<tr><td>${esc(software.name)}</td><td>${esc(software.publisher||'—')}</td><td>${esc(software.version||'?')}</td><td>${recTd}</td>${statusTd}</tr>`;
    }).join('\n');

    const cleanRows = (report.cleanResults || []).map(r =>
        `<tr><td>${esc(r.software.name)}</td><td>${esc(r.software.publisher||'—')}</td><td>${esc(r.software.version||'?')}</td><td>—</td><td class="st safe">✓ 無弱點</td></tr>`
    ).join('\n');

    const tableRows = affectedRows + (cleanRows
        ? `\n<tr class="sep-row"><td colspan="5" style="background:#f0fdf4;color:#16a34a;font-size:.78rem;font-weight:600;padding:5px 12px">── 以下軟體掃描後無發現 ${esc(report.minSeverity)} 以上弱點 ──</td></tr>\n` + cleanRows
        : '');

    // CVE 詳細資訊：只列「需行動」項目
    const detailsHTML = actionResults.map(r => {
        const { software, cves, recommendedVersion, searchName } = r;
        const installed = software.version || '?';
        const topSev = cves[0]?.severity || 'NONE';

        let recHtml;
        if (recommendedVersion) {
            recHtml = !_isSafeVersion(installed, recommendedVersion)
                ? `<div class="rec danger">✗ 建議升級至 ${recommendedVersion.op === '>=' ? '≥' : '>'} ${esc(recommendedVersion.version)}（目前：${esc(installed)}）</div>`
                : `<div class="rec warn">? 部分 CVE 無版本修復資訊，請手動確認</div>`;
        } else {
            recHtml = `<div class="rec warn">? 無版本修復資訊，請查閱各 CVE 連結</div>`;
        }

        const cveRows = cves.map(cve => {
            let fixHtml = '';
            if (cve.affectedRanges && cve.affectedRanges.length > 0) {
                const rows = cve.affectedRanges.map(rv => {
                    const fromStr = rv.from ? `${rv.fromOp === '>' ? '>' : '≥'} ${esc(rv.from)}` : '＊';
                    const toStr   = `${rv.toOp === '>=' ? '≥' : '>'} ${esc(rv.to)}`;
                    return `<tr><td class="r-from">${fromStr}</td><td class="r-arr">→</td><td class="r-to">${toStr}</td></tr>`;
                }).join('');
                fixHtml = `<div class="fix">✓ 安全版本（各分支）：<table class="ranges">${rows}</table></div>`;
            } else if (cve.fixedVersion) {
                fixHtml = `<div class="fix">✓ 安全版本：${cve.fixedVersion.op === '>=' ? '≥' : '>'} ${esc(cve.fixedVersion.version)}</div>`;
            }
            const pendingHtml = cve.pendingNvdAnalysis
                ? `<div class="pending-nvd">⚠ NVD 尚未完成分析（無 CPE 資料），請至 <a href="${esc(cve.url)}" target="_blank">NVD 頁面</a> 手動確認是否影響已安裝版本</div>`
                : '';
            return `
      <div class="cve${cve.pendingNvdAnalysis ? ' cve-pending' : ''}">
        <div class="cve-hd">
          <a href="${esc(cve.url)}" target="_blank" class="cve-id">${esc(cve.id)}</a>
          ${badge(cve.severity, cve.cvssScore)}
          <span class="cvss-v">CVSS${esc(cve.cvssVersion||'')}</span>
          <span class="pub">${(cve.published||'').substring(0,10)}</span>
          ${cve.pendingNvdAnalysis ? '<span class="nvd-pending-tag">⚠ NVD 分析中</span>' : ''}
        </div>
        <p class="desc">${esc(cve.description||'')}</p>
        ${fixHtml}${pendingHtml}
      </div>`;
        }).join('');

        return `
    <details>
      <summary>
        <span class="sw-name">${esc(software.name)}</span>
        <span class="sw-ver">v${esc(installed)}</span>
        ${badge(topSev, '')}
        <span class="cnt">${cves.length} CVE${cves.length > 1 ? 's' : ''}</span>
      </summary>
      <div class="sw-meta">Publisher: ${esc(software.publisher||'N/A')} &nbsp;|&nbsp; Search: "${esc(searchName)}"</div>
      <div class="cve-list">${cveRows}</div>
      ${recHtml}
    </details>`;
    }).join('\n');

    // 已修正弱點稽核區：有 CVE 但版本已達修復要求，僅供參考不需行動
    const fixedDetailsHTML = fixedResults.length === 0 ? '' : fixedResults.map(r => {
        const { software, cves, recommendedVersion, searchName } = r;
        const installed = software.version || '?';
        const topSev = cves[0]?.severity || 'NONE';
        const recVer = `${recommendedVersion.op === '>=' ? '≥' : '>'} ${esc(recommendedVersion.version)}`;

        const cveRows = cves.map(cve => {
            let fixHtml = '';
            if (cve.affectedRanges && cve.affectedRanges.length > 0) {
                const rows = cve.affectedRanges.map(rv => {
                    const fromStr = rv.from ? `${rv.fromOp === '>' ? '>' : '≥'} ${esc(rv.from)}` : '＊';
                    const toStr   = `${rv.toOp === '>=' ? '≥' : '>'} ${esc(rv.to)}`;
                    return `<tr><td class="r-from">${fromStr}</td><td class="r-arr">→</td><td class="r-to">${toStr}</td></tr>`;
                }).join('');
                fixHtml = `<div class="fix">✓ 安全版本（各分支）：<table class="ranges">${rows}</table></div>`;
            } else if (cve.fixedVersion) {
                fixHtml = `<div class="fix">✓ 安全版本：${cve.fixedVersion.op === '>=' ? '≥' : '>'} ${esc(cve.fixedVersion.version)}</div>`;
            }
            return `
      <div class="cve">
        <div class="cve-hd">
          <a href="${esc(cve.url)}" target="_blank" class="cve-id">${esc(cve.id)}</a>
          ${badge(cve.severity, cve.cvssScore)}
          <span class="cvss-v">CVSS${esc(cve.cvssVersion||'')}</span>
          <span class="pub">${(cve.published||'').substring(0,10)}</span>
        </div>
        <p class="desc">${esc(cve.description||'')}</p>
        ${fixHtml}
      </div>`;
        }).join('');

        return `
    <details class="details-fixed">
      <summary>
        <span class="sw-name">${esc(software.name)}</span>
        <span class="sw-ver">v${esc(installed)}</span>
        ${badge(topSev, '')}
        <span class="fixed-tag">✓ 已修正</span>
        <span class="cnt">${cves.length} CVE${cves.length > 1 ? 's' : ''}</span>
      </summary>
      <div class="sw-meta">Publisher: ${esc(software.publisher||'N/A')} &nbsp;|&nbsp; Search: "${esc(searchName)}" &nbsp;|&nbsp; 最低安全版本：${recVer}</div>
      <div class="cve-list">${cveRows}</div>
      <div class="rec safe">✓ 目前版本 (${esc(installed)}) 已達修復要求 ${recVer}，無需行動</div>
    </details>`;
    }).join('\n');

    const fixedSection = fixedResults.length === 0 ? '' : `
  <section id="fixed-cves">
    <h2>✓ 已修正的已知弱點（${fixedResults.length} 套件，目前版本已達修復要求，點擊展開）</h2>
    <p class="sec-note">以下軟體在 NVD 中有已知 CVE 紀錄，但目前安裝版本符合或超過最低安全版本要求，<strong>無需採取行動</strong>。列出此紀錄供稽核參考，確認掃描確有執行。</p>
    ${fixedDetailsHTML}
  </section>`;

    return `<!DOCTYPE html>
<html lang="zh-TW">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CVE Report — ${esc(report.generatedAt.substring(0,10))}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f3f4f6;color:#1f2937;line-height:1.5}
a{color:#2563eb;text-decoration:none}a:hover{text-decoration:underline}
header{background:#1e3a5f;color:#fff;padding:24px 32px}
header h1{font-size:1.5rem;font-weight:700;margin-bottom:6px}
.meta{font-size:.83rem;opacity:.8;margin-bottom:16px}
.dash{display:flex;align-items:stretch;gap:0;margin-top:16px;flex-wrap:wrap;gap:2px}
.dash-grp{display:flex;flex-direction:column;gap:5px;padding:0 18px}
.dash-grp:first-child{padding-left:0}
.dash-grp-lbl{font-size:.58rem;text-transform:uppercase;letter-spacing:.12em;opacity:.4;margin-bottom:1px}
.dash-cards{display:flex;align-items:center;gap:4px}
.dash-sep{width:1px;background:rgba(255,255,255,.16);margin:0 4px;align-self:stretch;flex-shrink:0}
.darr{font-size:.65rem;opacity:.3;flex-shrink:0;padding:0 2px}
.dc{border-radius:10px;padding:18px 24px;text-align:center;min-width:100px;flex-shrink:0}
.dc .n{font-size:2.8rem;font-weight:800;line-height:1;letter-spacing:-.03em}
.dc .l{font-size:.69rem;opacity:.72;margin-top:8px;white-space:nowrap}
.dc .s{font-size:.62rem;opacity:.48;margin-top:3px}
.dc.tot{background:rgba(255,255,255,.16)}.dc.tot .n{color:#f1f5f9}
.dc.skip{background:rgba(148,163,184,.14)}.dc.skip .n{color:#94a3b8}
.dc.scan{background:rgba(59,130,246,.22)}.dc.scan .n{color:#93c5fd}
.dc.ok{background:rgba(34,197,94,.18)}.dc.ok .n{color:#86efac}
.dc.hi{background:rgba(239,68,68,.22)}.dc.hi .n{color:#fca5a5}
.dc.neu{background:rgba(234,179,8,.16)}.dc.neu .n{color:#fde68a}
main{max-width:1100px;margin:24px auto;padding:0 16px}
section{background:#fff;border-radius:10px;padding:20px 24px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
h2{font-size:1rem;font-weight:700;margin-bottom:14px;color:#1e3a5f;border-bottom:2px solid #e5e7eb;padding-bottom:8px}
#fixed-cves h2{color:#166534;border-bottom-color:#bbf7d0}
.sec-note{font-size:.85rem;color:#6b7280;margin-bottom:12px}
table{width:100%;border-collapse:collapse;font-size:.875rem}
th{background:#f9fafb;text-align:left;padding:8px 12px;font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;color:#6b7280;border-bottom:2px solid #e5e7eb}
td{padding:8px 12px;border-bottom:1px solid #f3f4f6}
tr:last-child td{border-bottom:none}tr:hover td{background:#fafafa}
.st{font-weight:700;font-size:.85rem}.st.safe{color:#16a34a}.st.danger{color:#dc2626}.st.warn{color:#d97706}
details{border:1px solid #e5e7eb;border-radius:8px;margin-bottom:8px;overflow:hidden}
details.details-fixed{border-color:#bbf7d0}
summary{display:flex;align-items:center;gap:8px;padding:11px 16px;cursor:pointer;background:#f9fafb;list-style:none;flex-wrap:wrap;user-select:none}
details.details-fixed>summary{background:#f0fdf4}
summary::-webkit-details-marker{display:none}
summary::before{content:'▶';font-size:.65rem;color:#9ca3af;transition:transform .15s;flex-shrink:0}
details[open]>summary::before{transform:rotate(90deg)}
summary:hover{background:#f0f0f0}
details.details-fixed>summary:hover{background:#dcfce7}
.sw-name{font-weight:600;font-size:.93rem;flex:1}
.sw-ver{color:#6b7280;font-size:.82rem}
.cnt{color:#6b7280;font-size:.78rem;margin-left:auto}
.fixed-tag{font-size:.75rem;font-weight:700;color:#166534;background:#dcfce7;border:1px solid #86efac;border-radius:4px;padding:1px 7px;white-space:nowrap}
.sw-meta{padding:5px 16px;font-size:.78rem;color:#9ca3af}
.sw-cpe{font-size:.7rem;color:#9ca3af;font-family:monospace;margin-top:2px}
.badge{display:inline-block;padding:2px 7px;border-radius:4px;color:#fff;font-size:.73rem;font-weight:700;white-space:nowrap}
.cve-list{padding:8px 16px 4px}
.cve{background:#f9fafb;border-radius:6px;padding:9px 13px;margin-bottom:7px}
.cve-pending{background:#fffbeb;border-left:3px solid #d97706}
.cve-hd{display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-bottom:3px}
.cve-id{font-weight:700;font-family:monospace;font-size:.88rem;color:#1e3a5f}
.cvss-v{font-size:.72rem;color:#9ca3af}
.pub{font-size:.72rem;color:#9ca3af;margin-left:auto}
.nvd-pending-tag{font-size:.7rem;font-weight:600;color:#92400e;background:#fef3c7;border:1px solid #fcd34d;border-radius:3px;padding:1px 5px;white-space:nowrap}
.desc{font-size:.82rem;color:#4b5563;margin:3px 0}
.fix{font-size:.78rem;color:#16a34a;font-weight:600;margin-top:3px}
.ranges{border-collapse:collapse;margin:3px 0 0 8px;font-family:monospace;font-size:.76rem}
.ranges td{padding:1px 4px;vertical-align:middle}
.r-from{color:#374151}.r-arr{color:#9ca3af;padding:0 2px}.r-to{color:#16a34a;font-weight:700}
.pending-nvd{font-size:.78rem;color:#92400e;font-weight:600;margin-top:4px}
.rec{padding:9px 16px;font-size:.85rem;font-weight:600;border-top:1px solid #e5e7eb}
.rec.safe{color:#166534;background:#f0fdf4}.rec.danger{color:#991b1b;background:#fef2f2}.rec.warn{color:#92400e;background:#fffbeb}
.wl-group{margin-bottom:16px}
.wl-rule{display:inline-block;background:#e0f2fe;color:#0369a1;font-size:.78rem;font-weight:700;padding:2px 10px;border-radius:4px;margin-bottom:6px}
footer{text-align:center;padding:20px;font-size:.78rem;color:#9ca3af}
</style>
</head>
<body>
<header>
  <h1>CVE Vulnerability Report</h1>
  <div class="meta">
    Generated: ${esc(_formatDateTime(report.generatedAt))} &nbsp;|&nbsp;
    Host: ${esc(report.hostname||'?')} &nbsp;|&nbsp;
    IP: ${esc(report.ip||'?')} &nbsp;|&nbsp;
    User: ${esc(report.username||'?')} &nbsp;|&nbsp;
    Min Severity: <strong>${esc(report.minSeverity)}</strong> &nbsp;|&nbsp;
    CVE 日期範圍：<strong>${esc(minYearLabel)}</strong>
  </div>
  <div class="dash">
    <div class="dash-grp">
      <div class="dash-grp-lbl">軟體清單</div>
      <div class="dash-cards">
        <div class="dc tot"><div class="n">${report.summary.totalSoftware}</div><div class="l">軟體總計</div></div>
        <span class="darr">▶</span>
        <div class="dc skip"><div class="n">${(report.whitelisted||[]).length}</div><div class="l">白名單略過</div></div>
        <span class="darr">▶</span>
        <div class="dc skip"><div class="n">${(report.skippedByPattern||[]).length+(report.skippedByDedup||[]).length}</div><div class="l">子元件/重複略過</div><div class="s">${(report.skippedByPattern||[]).length} 子元件・${(report.skippedByDedup||[]).length} 重複</div></div>
        <span class="darr">▶</span>
        <div class="dc scan"><div class="n">${report.summary.queriedSoftware}</div><div class="l">實際掃描</div></div>
      </div>
    </div>
    <div class="dash-sep"></div>
    <div class="dash-grp">
      <div class="dash-grp-lbl">掃描結果</div>
      <div class="dash-cards">
        <div class="dc scan"><div class="n">${report.summary.queriedSoftware}</div><div class="l">實際掃描</div></div>
        <span class="darr">▶</span>
        <div class="dc ok"><div class="n">${cleanCount}</div><div class="l">無弱點</div></div>
        ${alreadySafe > 0 ? `<span class="darr">▶</span>
        <div class="dc ok"><div class="n">${alreadySafe}</div><div class="l">版本已修正</div><div class="s">CVE 已記錄</div></div>` : ''}
        <span class="darr">▶</span>
        <div class="dc ${needUpgrade>0?'hi':'ok'}"><div class="n">${needUpgrade}</div><div class="l">建議升級</div></div>
        ${noRecCount>0?`<span class="darr">▶</span><div class="dc neu"><div class="n">${noRecCount}</div><div class="l">請手動確認</div></div>`:''}
      </div>
    </div>
  </div>
</header>
<main>
  <section>
    <h2>升級建議摘要（共 ${report.summary.queriedSoftware} 筆：${needUpgrade} 需升級${noRecCount>0?'・'+noRecCount+' 請手動確認':''}・${cleanCount} 無弱點${alreadySafe>0?'・'+alreadySafe+' 版本已修正（詳見下方）':''}）</h2>
    <table>
      <thead><tr><th>Software</th><th>Publisher</th><th>已安裝版本</th><th>最低安全版本（需達到）</th><th>狀態</th></tr></thead>
      <tbody>${tableRows||'<tr><td colspan="5" style="color:#6b7280;text-align:center;padding:16px">所有掃描軟體均無發現弱點</td></tr>'}</tbody>
    </table>
  </section>
  <section>
    <h2>CVE 詳細資訊（點擊展開）</h2>
    ${detailsHTML||'<p class="sec-note">所有掃描軟體均無發現需處理的 CVE</p>'}
  </section>
  ${fixedSection}
  ${wlHTML}${patternHTML}${dedupHTML}
</main>
<footer>NIST NVD CVE Scanner &nbsp;·&nbsp; ${esc(report.generatedAt)}<br>This product uses data from the NVD API but is not endorsed or certified by the NVD.</footer>
</body>
</html>`;
}

if (typeof module !== 'undefined') {
    module.exports = { buildHTMLReport };
}
