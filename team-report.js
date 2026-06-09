#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const { compareVersions, isSafeVersion } = require('./lib/cve-logic');

// ─── Load Reports ────────────────────────────────────────────────────────────
async function loadTeamReports(teamDir) {
    try {
        await fs.promises.access(teamDir);
    } catch {
        console.error(`找不到目錄：${teamDir}`);
        process.exit(1);
    }

    const allFiles = await fs.promises.readdir(teamDir);
    const files = allFiles
        .filter(f => f.toLowerCase().endsWith('.json'))
        .sort();

    if (files.length === 0) {
        console.error(`目錄中沒有 JSON 檔案：${teamDir}`);
        process.exit(1);
    }

    const reports = [];
    for (const f of files) {
        const fullPath = path.join(teamDir, f);
        try {
            const raw = await fs.promises.readFile(fullPath, 'utf-8');
            const data = JSON.parse(raw);
            if (!data.summary || !Array.isArray(data.results)) {
                console.warn(`跳過 ${f}：缺少必要欄位（summary / results）`);
                continue;
            }
            reports.push({ _file: f, ...data });
        } catch (e) {
            console.warn(`跳過 ${f}：${e.message}`);
        }
    }

    return reports;
}

// ─── HTML Generator ──────────────────────────────────────────────────────────
async function generateTeamHTML(reports, outputPath) {
    const esc = s => (s || '')
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');

    const SEV_COLOR = {
        CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#d97706', LOW: '#2563eb',
    };

    const badge = (sev, score) => {
        const bg = SEV_COLOR[sev] || '#6b7280';
        const label = (score !== undefined && score !== '') ? `${esc(sev)} ${score}` : esc(sev);
        return `<span class="badge" style="background:${bg}">${label}</span>`;
    };

    const _now = new Date();
    const _p2 = n => String(n).padStart(2, '0');
    const generatedAt = `${_now.getFullYear()}-${_p2(_now.getMonth()+1)}-${_p2(_now.getDate())} ${_p2(_now.getHours())}:${_p2(_now.getMinutes())}:${_p2(_now.getSeconds())}`;

    // ── Aggregate stats ───────────────────────────────────────────────────────
    const totalMachines = reports.length;
    const totalSoftware = reports.reduce((s, r) => s + (r.summary?.totalSoftware || 0), 0);
    const totalQueried  = reports.reduce((s, r) => s + (r.summary?.queriedSoftware || 0), 0);
    const totalAffected = reports.reduce((s, r) => s + (r.summary?.affectedSoftware || 0), 0);
    const totalCVEs     = reports.reduce((s, r) => s + (r.summary?.totalCVEs || 0), 0);
    const machinesWithVulns = reports.filter(r => (r.summary?.affectedSoftware || 0) > 0).length;

    // ── Machine summary table ─────────────────────────────────────────────────
    const machineRows = reports.map((r, i) => {
        const needUpgrade = (r.results || []).filter(res =>
            res.recommendedVersion && !isSafeVersion(res.software?.version, res.recommendedVersion)
        ).length;
        const noRec = (r.results || []).filter(res =>
            !res.recommendedVersion ||
            (isSafeVersion(res.software?.version, res.recommendedVersion) && (res.cves || []).some(v => !v.fixedVersion))
        ).length;

        let stClass, stText;
        if (needUpgrade > 0) {
            stClass = 'danger'; stText = `✗ ${needUpgrade} 需升級`;
        } else if (noRec > 0) {
            stClass = 'warn'; stText = `? ${noRec} 請手動確認`;
        } else if ((r.summary?.affectedSoftware || 0) > 0) {
            stClass = 'safe'; stText = '✓ 已是最新版';
        } else {
            stClass = 'safe'; stText = '✓ 安全';
        }

        const scanDateStr = (r.scanDate || r.generatedAt || '').substring(0, 10).replace(/-/g, '/');
        const dateRange = r.minYear ? `${r.minYear}/01/01~${scanDateStr}` : scanDateStr;

        return `<tr>
          <td><a href="#machine-${i}" class="mlink">${esc(r.hostname || '?')}</a></td>
          <td>${esc(r.username || '?')}</td>
          <td>${esc(dateRange)}</td>
          <td style="text-align:center">${r.summary?.totalSoftware || 0}</td>
          <td style="text-align:center">${r.summary?.queriedSoftware || 0}</td>
          <td style="text-align:center;font-weight:700;color:${(r.summary?.affectedSoftware || 0) > 0 ? '#dc2626' : '#16a34a'}">${r.summary?.affectedSoftware || 0}</td>
          <td style="text-align:center">${r.summary?.totalCVEs || 0}</td>
          <td class="st ${stClass}">${stText}</td>
        </tr>`;
    }).join('\n');

    // ── Aggregated: software needing upgrade across machines ──────────────────
    const softwareMap = new Map(); // name → [{hostname, version, rec, needsUpgrade}]
    for (const r of reports) {
        for (const res of (r.results || [])) {
            const name = res.software?.name || '?';
            if (!softwareMap.has(name)) softwareMap.set(name, []);
            softwareMap.get(name).push({
                hostname: r.hostname || '?',
                version: res.software?.version || '?',
                recommendedVersion: res.recommendedVersion,
                needsUpgrade: !!(res.recommendedVersion && !isSafeVersion(res.software?.version, res.recommendedVersion)),
            });
        }
    }

    const needUpgradeSoftware = [...softwareMap.entries()]
        .filter(([, machines]) => machines.some(m => m.needsUpgrade))
        .sort((a, b) => {
            const diff = b[1].filter(m => m.needsUpgrade).length - a[1].filter(m => m.needsUpgrade).length;
            return diff !== 0 ? diff : a[0].localeCompare(b[0]);
        });

    const aggregatedRows = needUpgradeSoftware.map(([name, machines]) => {
        const affected = machines.filter(m => m.needsUpgrade);
        const rec = machines.find(m => m.recommendedVersion)?.recommendedVersion;
        const recText = rec ? `${rec.op === '>=' ? '≥' : '>'} ${esc(rec.version)}` : '—';
        const tags = affected.map(m =>
            `<span class="mtag">${esc(m.hostname)}<span class="mver"> v${esc(m.version)}</span></span>`
        ).join(' ');
        return `<tr>
          <td>${esc(name)}</td>
          <td style="white-space:nowrap">${recText}</td>
          <td style="text-align:center;font-weight:700;color:#dc2626">${affected.length}</td>
          <td>${tags}</td>
        </tr>`;
    }).join('\n');

    // ── Per-machine detail sections ───────────────────────────────────────────
    const SEV_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

    const machineSections = reports.map((r, i) => {
        const hasUnfixedCVE = res => (res.cves || []).some(v => !v.fixedVersion);
        const needUpgrade = (r.results || []).filter(res =>
            res.recommendedVersion && !isSafeVersion(res.software?.version, res.recommendedVersion)
        ).length;
        const noRec = (r.results || []).filter(res =>
            !res.recommendedVersion ||
            (isSafeVersion(res.software?.version, res.recommendedVersion) && hasUnfixedCVE(res))
        ).length;
        const aff = r.summary?.affectedSoftware || 0;
        const borderColor = needUpgrade > 0 ? '#dc2626' : noRec > 0 ? '#d97706' : '#16a34a';
        const iconColor   = needUpgrade > 0 ? '#dc2626' : noRec > 0 ? '#d97706' : '#16a34a';
        const icon = needUpgrade > 0 ? '✗' : noRec > 0 ? '?' : '✓';
        const mScanDateStr = (r.scanDate || r.generatedAt || '').substring(0, 10).replace(/-/g, '/');
        const mDateRange = r.minYear ? `${r.minYear}/01/01~${mScanDateStr}` : mScanDateStr;
        const wlCount = (r.whitelisted || []).length;
        const patternCount = (r.skippedByPattern || []).length;
        const dedupCount = (r.skippedByDedup || []).length;
        const skipCount = patternCount + dedupCount;

        const affectedRows = (r.results || []).map(res => {
            const installed = esc(res.software?.version || '?');
            const unfixedCVE = hasUnfixedCVE(res);
            let recTd, stTd;
            if (res.recommendedVersion) {
                const safe = isSafeVersion(res.software?.version, res.recommendedVersion);
                recTd = `${res.recommendedVersion.op === '>=' ? '≥' : '>'} ${esc(res.recommendedVersion.version)}`;
                if (!safe) {
                    stTd = `<td class="st danger">✗ 需要升級</td>`;
                } else if (unfixedCVE) {
                    stTd = `<td class="st warn">? 請手動確認</td>`;
                } else {
                    stTd = `<td class="st safe">✓ 無須升級</td>`;
                }
            } else {
                recTd = '—';
                stTd  = `<td class="st warn">? 請手動確認</td>`;
            }
            return `<tr>
              <td>${esc(res.software?.name || '?')}</td>
              <td>${esc(res.software?.publisher || '—')}</td>
              <td>${installed}</td>
              <td style="white-space:nowrap">${recTd}</td>
              ${stTd}
            </tr>`;
        }).join('\n');

        const cleanRows = (r.cleanResults || []).map(res => `<tr>
              <td>${esc(res.software?.name || '?')}</td>
              <td>${esc(res.software?.publisher || '—')}</td>
              <td>${esc(res.software?.version || '?')}</td>
              <td>—</td>
              <td class="st safe">✓ 無弱點</td>
            </tr>`).join('\n');

        const separator = cleanRows
            ? `<tr><td colspan="5" class="sep-lbl">── 以下軟體掃描後無發現弱點 ──</td></tr>`
            : '';

        const tableHTML = (affectedRows || cleanRows) ? `
      <table>
        <thead><tr><th>Software</th><th>Publisher</th><th>已安裝版本</th><th>最低安全版本</th><th>狀態</th></tr></thead>
        <tbody>${affectedRows}${separator}${cleanRows}</tbody>
      </table>` : '<p class="empty">無掃描結果</p>';

        const cveDetailsHTML = (r.results || [])
            .filter(res => (res.cves || []).length > 0)
            .map(res => {
                const installed = res.software?.version || '?';
                const sortedCves = [...(res.cves || [])].sort((a, b) =>
                    (b.published || '').localeCompare(a.published || ''));
                const topCVE = (res.cves || []).reduce((best, cve) =>
                    (SEV_ORDER[cve.severity] || 0) > (SEV_ORDER[best?.severity] || 0) ? cve : best, null);
                const topSev   = topCVE?.severity || 'NONE';
                const topScore = topCVE?.cvssScore ?? '';
                const unfixedCVE = hasUnfixedCVE(res);

                let recHtml;
                if (res.recommendedVersion) {
                    const safe = isSafeVersion(res.software?.version, res.recommendedVersion);
                    if (!safe) {
                        recHtml = `<div class="rec-bar danger">✗ 建議升級至 ${res.recommendedVersion.op === '>=' ? '≥' : '>'} ${esc(res.recommendedVersion.version)}（目前：${esc(installed)}）</div>`;
                    } else if (unfixedCVE) {
                        recHtml = `<div class="rec-bar warn">? 目前版本 (${esc(installed)}) 部分 CVE 無修復版資訊，請手動確認</div>`;
                    } else {
                        recHtml = `<div class="rec-bar safe">✓ 目前版本 (${esc(installed)}) 無弱點，無須升級</div>`;
                    }
                } else {
                    recHtml = `<div class="rec-bar warn">? 無版本修復資訊，請查閱各 CVE 連結</div>`;
                }

                const cveRows = sortedCves.map(cve => {
                    const fixHtml = cve.fixedVersion
                        ? `<div class="fix">✓ 安全版本：${cve.fixedVersion.op === '>=' ? '≥' : '>'} ${esc(cve.fixedVersion.version)}</div>`
                        : '';
                    return `
            <div class="cve-item">
              <div class="cve-hd">
                <a href="${esc(cve.url)}" target="_blank" class="cve-id">${esc(cve.id)}</a>
                ${badge(cve.severity, cve.cvssScore)}
                <span class="cvss-v">CVSS${esc(String(cve.cvssVersion || ''))}</span>
                <span class="pub">${(cve.published || '').substring(0, 10)}</span>
              </div>
              <p class="desc">${esc(cve.description || '')}</p>
              ${fixHtml}
            </div>`;
                }).join('');

                return `
        <details>
          <summary>
            <span class="sw-name">${esc(res.software?.name || '?')}</span>
            <span class="sw-ver">v${esc(installed)}</span>
            ${badge(topSev, topScore)}
            <span class="cnt">${res.cves.length} CVE${res.cves.length > 1 ? 's' : ''}</span>
          </summary>
          <div class="sw-meta">Publisher: ${esc(res.software?.publisher || 'N/A')} | Search: "${esc(res.searchName || '')}"</div>
          <div class="cve-list">${cveRows}</div>
          ${recHtml}
        </details>`;
            }).join('\n');

        const cveDetailsWrapHTML = cveDetailsHTML ? `
      <div class="cve-details-wrap">
        <p class="cve-details-lbl">CVE 詳細資訊（點擊展開）</p>
        ${cveDetailsHTML}
      </div>` : '';

        return `
    <section id="machine-${i}" style="border-left:4px solid ${borderColor}">
      <h2><span style="color:${iconColor};margin-right:6px">${icon}</span>${esc(r.hostname || '?')}<span class="muser"> @${esc(r.username || '?')}</span></h2>
      <p class="mmeta">
        CVE 日期範圍：${esc(mDateRange)} &nbsp;|&nbsp;
        來源：${esc(r.source || '?')} &nbsp;|&nbsp;
        最低嚴重度：<strong>${esc(r.minSeverity || '?')}</strong> &nbsp;|&nbsp;
        軟體總計 ${r.summary?.totalSoftware || 0} &nbsp;|&nbsp;
        白名單 ${wlCount} &nbsp;|&nbsp;
        子元件/重複 ${skipCount} &nbsp;|&nbsp;
        掃描 ${r.summary?.queriedSoftware || 0} &nbsp;|&nbsp;
        <strong style="color:${needUpgrade > 0 ? '#dc2626' : '#16a34a'}">${needUpgrade}</strong> 需升級・<strong style="color:${noRec > 0 ? '#d97706' : '#16a34a'}">${aff - needUpgrade}</strong> 已最新版・<strong>${(r.cleanResults || []).length}</strong> 無弱點
      </p>
      ${tableHTML}
      ${cveDetailsWrapHTML}
    </section>`;
    }).join('\n');

    // ── HTML template ─────────────────────────────────────────────────────────
    const html = `<!DOCTYPE html>
<html lang="zh-TW">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Team CVE Report — ${esc(generatedAt.substring(0, 10))}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f3f4f6;color:#1f2937;line-height:1.5}
a{color:#2563eb;text-decoration:none}a:hover{text-decoration:underline}
header{background:#1e3a5f;color:#fff;padding:24px 32px}
header h1{font-size:1.5rem;font-weight:700;margin-bottom:6px}
.hmeta{font-size:.83rem;opacity:.8;margin-bottom:16px}
.dash{display:flex;gap:6px;margin-top:16px;flex-wrap:wrap}
.dc{border-radius:10px;padding:16px 22px;text-align:center;min-width:88px}
.dc .n{font-size:2.4rem;font-weight:800;line-height:1;letter-spacing:-.03em}
.dc .l{font-size:.67rem;opacity:.72;margin-top:6px;white-space:nowrap}
.dc.tot{background:rgba(255,255,255,.16)}.dc.tot .n{color:#f1f5f9}
.dc.scan{background:rgba(59,130,246,.22)}.dc.scan .n{color:#93c5fd}
.dc.ok{background:rgba(34,197,94,.18)}.dc.ok .n{color:#86efac}
.dc.hi{background:rgba(239,68,68,.22)}.dc.hi .n{color:#fca5a5}
.dc.neu{background:rgba(234,179,8,.16)}.dc.neu .n{color:#fde68a}
main{max-width:1200px;margin:24px auto;padding:0 16px}
section{background:#fff;border-radius:10px;padding:20px 24px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
h2{font-size:1rem;font-weight:700;margin-bottom:12px;color:#1e3a5f;border-bottom:2px solid #e5e7eb;padding-bottom:8px;display:flex;align-items:center;gap:6px}
table{width:100%;border-collapse:collapse;font-size:.875rem}
th{background:#f9fafb;text-align:left;padding:8px 12px;font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;color:#6b7280;border-bottom:2px solid #e5e7eb}
td{padding:8px 12px;border-bottom:1px solid #f3f4f6;vertical-align:middle}
tr:last-child td{border-bottom:none}tr:hover td{background:#fafafa}
.st{font-weight:700;font-size:.85rem}.st.safe{color:#16a34a}.st.danger{color:#dc2626}.st.warn{color:#d97706}
.badge{display:inline-block;padding:2px 7px;border-radius:4px;color:#fff;font-size:.73rem;font-weight:700;white-space:nowrap}
.mlink{font-weight:600}
.muser{font-size:.78rem;color:#6b7280;font-weight:400}
.mmeta{font-size:.78rem;color:#6b7280;margin-bottom:12px}
.mtag{display:inline-block;background:#fef2f2;color:#991b1b;border:1px solid #fecaca;font-size:.72rem;padding:1px 7px;border-radius:4px;margin:1px 2px}
.mver{color:#b91c1c;opacity:.7}
.sep-lbl{background:#f0fdf4;color:#16a34a;font-size:.76rem;font-weight:600;padding:5px 12px}
.empty{color:#6b7280;font-size:.85rem;padding:8px 0}
.cve-details-wrap{margin-top:14px}
.cve-details-lbl{font-size:.76rem;color:#6b7280;font-weight:600;margin-bottom:6px;padding-left:2px}
details{border:1px solid #e5e7eb;border-radius:8px;margin-bottom:6px;overflow:hidden}
summary{display:flex;align-items:center;gap:8px;padding:10px 14px;cursor:pointer;background:#f9fafb;list-style:none;flex-wrap:wrap;user-select:none}
summary::-webkit-details-marker{display:none}
summary::before{content:'▶';font-size:.65rem;color:#9ca3af;transition:transform .15s;flex-shrink:0}
details[open]>summary::before{transform:rotate(90deg)}
summary:hover{background:#f0f0f0}
.sw-name{font-weight:600;font-size:.9rem;flex:1}
.sw-ver{color:#6b7280;font-size:.8rem}
.cnt{color:#6b7280;font-size:.76rem;margin-left:auto}
.sw-meta{padding:4px 14px;font-size:.76rem;color:#9ca3af}
.cve-list{padding:8px 14px 4px}
.cve-item{background:#f9fafb;border-radius:6px;padding:8px 12px;margin-bottom:6px}

.cve-hd{display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-bottom:3px}
.cve-id{font-weight:700;font-family:monospace;font-size:.86rem;color:#1e3a5f}
.cvss-v{font-size:.7rem;color:#9ca3af}
.pub{font-size:.7rem;color:#9ca3af;margin-left:auto}
.desc{font-size:.8rem;color:#4b5563;margin:3px 0}
.fix{font-size:.76rem;color:#16a34a;font-weight:600;margin-top:3px}
.rec-bar{padding:8px 14px;font-size:.83rem;font-weight:600;border-top:1px solid #e5e7eb}
.rec-bar.safe{color:#166534;background:#f0fdf4}.rec-bar.danger{color:#991b1b;background:#fef2f2}.rec-bar.warn{color:#92400e;background:#fffbeb}

footer{text-align:center;padding:20px;font-size:.78rem;color:#9ca3af}
</style>
</head>
<body>
<header>
  <h1>Team CVE Vulnerability Report</h1>
  <div class="hmeta">
    Generated: ${esc(generatedAt)} &nbsp;|&nbsp;
    機器總數：<strong>${totalMachines}</strong> &nbsp;|&nbsp;
    有弱點機器：<strong>${machinesWithVulns}</strong>
  </div>
  <div class="dash">
    <div class="dc tot"><div class="n">${totalMachines}</div><div class="l">機器總數</div></div>
    <div class="dc ${machinesWithVulns > 0 ? 'hi' : 'ok'}"><div class="n">${machinesWithVulns}</div><div class="l">有弱點機器</div></div>
    <div class="dc tot"><div class="n">${totalSoftware}</div><div class="l">軟體總計</div></div>
    <div class="dc scan"><div class="n">${totalQueried}</div><div class="l">實際掃描</div></div>
    <div class="dc ${totalAffected > 0 ? 'hi' : 'ok'}"><div class="n">${totalAffected}</div><div class="l">發現弱點</div></div>
    <div class="dc ${totalCVEs > 0 ? 'neu' : 'ok'}"><div class="n">${totalCVEs}</div><div class="l">CVE 總數</div></div>
  </div>
</header>
<main>
  <section>
    <h2>機器總覽（${totalMachines} 台）</h2>
    <table>
      <thead><tr><th>主機名稱</th><th>使用者</th><th>CVE 日期範圍</th><th style="text-align:center">軟體總計</th><th style="text-align:center">掃描數</th><th style="text-align:center">有弱點</th><th style="text-align:center">CVE 數</th><th>狀態</th></tr></thead>
      <tbody>${machineRows}</tbody>
    </table>
  </section>
  ${needUpgradeSoftware.length > 0 ? `
  <section>
    <h2>需要升級的軟體彙整（${needUpgradeSoftware.length} 種，跨機器統計）</h2>
    <table>
      <thead><tr><th>軟體名稱</th><th>最低安全版本</th><th style="text-align:center">受影響機器數</th><th>受影響機器 / 版本</th></tr></thead>
      <tbody>${aggregatedRows}</tbody>
    </table>
  </section>` : `
  <section>
    <h2>需要升級的軟體彙整</h2>
    <p class="empty">✓ 所有機器均無需升級</p>
  </section>`}
  <section>
    <h2>各機器詳細結果</h2>
    <p style="font-size:.82rem;color:#6b7280;margin-bottom:0">點擊機器名稱可跳轉至對應區塊</p>
  </section>
  ${machineSections}
</main>
<footer>NIST NVD Team CVE Report &nbsp;·&nbsp; ${esc(generatedAt)}<br>This product uses data from the NVD API but is not endorsed or certified by the NVD.</footer>
</body>
</html>`;

    const htmlBuf = Buffer.concat([Buffer.from([0xEF, 0xBB, 0xBF]), Buffer.from(html, 'utf8')]);
    await fs.promises.writeFile(outputPath, htmlBuf);
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
    const args = process.argv.slice(2);
    const teamDir   = path.resolve(args[0] || path.join(__dirname, 'team'));
    const reportDir = path.join(__dirname, 'report');

    console.log(`Loading reports from: ${teamDir}`);
    const reports = await loadTeamReports(teamDir);
    console.log(`Loaded ${reports.length} report(s): ${reports.map(r => r._file).join(', ')}`);

    await fs.promises.mkdir(reportDir, { recursive: true });

    const nowTs = new Date();
    const pad2 = n => String(n).padStart(2, '0');
    const dateStamp = `${nowTs.getFullYear()}${pad2(nowTs.getMonth()+1)}${pad2(nowTs.getDate())}`;
    const outputPath = path.join(reportDir, `team_${dateStamp}.html`);

    await generateTeamHTML(reports, outputPath);
    console.log(`Team report saved: ${outputPath}`);
}

main().catch(e => {
    console.error(`Fatal error: ${e.message}`);
    process.exit(1);
});
