# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 專案執行原則

1. 所有的交談都以繁體中文為主。
2. 每當討論出架構決策或注意事項，立即更新本文件的對應章節，不要等到對話結束才整理。
3. 程式碼、函式庫應用繁體中文記錄註解，讓使用者知道這段程式碼用途。
4. Node.js 請使用原生功能，不要使用任何需額外下載之套件。**唯一例外**：`adm-zip`（`scripts/mitre-sync.js` 解壓 MITRE cvelistV5 ZIP 用，Node 原生 zlib 只能處理 deflate/gzip，無法解析 ZIP 容器格式），使用者已明確核准此例外。
5. 操作方式（指令、參數、設定檔）與資料格式範例（輸入/輸出 JSON、快取檔案結構、目錄總覽）寫在 `README.md`；本文件只放系統處理原則與架構決策。

## 常用指令

| 指令 | 說明 |
|------|------|
| `npm start` | CLI 掃描（讀取本機 Registry 或 `.env.local` 的 `PORTABLE_N`） |
| `npm test` | 執行 `lib/cve-logic.js` 回歸測試（Node 原生 `node --test "scripts/test/*.test.js"`，無外部套件；全部集中在單一檔 `scripts/test/cve-logic.test.js`）。單獨執行一個測試：`node --test --test-name-pattern="<測試名稱關鍵字>" "scripts/test/cve-logic.test.js"` |
| `npm run check` | 快速掃描：HIGH 以上、限掃前 5 筆軟體（年份用預設「當年 − 1」） |
| `npm run web` | 啟動 Web 伺服器（自動先執行 `node scripts/build.js`，port 預設 8093） |
| `npm run bundle` | 單獨執行 `node scripts/build.js`（修改 `lib/cve-logic.js` 或 `lib/report-html.js` 後須執行） |
| `npm run sync-mitre` | 同步 MITRE cvelistV5 本機鏡像（首次使用 `CVE_SOURCE=MITRE` 前須執行） |
| `npm run package` | 部署打包：把必要檔案壓成 `dist/NISTCVECheck_deploy_<date>.zip`（`scripts/package-deploy.js`）。預設含 CVE 快取、排除機密/大型/建置產物；旗標：`--no-cache`（乾淨部署）、`--with-node-modules`（離線）、`--out=<路徑>` |
| `node scripts/team-report.js <目錄>` | 讀取目錄下所有 JSON 個人報表，產生跨機器彙整 HTML 報告 |
| `powershell -ExecutionPolicy Bypass -File findSW.ps1` | 掃描本機安裝軟體，輸出 `scan.json`（可作為 CLI 輸入） |

設定檔：複製 `.env.local.example` 為 `.env.local` 並填入 `NIST_API_KEY`（可選，無 Key 速率限制較嚴）與 `PORTABLE_N` 清單。

## 架構說明

### 進入點速查

- **CLI 掃描**：`scripts/cve-checker.js`（`npm start`）。
- **Web 伺服器**：`scripts/web-server.js`（`npm run web`）→ 服務 `scripts/web-client.html`（由 `build.js` 產生）。
- **掃描輸入**：Windows Registry（`getInstalledSoftware()`）／`scan.json`（`findSW.ps1` 或遠端機器產生）／`.env.local` 的 `PORTABLE_N`。
- **業務邏輯唯一來源**：`lib/cve-logic.js`（CLI 直接 require、Web 由 `build.js` 注入，行為必然一致）。
- **完整資料流程圖**（含三種快取、精確/模糊 CPE 比對、補撈邏輯）：`docs/cve-flow.md`。

### 核心模組（唯一來源原則）

修改邏輯時只需動一個檔案，`scripts/build.js` 負責將其注入 web 頁面：

| 模組 | 職責 | 修改後需執行 |
|------|------|------------|
| `lib/cve-logic.js` | 所有 CVE 業務邏輯（版本比對、CPE 比對、關聯性檢查、修復版本推算等） | `node scripts/build.js` |
| `lib/report-html.js` | 匯出 `buildHTMLReport(report)`：純函式，CLI 與 Web 版報表共用 | `node scripts/build.js` |
| `lib/nvd-client.js` | NVD API 客戶端（**純 server-side，不注入 web**）：本機快取、日期分段查詢、增量更新、alias 對應。匯出 `createNvdClient({ fetchFn, apiKey, delay, cacheDir, aliases, slotFn, logger })`。CLI 與 Web Server 均 require 此模組，確保快取與速率限制共用同一套邏輯。 | — |
| `lib/mitre-client.js` | MITRE 本機鏡像客戶端（**純 server-side**）：讀取 `data/mitre_mirror/index/` 的 NDJSON 索引。匯出 `createMitreClient({ mirrorDir, logger })`，介面（`{fetchCVEs, fetchCPEs}`）與 `createNvdClient()` 完全相容。 | — |
| `lib/mitre-adapter.js` | 純函式：把 MITRE 索引記錄轉成 synthetic NVD 格式（`{cve:{...,configurations:[...]}}`），讓 `lib/cve-logic.js` 不需修改即可運作於 MITRE 資料。 | — |
| `scripts/team-report.js` | 讀取一個目錄下所有個人 JSON 報表（`cve-checker.js` 輸出），產生跨機器彙整 HTML，統計各機器受影響軟體數與需升級項目。 | — |

`lib/report-html.js` 在瀏覽器中依賴 `isSafeVersion`，`build.js` 注入時必須先注入 `cve-logic.js`（`@@CVE_LOGIC@@`）再注入 `report-html.js`（`@@REPORT_HTML@@`）。

**Web 頁面原始模板**：`scripts/web-client.src.html` 是手動編輯的原始檔，包含 `// @@CVE_LOGIC@@` 與 `// @@REPORT_HTML@@` 佔位符；`scripts/web-client.html` 是 `build.js` 產生的輸出檔，**不可直接編輯**，修改後會被覆蓋。同理 `scripts/_bundle.js` 也是產生的，`web-server.js` `require('./_bundle')` 取得打包後的 HTML 與設定。

### 資料流程

```
Windows Registry  ──┐
                     ├─► softwares[]  ──► 白名單過濾 → SKIP_PATTERNS 過濾 → cleanProductName 去重
findSW.ps1 JSON  ──┘                                                        ──► nvd-client.fetchCVEs()
PORTABLE_N       ──────────────────────────────────────────────────────────► NVD CPE API → nvd-client.fetchCVEs()
                                                                             ↑
                                                               data/cve_cache/<key>.json（本機快取）
                                                               同一天已查過：直接回傳
                                                               跨天：增量查詢（lastModStartDate）
                                                               未命中：全量查詢（120 天分段）
                                                                             ──► 關聯性檢查 → HTML/JSON 報表
```

**快取分兩個子目錄**：`data/cve_cache/`（CVE 查詢快取，`kw_*`/`cpe_*`）與 `data/cpe_cache/`（CPE 字典查找快取，`cpekw_*`），避免兩種性質不同的快取混在同一層。`lib/nvd-client.js` 的 `_dirFor(cacheKey)` 依 `cacheKey` 前綴（`cpekw_` → `cpe_cache`，其餘 → `cve_cache`）自動分流，呼叫端（CLI／Web）只需傳入快取根目錄（`data/`），不需關心分流細節。檔案格式範例見 README.md「資料格式」。

**`fetchCPEs()` 的 log 責任在呼叫端**：它回傳 `{ products, fromCache, totalResults, tooGeneric }`，**不在內部印 log**——此時只知道 NVD 原始條目數（含各版本，可能上百筆），不知道 `findAllCPEBases()` 去重後剩幾個 vendor:product。呼叫端跑完 `findAllCPEBases` 算出 `cpeBases.length` 後，才合併印成一行（`[CPE 快取] 命中（N 筆）` 或 `[CPE] 查詢完成（N 筆）`），N 是去重後的數量。新增呼叫 `fetchCPEs()` 的地方別在它內部加 log。

**`fetchCPEs()` 先探測 `totalResults` 再決定是否列舉（避免通用關鍵字逾時）**：CPE 字典查詢用 `keywordSearch` 是**子字串**比對，單字通用名稱會命中上萬筆（實測 Git 12546、Python 20067、Node.js 116997；一般軟體僅數十筆，如 Apache Maven 31、PuTTY 70、7-Zip 295）。過往一次要求 `resultsPerPage=10000`，NVD 光組裝 Git 的 1 萬筆回應就約 **113 秒**，遠超 60 秒逾時 → 每次查 Git 都白等逾時與重試才 fallback。現改為先抓一頁（`CPE_PAGE=500`）取得 `totalResults`，再三分流：(1) `total ≤ 500` 一頁即全部（一般軟體 1 次請求，與過往同樣快）；(2) `500 < total ≤ MAX_CPE_DICT(2000)` 分頁補齊；(3) `total > 2000` 視為**過於通用**（`tooGeneric=true`，回空陣列），逐一列舉同名異 vendor 既慢又不精準，直接讓呼叫端 fallback 到關鍵字 CVE 搜尋（搭配前述詞邊界關聯性比對，Git/Python 仍能得到精準結果）。呼叫端（CLI／Web Server／直連模式）以 `cpeData.tooGeneric` 印「關鍵字過於通用（命中 N 筆 CPE），改用關鍵字搜尋」。

**通用知名軟體可用 `.env.local` 的 `CPE_BASE_N` 指定標準 CPE base，跳過字典查詢直接精準查**：Python/Git 等過於通用（>2000）→ 退化成關鍵字搜尋，而 `keywordSearch` 只比對描述全文——描述沒提到產品名就漏（實證 Python `CVE-2026-3298` 描述只寫 `asyncio.ProactorEventLoop`、無「Python」字，keyword 查不到）、提到別產品就誤報。解法：`.env.local` 設 `CPE_BASE_N=名稱|vendor:product[|vendor:product...]`（例 `CPE_BASE_0=python|python:python`），程式在「決定 cpeBases」處**先查此對照表**（鍵為清理後的軟體名、不分大小寫）：命中就直接用該 CPE base、**完全略過 `fetchCPEs()` 字典查詢**，走精準的 `virtualMatchString` CVE 查詢（不受描述用字影響，且無同名異 vendor 誤報）。其餘流程（多 base OR 合併、keyword 補撈）不變。三端一致：CLI（`loadCpeBases()`）、Web Server（`_loadCpeBases()`）皆讀 `CPE_BASE_N`；Web 直連模式由 server 注入 `window.__CPE_BASES__`，於 portable 預查與主迴圈 `bases` 解析時套用。**仍救不到的唯一例外**：CVE 同時「無 CPE（Awaiting Analysis）且描述無產品名」（如 `CVE-2026-3298`）——CPE 查（無 CPE）與 keyword 補撈（描述無關鍵字）都搆不著，須等 NVD 完成 enrichment 補上 CPE。

### 第二資料來源：MITRE cvelistV5（`CVE_SOURCE=NIST|MITRE`）

**為何不能直接打 MITRE 的 live API**：MITRE 的 CVE Services API（`cveawg.mitre.org`）只有「已知 CVE ID 查單筆」是公開、不需驗證的；關鍵字搜尋與日期區段查詢端點（`/cve`、`/cve_cursor`）都鎖在僅有 CVE Program 內部 Secretariat 角色才能存取，外部使用者（包括一般 CNA）完全拿不到。因此無法像 NVD 一樣做「即時查詢 + 快取」，唯一可行的替代做法是**定期把官方 `CVEProject/cvelistV5` GitHub 的每日 baseline + 當次 delta 壓縮檔同步到本機，建立自己的搜尋索引**（`cve-search` 等知名工具也是用同樣策略繞開公開 CVE 資料庫的限制）。

**同步策略（`scripts/mitre-sync.js`，`npm run sync-mitre`）**：每個 GitHub Release 都把 baseline 與當次 delta 打包在一起、內容互相一致，所以**不需要自己串接多個小時的 delta**——每次同步只需抓最新一個 release。Baseline 解壓後只保留近 5 年資料（掃描預設只看「當年−1」，但鏡像多留幾年以便手動調大 `MIN_YEAR` 往前查詢），其餘立即捨棄以控制磁碟用量。需防禦處理已知的「雙重 `.zip.zip`」bug（[CVEProject/cvelistV5#67](https://github.com/CVEProject/cvelistV5/issues/67)/[#68](https://github.com/CVEProject/cvelistV5/issues/68)，長期未修復）：解壓後找不到預期的頂層目錄、但頂層只有一個 `.zip` 檔時，視為內層還包一層，再解一次。

**baseline 與 delta 的 zip 內部結構不同，不可共用同一套攤平邏輯**：baseline 解壓後頂層是 `cves/<year>/<bucket>/CVE-*.json`（有年份/bucket 兩層子目錄）；delta 解壓後頂層是 `deltaCves/CVE-*.json`（**扁平結構，沒有年份子目錄**，曾因此誤判為雙重 zip bug 而同步失敗）。因此 `_extractZipDefensive()` 改為接受預期的頂層目錄名稱參數（baseline 傳 `'cves'`，delta 傳 `'deltaCves'`），且 delta 另外用 `_flattenDeltaInto()` 依檔名 `CVE-<year>-<seq>.json` 解析年份分流，不能沿用 baseline 的 `_flattenYearsInto()`。

**同步流程具備 checkpoint／resume 機制，失敗重跑不會重新下載已完成的部分**：整個同步拆成 7 個階段（下載/解壓/攤平 baseline、下載/解壓/攤平 delta、重建索引+寫入 `meta.json`），每完成一個階段就把進度寫入 `data/mitre_mirror/_tmp/progress.json`（含當次鎖定的 release 資產資訊，避免重跑時抓到更新的 release 導致已下載內容報廢）。理由：原本 `meta.json` 只在整個流程最後才寫一次，若 delta 處理中途失敗（例如上述結構誤判），baseline 雖已下載解壓完成，但因為例外中斷導致 `meta.json` 沒更新，下次重跑會誤判「今天 baseline 還沒同步」而把 517MB 整個重新下載——這是必須避免的浪費。下載階段另外比對暫存 zip 檔案大小是否與 GitHub 資產一致，相符就略過重新下載。**只有全部 7 個階段都成功，才會清除 `_tmp`（含 `progress.json`）**；任何一個階段失敗，下次執行 `npm run sync-mitre` 會自動偵測進度檔並從中斷處繼續，不需要任何手動清理。可用 `--step=<download-baseline|extract-baseline|flatten-baseline|download-delta|extract-delta|flatten-delta|finalize>` 手動單獨執行某一階段（除錯用）；`--full` 會忽略既有進度與 `meta.lastBaselineDate`，強制重新判定需要 baseline。

**索引設計**：`data/mitre_mirror/index/<year>.ndjson`，一行一筆 `state==='PUBLISHED'` 的 CVE（`REJECTED` 等狀態不進索引），延續 `data/cve_cache` 既有的「純 `fs`+`JSON.parse`，不引入 DB」慣例，不因為資料量變大就破例用 SQLite 等其他機制。欄位設計直接對應 NVD 的三種查詢維度：`vendors[]`/`products[]` 對應 CPE 查詢、`descLower` 對應 `keywordSearch`、`published`/`lastModified` 對應 `pubStartDate`/`lastModStartDate`。`cna` 容器缺資料（`affected`/`metrics`）時，於索引建構階段（非查詢階段）fallback 到第一個非空的 `adp[]` 項目（CISA Vulnrichment 補完）。

**synthetic NVD 格式轉換與精確度取捨（`lib/mitre-adapter.js`）**：已驗證 `lib/cve-logic.js` 所有比對函式只讀 `cve.configurations[].nodes[].cpeMatch[]`（`criteria`/`vulnerable`/`versionStart/EndIncluding/Excluding`）與 `cve.metrics.cvssMetricV40/V31/V30/V2`，MITRE 的 `affected[].versions[]`（`version`/`status`/`lessThan`/`lessThanOrEqual`）資訊內容對等，只是欄位命名與巢狀方式不同——寫成 synthetic 轉換層後，`lib/cve-logic.js` **完全不需修改**：
- 有真實 `cpes[]`（約 58% 案例）：直接當 `criteria`。
- 無 `cpes[]` 但有 vendor/product 文字（約 42% 案例）：合成 `cpe:2.3:a:<vendor>:<product>:*` 當 `criteria`——精確度低於真正 CPE 字典比對（沒有 vendor 名稱消歧義），但能重用既有比對邏輯而不必另開一套判斷路徑。
- 連 vendor/product 文字都沒有：輸出 `configurations: []`（不亂湊），讓 `cveRelevanceCheck`/`cveMatchesCPEBase` 自然回 `null`，套用既有「無 CPE 資料→過濾」政策（與 NVD 未完成 enrichment 時一致）。
- `versions[]` 條目沒有 `lessThan`/`lessThanOrEqual` 時是「單一精確版本」，不是「此版本之後全部」——寫入 `criteria` 第 5 欄（精確版本 CPE 慣例），不設 `versionStart/End`，否則會被誤判為無上界的開放範圍。

**已知範圍限制**：`GET /api/cve-data`（CVE 查詢頁籤後端）目前固定讀 `data/cve_cache/*.json`，是 NVD 專屬 schema，尚未接上 MITRE 索引——`CVE_SOURCE=MITRE` 時這個頁籤會回傳空結果，這是已知限制，非缺陷。

**Fail-fast 契約**：`CVE_SOURCE=MITRE` 但 `data/mitre_mirror/index/meta.json` 不存在時，`createMitreClient()` 在**建構時**（不是等第一次查詢）就立即 throw，CLI/Web Server 都會印出繁體中文錯誤訊息後 `process.exit(1)`——絕不能靜默 fallback 回 NIST 或卡在第一次查詢才失敗。

### 主要處理邏輯

**CPE 查找分兩種模式（`findAllCPEBases(products, nameWords, exact)`）**：依軟體來源切換精準度／recall。

- **精確模式（`exact=true`，scan.json／Windows Registry 找到的軟體）**：直接以「軟體名＝CPE 的 `product`（或 `vendor+product` 合併）詞集合**完全相等**」比對，**跳過下方模糊邏輯**。理由——多產品 vendor 用模糊比對會一次撈出數十個無關 product，每個都要逐一查 CVE（再乘日期分段），效能極差：實證 Cisco 旗下 37 個 `webex_*` 產品，掃「Webex」一個軟體卻得查 37 次。精確比對讓「Webex」只命中 `cisco:webex`、「PostgreSQL」只命中 `*:postgresql`（37→1、7→2），效能與精準度同時提升。**刻意不採「vendor 詞集合相等」**：vendor 名與軟體同名時（vendor 就叫 `postgresql`）會把該 vendor 底下全部 product（`psqlodbc`/`pgjdbc`/`pgadmin_4`…）撈回而退化回爆量。同名異 vendor（PuTTY 的 `putty`/`simon_tatham`/`greenend`、Bruno 的 `usebruno`/`yaxim`）因 product 皆等於軟體名，仍以 OR 全數保留。**精確命中 0 筆時 fall back 到下方模糊邏輯**（保留 recall），避免「neo4j community edition」「7-zip」等軟體名與 CPE product 對不齊時整批漏查。三端一致：CLI（`cve-checker.js`，`!sw._portable`）、Web Server（`web-server.js`，`!isPortable`）；Web 直連模式只處理 Portable，維持模糊。

- **模糊模式（`exact=false`，Portable 軟體 / 精確 fall back）**：三個 Pass 依序比對，Pass 0 優先（vendor 單獨含關鍵字），Pass 1（vendor+product 合併含關鍵字），Pass 2 fallback（product 含第一個字）。回傳**所有符合**的 `{vendor, product}` 陣列（OR 邏輯），確保同一軟體不同 vendor 名稱均能命中。

**收斂兩步驟：(1) 詞邊界比對 → (2) vendor 錨定**。`findAllCPEBases` 在三個 Pass 跑完後依序套用：

1. **詞邊界（token）完全相等比對**（取代子字串 `includes`）：三個 Pass 都先用 `tokenize()` 把 CPE 欄位以 `_ - . :` 與空白切成詞陣列，要求 name word 恰好**等於**其中某個詞。理由——短關鍵字（如 `git`）用子字串比對會誤命中任何內含相同字母序列的無關 vendor（`digital`、`legitimate`…），曾使單一軟體爆出 72 組 base，每組都要逐一查 CVE（再乘以日期分段數），效率極差。詞邊界比對不影響既有正確案例（`usebruno:bruno`/`yaxim:bruno` 仍透過 product 詞 `bruno` 命中）。

2. **vendor 錨定**：對「本身就是常見英文字典詞」的關鍵字（如 `line`），詞邊界仍擋不掉大量無關 product 裡的合法 line 詞（`command_line_interface`…，line 詞邊界後仍 41 組）。錨定先找出「vendor / product / 兩者合併」詞集合**恰好等於**關鍵字集合的 base 當錨點（如 `line:line`、`linecorp:line` 的 product 剛好就是 `line`），取其 vendor 集合 `{line, linecorp}`，只保留同 vendor 的 base，擋掉 `amazon`/`horde` 等無關 vendor（line 41→6）。**無任何錨點時維持詞邊界結果、不收斂**（如 `7-zip` 關鍵字被截成 `zip` 找不到錨點，維持 3 組）。

   **為何不用 publisher 加權**：曾評估「用軟體 `publisher` 欄位給 base 打分排序」，但 publisher 與 CPE vendor 命名常不一致——實測 LINE 的 publisher 是 `LY Corporation`，對 `linecorp:line`/`line:line`（本尊）全給 0 分，只有 `lycorp:line_mini_app` 得分，硬過濾會把本尊丟掉導致漏報。故改用不依賴 publisher 命名的 vendor 錨定。
   **已確認接受的 recall 取捨**：第三方衍生工具（`acs:putty_connection_manager`、`bramp:ffmpeg-cli-wrapper`）vendor 與本尊不同會被擋掉，屬刻意的精準度提升。

已用全部 `data/cpe_cache` 快取驗證 bruno/maven/putty/neo4j/docker/webex/7-zip 等零退化或精準度提升。

**多 CPE base 查詢（CLI / Web 共用原則）**：`findAllCPEBases` 找到多個 base 時，CLI（`cve-checker.js`）、Web 代理（`web-server.js`）、Web 直連模式（`web-client.src.html`）都必須**逐一查詢每個 base 並依 CVE id 合併去重**，不可只查第一個（曾經的 bug：只查 `cpeBases[0]`，導致第二個 vendor 名稱下的 CVE 永遠不會被查到）。查詢時須以 log 明確標示「查詢 (i/N)CPE：cpe:2.3:a:vendor:product:*」（含目前進度索引），方便追蹤目前查的是哪一個。

**多 CPE base 的「版本/範圍擷取」也必須吃整個陣列（OR 比對），不可只用 `cpeBases[0]`**：關聯性判斷 `cveMatchesCPEBase` 本來就吃整個 base 陣列，但 `extractFixedVersion`／`isVersionInAnyRange`／`getBranchFixVersion`／`extractAllRanges`／`cveExactVersionCheck` 過去只收單一 `cpeBase = cpeBases[0]`，用它的詞做 criteria 詞邊界比對。當第一個 base 與某 CVE 的真正 vendor 不同（如 Bruno 查到 `yaxim:bruno`+`usebruno:bruno`，但 `cpeBases[0]` 是 `yaxim`，CVE 的 criteria 卻是 `usebruno:bruno`），比對要求同時含 `yaxim`+`bruno` → 永遠不符 → 整批屬於其他 vendor 的 CVE 抓不到版本（症狀：CLI 與 WebUI 都顯示 3 筆 CVE、「查無對應版本號／無版本修復資訊」，且 `isVersionInAnyRange` 因無命中而回 `null`，連帶讓 `getBranchFixVersion` 的「已修正」過濾失效）。修正：新增 `_criteriaMatcher(searchName, cpeBase)`，`cpeBase` 可傳單一物件或 base 陣列，criteria 只要「完全符合任一 base 的詞集合」即視為相關（無 cpeBase 時退回 searchName 詞邊界）。呼叫端（`cve-checker.js`、`web-client.src.html`）對這 5 個函式一律改傳整個 `cpeBases` 陣列；`isComparableRecVersion` 仍傳單一 `cpeBase`（它靠 truthy 判斷 keyword/CPE 模式，傳空陣列會誤判）。`cve-checker.js` 的 `results.push` 另存 `cpeBases`，讓升級建議列與 JSON 報表的彙整也用得到陣列。

**CPE 查詢漏掉 NVD 尚未分析的新 CVE → 以 keyword 補撈（`isPendingSupplementCVE`）**：NVD 對剛發布的 CVE 常處於 `Awaiting Analysis`，CNA 已給描述/CVSS 但 NVD 尚未建立 CPE 適用性（`configurations` 為空）。CPE 查詢（`virtualMatchString`）只回傳「已有 CPE 聲明」的 CVE，因此這類新 CVE 會被整批漏掉（實證：FFmpeg `CVE-2026-8461`，CPE 查詢 6 月時間窗回 0 筆、keyword 查詢回 3 筆含它）。對策：以 CPE 查詢的軟體在 CPE 合併後，**再打一次同 `coverageStart` 的 keyword 查詢**，把「CPE 結果沒有、且符合 `isPendingSupplementCVE`」者併入；後續 relevance 對無 CPE 的 CVE 回 `null`、既有邏輯標 `_pendingNvd=true`（顯示「⚠ NVD 分析中」供人工確認）。`isPendingSupplementCVE(cve, cpeBase)` 的兩道守門：(1) `cveHasNoCpe`——有 CPE 卻沒被 CPE 查詢命中＝屬別 vendor（CPE 已正確排除），不可併入；(2) `cveRefsMentionProduct`——**參考連結的「網域 host」或「路徑第一段（GitHub 等的 owner/org）」以「詞邊界完全相等」含本軟體 vendor/product 詞**才算數，擋掉「描述只是提到本軟體、實際屬別產品」的誤命中。**刻意不比對完整路徑、且用詞邊界而非子字串**：(a) 本軟體只是「被呼叫的元件/媒介」時，別產品的 advisory 常把元件名寫進描述型 slug——實證 `CVE-2024-58286`（dizqueTV 的 RCE，FFmpeg 只是被呼叫的執行檔路徑），參考連結 `vulncheck.com/advisories/dizquetv-...-via-ffmpeg-executable-path` 路徑含 ffmpeg，但網域與 GitHub owner（`github.com/vexorian/dizquetv`）都不是 ffmpeg，正確排除；(b) 詞邊界避免短關鍵字子字串誤命中——token `git` 不會命中 owner `gitpython-developers`、token `python` 不會命中 `pythonhosted`。對照真品 `CVE-2026-8461` 的 `code.ffmpeg.org`（host 詞含 ffmpeg）、Python `CVE-2026-3298`/`CVE-2025-4517` 的 `github.com/python/cpython`（owner=python）正確撿回。

**keyword 模式（過於通用的軟體，如 Python/Git）也要撿回無 CPE 的真品**：`relevance` 對「無 CPE」的 CVE 過去一律丟棄（`cveRelevanceCheck` 回 `null` → 過濾，避免關鍵字描述誤報），但這會漏掉 NVD Awaiting Analysis/Deferred、只有 CNA 分數、尚無 CPE 的真品（實證：Python `CVE-2026-3298` 8.8 HIGH、`CVE-2025-4517` 9.4 CRITICAL，皆無 CPE、參考連結指向 `github.com/python/cpython`，但 Python 因 CPE 字典 >2000 走 keyword 模式而被漏掉）。修正：`relevance` 的 `null` 分支改為——CPE 模式（有 cpeBases）一律保留為待分析；**keyword 模式（無 cpeBases）改用 `isPendingSupplementCVE(cve, {vendor:searchName, product:searchName})` 以參考連結 host/owner 守門撿回確屬本軟體者**，其餘才丟棄。撿回者標 `_pendingNvd=true`（顯示「⚠ NVD 分析中」，不納入版本/推薦判斷）。CLI（`cve-checker.js`）與 Web（`web-client.src.html`）一致；Web 端並補上過去缺漏的 `pendingNvdAnalysis` 旗標與顯示。三端一致：`cve-checker.js`、`web-server.js`、`web-client.src.html`（直連模式）都在 CPE 合併後做此補撈。

**推薦版本守門擋掉「日期型版本」（`isComparableRecVersion`）**：NVD 偶爾用 git 快照「日期」當 `versionEndExcluding`（實證：FFmpeg `CVE-2025-25468/25469` 用 `2025-01-13`）。日期字串無法與語意化版本（`7.1`）比較，`compareVersions` 會把 `2025` 當成遠大於 `8`，污染彙整後的「建議升級版本」（出現「建議升級至 ≥ 2025-01-13」）。守門：已安裝版本非日期、修復版本卻是日期（`YYYY-MM-DD` 或 8 碼數字）時，排除其進入推薦彙整——個別 CVE 的「安全版本」仍照 NVD 原樣顯示，資訊不遺失。

**CVSS 取分以 Primary（NVD 官方）優先（`getCvss`）**：一筆 CVE 的 `metrics` 常同時有多組評分，且各有 `type`（`Primary` = NVD 官方 `nvd@nist.gov`／`Secondary` = CNA、廠商自評）。`getCvss` 的取用優先序為 **(1) Primary 勝過 Secondary → (2) 同類取較新 CVSS 版本（4.0 > 3.1 > 3.0 > 2.0）**。**不可**像過去那樣「一律先取 V4.0、且每個版本取陣列 `[0]`」——`[0]` 常是排在前面的 Secondary/CNA 分數，會蓋掉 NVD 官方的 Primary，造成嚴重度誤判（實證：`CVE-2026-2664` Docker 自評 Secondary CVSS4.0 6.8 MEDIUM vs NVD Primary CVSS3.1 7.8 **HIGH**；`CVE-2026-40962` MITRE Secondary CVSS3.1 4.9 MEDIUM 排在 NVD Primary CVSS3.1 9.8 **CRITICAL** 之前——舊邏輯都會取到較低的 Secondary，在 HIGH 門檻被誤濾）。無 Primary（如 Awaiting Analysis 只有 CNA 分數）時退回 Secondary 取較新版本（FFmpeg `CVE-2026-8461` 的 Secondary CVSS3.1 8.8 HIGH 仍正確取得）。此分類對齊 NVD 網站頭條顯示。

**NVD CVE API 限制**：`pubStartDate`/`pubEndDate` 必須成對使用，且範圍上限 120 天，超過回 HTTP 404。`lib/nvd-client.js` 的 `splitDateRange()` 自動將查詢切為多段（每段 ≤ 120 天，由新到舊）。

**年份過濾（`minYear`/`coverageStart`）**：快取以軟體（keyword/CPE）為單位，不是以查詢年份為單位，因此同一份快取可能比本次要求的範圍更廣（例如曾被較寬鬆的 `MIN_YEAR` 查過）。`fetchCVEs()` 在三個回傳路徑（快取命中、增量更新、全量查詢）都會以 `_filterFromStart()` 過濾掉 `published < coverageStart` 的項目，因此**呼叫端（CLI／Web 代理）拿到的 `cves` 已經是裁切過的**，不需再自行依年份過濾一次。唯一例外是 `web-client.src.html` 的「直連模式」（無 server proxy、無快取、無日期分段查詢時的 fallback），那裡仍保留 `getFullYear()` 年份過濾，因為該路徑根本沒有經過 `nvd-client.js`。嚴重度（`MIN_SEVERITY`）則維持在呼叫端過濾，因為快取必須保留全部嚴重度的 CVE，才能讓未來更低門檻的查詢直接複用快取而不漏資料。

**關聯性檢查回傳值**：
- `true` = 確認相關，保留
- `false` = 確認不符，列入 `mismatchedCVEs`（不顯示）
- `null` = 無 CPE 資料（NVD 未完成 enrichment），預設過濾。理由：`keywordSearch` 比對描述全文，無 CPE 時無法驗證相關性，無條件保留反而大量誤報。
- **例外 1（CPE 模式）**：有 `cpeBases`（Portable／CPE 已確認）時 `null` 一律標記 `_pendingNvd=true` 保留，供人工確認。
- **例外 2（keyword 模式）**：無 `cpeBases`（過於通用走關鍵字，如 Python/Git）時，改用 `isPendingSupplementCVE(cve, {vendor:searchName, product:searchName})` 以參考連結 host/owner 詞邊界守門——確屬本軟體者標 `_pendingNvd=true` 保留，其餘才過濾（詳見上方 keyword 模式段落）。

**詞邊界比對延伸至關聯性/版本擷取（`_criteriaMatchesWords`）**：`findAllCPEBases` 的「詞邊界（token）比對」原則同樣套用到 `cveRelevanceCheck`、`extractFixedVersion`、`cveExactVersionCheck`、`isVersionInAnyRange`、`getBranchFixVersion`、`extractAllRanges`——這些函式過去用 `criteria.includes(word)` 子字串比對，短關鍵字會誤命中（`git` → git**hub**／git**bucket**／git**python**，`python` → git**python**），導致關鍵字查詢爆出大量無關 CVE。改用 `_criteriaTokenSet()`（以空白、`_ : .` 切詞，**刻意保留 `-` 不切**，讓 `7-zip` 維持完整詞、`go-git` 不被拆出 `git`）後要求關鍵字恰好等於某個詞。注意：產品名「本身就等於關鍵字」的同名異 vendor 案例（`jenkins:git` 外掛、`microsoft:python` 擴充套件）仍會通過詞邊界比對，需靠下一條的推薦版本守門。

**關鍵字查詢的推薦版本守門（`isComparableRecVersion`）**：彙總「建議升級版本」時，keyword 查詢（無 cpeBase）只採計與已安裝版本**主版號相同**的修復版本。理由——同名異 vendor 產品的版本體系不相容（`jenkins:git` 外掛是 `444.vca_b_84d3703c2`、`microsoft:python` 擴充是 `2025.8.1`），`compareVersions` 會把 `444`/`2025` 當成比 Git `2.x`／Python `3.x` 還新而推薦離譜版本。CPE 查詢已精準鎖定 `vendor:product`，**不套用**此限制（避免擋掉合法跨主版號升級）。此限制只作用於彙總後的推薦版本，個別 CVE 的「安全版本」仍照常顯示，資訊不遺失。三個彙總點（`cve-checker.js` 的即時輸出與 JSON 報表、`web-client.src.html` 的掃描）都須一致套用。

**`extractFixedVersion` 三層 fallback（已安裝版本超過所有範圍＝已修復，不可回 null）**：傳入 `installedVersion` 時依精準度由高到低取候選——(1) `inRange`：已安裝版本落在此受影響範圍 → 該分支修復上界（使用者正受影響，最精準）；(2) `sameMajor`：修復版本與已安裝版本同主版號 → 已超出範圍（已修復）時的正解；(3) `global`：全域最大修復版本（保底）。回傳 `inRange || sameMajor || global`。**為何不能像舊版那樣「不在範圍就 continue 掉」**：已安裝版本超過所有受影響範圍其實代表「已修復」，舊版會因此回 `null`，使 `recommendedVersion` 與每筆 `fixedVersion` 全變 null，報表誤判為「待修正／無版本修復資訊」（實測症狀：Bruno 3.4.2 明明 ≥ 修復版 3.2.1 卻顯示「查無對應版本號」）。三層 fallback 同時保住多分支精準度：Node.js 24.15.0 對 `[24.0,24.13)`+`[25.0,25.3)` 仍回 `24.13.0`（同分支）而非全域最大 `25.3.0`。`installedVersion` 未知時沿用全域最大（legacy）。CLI 與 Web UI 共用此函式（Web 由 `build.js` 原樣注入 `lib/cve-logic.js`），行為必然一致。

**升級狀態判斷**（優先順序）：✗ 需升級 → ? 手動確認（有 `recommendedVersion` 但任一 CVE `fixedVersion===null`，或無 `recommendedVersion`） → ✓ 無須升級。

### Web 伺服器架構（`scripts/web-server.js`）

**NDJSON 代理**（`POST /api/scan`）：採單一長連線串流每筆 NVD 結果，避免舊版 per-request 代理因 NVD 6.5s 延遲超過 keepAliveTimeout 導致 socket 被複用時拋出 TypeError。

**全域速率限制**：`nvdSlot()` 以 Promise 鏈確保所有並行 session 共用同一 NVD 計時器，合計速率不超過 `REQUEST_DELAY`。

**NDJSON 標頭順序（與 CLI 一致）**：`scanHandler` 必須在迴圈一開始（CPE 偵測之前）就送出 `{keyword, header:{name,version}}`，前端收到立即印標頭，之後才處理同 keyword 的過程訊息/最終資料行。若等到「最終結果」才印標頭，過程訊息（中途陸續串流回來）會排在標頭之前，順序與 CLI 顛倒。直連模式（無 server proxy）原本就是同步呼叫，順序本來就正確。

**CVE 顯示內容對齊 CLI**：即時進度與 `/api/log` 寫入的後端日誌（`logs/server_*.log`）皆採用與 CLI 相同的結構——每筆 CVE 三行（id/嚴重度/CVSS/日期 → 描述截 130 字 → 安全版本或警告），依發布日期新到舊只顯示前 5 筆，超過則印 `… and N more`。每個軟體的區塊結束後印一行真正空白行分隔（WebUI 用 `logLine('&nbsp;')`；log 檔用 `slogBlank()`），避免軟體與軟體之間的紀錄黏在一起。

**Web log 檔順序與 CLI/WebUI 對齊（ack 機制）**：CPE/CVE 抓取進度由伺服器同步寫 log，但「是否相關／安全版本」的判斷邏輯刻意留在前端（瀏覽器）計算，算完才用 `fetch('/api/log')` 回傳——兩條路徑完全不同步，若伺服器不等前端，命中快取時伺服器會瞬間跑完所有軟體，log 檔會變成「CPE/CVE 全部抓完，最後才集中判斷」。解法：`scanHandler` 送出每筆軟體資料後 `await waitForAck(sid, keyword)`，等前端把**同一個 keyword** 的判斷結果 POST 回 `/api/log`（核對 `keyword` 避免其他呼叫誤觸發 ack）才繼續下一筆；`_pendingAcks`（`sid → {keyword, resolve}`）搭配 10 秒 timeout 與 `req.on('close')` 連線中斷偵測，避免前端異常時卡住整個掃描。對掃描總時間影響可忽略（NVD 速率限制本身就有 0.7~6.5 秒延遲，遠大於本機網路往返時間）。

**`GET /api/cve-data?q=<text>`**：CVE 查詢頁籤用，只讀本機 `data/cve_cache/` 已快取的 CVE，**不會對 NVD 發出任何請求**。`CACHE_DISABLE=true` 時直接回傳空結果。沿用 `/api/scan` 的分工慣例：server 只管資料存取，relevance/版本邏輯留在 `lib/cve-logic.js` 與前端。

**CSP**：每次請求產生隨機 nonce，注入頁面設定 `Content-Security-Policy: script-src 'nonce-...'`。`_bundle.js` 不含 `NIST_API_KEY`（刻意排除）；`PORTABLE_N` bundle 時僅保留 `{name, version}`，不含 publisher。

## Claude Code 內建指令

| 指令 | 用途 |
|------|------|
| `/code-verify` | 確認 Node.js 版本、JS 語法正確、v18+ API 使用情況 |
| `/code-security` | 靜態安全分析（XSS、命令注入、路徑遍歷等）並評估 Node.js 現代化程度 |
| `/project-document` | 根據實際程式碼狀態，同步更新 `README.md`、`CLAUDE.md`、`docs/operator.html` |

## MCP 伺服器（`.mcp.json`）

- `context7`：查詢函式庫/框架最新文件（本專案無外部套件依賴，主要用於查 Node.js 內建 API 行為）。
- `playwright`（Edge）：預設停用，設定範例保留於 `.mcp.json.example`（已註解）。需要實際開啟 `scripts/web-client.html` 操作驗證 Web 介面時，取消註解並複製為 `.mcp.json` 即可啟用。
