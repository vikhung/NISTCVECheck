# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 專案執行原則

1. 所有的交談都以繁體中文為主。
2. 每當討論出架構決策或注意事項，立即更新本文件的對應章節，不要等到對話結束才整理。
3. 程式碼、函式庫應用繁體中文記錄註解，讓使用者知道這段程式碼用途。
4. Node.js 請使用原生功能，不要使用任何需額外下載之套件。**唯一例外**：`adm-zip`（`scripts/package-deploy.js` 產生部署 zip 用，Node 原生 zlib 只能處理 deflate/gzip，無法產生 ZIP 容器格式），使用者已明確核准此例外。
5. 操作方式（指令、參數、設定檔）與資料格式範例（輸入/輸出 JSON、快取檔案結構、目錄總覽）寫在 `README.md`；本文件只放系統處理原則與架構決策。

## 常用指令

| 指令 | 說明 |
|------|------|
| `npm start` | CLI 掃描（讀取本機 Registry 或 `.env.local` 的 `PORTABLE_N`） |
| `npm test` | 執行回歸測試（Node 原生 `node --test "scripts/test/*.test.js"`，無外部套件）：`scripts/test/cve-logic.test.js` 涵蓋 `lib/cve-logic.js`，`scripts/test/scan-software.test.js` 涵蓋 `lib/scan-software.js`（用假的 nvdClient，不需網路），`scripts/test/cache-file.test.js` 涵蓋 `lib/cache-file.js`（快取分檔）。單獨執行一個測試：`node --test --test-name-pattern="<測試名稱關鍵字>" "scripts/test/cve-logic.test.js"` |
| `npm run check` | 快速掃描：HIGH 以上、限掃前 5 筆軟體（年份用預設「當年 − 1」） |
| `npm run web` | 啟動 Web 伺服器（自動先執行 `node scripts/build.js`，port 預設 8093） |
| `npm run bundle` | 單獨執行 `node scripts/build.js`（修改 `lib/cve-logic.js` 或 `lib/report-html.js` 後須執行） |
| `npm run deploy` | 部署打包：把必要檔案壓成 `dist/NISTCVECheck_deploy_<date>.zip`（`scripts/package-deploy.js`）。預設含 CVE 快取、排除機密/大型/建置產物；旗標：`--no-cache`（乾淨部署）、`--with-node-modules`（離線）、`--out=<路徑>` |
| `npm run split-cache` | 快取分檔工具（`scripts/split-cache.js`）：把 `data/` 內超過 10MB 的快取檔一次切成分檔並讀回比對。**平常不需執行**（程式讀寫快取時自動分檔），供離線環境想事先整理時使用；旗標：`--dry-run`（只列出不寫入）、`--dir=<路徑>` |
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
| `lib/nvd-client.js` | NVD API 客戶端（**純 server-side，不注入 web**）：本機快取、日期分段查詢、增量更新、alias 對應。匯出 `createNvdClient({ fetchFn, apiKey, delay, cacheDir, aliases, slotFn, logger })`。回傳 `{ fetchCVEs, updateCVECache, queryCVECache, fetchCPEs }`：CVE 查詢請用 `updateCVECache`（補增量）＋`queryCVECache`（讀快取）兩步驟。CLI 與 Web Server 均 require 此模組，確保快取與速率限制共用同一套邏輯。 | — |
| `lib/scan-software.js` | 單一軟體的「CPE 偵測 → 逐 base 查 CVE 並合併去重 → keyword 補撈 NVD 尚未分析者」流程編排（**純 server-side，不注入 web**）。匯出 `lookupSoftwareCVEs({ nvdClient, searchName, isPortable, cpeBaseMap, coverageStart, log })`（及可單獨使用的 `resolveCpeBases`／`fetchSoftwareCVEs`），另含 `.env.local` 解析 `parseCpeBases`（`CPE_BASE_N`）與 `parseCacheAliases`（`CACHE_ALIAS_N`）。CLI（`cve-checker.js`）與 Web Server（`web-server.js`）共用，兩端只傳入 `log(level, msg)` 回調與 `isPortable`。 | — |
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

**快取檔超過 10MB 自動分檔（`lib/cache-file.js`，唯一來源）**：通用關鍵字的 CVE 快取很大（實測 `kw_local` 87MB、`kw_git` 25MB），單一檔不利版控與搬移。`writeCacheFile()` 在序列化後超過 `MAX_CACHE_FILE_BYTES`（10MB）時，把陣列欄位（`cves`／`products`）拆到 `<key>.part001.json`…，主檔 `<key>.json` 只留描述欄位＋`parts`／`partField`／`itemCount`；未超過者維持原本的單一檔格式（小檔零變動）。`readCacheFile()` 讀主檔時自動合併，**呼叫端拿到的永遠是完整物件、不需知道是否分檔**。設計要點：(1) 以「陣列元素」為單位切分，不會把一筆 CVE 切成兩半，單筆超過上限則獨佔一檔；(2) 寫入順序為分檔 → 主檔 → 清除多餘舊分檔，讀取時核對 `itemCount`，分檔缺漏或筆數不符即拋例外，`_loadCache` 視為未命中而重新下載（寧可重抓也不回傳殘缺資料）；(3) 舊版超大單一檔由 `nvd-client` 的 `_loadCache` 在讀到時自動改存成分檔（一次性）。**任何直接讀 `data/cve_cache/` 的程式都必須透過 `readCacheFile()` 並用 `isPartFile()` 略過分檔**（`web-server.js` 的 `/api/cve-data` 即如此），不可自行 `JSON.parse` 檔案。上限可由 `createNvdClient({ maxFileBytes })` 調整（測試用）。回歸測試：`scripts/test/cache-file.test.js`。

**`fetchCPEs()` 的 log 責任在呼叫端**：它回傳 `{ products, fromCache, totalResults, tooGeneric }`，**不在內部印 log**——此時只知道 NVD 原始條目數（含各版本，可能上百筆），不知道 `findAllCPEBases()` 去重後剩幾個 vendor:product。呼叫端跑完 `findAllCPEBases` 算出 `cpeBases.length` 後，才合併印成一行（`[CPE 快取] 命中（N 筆）` 或 `[CPE] 查詢完成（N 筆）`），N 是去重後的數量。新增呼叫 `fetchCPEs()` 的地方別在它內部加 log。

**`fetchCPEs()` 先探測 `totalResults` 再決定是否列舉（避免通用關鍵字逾時）**：CPE 字典查詢用 `keywordSearch` 是**子字串**比對，單字通用名稱會命中上萬筆（實測 Git 12546、Python 20067、Node.js 116997；一般軟體僅數十筆，如 Apache Maven 31、PuTTY 70、7-Zip 295）。過往一次要求 `resultsPerPage=10000`，NVD 光組裝 Git 的 1 萬筆回應就約 **113 秒**，遠超 60 秒逾時 → 每次查 Git 都白等逾時與重試才 fallback。現改為先抓一頁（`CPE_PAGE=500`）取得 `totalResults`，再三分流：(1) `total ≤ 500` 一頁即全部（一般軟體 1 次請求，與過往同樣快）；(2) `500 < total ≤ MAX_CPE_DICT(2000)` 分頁補齊；(3) `total > 2000` 視為**過於通用**（`tooGeneric=true`，回空陣列），逐一列舉同名異 vendor 既慢又不精準，直接讓呼叫端 fallback 到關鍵字 CVE 搜尋（搭配前述詞邊界關聯性比對，Git/Python 仍能得到精準結果）。呼叫端（CLI／Web Server）以 `cpeData.tooGeneric` 印「關鍵字過於通用（命中 N 筆 CPE），改用關鍵字搜尋」。

**通用知名軟體可用 `.env.local` 的 `CPE_BASE_N` 指定標準 CPE base，跳過字典查詢直接精準查**：Python/Git 等過於通用（>2000）→ 退化成關鍵字搜尋，而 `keywordSearch` 只比對描述全文——描述沒提到產品名就漏（實證 Python `CVE-2026-3298` 描述只寫 `asyncio.ProactorEventLoop`、無「Python」字，keyword 查不到）、提到別產品就誤報。解法：`.env.local` 設 `CPE_BASE_N=名稱|vendor:product[|vendor:product...]`（例 `CPE_BASE_0=python|python:python`），程式在「決定 cpeBases」處**先查此對照表**（鍵為清理後的軟體名、不分大小寫）：命中就直接用該 CPE base、**完全略過 `fetchCPEs()` 字典查詢**，走精準的 `virtualMatchString` CVE 查詢（不受描述用字影響，且無同名異 vendor 誤報）。其餘流程（多 base OR 合併、keyword 補撈）不變。解析（`parseCpeBases()`）與套用（`resolveCpeBases()`）都在 `lib/scan-software.js`，CLI／Web Server 共用（Web 前端不處理 CPE，一律由 server 偵測後以 `cpeBases` 回傳）。**仍救不到的唯一例外**：CVE 同時「無 CPE（Awaiting Analysis）且描述無產品名」（如 `CVE-2026-3298`）——CPE 查（無 CPE）與 keyword 補撈（描述無關鍵字）都搆不著，須等 NVD 完成 enrichment 補上 CPE。

### 主要處理邏輯

**CPE 查找分兩種模式（`findAllCPEBases(products, nameWords, exact)`）**：依軟體來源切換精準度／recall。

- **精確模式（`exact=true`，scan.json／Windows Registry 找到的軟體）**：直接以「軟體名＝CPE 的 `product`（或 `vendor+product` 合併）詞集合**完全相等**」比對，**跳過下方模糊邏輯**。理由——多產品 vendor 用模糊比對會一次撈出數十個無關 product，每個都要逐一查 CVE（再乘日期分段），效能極差：實證 Cisco 旗下 37 個 `webex_*` 產品，掃「Webex」一個軟體卻得查 37 次。精確比對讓「Webex」只命中 `cisco:webex`、「PostgreSQL」只命中 `*:postgresql`（37→1、7→2），效能與精準度同時提升。**刻意不採「vendor 詞集合相等」**：vendor 名與軟體同名時（vendor 就叫 `postgresql`）會把該 vendor 底下全部 product（`psqlodbc`/`pgjdbc`/`pgadmin_4`…）撈回而退化回爆量。同名異 vendor（PuTTY 的 `putty`/`simon_tatham`/`greenend`、Bruno 的 `usebruno`/`yaxim`）因 product 皆等於軟體名，仍以 OR 全數保留。**精確命中 0 筆時 fall back 到下方模糊邏輯**（保留 recall），避免「neo4j community edition」「7-zip」等軟體名與 CPE product 對不齊時整批漏查。由 `lib/scan-software.js` 的 `resolveCpeBases()` 依 `isPortable` 決定（`exact = !isPortable`），CLI／Web Server 共用。

- **模糊模式（`exact=false`，Portable 軟體 / 精確 fall back）**：三個 Pass 依序比對，Pass 0 優先（vendor 單獨含關鍵字），Pass 1（vendor+product 合併含關鍵字），Pass 2 fallback（product 含第一個字）。回傳**所有符合**的 `{vendor, product}` 陣列（OR 邏輯），確保同一軟體不同 vendor 名稱均能命中。

**收斂兩步驟：(1) 詞邊界比對 → (2) vendor 錨定**。`findAllCPEBases` 在三個 Pass 跑完後依序套用：

1. **詞邊界（token）完全相等比對**（取代子字串 `includes`）：三個 Pass 都先用 `tokenize()` 把 CPE 欄位以 `_ - . :` 與空白切成詞陣列，要求 name word 恰好**等於**其中某個詞。理由——短關鍵字（如 `git`）用子字串比對會誤命中任何內含相同字母序列的無關 vendor（`digital`、`legitimate`…），曾使單一軟體爆出 72 組 base，每組都要逐一查 CVE（再乘以日期分段數），效率極差。詞邊界比對不影響既有正確案例（`usebruno:bruno`/`yaxim:bruno` 仍透過 product 詞 `bruno` 命中）。

2. **vendor 錨定**：對「本身就是常見英文字典詞」的關鍵字（如 `line`），詞邊界仍擋不掉大量無關 product 裡的合法 line 詞（`command_line_interface`…，line 詞邊界後仍 41 組）。錨定先找出「vendor / product / 兩者合併」詞集合**恰好等於**關鍵字集合的 base 當錨點（如 `line:line`、`linecorp:line` 的 product 剛好就是 `line`），取其 vendor 集合 `{line, linecorp}`，只保留同 vendor 的 base，擋掉 `amazon`/`horde` 等無關 vendor（line 41→6）。**無任何錨點時維持詞邊界結果、不收斂**（如 `7-zip` 關鍵字被截成 `zip` 找不到錨點，維持 3 組）。

   **為何不用 publisher 加權**：曾評估「用軟體 `publisher` 欄位給 base 打分排序」，但 publisher 與 CPE vendor 命名常不一致——實測 LINE 的 publisher 是 `LY Corporation`，對 `linecorp:line`/`line:line`（本尊）全給 0 分，只有 `lycorp:line_mini_app` 得分，硬過濾會把本尊丟掉導致漏報。故改用不依賴 publisher 命名的 vendor 錨定。
   **已確認接受的 recall 取捨**：第三方衍生工具（`acs:putty_connection_manager`、`bramp:ffmpeg-cli-wrapper`）vendor 與本尊不同會被擋掉，屬刻意的精準度提升。

已用全部 `data/cpe_cache` 快取驗證 bruno/maven/putty/neo4j/docker/webex/7-zip 等零退化或精準度提升。

**多 CPE base 查詢（`fetchSoftwareCVEs`，CLI / Web Server 共用）**：`findAllCPEBases` 找到多個 base 時，必須**逐一查詢每個 base 並依 CVE id 合併去重**，不可只查第一個（曾經的 bug：只查 `cpeBases[0]`，導致第二個 vendor 名稱下的 CVE 永遠不會被查到）。查詢時須以 log 明確標示「查詢 (i/N)CPE：cpe:2.3:a:vendor:product:*」（含目前進度索引），方便追蹤目前查的是哪一個。

**多 CPE base 的「版本/範圍擷取」也必須吃整個陣列（OR 比對），不可只用 `cpeBases[0]`**：關聯性判斷 `cveMatchesCPEBase` 本來就吃整個 base 陣列，但 `extractFixedVersion`／`isVersionInAnyRange`／`getBranchFixVersion`／`extractAllRanges`／`cveExactVersionCheck` 過去只收單一 `cpeBase = cpeBases[0]`，用它的詞做 criteria 詞邊界比對。當第一個 base 與某 CVE 的真正 vendor 不同（如 Bruno 查到 `yaxim:bruno`+`usebruno:bruno`，但 `cpeBases[0]` 是 `yaxim`，CVE 的 criteria 卻是 `usebruno:bruno`），比對要求同時含 `yaxim`+`bruno` → 永遠不符 → 整批屬於其他 vendor 的 CVE 抓不到版本（症狀：CLI 與 WebUI 都顯示 3 筆 CVE、「查無對應版本號／無版本修復資訊」，且 `isVersionInAnyRange` 因無命中而回 `null`，連帶讓 `getBranchFixVersion` 的「已修正」過濾失效）。修正：新增 `_criteriaMatcher(searchName, cpeBase)`，`cpeBase` 可傳單一物件或 base 陣列，criteria 只要「完全符合任一 base 的詞集合」即視為相關（無 cpeBase 時退回 searchName 詞邊界）。呼叫端（`cve-checker.js`、`web-client.src.html`）對這 5 個函式一律改傳整個 `cpeBases` 陣列；`isComparableRecVersion` 仍傳單一 `cpeBase`（它靠 truthy 判斷 keyword/CPE 模式，傳空陣列會誤判）。`cve-checker.js` 的 `results.push` 另存 `cpeBases`，讓升級建議列與 JSON 報表的彙整也用得到陣列。

**CPE 查詢漏掉 NVD 尚未分析的新 CVE → 以 keyword 補撈（`isPendingSupplementCVE`）**：NVD 對剛發布的 CVE 常處於 `Awaiting Analysis`，CNA 已給描述/CVSS 但 NVD 尚未建立 CPE 適用性（`configurations` 為空）。CPE 查詢（`virtualMatchString`）只回傳「已有 CPE 聲明」的 CVE，因此這類新 CVE 會被整批漏掉（實證：FFmpeg `CVE-2026-8461`，CPE 查詢 6 月時間窗回 0 筆、keyword 查詢回 3 筆含它）。對策：以 CPE 查詢的軟體在 CPE 合併後，**再打一次同 `coverageStart` 的 keyword 查詢**，把「CPE 結果沒有、且符合 `isPendingSupplementCVE`」者併入；後續 relevance 對無 CPE 的 CVE 回 `null`、既有邏輯標 `_pendingNvd=true`（顯示「⚠ NVD 分析中」供人工確認）。`isPendingSupplementCVE(cve, cpeBase)` 的兩道守門：(1) `cveHasNoCpe`——有 CPE 卻沒被 CPE 查詢命中＝屬別 vendor（CPE 已正確排除），不可併入；(2) `cveRefsMentionProduct`——**參考連結的「網域 host」或「路徑第一段（GitHub 等的 owner/org）」以「詞邊界完全相等」含本軟體 vendor/product 詞**才算數，擋掉「描述只是提到本軟體、實際屬別產品」的誤命中。**刻意不比對完整路徑、且用詞邊界而非子字串**：(a) 本軟體只是「被呼叫的元件/媒介」時，別產品的 advisory 常把元件名寫進描述型 slug——實證 `CVE-2024-58286`（dizqueTV 的 RCE，FFmpeg 只是被呼叫的執行檔路徑），參考連結 `vulncheck.com/advisories/dizquetv-...-via-ffmpeg-executable-path` 路徑含 ffmpeg，但網域與 GitHub owner（`github.com/vexorian/dizquetv`）都不是 ffmpeg，正確排除；(b) 詞邊界避免短關鍵字子字串誤命中——token `git` 不會命中 owner `gitpython-developers`、token `python` 不會命中 `pythonhosted`。對照真品 `CVE-2026-8461` 的 `code.ffmpeg.org`（host 詞含 ffmpeg）、Python `CVE-2026-3298`/`CVE-2025-4517` 的 `github.com/python/cpython`（owner=python）正確撿回。

**keyword 模式（過於通用的軟體，如 Python/Git）也要撿回無 CPE 的真品**：`relevance` 對「無 CPE」的 CVE 過去一律丟棄（`cveRelevanceCheck` 回 `null` → 過濾，避免關鍵字描述誤報），但這會漏掉 NVD Awaiting Analysis/Deferred、只有 CNA 分數、尚無 CPE 的真品（實證：Python `CVE-2026-3298` 8.8 HIGH、`CVE-2025-4517` 9.4 CRITICAL，皆無 CPE、參考連結指向 `github.com/python/cpython`，但 Python 因 CPE 字典 >2000 走 keyword 模式而被漏掉）。修正：`relevance` 的 `null` 分支改為——CPE 模式（有 cpeBases）一律保留為待分析；**keyword 模式（無 cpeBases）改用 `isPendingSupplementCVE(cve, {vendor:searchName, product:searchName})` 以參考連結 host/owner 守門撿回確屬本軟體者**，其餘才丟棄。撿回者標 `_pendingNvd=true`（顯示「⚠ NVD 分析中」，不納入版本/推薦判斷）。CLI（`cve-checker.js`）與 Web（`web-client.src.html`）一致；Web 端並補上過去缺漏的 `pendingNvdAnalysis` 旗標與顯示。補撈統一在 `lib/scan-software.js` 的 `fetchSoftwareCVEs()`（CPE 合併後），CLI／Web Server 共用。

**推薦版本守門擋掉「日期型版本」（`isComparableRecVersion`）**：NVD 偶爾用 git 快照「日期」當 `versionEndExcluding`（實證：FFmpeg `CVE-2025-25468/25469` 用 `2025-01-13`）。日期字串無法與語意化版本（`7.1`）比較，`compareVersions` 會把 `2025` 當成遠大於 `8`，污染彙整後的「建議升級版本」（出現「建議升級至 ≥ 2025-01-13」）。守門：已安裝版本非日期、修復版本卻是日期（`YYYY-MM-DD` 或 8 碼數字）時，排除其進入推薦彙整——個別 CVE 的「安全版本」仍照 NVD 原樣顯示，資訊不遺失。

**CVSS 取分以 Primary（NVD 官方）優先（`getCvss`）**：一筆 CVE 的 `metrics` 常同時有多組評分，且各有 `type`（`Primary` = NVD 官方 `nvd@nist.gov`／`Secondary` = CNA、廠商自評）。`getCvss` 的取用優先序為 **(1) Primary 勝過 Secondary → (2) 同類取較新 CVSS 版本（4.0 > 3.1 > 3.0 > 2.0）**。**不可**像過去那樣「一律先取 V4.0、且每個版本取陣列 `[0]`」——`[0]` 常是排在前面的 Secondary/CNA 分數，會蓋掉 NVD 官方的 Primary，造成嚴重度誤判（實證：`CVE-2026-2664` Docker 自評 Secondary CVSS4.0 6.8 MEDIUM vs NVD Primary CVSS3.1 7.8 **HIGH**；`CVE-2026-40962` MITRE Secondary CVSS3.1 4.9 MEDIUM 排在 NVD Primary CVSS3.1 9.8 **CRITICAL** 之前——舊邏輯都會取到較低的 Secondary，在 HIGH 門檻被誤濾）。無 Primary（如 Awaiting Analysis 只有 CNA 分數）時退回 Secondary 取較新版本（FFmpeg `CVE-2026-8461` 的 Secondary CVSS3.1 8.8 HIGH 仍正確取得）。此分類對齊 NVD 網站頭條顯示。

**NVD CVE API 限制**：`pubStartDate`/`pubEndDate` 必須成對使用，且範圍上限 120 天，超過回 HTTP 404。`lib/nvd-client.js` 的 `splitDateRange()` 自動將查詢切為多段（每段 ≤ 120 天，由新到舊）。

**年份過濾（`minYear`/`coverageStart`）**：快取以軟體（keyword/CPE）為單位，不是以查詢年份為單位，因此同一份快取可能比本次要求的範圍更廣（例如曾被較寬鬆的 `MIN_YEAR` 查過）。`fetchCVEs()` 在三個回傳路徑（快取命中、增量更新、全量查詢）都會以 `_filterFromStart()` 過濾掉 `published < coverageStart` 的項目，因此**呼叫端（CLI／Web Server）拿到的 `cves` 已經是裁切過的**，不需再自行依年份過濾一次（前端 `web-client.src.html` 也不再做年份過濾）。嚴重度（`MIN_SEVERITY`）則維持在呼叫端過濾，因為快取必須保留全部嚴重度的 CVE，才能讓未來更低門檻的查詢直接複用快取而不漏資料。

**單一軟體的查詢流程只有一份實作（`lib/scan-software.js`）**：過去「決定 cpeBases → 逐 base 查 CVE 合併 → keyword 補撈」在 `cve-checker.js` 與 `web-server.js` 各複製約 80 行，`loadCpeBases`／`loadAliases` 也各一份，改一邊漏另一邊就會行為不一致。現統一由 `lookupSoftwareCVEs()` 處理，回傳 `{ cpeBases, cves, fromCache, newCount }`；呼叫端只負責顯示（CLI 用 `console.log` 上色、Web Server 寫 server log 並以 NDJSON 推給前端）。**log 責任**：流程內只透過 `log(level, msg)`（level：`cache`／`info`／`warn`／`debug`）輸出，`fetchCPEs()` 仍不自行印 log、由 `resolveCpeBases()` 在算出去重後的 base 數量後合併成一行。**CVE 查詢分成「下載增量」與「查詢快取」兩個步驟（`nvd-client` 的 `updateCVECache`／`queryCVECache`）**：過去 `fetchCVEs` 把「補增量進快取」與「從快取取出」混在一起，每天首次執行與平常執行的畫面不同。現拆成兩步，由 `lib/scan-software.js` 的 `fetchSoftwareCVEs` 依序執行四個階段，畫面固定為：`-----下載增量CVE-----`（逐 base `(i/N) cpe:…`；有下載時接 `[CVE 快取] 補查 YYYY-MM-DD 至今的增量(N 段)`／分段進度，今天已更新過則印 `[CVE 快取] 今天已查詢，略過下載`）→ `-----查詢CVE快取-----`（逐 base `[CVE 快取] 命中 N 筆`）→ `-----下載NVD尚未立案增量CVE-----`（keyword 補撈查詢的下載）→ `-----查詢NVD尚未立案CVE快取-----`（`[CVE 快取] 命中 <併入> 筆(共命中 <keyword總數> 筆，<重複>筆上述已重複，<無相關>筆無相關，<cacheNote>)`）。**每天首次執行只是第一、三階段多了下載內容，第二、四階段與每次執行完全相同**。`updateCVECache` 回傳 `{ updated, newCount, cacheNote }`（不回傳 CVE），`queryCVECache` 純讀取不連網；`fetchCVEs` 保留為兩者組合（相容用）。快取停用（`CACHE_DISABLE`）時以記憶體暫存本次下載的資料銜接兩步驟。**所有筆數都是年份（`coverageStart`）與嚴重度門檻套用後的數量**，彼此可對帳（keyword 總數＝併入＋重複＋無相關）；`cacheNote` 有 `今天已查詢`／`已補查 YYYY-MM-DD 至今增量，新增 N 筆`／`首次全量下載並存入快取`／`已接續補查舊資料並存入快取`，只出現在補撈對帳行。階段分隔線與各行訊息一併以 `info`／`cache` 輸出，因此 Web 的進度與 server log 也會看到，與 CLI 一致。**新增/調整查詢步驟只改 `lib/scan-software.js`**，並補 `scripts/test/scan-software.test.js`。

**黑名單（`BLACKLIST`，依軟體名稱略過）**：給「只有名稱、CPE 字典命中過多（如 `Local`）又無法得知完整 CPE（故不能用 `CPE_BASE_N`）」的軟體。與白名單（比對 `publisher`）不同，比對的是**軟體名稱**。語法與比對在 `lib/cve-logic.js` 的 `matchBlacklist(names, rules)`（CLI 與 Web 共用）：不分大小寫、以「詞」為單位（標點、版本號不影響）；`Maven` 含該詞即符合（`Apache Maven 3.8.6` 符合、`Mavenize` 不符合）、多個詞須連續出現、`=Local` 為「名稱完全等於」（避免誤傷 `Local Storage Tool`）；名稱同時以原始名稱與 `cleanProductName` 後的名稱比對。**預設用「詞」而非完全相等**：使用者寫 `Maven` 通常就是想排除 `Apache Maven x.y`，而需要精確時用 `=` 前綴。**為何不能悄悄略過**：黑名單是弱點盲區，所有被略過者一律列出——CLI 結尾「黑名單跳過的軟體」、報表 JSON 的 `blacklisted`（含 `matchedRule`）、HTML 的「黑名單跳過」區塊與儀表板卡片（有黑名單才顯示）、Web 進度與 server log 的筆數。處理順序：白名單 → 黑名單 → SKIP_PATTERNS → 去重。**Portable 不受黑名單影響**（與白名單相同，是使用者明確指定要掃的）。Web 頁面有「黑名單」輸入欄（步驟 3，位於白名單與 Portable 之間），預設值由伺服器依 `.env.local` 的 `BLACKLIST` 注入（與白名單相同：瀏覽器已存過值時以該值為準；比對在前端以 `matchBlacklist` 進行，結果寫入報表 `blacklisted`）。

**Web 的「CVE 最早年份」每次開啟頁面都預設為今年−1（與 CLI 一致），不再記憶在瀏覽器**：過去記住上次的值（曾存成 2024），而 CLI 預設為今年−1（2025），兩者年份不同使得快取涵蓋範圍不足（快取只到 2025-01-01），Web 第一次掃描要把 2024 年那段補下載（14 個軟體、88 個分段、約 93 秒），看起來像「沒用到本機快取」。快取位置本來就相同（`data/`），差別只在要求的年份範圍；改成更早的年份時第一次仍會補下載該段舊資料，補完後涵蓋範圍延伸、之後皆直接命中。

**Console 顏色以「語意樣式」統一管理（`scripts/cve-checker.js` 的 `st`）**：輸出一律用 `st.head`（粗體亮白：每個軟體的標題行 `[i/N] 名稱 v版本`）／`st.title`（粗體：Summary、各清單標題）／`st.step`（青：流程階段分隔線 `-----…-----`）／`st.proc`（灰：Search、CPE、(i/N) 查詢列、快取命中、對帳、描述、略過清單等過程與次要資訊）／`st.good`（綠：安全、無須處理）／`st.warn`（黃：需人工確認，如 ⚠、NVD 尚未立案）／`st.bad`（紅：確認受影響、建議升級、錯誤），**不要在各處直接寫 `c.red` 之類**，要調整只改這裡。嚴重度：CRITICAL 粗紅、HIGH 紅、MEDIUM 黃、LOW 灰（過去 LOW 用青色，與「過程」同色造成混淆）。`cliLog` 依 level 與內容分流：`warn`→黃、以 `-----` 開頭→青、其餘（cache／info／debug）→灰；原本 `cache` 用青色、`info` 用灰色交錯出現是畫面雜亂的主因。小結分組中「確認受影響」粗紅、「NVD 尚未立案」粗黃、其餘說明性分組（無關／已含修復）灰色淡化。非 TTY（導向檔案/管線）或設定 `NO_COLOR` 時自動關閉色碼，`FORCE_COLOR=1` 可強制開啟。此規劃只涵蓋 CLI；Web 進度框另有 `l-ok／l-warn／l-err／l-gray` 樣式類別。

**每個軟體的「掃描小結」要交代每一筆命中 CVE 的去向（`buildCveAnalysis`）**：過去只列「確認受影響＋待分析」，被判為無關或低於嚴重度門檻的 CVE 完全沒有說明，使用者看到前面「命中 3 筆」卻無下文。現於 `-----CVE分析-----` 之後依序分組並編號（空的組不顯示）：(1) 目前版本與這些 CVE 無關（版本不在受影響範圍，附修復版本）(2) 非本軟體（CPE／參考連結不符）(3) 目前版本已含修復（同分支）(4) 確認受影響 (5) NVD 尚未立案、請人工確認。每組最多列 5 筆（發布日期新到舊），其餘以「… and N more」表示。分組、標題與無關清單文字由 `lib/cve-logic.js` 的 `buildCveAnalysis` 產生（`classifyCVE` 另回傳 `mismatchKind`：`version`／`other`），CLI（`console.log` 上色）與 Web（進度框 HTML＋後端 log 純文字，雙軌同步）只負責輸出。**嚴重度門檻在「查詢結果取回的當下」就套用（`fetchSoftwareCVEs` 的 `minSeverity`），低於門檻的 CVE 不算命中、也不進小結**——所有命中筆數與重複/無相關對帳都以門檻以上計算；快取檔仍保留全部嚴重度（供更低門檻的查詢複用）。**新增分組或調整文字只改 `buildCveAnalysis`**，並補 `scripts/test/cve-logic.test.js`。

**單一 CVE 的分類與推薦版本只有一份實作（`classifyCVE`／`getRecommendedVersion`）**：過去「關聯性＋版本範圍＋同分支已修正」的判斷在 `cve-checker.js` 與 `web-client.src.html` 各複製一份（約 60 行），「取最大修復版本」的 `reduce` 更複製 4 處，兩端改一邊漏另一邊就會不一致。現統一在 `lib/cve-logic.js`：`classifyCVE(cve, installedVersion, searchName, cpeBases)` 回傳 `{relevant, pendingNvd, mismatchReason, alreadyFixed, branchFix}`；`getCveFixVersion(v, …)` 取單一 CVE 修復版本（已修正者用同分支修復版）；`getRecommendedVersion(cves, searchName, cpeBases, installedVersion)` 彙整建議升級版本（內含 `isComparableRecVersion` 守門）。CLI 與 Web 只負責呼叫並套用顯示，**新增/調整判斷規則只改 `lib/cve-logic.js`**。已用全部本機 CVE 快取（約 7.4 萬組合）驗證與舊內嵌邏輯逐筆相同；`scripts/test/cve-logic.test.js` 固定關鍵分支。

**關聯性檢查回傳值**：
- `true` = 確認相關，保留
- `false` = 確認不符，列入 `mismatchedCVEs`（不顯示）
- `null` = 無 CPE 資料（NVD 未完成 enrichment），預設過濾。理由：`keywordSearch` 比對描述全文，無 CPE 時無法驗證相關性，無條件保留反而大量誤報。
- **例外 1（CPE 模式）**：有 `cpeBases`（Portable／CPE 已確認）時 `null` 一律標記 `_pendingNvd=true` 保留，供人工確認。
- **例外 2（keyword 模式）**：無 `cpeBases`（過於通用走關鍵字，如 Python/Git）時，改用 `isPendingSupplementCVE(cve, {vendor:searchName, product:searchName})` 以參考連結 host/owner 詞邊界守門——確屬本軟體者標 `_pendingNvd=true` 保留，其餘才過濾（詳見上方 keyword 模式段落）。

**詞邊界比對延伸至關聯性/版本擷取（`_criteriaMatchesWords`）**：`findAllCPEBases` 的「詞邊界（token）比對」原則同樣套用到 `cveRelevanceCheck`、`extractFixedVersion`、`cveExactVersionCheck`、`isVersionInAnyRange`、`getBranchFixVersion`、`extractAllRanges`——這些函式過去用 `criteria.includes(word)` 子字串比對，短關鍵字會誤命中（`git` → git**hub**／git**bucket**／git**python**，`python` → git**python**），導致關鍵字查詢爆出大量無關 CVE。改用 `_criteriaTokenSet()`（以空白、`_ : .` 切詞，**刻意保留 `-` 不切**，讓 `7-zip` 維持完整詞、`go-git` 不被拆出 `git`）後要求關鍵字恰好等於某個詞。注意：產品名「本身就等於關鍵字」的同名異 vendor 案例（`jenkins:git` 外掛、`microsoft:python` 擴充套件）仍會通過詞邊界比對，需靠下一條的推薦版本守門。

**關鍵字查詢的推薦版本守門（`isComparableRecVersion`）**：彙總「建議升級版本」時，keyword 查詢（無 cpeBase）只採計與已安裝版本**主版號相同**的修復版本。理由——同名異 vendor 產品的版本體系不相容（`jenkins:git` 外掛是 `444.vca_b_84d3703c2`、`microsoft:python` 擴充是 `2025.8.1`），`compareVersions` 會把 `444`/`2025` 當成比 Git `2.x`／Python `3.x` 還新而推薦離譜版本。CPE 查詢已精準鎖定 `vendor:product`，**不套用**此限制（避免擋掉合法跨主版號升級）。此限制只作用於彙總後的推薦版本，個別 CVE 的「安全版本」仍照常顯示，資訊不遺失。三個彙總點（`cve-checker.js` 的即時輸出與 JSON 報表、`web-client.src.html` 的掃描）都須一致套用。

**`extractFixedVersion` 三層 fallback（已安裝版本超過所有範圍＝已修復，不可回 null）**：傳入 `installedVersion` 時依精準度由高到低取候選——(1) `inRange`：已安裝版本落在此受影響範圍 → 該分支修復上界（使用者正受影響，最精準）；(2) `sameMajor`：修復版本與已安裝版本同主版號 → 已超出範圍（已修復）時的正解；(3) `global`：全域最大修復版本（保底）。回傳 `inRange || sameMajor || global`。**為何不能像舊版那樣「不在範圍就 continue 掉」**：已安裝版本超過所有受影響範圍其實代表「已修復」，舊版會因此回 `null`，使 `recommendedVersion` 與每筆 `fixedVersion` 全變 null，報表誤判為「待修正／無版本修復資訊」（實測症狀：Bruno 3.4.2 明明 ≥ 修復版 3.2.1 卻顯示「查無對應版本號」）。三層 fallback 同時保住多分支精準度：Node.js 24.15.0 對 `[24.0,24.13)`+`[25.0,25.3)` 仍回 `24.13.0`（同分支）而非全域最大 `25.3.0`。`installedVersion` 未知時沿用全域最大（legacy）。CLI 與 Web UI 共用此函式（Web 由 `build.js` 原樣注入 `lib/cve-logic.js`），行為必然一致。

**升級狀態判斷**（優先順序）：✗ 需升級 → ? 手動確認（有 `recommendedVersion` 但任一 CVE `fixedVersion===null`，或無 `recommendedVersion`） → ✓ 無須升級。**報表（`lib/report-html.js`）依此把需行動項目分成互斥的兩個詳細區塊**：`✗ 待修正套件`（`recommendedVersion` 存在且目前版本低於它）與 `? 待確認套件`（其餘：目前版本未低於任何已知修復版本，但有 CVE 無法判定，如 NVD 尚未分析）。過去全放同一區塊，導致「只有一筆待確認」的軟體（如 Bruno 4.2.1）被當成待修正；儀表板的「建議升級」「請手動確認」兩個數字也曾因判斷條件重疊而重複計算，現已互斥。同一軟體若同時有確定受影響與待確認的 CVE，歸入「待修正」（✗ 優先），待確認的 CVE 以「⚠ NVD 分析中」標記。

### Web 伺服器架構（`scripts/web-server.js`）

**Web 前端只支援 Web Server 模式（已廢除「直連模式」）**：`web-client.html` 一律透過 `POST /api/scan` 由伺服器查 NVD。過去曾支援「雙擊 `web-client.html` 由瀏覽器自己 `fetch()` NVD」的直連模式，已移除——它沒有快取／速率限制共用／CPE 對照表／CVE 查詢頁籤，且前端 `sleep()` 從未定義，查第二筆軟體就會 `ReferenceError`，等於早已不可用。以 `file://` 開啟時，掃描會直接提示「請先執行 `npm run web`」，CVE 查詢頁籤顯示需伺服器的提示。API Key 只由伺服器 `.env.local` 提供，前端已無 API Key 欄位（並清除舊版殘留在瀏覽器 localStorage 的 `nvd_api_key`）。原本只服務直連模式 Portable 預查的 `GET /api/cpe` 端點亦已移除（現存端點：`POST /api/scan`、`GET /api/cve-data`、`POST /api/log`）。

**NDJSON 代理**（`POST /api/scan`）：採單一長連線串流每筆 NVD 結果，避免舊版 per-request 代理因 NVD 6.5s 延遲超過 keepAliveTimeout 導致 socket 被複用時拋出 TypeError。

**全域速率限制**：`nvdSlot()` 以 Promise 鏈確保所有並行 session 共用同一 NVD 計時器，合計速率不超過 `REQUEST_DELAY`。

**NDJSON 標頭順序（與 CLI 一致）**：`scanHandler` 必須在迴圈一開始（CPE 偵測之前）就送出 `{keyword, header:{name,version}}`，前端收到立即印標頭，之後才處理同 keyword 的過程訊息/最終資料行。若等到「最終結果」才印標頭，過程訊息（中途陸續串流回來）會排在標頭之前，順序與 CLI 顛倒。

**CVE 顯示內容對齊 CLI**：即時進度與 `/api/log` 寫入的後端日誌（`logs/server_*.log`）皆採用與 CLI 相同的「掃描小結」結構（見上方 `buildCveAnalysis`）——`-----CVE分析-----` 後依序為各分組（每組最多 5 筆，每筆確認受影響／待分析的 CVE 三行：id/嚴重度/CVSS/日期 → 描述截 130 字 → 安全版本或警告，超過則印 `… and N more`），最後為 `→` 結論行。每個軟體的區塊結束後印一行真正空白行分隔（WebUI 用 `logLine('&nbsp;')`；log 檔用 `slogBlank()`），避免軟體與軟體之間的紀錄黏在一起。

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
