更新專案文件確保內容一致、正確。

---
name: project-document
description: 當使用者要求同步文件與程式碼、更新操作手冊、或詢問現有文件是否正確時使用。
---


## 更新目標

1. **README.md** — 使用者入門說明；重點確認執行指令（npm scripts）、參數說明、Node.js 版本需求是否與 `package.json` 及 `cve-checker.js` 的 `--help` 輸出一致
2. **CLAUDE.md** — 給 Claude AI 參考的架構說明
3. **docs/operator.html** — 操作員使用手冊（HTML 格式，含左側導覽列）

## 更新原則

- **以程式碼為準**：先讀取 `cve-checker.js`、`web-server.js`、`team-report.js` 的實際內容，以及要更新的目標文件目前的內容，再逐段比對；不要根據記憶修改
- 只更新與程式碼實際行為不符的地方，不要改動仍然正確的內容
- 不要修改 `## 專案執行原則` 等人工維護的段落（非從程式碼衍生的規範）
- `docs/operator.html` 使用局部字串替換，不要整個重寫

## 更新完畢後

列出每個文件實際修改了哪些地方（檔名 + 簡述），若某個文件不需要修改請說明原因。
